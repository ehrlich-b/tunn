package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

const reportBodyLimit = 64 * 1024
const reportPageSize = 50

var reportMu sync.Mutex
var reportPage = template.Must(template.New("report").Parse(`<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Report a bug</title><style>body{font:16px system-ui;margin:0}main{max-width:42rem;margin:auto;padding:24px}label{display:block;margin:1em 0}input,textarea{box-sizing:border-box;width:100%;font:inherit;padding:8px}textarea{min-height:12em} .trap{position:absolute;left:-9999px}button{padding:10px}</style></head><body><main><h1>Report a bug</h1>{{if .}}<p>Report received. ID: {{.}}</p>{{else}}<form method="post"><label>What happened? <textarea name="text" required maxlength="4000"></textarea></label><label>Contact email (optional) <input name="email" type="email"></label><label>Version (optional) <input name="version"></label><label>OS (optional) <input name="os"></label><label class="trap">Website <input name="website" tabindex="-1" autocomplete="off"></label><button>Send report</button></form>{{end}}<footer><a href="/report">Report a bug</a> · <a href="mailto:support@tunn.to">Support</a></footer></main></body></html>`))

type bugReport struct {
	ID        int64  `json:"id"`
	CreatedAt int64  `json:"created_at"`
	Status    string `json:"status"`
	Text      string `json:"text"`
	Email     string `json:"email"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	Website   string `json:"website,omitempty"`
}

func (p *ProxyServer) handleBugReport(w http.ResponseWriter, r *http.Request) {
	if extractTunnelID(r.Host, p.Domain) != "" {
		p.handleWebProxy(w, r)
		return
	}
	peer, _ := p.forwardingPeer(r)
	r = r.Clone(r.Context())
	r.RemoteAddr = peer
	if !p.isLoginNode && r.Method != http.MethodGet {
		p.forwardBugReport(w, r)
		return
	}
	bugReportHandler(store.DB(), w, r)
}
func bugReportHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = reportPage.Execute(w, nil)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, reportBodyLimit)
	var b bugReport
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "Invalid report", 400)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid report", 400)
			return
		}
		b.Text = r.FormValue("text")
		b.Email = r.FormValue("email")
		b.Version = r.FormValue("version")
		b.OS = r.FormValue("os")
		b.Website = r.FormValue("website")
	}
	if strings.TrimSpace(b.Text) == "" || utf8.RuneCountInString(b.Text) > 4000 || len(b.Email) > 320 || len(b.Version) > 256 || len(b.OS) > 256 {
		http.Error(w, "Invalid report", 400)
		return
	}
	if b.Website != "" {
		http.Error(w, "Invalid report", 400)
		return
	}
	if db == nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	now := time.Now().Unix()
	reportMu.Lock()
	defer reportMu.Unlock()
	var hourly, daily int
	if err = db.QueryRow(`SELECT count(*) FROM bug_reports WHERE ip=? AND created_at>?`, ip, now-3600).Scan(&hourly); err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	if err = db.QueryRow(`SELECT count(*) FROM bug_reports WHERE created_at>?`, now-86400).Scan(&daily); err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	if hourly >= 5 || daily >= 200 {
		http.Error(w, "Too many reports", 429)
		return
	}
	res, err := db.Exec(`INSERT INTO bug_reports(created_at,ip,text,email,version,os) VALUES(?,?,?,?,?,?)`, now, ip, b.Text, b.Email, b.Version, b.OS)
	if err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	id, _ := res.LastInsertId()
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"id": id})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = reportPage.Execute(w, id)
}
func (p *ProxyServer) handleBugReportsRead(w http.ResponseWriter, r *http.Request) {
	if extractTunnelID(r.Host, p.Domain) != "" {
		p.handleWebProxy(w, r)
		return
	}
	if !p.isLoginNode {
		p.forwardBugReport(w, r)
		return
	}
	bugReportsRead(store.DB(), os.Getenv("TUNN_REPORTS_TOKEN"), w, r)
}
func bugReportsRead(db *sql.DB, token string, w http.ResponseWriter, r *http.Request) {
	if token == "" {
		http.NotFound(w, r)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	gotHash, tokenHash := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(token))
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(gotHash[:], tokenHash[:]) != 1 {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	since := int64(0)
	var err error
	if r.URL.Query().Get("since") != "" {
		since, err = strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		if err != nil || since < 0 {
			http.Error(w, "Invalid id", 400)
			return
		}
	}
	if db == nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	rows, err := db.Query(`SELECT id,created_at,status,text,email,version,os FROM bug_reports WHERE status='new' AND id>? ORDER BY id LIMIT ?`, since, reportPageSize)
	if err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	defer rows.Close()
	out := []bugReport{}
	for rows.Next() {
		var b bugReport
		if rows.Scan(&b.ID, &b.CreatedAt, &b.Status, &b.Text, &b.Email, &b.Version, &b.OS) != nil {
			http.Error(w, "Unavailable", 503)
			return
		}
		out = append(out, b)
	}
	if rows.Err() != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// forwardBugReport uses the authenticated internal connection to reach the durable store.
func (p *ProxyServer) forwardBugReport(w http.ResponseWriter, r *http.Request) {
	p.loginNodeMu.RLock()
	conn := p.loginNodeConn
	p.loginNodeMu.RUnlock()
	if conn == nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, reportBodyLimit+1))
	if err != nil || len(body) > reportBodyLimit {
		http.Error(w, "Invalid report", 400)
		return
	}
	req := &internalv1.BugReportHTTPRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body, ContentType: r.Header.Get("Content-Type"), Authorization: r.Header.Get("Authorization"), RemoteAddr: r.RemoteAddr}
	response, err := internalv1.NewLoginNodeDBClient(conn).BugReportHTTP(r.Context(), req)
	if err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", response.ContentType)
	w.WriteHeader(int(response.Code))
	_, _ = w.Write(response.Body)
}

func (s *LoginNodeDBServer) BugReportHTTP(ctx context.Context, in *internalv1.BugReportHTTPRequest) (*internalv1.BugReportHTTPResponse, error) {
	if len(in.Body) > reportBodyLimit || (in.Method != "GET" && in.Method != "POST") || (in.Path != "/report" && in.Path != "/ops/reports") {
		return nil, fmt.Errorf("invalid report request")
	}
	r := httptest.NewRequest(in.Method, in.Path, bytes.NewReader(in.Body)).WithContext(ctx)
	r.URL.RawQuery = in.Query
	r.RemoteAddr = in.RemoteAddr
	r.Header.Set("Content-Type", in.ContentType)
	r.Header.Set("Authorization", in.Authorization)
	w := httptest.NewRecorder()
	db := s.reportDB
	if db == nil {
		db = store.DB()
	}
	if in.Path == "/report" {
		bugReportHandler(db, w, r)
	} else {
		bugReportsRead(db, os.Getenv("TUNN_REPORTS_TOKEN"), w, r)
	}
	return &internalv1.BugReportHTTPResponse{Code: int32(w.Code), Body: w.Body.Bytes(), ContentType: w.Header().Get("Content-Type")}, nil
}
