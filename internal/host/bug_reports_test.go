package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestBugReports(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	post := func(text, ip string) int {
		r := httptest.NewRequest("POST", "/report", strings.NewReader(text))
		r.RemoteAddr = ip + ":123"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		bugReportHandler(db, w, r)
		return w.Code
	}
	if got := post(`{"text":"<script>alert(1)</script>"}`, "1.2.3.4"); got != 200 {
		t.Fatal(got)
	}
	for i := 0; i < 4; i++ {
		if post(`{"text":"hello"}`, "1.2.3.4") != 200 {
			t.Fatal("unexpected limit")
		}
	}
	if post(`{"text":"hello"}`, "1.2.3.4") != 429 {
		t.Fatal("missing hourly limit")
	}
	if post(`{"text":"`+strings.Repeat("x", 4001)+`"}`, "1.2.3.5") != 400 {
		t.Fatal("missing size limit")
	}
	for i := 0; i < 195; i++ {
		_, err = db.Exec(`INSERT INTO bug_reports(created_at,ip,text,email,version,os) VALUES(strftime('%s','now'),?,'x','','','')`, i)
		if err != nil {
			t.Fatal(err)
		}
	}
	if post(`{"text":"hello"}`, "1.2.3.6") != 429 {
		t.Fatal("missing daily limit")
	}
	for _, tc := range []struct {
		token, header string
		want          int
	}{{"", "", 404}, {"secret", "Bearer wrong", 401}, {"secret", "Bearer secret", 200}} {
		r := httptest.NewRequest("GET", "/ops/reports?since=0", nil)
		r.Header.Set("Authorization", tc.header)
		w := httptest.NewRecorder()
		bugReportsRead(db, tc.token, w, r)
		if w.Code != tc.want {
			t.Fatal(w.Code)
		}
		if tc.want == 200 && (bytes.Contains(w.Body.Bytes(), []byte("<script>")) || !bytes.Contains(w.Body.Bytes(), []byte(`\u003cscript\u003e`))) {
			t.Fatal(w.Body.String())
		}
	}
}

// TestReportScreenshotServer serves the actual handler for local visual checks.
func TestReportScreenshotServer(t *testing.T) {
	addr := os.Getenv("TUNN_REPORT_SCREENSHOT_ADDR")
	if addr == "" {
		t.Skip("visual check only")
	}
	t.Fatal(http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { bugReportHandler(nil, w, r) })))
}

func TestBugReportRemote(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	internalv1.RegisterLoginNodeDBServer(server, &LoginNodeDBServer{reportDB: db})
	go server.Serve(listener)
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///reports", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	proxy := &ProxyServer{loginNodeConn: conn}
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest("POST", "/report", strings.NewReader(`{"text":"remote"}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "192.0.2.1:123"
		w := httptest.NewRecorder()
		proxy.forwardBugReport(w, r)
		want := 200
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	t.Setenv("TUNN_REPORTS_TOKEN", "secret")
	r := httptest.NewRequest("GET", "/ops/reports?since=4", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	proxy.forwardBugReport(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":5`) || strings.Contains(w.Body.String(), `"id":4`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// TestReportPaginationAndUnicode exercises the gRPC forwarding path with a backlog
// whose unbounded JSON representation exceeds the default gRPC message limit.
func TestReportPaginationAndUnicode(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	internalv1.RegisterLoginNodeDBServer(server, &LoginNodeDBServer{reportDB: db})
	go server.Serve(listener)
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///reports", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	proxy := &ProxyServer{loginNodeConn: conn}
	form := url.Values{"text": {strings.Repeat("界", 4000)}}.Encode()
	r := httptest.NewRequest("POST", "/report", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.5:123"
	w := httptest.NewRecorder()
	proxy.forwardBugReport(w, r)
	if w.Code != 200 {
		t.Fatalf("unicode: %d %s", w.Code, w.Body.String())
	}
	for i := 0; i < 180; i++ {
		if _, err := db.Exec(`INSERT INTO bug_reports(created_at,ip,text,email,version,os) VALUES(1,? ,?,'','','')`, i, strings.Repeat("<", 4000)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TUNN_REPORTS_TOKEN", "secret")
	var since int64
	count := 0
	for {
		r := httptest.NewRequest("GET", fmt.Sprintf("/ops/reports?since=%d", since), nil)
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		proxy.forwardBugReport(w, r)
		if w.Code != 200 {
			t.Fatalf("page: %d %s", w.Code, w.Body.String())
		}
		var page []bugReport
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > reportPageSize {
			t.Fatal("unbounded page")
		}
		for _, report := range page {
			if report.ID <= since {
				t.Fatal("page did not advance")
			}
			since = report.ID
			count++
		}
	}
	if count != 181 {
		t.Fatalf("got %d reports", count)
	}
}
