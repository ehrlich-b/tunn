package host

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Project the ledger into the documented customer view; never export grants,
// caller identities, credentials or admission internals with the request rows.
type auditRow struct {
	ID              string    `json:"id"`
	When            time.Time `json:"when"`
	Endpoint        string    `json:"endpoint"`
	Path            *string   `json:"path"`
	Status          int32     `json:"status"`
	BytesIn         int64     `json:"bytes_in"`
	BytesOut        int64     `json:"bytes_out"`
	DurationMS      int64     `json:"duration_ms"`
	ClientIP        *string   `json:"client_ip"`
	UserAgentFamily *string   `json:"user_agent_family"`
	Finished        bool      `json:"finished"`
}
type auditCursor struct {
	Started int64
	ID      string
}
type auditPageData struct {
	Rows                                                       []auditRow
	Endpoint, StatusClass, Since, Until, CSV, JSON, Next, CSRF string
	Retention                                                  int32
	Saved                                                      bool
}

func auditFilters(r *http.Request, now time.Time) (*pb.AuditRequest, error) {
	q := r.URL.Query()
	in := &pb.AuditRequest{Operation: "list", Endpoint: q.Get("endpoint"), RequestId: q.Get("request_id"), Limit: 50}
	if in.Endpoint != "" && !isValidDNSLabel(in.Endpoint) {
		return nil, fmt.Errorf("Invalid endpoint")
	}
	if in.RequestId != "" && len(in.RequestId) != 32 {
		return nil, fmt.Errorf("Invalid request ID")
	}
	if raw := q.Get("status"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > 5 {
			return nil, fmt.Errorf("Choose a status class from 1xx to 5xx")
		}
		in.StatusClass = int32(v)
	}
	parse := func(key string, fallback time.Time) (int64, error) {
		raw := q.Get(key)
		if raw == "" {
			return fallback.Truncate(time.Second).UnixMilli(), nil
		}
		t, err := time.Parse("2006-01-02T15:04:05", raw)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04", raw)
		}
		if err != nil || t.UnixMilli() <= 0 {
			return 0, fmt.Errorf("Invalid %s time; use UTC", key)
		}
		return t.UnixMilli(), nil
	}
	var err error
	in.Since, err = parse("since", now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	in.Until, err = parse("until", now.Truncate(time.Second).Add(time.Second))
	if err != nil {
		return nil, err
	}
	if in.Until <= in.Since {
		return nil, fmt.Errorf("End time must follow start time")
	}
	if raw := q.Get("cursor"); raw != "" {
		data, err := base64.RawURLEncoding.DecodeString(raw)
		var c auditCursor
		if err != nil || len(raw) > 256 || json.Unmarshal(data, &c) != nil || c.Started <= 0 || len(c.ID) != 32 {
			return nil, fmt.Errorf("Invalid page cursor")
		}
		in.BeforeStarted, in.BeforeId = c.Started, c.ID
	}
	return in, nil
}

func (p *ProxyServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	w = protectResponse(w)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", 403)
		return
	}
	page := r.URL.Path == "/account/audit"
	if r.Method != http.MethodGet && !(page && r.Method == http.MethodPost) {
		w.Header().Set("Allow", "GET")
		if page {
			w.Header().Set("Allow", "GET, POST")
		}
		http.Error(w, "Method not allowed", 405)
		return
	}
	a := p.revenueAccount(w, r)
	if a == nil {
		return
	}
	backend, ok := p.meter.(metering.AuditBackend)
	if !ok {
		http.Error(w, "Audit log unavailable; retry later", 503)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if !p.requireCSRFToken(w, r, "audit-retention") {
			return
		}
		days, err := strconv.Atoi(r.PostFormValue("days"))
		if err != nil || days != 0 && days != 7 && days != 30 && days != 90 {
			http.Error(w, "Choose 7, 30 or 90 days", 400)
			return
		}
		_, err = backend.Audit(r.Context(), &pb.AuditRequest{Owner: a.ID, Operation: "retention", RetentionDays: int32(days)})
		if err != nil {
			http.Error(w, "Could not save retention; retry later", 503)
			return
		}
		http.Redirect(w, r, "/account/audit?saved=1", 303)
		return
	}
	in, err := auditFilters(r, time.Now().UTC())
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	in.Owner = a.ID
	direct := strings.HasPrefix(r.URL.Path, "/api/account/audit/")
	if direct {
		in.RequestId = strings.TrimPrefix(r.URL.Path, "/api/account/audit/")
		if len(in.RequestId) != 32 || strings.Contains(in.RequestId, "/") {
			http.NotFound(w, r)
			return
		}
		in.Since, in.Until, in.BeforeStarted, in.BeforeId = 0, 0, 0, ""
	}
	exporting := r.URL.Path == "/account/audit.csv" || r.URL.Path == "/account/audit.json"
	if exporting {
		in.Limit = metering.MaxEvents
		in.BeforeStarted, in.BeforeId = 0, ""
	}
	out, err := backend.Audit(r.Context(), in)
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			http.Error(w, "Invalid audit filters", 400)
		} else {
			http.Error(w, "Audit log unavailable; retry later", 503)
		}
		return
	}
	if (direct || in.RequestId != "") && len(out.Events) == 0 {
		http.NotFound(w, r)
		return
	}
	rows := make([]auditRow, 0, len(out.Events))
	for _, e := range out.Events {
		rows = append(rows, auditRow{ID: e.RequestId, When: time.UnixMilli(e.StartedAt).UTC(), Endpoint: e.Endpoint, Status: e.Status, BytesIn: e.RequestBytes, BytesOut: e.ResponseBytes, DurationMS: e.DurationMs, Finished: e.Finished})
	}
	if r.URL.Path == "/account/audit.csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="access-audit.csv"`)
		c := csv.NewWriter(w)
		_ = c.Write([]string{"id", "when", "endpoint", "path", "status", "bytes_in", "bytes_out", "duration_ms", "client_ip", "user_agent_family", "finished"})
		for _, v := range rows {
			endpoint := v.Endpoint
			if strings.HasPrefix(endpoint, "=") || strings.HasPrefix(endpoint, "+") || strings.HasPrefix(endpoint, "-") || strings.HasPrefix(endpoint, "@") || strings.HasPrefix(endpoint, "\t") || strings.HasPrefix(endpoint, "\r") {
				endpoint = "'" + endpoint
			}
			_ = c.Write([]string{v.ID, v.When.Format(time.RFC3339Nano), endpoint, "", strconv.Itoa(int(v.Status)), strconv.FormatInt(v.BytesIn, 10), strconv.FormatInt(v.BytesOut, 10), strconv.FormatInt(v.DurationMS, 10), "", "", strconv.FormatBool(v.Finished)})
		}
		c.Flush()
		return
	}
	if direct || r.URL.Path == "/account/audit.json" {
		w.Header().Set("Content-Type", "application/json")
		if exporting {
			w.Header().Set("Content-Disposition", `attachment; filename="access-audit.json"`)
		}
		_ = json.NewEncoder(w).Encode(struct {
			Requests  []auditRow `json:"requests"`
			Retention int32      `json:"retention_days"`
		}{rows, out.RetentionDays})
		return
	}
	q := url.Values{"endpoint": {in.Endpoint}, "status": {r.URL.Query().Get("status")}, "since": {time.UnixMilli(in.Since).UTC().Format("2006-01-02T15:04:05")}, "until": {time.UnixMilli(in.Until).UTC().Format("2006-01-02T15:04:05")}}
	if in.RequestId != "" {
		q.Set("request_id", in.RequestId)
	}
	data := auditPageData{Rows: rows, Endpoint: in.Endpoint, StatusClass: q.Get("status"), Since: q.Get("since"), Until: q.Get("until"), CSV: "/account/audit.csv?" + q.Encode(), JSON: "/account/audit.json?" + q.Encode(), Retention: out.RetentionDays, Saved: r.URL.Query().Get("saved") == "1"}
	if out.HasMore {
		last := out.Events[len(out.Events)-1]
		c, _ := json.Marshal(auditCursor{last.StartedAt, last.RequestId})
		q.Set("cursor", base64.RawURLEncoding.EncodeToString(c))
		data.Next = "/account/audit?" + q.Encode()
	}
	data.CSRF, err = p.createCSRFToken(r, "audit-retention")
	if err != nil {
		http.Error(w, "Session unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = auditPage.Execute(w, data)
}

var auditPage = template.Must(template.New("audit").Funcs(template.FuncMap{"statuses": func() []string { return []string{"1", "2", "3", "4", "5"} }}).Parse(withSiteChrome(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access audit log — tunn</title><style>` + baseCSS + `
.audit{max-width:1200px;margin:32px auto;padding:0 32px 48px}.audit h1{font-size:30px;margin:16px 0 8px}.audit p{margin:10px 0;color:var(--ink2)}.audit section{border:1px solid var(--plate-lo);background:var(--plate);border-radius:10px;padding:20px;margin:24px 0}.audit .filters{display:flex;flex-wrap:wrap;gap:16px;align-items:end}.audit label{display:grid;gap:6px;font-size:13px;font-weight:600}.audit input,.audit select{font:inherit;padding:10px;border:1px solid var(--plate-lo);border-radius:5px;background:var(--glass);color:var(--ink);max-width:100%;min-width:0}.audit .exports{display:flex;gap:20px;flex-wrap:wrap;margin:18px 0}.audit table{border-collapse:collapse;width:100%;font-size:13px}.audit th,.audit td{text-align:left;vertical-align:top;padding:14px 10px;border-bottom:1px solid var(--plate-lo);overflow-wrap:anywhere}.audit th{color:var(--engrave);font-weight:500}.audit .endpoint{font-weight:600}.audit .absent{color:var(--engrave);font-size:12px}.audit .meta{font-size:13px}.audit h2{font-size:18px;margin-bottom:10px}.audit .retention{display:flex;gap:12px;align-items:end;flex-wrap:wrap}.audit nav{margin-top:20px}.audit .notice{padding:12px;background:var(--ok-bg);color:var(--ok-ink);border-radius:5px}
@media(max-width:700px){.audit{margin:20px auto;padding:0 16px 32px}.audit h1{font-size:26px}.audit section{padding:16px}.audit .filters{display:grid;grid-template-columns:minmax(0,1fr);gap:12px}.audit table,.audit tbody{display:block}.audit thead{display:none}.audit tr{display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--plate-lo);border-radius:8px;margin-bottom:16px;padding:8px}.audit td{display:block;border:0;padding:8px;min-width:0}.audit td:before{content:attr(data-label);display:block;font-size:11px;color:var(--engrave);margin-bottom:4px}.audit td:first-child,.audit td:nth-child(2){grid-column:1/-1}}
</style></head><body><!--site-header:none--><main class="audit" id="main"><a href="/account">← Account</a><h1>Access audit log</h1><p>Recent requests to your endpoints. Times are in UTC; byte counts include request and response bodies.</p>
{{if .Saved}}<p class="notice" role="status">Retention saved. Older completed records are removed in background batches. Deleted records cannot be restored.</p>{{end}}
<section aria-label="Filter requests"><form class="filters" method="get"><label>Endpoint<input name="endpoint" maxlength="63" placeholder="All endpoints" value="{{.Endpoint}}"></label><label>Status<select name="status"><option value="">All statuses</option>{{range $v := statuses}}<option value="{{$v}}" {{if eq $.StatusClass $v}}selected{{end}}>{{$v}}xx</option>{{end}}</select></label><label>From (UTC)<input type="datetime-local" step="1" name="since" value="{{.Since}}" required></label><label>Until (UTC, exclusive)<input type="datetime-local" step="1" name="until" value="{{.Until}}" required></label><button class="btn" type="submit">Apply filters</button><a href="/account/audit">Reset</a></form></section>
<div class="exports"><a href="{{.CSV}}">Export CSV</a><a href="{{.JSON}}">Export JSON</a></div><p class="meta">Exports include all retained requests matching these filters. Path, client IP and user agent family are not recorded and appear as absent. Records may be removed earlier when the existing storage capacity is reached.</p>
{{if .Rows}}<table aria-label="Recent endpoint requests"><thead><tr><th>When (UTC)</th><th>Endpoint / path</th><th>Status</th><th>Bytes in / out</th><th>Duration</th><th>Client IP</th><th>User agent</th></tr></thead><tbody>{{range .Rows}}<tr><td data-label="When (UTC)"><a href="/api/account/audit/{{.ID}}"><time datetime="{{.When.Format "2006-01-02T15:04:05Z"}}">{{.When.Format "Jan 02, 2006 15:04:05"}}</time></a></td><td data-label="Endpoint / path"><span class="endpoint">{{.Endpoint}}</span><br><span class="absent">Path not recorded</span></td><td data-label="Status">{{if .Status}}{{.Status}}{{else}}Pending{{end}}{{if not .Finished}}<br><span class="absent">In progress</span>{{end}}</td><td data-label="Bytes in / out">{{.BytesIn}} / {{.BytesOut}}</td><td data-label="Duration">{{if .Finished}}{{.DurationMS}} ms{{else}}In progress{{end}}</td><td data-label="Client IP" class="absent">Not recorded</td><td data-label="User agent family" class="absent">Not recorded</td></tr>{{end}}</tbody></table>{{else}}<section><h2>No matching requests</h2><p>Try another endpoint, status class or time range. Only retained request records are available.</p></section>{{end}}
<nav aria-label="Request pages">{{if .Next}}<a class="btn" href="{{.Next}}">Older requests →</a>{{else}}<p class="meta">End of retained results for these filters.</p>{{end}}</nav>
<section aria-labelledby="retention-title"><h2 id="retention-title">Request retention</h2><p>Choose how long to keep completed request records. This applies to all your endpoints and does not change aggregate usage totals.</p><form class="retention" method="post" action="/account/audit"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label>Keep request records<select name="days"><option value="0" {{if eq .Retention 0}}selected{{end}}>Existing policy (capacity based)</option><option value="7" {{if eq .Retention 7}}selected{{end}}>7 days</option><option value="30" {{if eq .Retention 30}}selected{{end}}>30 days</option><option value="90" {{if eq .Retention 90}}selected{{end}}>90 days</option></select></label><button class="btn" type="submit">Save retention</button></form><p class="meta">Shortening retention permanently removes older completed records. Increasing it cannot recover deleted records.</p></section></main><!--site-footer--></body></html>`)))
