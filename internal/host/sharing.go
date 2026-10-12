package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func (p *ProxyServer) sharingBackend() metering.SharingBackend {
	b, _ := p.meter.(metering.SharingBackend)
	return b
}
func (p *ProxyServer) webResource(ctx context.Context, t *TunnelConnection) (*pb.WebResource, error) {
	b := p.sharingBackend()
	if b == nil {
		return nil, fmt.Errorf("authority unavailable")
	}
	out, err := b.Sharing(ctx, &pb.SharingRequest{Operation: "get", Owner: t.AccountID, Endpoint: t.TunnelID, ResourceId: t.ResourceID})
	if err != nil {
		return nil, err
	}
	if len(out.Resources) != 1 {
		return nil, fmt.Errorf("resource unavailable")
	}
	return out.Resources[0], nil
}
func webPersonAllowed(r *pb.WebResource, emails []string, creator string, now time.Time) bool {
	return webIdentityAllowed(r, emails, nil, creator, now)
}

func webIdentityAllowed(r *pb.WebResource, emails, groups []string, creator string, now time.Time) bool {
	if r.Mode == "public" {
		return true
	}
	if creator != "" && isEmailBucketAllowed(emails, []string{creator}) {
		return true
	}
	for _, g := range r.People {
		if !g.Revoked && g.ExpiresAt > now.UnixMilli() && strings.HasPrefix(g.Consumer, "group:") {
			for _, membership := range groups {
				if g.Consumer == membership {
					return true
				}
			}
		}
		if !g.Revoked && g.ExpiresAt > now.UnixMilli() && strings.HasPrefix(g.Consumer, "person:") && isEmailBucketAllowed(emails, []string{strings.TrimPrefix(g.Consumer, "person:")}) {
			return true
		}
	}
	return false
}

// Poll once per second and bound authority latency to two seconds: idle SSE and
// WebSocket sessions stop within five seconds, including authority outages.
func (p *ProxyServer) watchWebPermission(r *http.Request, t *TunnelConnection, emails []string, anonymous bool) (*http.Request, func()) {
	ctx, cancel := context.WithCancelCause(r.Context())
	initialOrg, hasOrg := p.getOrgSession(r)
	if hasOrg {
		configured, _ := p.config.OIDCOrg(initialOrg.Org)
		hasOrg = len(emails) == 1 && emails[0] == orgPrincipal(configured, initialOrg.Subject)
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, stop := context.WithTimeout(ctx, 2*time.Second)
				resource, err := p.webResource(check, t)
				stop()
				var groups []string
				orgExpired := false
				if hasOrg && len(emails) > 0 {
					current, valid := p.getOrgSession(r)
					orgExpired = !valid || current.Org != initialOrg.Org || current.Subject != initialOrg.Subject
					if !orgExpired {
						groups = current.Groups
					}
				}
				if err != nil || orgExpired || anonymous && resource.Mode == "private" || len(emails) > 0 && !webIdentityAllowed(resource, emails, groups, t.CreatorEmail, p.currentTime()) {
					if err != nil {
						cancel(&webPermissionError{"permission_authority_unavailable"})
					} else {
						cancel(&webPermissionError{"permission_revoked_or_expired"})
					}
					_ = r.Body.Close()
					return
				}
			}
		}
	}()
	return r.WithContext(ctx), func() { cancel(nil) }
}
func (p *ProxyServer) sharingOwner(w http.ResponseWriter, r *http.Request, browser bool) *storage.Account {
	var email string
	var ok bool
	if browser {
		email, ok = p.getAuthFromCookie(r)
	} else {
		var capability bool
		email, _, capability, ok = p.getAuthFromTunnelBearer(r, &TunnelConnection{})
		ok = ok && !capability
	}
	if !ok {
		http.Error(w, "Owner sign-in required", 401)
		return nil
	}
	if p.storage == nil || !p.storage.Available() || p.sharingBackend() == nil {
		http.Error(w, "Sharing authority unavailable", 503)
		return nil
	}
	a, err := p.storage.GetAccountByEmail(r.Context(), common.NormalizeEmail(email))
	if err != nil || a == nil || a.ID == "" || a.OperationalState != "active" {
		http.Error(w, "Active owner account required", 403)
		return nil
	}
	return a
}
func (p *ProxyServer) handleSharingAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", 403)
		return
	}
	a := p.sharingOwner(w, r, false)
	if a == nil {
		return
	}
	endpoint := strings.TrimPrefix(r.URL.Path, "/api/sharing/")
	in := &pb.SharingRequest{Owner: a.ID, Endpoint: endpoint}
	if r.URL.Path == "/api/sharing" {
		in.Operation = "list"
		in.Endpoint = ""
	} else if !isValidDNSLabel(endpoint) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case "GET":
		if in.Operation == "" {
			in.Operation = "get"
		}
	case "POST", "DELETE":
		if in.Operation == "list" {
			http.Error(w, "Choose a resource", 400)
			return
		}
		if !p.requireAuthOrigin(w, r, true) {
			return
		}
		var input struct {
			Email     string `json:"email"`
			Group     string `json:"group"`
			ExpiresAt int64  `json:"expires_at"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if err := d.Decode(&input); err != nil {
			http.Error(w, "Invalid person or expiry", 400)
			return
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			http.Error(w, "Invalid sharing request", 400)
			return
		}
		in.Email, in.ExpiresAt = input.Email, input.ExpiresAt
		if input.Group != "" {
			if input.Email != "" {
				http.Error(w, "Choose an email or an organization group", 400)
				return
			}
			in.Email = "group:" + input.Group
		}
		if !p.validShareGroup(in.Email, r.Method == "DELETE") {
			http.Error(w, "Unknown organization group", 400)
			return
		}
		if r.Method == "POST" {
			in.Operation = "share"
			if in.ExpiresAt == 0 {
				in.ExpiresAt = time.Now().AddDate(100, 0, 0).UnixMilli()
			}
		} else {
			in.Operation = "unshare"
		}
	default:
		http.Error(w, "Use GET, POST or DELETE", 405)
		return
	}
	out, err := p.sharingBackend().Sharing(r.Context(), in)
	if err != nil {
		writeSharingFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var machine []*pb.Grant
	if in.Endpoint != "" {
		grants, err := p.meter.ListGrants(r.Context(), &pb.ListGrantsRequest{Owner: a.ID, Endpoint: in.Endpoint})
		if err != nil {
			http.Error(w, "Grant authority unavailable", 503)
			return
		}
		machine = grants.Grants
	}
	_ = json.NewEncoder(w).Encode(struct {
		*pb.SharingResponse
		MachineGrants []*pb.Grant `json:"machine_grants,omitempty"`
	}{out, machine})
}

var sharingPage = template.Must(template.New("sharing").Funcs(template.FuncMap{
	"email": func(g *pb.Grant) string { return strings.TrimPrefix(g.Consumer, "person:") },
	"expires": func(g *pb.Grant) string {
		if g.ExpiresAt > time.Now().AddDate(50, 0, 0).UnixMilli() {
			return "No scheduled expiry"
		}
		return time.UnixMilli(g.ExpiresAt).UTC().Format(time.RFC3339)
	},
	"active": func(g *pb.Grant) bool { return !g.Revoked && g.ExpiresAt > time.Now().UnixMilli() },
}).Parse(`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Share access — tunn</title><style>` + baseCSS + `body{max-width:880px;margin:40px auto;padding:24px}table{width:100%;text-align:left}td,th{padding:8px}form{margin:16px 0}button{padding:8px}h1,h2,h3{margin:16px 0}</style></head><body>
<a href="/account">Account</a><h1>Share access</h1>
{{if .Resource}}<h2>{{.Resource.Endpoint}}</h2><p>Access: {{.Resource.Mode}}</p><p>Owner: {{.Owner}}</p>
<input id="link" readonly value="{{.URL}}"><button type="button" onclick="navigator.clipboard.writeText(document.getElementById('link').value)">Copy link</button>
<h3>People and groups who can open this resource</h3><p>The owner always has access. Removing access stops browser requests and open streams within five seconds. Company groups require company sign-in. Group membership is refreshed at sign-in, at least every 15 minutes.</p>
{{range .Resource.People}}{{if active .}}<form method="post"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="email" value="{{email .}}"><p>{{email .}} · {{expires .}} <button name="action" value="unshare">Remove access</button></p></form>{{end}}{{end}}
{{if eq .Resource.Mode "private"}}<form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label>Email <input required type="email" name="email"></label><label>Expires at (UTC, optional) <input type="datetime-local" name="expires"></label><button name="action" value="share">Share</button></form>{{else}}<p>Publish again with the current CLI without --public to make this resource private.</p>{{end}}
{{if and (eq .Resource.Mode "private") .Groups}}<form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label>Company group <select required name="group">{{range .Groups}}<option value="{{.Subject}}">{{.Name}}</option>{{end}}</select></label><label>Expires at (UTC, optional) <input type="datetime-local" name="expires"></label><button name="action" value="share">Share</button></form>{{end}}
{{if .MachineGrants}}<h3>Machine access</h3><p>These credentials are managed separately with tunn grant revoke.</p>{{range .MachineGrants}}{{if active .}}<p>{{.Consumer}} · {{.Id}} · {{expires .}}</p>{{end}}{{end}}{{end}}
<h3>Recent access</h3><table><tr><th>Time (UTC)</th><th>Person / credential</th><th>Result</th></tr>{{range .Events}}<tr><td>{{.Time}}</td><td>{{.Caller}}</td><td>{{.Result}}</td></tr>{{end}}</table>
{{else}}<p>Select a web resource.</p>{{range .Resources}}<p><a href="?tunnel={{.Endpoint}}">{{.Endpoint}}</a> · {{.Mode}}</p>{{end}}{{end}}</body></html>`))

func (p *ProxyServer) handleSharingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", 403)
		return
	}
	if _, ok := p.getAuthFromCookie(r); !ok {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), 302)
		return
	}
	a := p.sharingOwner(w, r, true)
	if a == nil {
		return
	}
	endpoint := r.URL.Query().Get("tunnel")
	in := &pb.SharingRequest{Owner: a.ID, Endpoint: endpoint, Operation: "get"}
	if endpoint == "" {
		in.Operation = "list"
	}
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if endpoint == "" {
			http.Error(w, "Choose a resource", 400)
			return
		}
		if !p.requireCSRFToken(w, r, "sharing:"+endpoint) {
			return
		}
		in.Operation = r.PostFormValue("action")
		in.Email = r.PostFormValue("email")
		if group := r.PostFormValue("group"); group != "" {
			if in.Email != "" {
				http.Error(w, "Choose an email or a company group", 400)
				return
			}
			in.Email = group
		}
		if !p.validShareGroup(in.Email, in.Operation == "unshare") {
			http.Error(w, "Unknown company group", 400)
			return
		}
		if in.Operation != "share" && in.Operation != "unshare" {
			http.Error(w, "Invalid action", 400)
			return
		}
		in.ExpiresAt = time.Now().AddDate(100, 0, 0).UnixMilli()
		if expiry := r.PostFormValue("expires"); expiry != "" {
			at, err := time.Parse("2006-01-02T15:04", expiry)
			if err != nil {
				http.Error(w, "Invalid expiry", 400)
				return
			}
			in.ExpiresAt = at.UnixMilli()
		}
	} else if r.Method != "GET" {
		http.Error(w, "Use GET or POST", 405)
		return
	}
	out, err := p.sharingBackend().Sharing(r.Context(), in)
	if err != nil {
		writeSharingFailure(w, err)
		return
	}
	if r.Method == "POST" {
		http.Redirect(w, r, r.URL.String(), 303)
		return
	}
	data := struct {
		Resource         *pb.WebResource
		Resources        []*pb.WebResource
		MachineGrants    []*pb.Grant
		Owner, URL, CSRF string
		Events           []struct{ Time, Caller, Result string }
		Groups           []struct{ Subject, Name string }
	}{Resources: out.Resources, Owner: a.PrimaryEmail}
	if org, ok := p.getOrgSession(r); ok {
		data.Owner = org.Email
	}
	for _, org := range p.config.OIDCOrgs {
		for _, group := range org.Groups {
			data.Groups = append(data.Groups, struct{ Subject, Name string }{"group:" + org.ID + ":" + group.ID, org.Name + " · " + group.Name})
		}
	}
	if endpoint != "" && len(out.Resources) == 1 {
		data.Resource = out.Resources[0]
		if grants, err := p.meter.ListGrants(r.Context(), &pb.ListGrantsRequest{Owner: a.ID, Endpoint: endpoint}); err == nil {
			data.MachineGrants = grants.Grants
		} else {
			http.Error(w, "Grant authority unavailable", 503)
			return
		}
		data.URL = "https://" + endpoint + "." + p.config.Domain
		data.CSRF, err = p.createCSRFToken(r, "sharing:"+endpoint)
		if err != nil {
			http.Error(w, "Session unavailable", 500)
			return
		}
		if events, err := p.meter.Export(r.Context(), &pb.ExportRequest{Owner: a.ID, Endpoint: endpoint, Month: time.Now().UTC().Format("2006-01")}); err == nil {
			for i := len(events.Events) - 1; i >= 0 && len(data.Events) < 20; i-- {
				e := events.Events[i]
				result := "denied: " + e.Reason
				if e.Allowed {
					result = "allowed"
				}
				data.Events = append(data.Events, struct{ Time, Caller, Result string }{time.UnixMilli(e.StartedAt).UTC().Format(time.RFC3339), e.Caller, result})
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = sharingPage.Execute(w, data)
}

func (p *ProxyServer) loginAuthority() string {
	if p.config.PublicAddr != "" {
		return p.config.PublicAddr
	}
	return p.config.Domain
}

func (p *ProxyServer) validShareGroup(subject string, removing bool) bool {
	if !strings.HasPrefix(subject, "group:") {
		return true
	}
	return p.config.OIDCGroupExists(subject) || removing && config.ValidOIDCGroupSubject(subject)
}

type webPermissionError struct{ reason string }

func (e *webPermissionError) Error() string { return e.reason }

func writeSharingFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, metering.ErrSharingRate) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Sharing rate limit reached; try again shortly", 429)
		return
	}
	if errors.Is(err, metering.ErrCapacity) {
		http.Error(w, "Sharing capacity reached", 429)
		return
	}
	http.Error(w, "Resource unavailable or invalid sharing request", 400)
}
