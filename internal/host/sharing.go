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
	"sort"
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
	return webExplicitIdentityAllowed(r, emails, groups, creator, now)
}

func webExplicitIdentityAllowed(r *pb.WebResource, emails, groups []string, creator string, now time.Time) bool {
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
	var email, header string
	var ok bool
	if browser {
		email, ok = p.getAuthFromCookie(r)
	} else {
		var capability bool
		email, header, capability, ok = p.getAuthFromTunnelBearer(r, &TunnelConnection{})
		ok = ok && !capability
	}
	signedOut := func() {
		if browser {
			http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), 302)
		} else {
			http.Error(w, "Owner sign-in required", 401)
		}
	}
	if !ok {
		signedOut()
		return nil
	}
	if p.storage == nil || !p.storage.Available() || p.sharingBackend() == nil {
		http.Error(w, "Sharing authority unavailable", 503)
		return nil
	}
	var a *storage.Account
	var err error
	if browser {
		if claims, valid := p.accountSession(r); valid {
			a, err = p.browserSessionAccount(w, r, claims)
		} else {
			a, err = p.storage.GetAccountByEmail(r.Context(), common.NormalizeEmail(email))
		}
	} else {
		a, err = p.bearerAccount(r, email, header)
	}
	if !browser && (err != nil || a == nil) {
		http.Error(w, "Active owner account required", 403)
		return nil
	}
	if err != nil {
		http.Error(w, "Sharing authority unavailable", 503)
		return nil
	}
	if a == nil {
		signedOut()
		return nil
	}
	if a.ID == "" || a.OperationalState != "active" {
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
			return ""
		}
		return time.UnixMilli(g.ExpiresAt).UTC().Format("Jan 2, 2006 · 15:04 UTC")
	},
	"active":     func(g *pb.Grant) bool { return !g.Revoked && g.ExpiresAt > time.Now().UnixMilli() },
	"personName": sharingPersonName,
	"moreCount":  func(n int) int { return n - 4 },
}).Parse(withSiteChrome(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Share access — tunn</title><style>` + baseCSS + sharingCSS + `</style><script defer src="/assets/ui.js"></script></head><body><!--site-header:none--><main id="main" class="page-container management sharing">
<a href="/account">Account</a><h1>Share access</h1>
{{if .Resource}}
<div class="sharing-selection"><form method="get"><label for="tunnel">Tunnel</label><div class="sharing-picker"><select id="tunnel" name="tunnel">{{range .Resources}}<option value="{{.Endpoint}}" {{if eq .Endpoint $.Resource.Endpoint}}selected{{end}}>{{.Endpoint}}</option>{{end}}</select><button class="btn">Choose</button></div></form><span class="tag">{{if eq .Resource.Mode "private"}}Private{{else}}Public{{end}}</span></div>
{{if eq .Resource.Mode "private"}}<form class="sharing-add" method="post" action="?tunnel={{.Resource.Endpoint}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="person-email">Email</label><div class="sharing-add-controls"><input id="person-email" required type="email" name="email" autocomplete="email" placeholder="person@example.com"><button class="btn sig" name="action" value="share">Share</button></div><details class="sharing-expiry"><summary>Set expiry</summary><label>Expires at (UTC) <input type="datetime-local" name="expires"></label><p class="fine">Leave blank for ongoing access.</p></details></form>{{else}}<p>To make this tunnel private, update tunn and publish again without <code>--public</code>.</p>{{end}}
<div class="sharing-link"><p>{{if eq .Resource.Mode "private"}}Only you and people with access can open this link.{{else}}Anyone with this link can open it.{{end}}</p><div class="link-tools"><input id="link" type="text" aria-label="Shared link" readonly value="{{.URL}}"><button class="btn" type="button" data-copy="{{.URL}}" data-copy-kind="link" aria-describedby="sharing-copy">Copy link</button></div><div id="sharing-copy" class="copy-status" role="status"></div></div>
<h2>People with access</h2><p class="fine">You ({{.Owner}}) always have access.</p>
<div class="sharing-people">{{range $i, $person := .People}}{{if eq $i 4}}<details class="sharing-more"><summary>+{{moreCount (len $.People)}} more</summary>{{end}}<form class="sharing-person" method="post" action="?tunnel={{$.Resource.Endpoint}}"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="email" value="{{email .}}"><div><span class="sharing-name">{{personName .Consumer $.Groups}}</span>{{with expires .}}<span class="sharing-until">Expires {{.}}</span>{{end}}</div><button class="btn" name="action" value="unshare" aria-label="Remove access for {{personName .Consumer $.Groups}}">Remove access</button></form>{{end}}{{if gt (len .People) 4}}</details>{{end}}</div>
<p class="fine">Removing access blocks requests and closes open connections within five seconds.</p>
{{if and (eq .Resource.Mode "private") .Groups}}<details class="sharing-groups"><summary>Add a company group</summary><p>Company groups require company sign-in.</p><form class="sharing-add" method="post" action="?tunnel={{.Resource.Endpoint}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label>Company group <select required name="group">{{range .Groups}}<option value="{{.Subject}}">{{.Name}}</option>{{end}}</select></label><details class="sharing-expiry"><summary>Set expiry</summary><label>Expires at (UTC) <input type="datetime-local" name="expires"></label></details><button class="btn sig" name="action" value="share">Share</button></form></details>{{end}}
{{if .MachineGrants}}<details><summary>Machine access</summary><p>Manage access keys with <code>tunn grant revoke</code>.</p>{{range .MachineGrants}}{{if active .}}<p>Access key <code>{{.Id}}</code>{{with expires .}} · Expires {{.}}{{end}}</p>{{end}}{{end}}</details>{{end}}
<details class="sharing-recent"><summary>Recent access</summary>{{if .Events}}<table><thead><tr><th>Time (UTC)</th><th>Visitor</th><th>Outcome</th></tr></thead><tbody>{{range .Events}}<tr><td>{{.Time}}</td><td>{{.Caller}}</td><td>{{.Result}}</td></tr>{{end}}</tbody></table>{{else}}<p>No recent visits.</p>{{end}}</details>
{{else}}<h2>No tunnels to share yet</h2><p>Start a private tunnel, then add people here.</p><p><a class="btn sig" href="/docs#s1">Start a tunnel</a></p>{{end}}</main><!--site-footer--></body></html>`)))

const sharingCSS = `
.sharing .sharing-selection{display:flex;align-items:center;gap:12px;margin:16px 0}
.sharing .sharing-selection form{flex:1;min-width:0;margin:0}
.sharing .sharing-selection label{margin:0}
.sharing .sharing-picker{display:flex;align-items:center;gap:8px}
.sharing .sharing-picker select{flex:1;width:100%;margin:0}
.sharing .sharing-selection .tag{align-self:flex-end;margin-bottom:8px}
.sharing .sharing-add{margin:20px 0}
.sharing .sharing-add>label{margin:0 0 4px}
.sharing .sharing-add-controls{display:flex;gap:8px;align-items:center}
.sharing .sharing-add-controls input{flex:1;width:100%;margin:0}
.sharing .sharing-expiry{margin:8px 0;color:var(--engrave);font-size:13px}
.sharing summary{cursor:pointer;padding:6px 0}
.sharing .sharing-link p{font-size:13px;margin:0 0 8px}
.sharing .sharing-link .link-tools{flex-wrap:nowrap;gap:8px}
.sharing .sharing-link input{width:100%;flex-basis:0;font-size:13px}
.sharing .sharing-person{display:flex;align-items:center;gap:12px;justify-content:space-between;margin:0;padding:12px 0;border-bottom:1px solid var(--plate-lo)}
.sharing .sharing-person>div{min-width:0}
.sharing .sharing-name{display:block;overflow-wrap:anywhere}
.sharing .sharing-until{display:block;color:var(--engrave);font-size:12px}
.sharing .sharing-person .btn{flex:none;font-size:13px;padding:8px;min-height:44px}
.sharing .sharing-recent,.sharing .sharing-groups{margin-top:20px;border-top:1px solid var(--plate-lo);padding-top:8px}
@media(max-width:760px){.sharing .sharing-selection{align-items:flex-start}.sharing .sharing-selection .tag{margin-bottom:6px}.sharing .sharing-person{gap:8px}.sharing .sharing-person .btn{max-width:88px}.sharing h1{margin-top:8px}}
`

func sharingPersonName(subject string, groups []struct{ Subject, Name string }) string {
	for _, group := range groups {
		if subject == group.Subject {
			return group.Name
		}
	}
	if strings.HasPrefix(subject, "person:") {
		return strings.TrimPrefix(subject, "person:")
	}
	if strings.HasPrefix(subject, "email:") {
		return strings.TrimPrefix(subject, "email:")
	}
	if strings.HasPrefix(subject, "group:") {
		return "Company group"
	}
	if subject == "anonymous" || subject == "" {
		return "Signed-out visitor"
	}
	return "Access key"
}

func sharingOutcome(e *pb.Event) string {
	if e.Allowed {
		return "Access allowed"
	}
	switch e.Reason {
	case "authentication_required":
		return "Sign-in required"
	case "allowlist_denied", "ip_policy_denied":
		return "Access denied"
	case "grant_expired":
		return "Access expired"
	case "grant_revoked", "permission_revoked_or_expired":
		return "Access removed or expired"
	case "account_quota", "owner_byte_budget", "owner_request_budget", "bandwidth_rate":
		return "Usage limit reached"
	case "endpoint_offline":
		return "Tunnel offline"
	case "permission_authority_unavailable", "ip_policy_authority_unavailable", "meter_unavailable", "account_unavailable":
		return "Temporarily unavailable"
	default:
		return "Access denied"
	}
}

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
	var resources []*pb.WebResource
	if r.Method == "GET" {
		listed, err := p.sharingBackend().Sharing(r.Context(), &pb.SharingRequest{Owner: a.ID, Operation: "list"})
		if err != nil {
			writeSharingFailure(w, err)
			return
		}
		resources = listed.Resources
		if endpoint == "" && len(resources) > 0 {
			endpoint = resources[0].Endpoint
			in.Endpoint = endpoint
			in.Operation = "get"
		}
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
		People           []*pb.Grant
		Resources        []*pb.WebResource
		MachineGrants    []*pb.Grant
		Owner, URL, CSRF string
		Events           []struct{ Time, Caller, Result string }
		Groups           []struct{ Subject, Name string }
	}{Resources: resources, Owner: a.PrimaryEmail}
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
		for _, person := range data.Resource.People {
			if !person.Revoked && person.ExpiresAt > time.Now().UnixMilli() {
				data.People = append(data.People, person)
			}
		}
		ongoing := time.Now().AddDate(50, 0, 0).UnixMilli()
		sort.SliceStable(data.People, func(i, j int) bool {
			a, b := data.People[i], data.People[j]
			if (a.ExpiresAt > ongoing) != (b.ExpiresAt > ongoing) {
				return a.ExpiresAt < b.ExpiresAt
			}
			if a.ExpiresAt <= ongoing && a.ExpiresAt != b.ExpiresAt {
				return a.ExpiresAt < b.ExpiresAt
			}
			return sharingPersonName(a.Consumer, data.Groups) < sharingPersonName(b.Consumer, data.Groups)
		})
		if grants, err := p.meter.ListGrants(r.Context(), &pb.ListGrantsRequest{Owner: a.ID, Endpoint: endpoint}); err == nil {
			data.MachineGrants = grants.Grants
		} else {
			http.Error(w, "Grant authority unavailable", 503)
			return
		}
		data.URL = relayPublicURL(p.config.Domain, p.config.PublicAddr, endpoint)
		data.CSRF, err = p.createCSRFToken(r, "sharing:"+endpoint)
		if err != nil {
			http.Error(w, "Session unavailable", 500)
			return
		}
		if events, err := p.meter.Export(r.Context(), &pb.ExportRequest{Owner: a.ID, Endpoint: endpoint, Month: time.Now().UTC().Format("2006-01")}); err == nil {
			for i := len(events.Events) - 1; i >= 0 && len(data.Events) < 20; i-- {
				e := events.Events[i]
				data.Events = append(data.Events, struct{ Time, Caller, Result string }{time.UnixMilli(e.StartedAt).UTC().Format("Jan 2, 15:04"), sharingPersonName(e.Caller, data.Groups), sharingOutcome(e)})
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
