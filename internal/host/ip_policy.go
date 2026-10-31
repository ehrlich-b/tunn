package host

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/ippolicy"
	"github.com/ehrlich-b/tunn/internal/metering"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p *ProxyServer) ipPolicyBackend() metering.IPPolicyBackend {
	b, _ := p.meter.(metering.IPPolicyBackend)
	return b
}

// Admission precedes domain app authentication, grants, sharing and all upstream
// protocols. The authority is read on every request; no fail-open policy cache.
func (p *ProxyServer) checkOwnerIPPolicy(w http.ResponseWriter, r *http.Request, owner, endpoint string) bool {
	if owner == "" {
		return true
	} // unowned self-hosted endpoints
	b := p.ipPolicyBackend()
	if b == nil {
		// Legacy in-process, unmetered fixtures have no durable owner policies.
		if p.meter == nil && !p.planMeter {
			return true
		}
		http.Error(w, "IP policy authority unavailable", 503)
		return false
	}
	parent := r.Context()
	if admission, _ := parent.Value(appAdmissionKey{}).(context.Context); admission != nil {
		parent = admission
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	policy, err := b.IPPolicy(ctx, &pb.IPPolicyRequest{Operation: "get", Owner: owner, Endpoint: endpoint})
	if err != nil || policy == nil {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "IP policy authority unavailable; retry later", 503)
		return false
	}
	peer, _ := p.forwardingPeer(r)
	if ippolicy.Allowed(peer, policy.AllowCidrs, policy.DenyCidrs) {
		return true
	}
	p.writeIPPolicyDenied(w)
	return false
}

func (p *ProxyServer) writeIPPolicyDenied(w http.ResponseWriter) {
	w.Header().Set("Tunn-Limit-Reason", "ip_policy_denied")
	writeBrowserError(w, http.StatusForbidden, browserErrorPage{
		Label: "IP restriction", Title: "Your IP address cannot access this endpoint",
		Detail: "Connect from an allowed network or ask the endpoint owner to update the IP restrictions. Signing in or using a shared link does not bypass this policy.",
		Action: "Try again", Href: "",
	}, p.loginAuthority(), p.statusUnconfigured())
}

func writeIPPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, metering.ErrCapacity), errors.Is(err, metering.ErrSharingRate), status.Code(err) == codes.ResourceExhausted:
		w.Header().Set("Retry-After", "60")
		http.Error(w, "IP policy capacity or update limit reached; retry later", 429)
	case status.Code(err) == codes.InvalidArgument:
		http.Error(w, status.Convert(err).Message(), 400)
	case status.Code(err) == codes.PermissionDenied:
		http.Error(w, "Active owner account required", 403)
	default:
		http.Error(w, "IP policy authority unavailable; retry later", 503)
	}
}

func (p *ProxyServer) handleIPPolicyAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", 403)
		return
	}
	if p.ipPolicyBackend() == nil {
		http.Error(w, "IP policy authority unavailable", 503)
		return
	}
	a := p.sharingOwner(w, r, false)
	if a == nil {
		return
	}
	endpoint := strings.TrimPrefix(r.URL.Path, "/api/ip-policy/")
	if r.URL.Path == "/api/ip-policy" {
		endpoint = ""
	} else if !isValidDNSLabel(endpoint) {
		http.NotFound(w, r)
		return
	}
	in := &pb.IPPolicyRequest{Owner: a.ID, Endpoint: endpoint}
	switch r.Method {
	case http.MethodGet:
		in.Operation = "get"
	case http.MethodPut:
		if !p.requireAuthOrigin(w, r, true) {
			return
		}
		var input *struct {
			Allow []string `json:"allow_cidrs"`
			Deny  []string `json:"deny_cidrs"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		d.DisallowUnknownFields()
		if err := d.Decode(&input); err != nil || input == nil {
			http.Error(w, "Invalid IP policy JSON", 400)
			return
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			http.Error(w, "Expected one IP policy object", 400)
			return
		}
		in.Operation, in.AllowCidrs, in.DenyCidrs = "set", input.Allow, input.Deny
	case http.MethodDelete:
		if !p.requireAuthOrigin(w, r, true) {
			return
		}
		in.Operation = "delete"
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "Use GET, PUT or DELETE", 405)
		return
	}
	out, err := p.ipPolicyBackend().IPPolicy(r.Context(), in)
	if err != nil {
		writeIPPolicyError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

var ipPolicyPage = template.Must(template.New("ip-policy").Parse(`<!doctype html><html lang="en"><head>` + iconHead + `<meta name="viewport" content="width=device-width, initial-scale=1"><title>IP restrictions — tunn</title><style>` + baseCSS + `body{max-width:760px;margin:40px auto;padding:24px}h1{font-size:30px;margin:20px 0}h2{font-size:22px;margin:0 0 12px}section{background:white;border:1px solid #ddd;border-radius:12px;padding:24px;margin:20px 0}label{display:block;margin-top:16px;font-weight:600}textarea{display:block;box-sizing:border-box;width:100%;min-height:110px;margin:8px 0 20px;padding:12px;font:14px monospace;border:1px solid #aaa;border-radius:6px}button,input{box-sizing:border-box;max-width:100%;padding:10px;border:1px solid #aaa;border-radius:6px}button{cursor:pointer;margin:8px 8px 8px 0}p{margin:12px 0;line-height:1.6}.notice{border-left:3px solid #16824b;padding:12px;background:#effaf4}.error{border-left:3px solid #b43232;padding:12px;background:#fff1f1}code{overflow-wrap:anywhere}@media(max-width:480px){body{margin:12px auto;padding:16px}section{padding:18px}}</style></head><body><a href="/account">Account</a><h1>IP restrictions</h1><p>Allow trusted networks and block unwanted addresses before sign-in or sharing.</p>
{{if .Saved}}<p class="notice" role="status">Policy saved. New requests use the current policy.</p>{{end}}{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<section><h2>{{if .Endpoint}}Endpoint: {{.Endpoint}}{{else}}Account default{{end}}</h2>
{{if .Endpoint}}{{if .Inherited}}<p>This endpoint inherits the account default. Saving here replaces that default for this endpoint.</p>{{else}}<p>This endpoint has its own policy. Use the account default to restore inheritance.</p>{{end}}{{else}}<p>Endpoints inherit this policy unless you save an endpoint policy.</p>{{end}}
<p>Deny rules take priority. An empty allow list permits any address except those denied. Enter one IPv4 or IPv6 CIDR per line (up to 64 per list).</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><label for="allow">Allowed CIDRs</label><textarea id="allow" name="allow_cidrs" spellcheck="false" placeholder="203.0.113.0/24&#10;2001:db8::/32">{{.Allow}}</textarea><label for="deny">Denied CIDRs</label><textarea id="deny" name="deny_cidrs" spellcheck="false" placeholder="203.0.113.42/32">{{.Deny}}</textarea><button name="action" value="set">Save policy</button><button name="action" value="delete">{{if .Endpoint}}Use account default{{else}}Clear account default{{end}}</button></form>
<p>Existing open streams keep their admission decision. Account sign-in and policy settings stay reachable so you can recover from a blocked network.</p></section>
<section><h2>Endpoint policy</h2><form method="get"><label for="endpoint">Endpoint name</label><input id="endpoint" name="endpoint" required pattern="[a-z0-9][a-z0-9-]*" maxlength="63" value="{{.Endpoint}}" placeholder="my-app"><button>Edit endpoint</button></form><p><a href="/account/ip-policy">Edit account default</a> · <a href="/docs/ip-restrictions">IP restrictions guide</a></p></section></body></html>`))

type ipPolicyPageData struct {
	Endpoint, CSRF, Allow, Deny, Error string
	Inherited, Saved                   bool
}

func (p *ProxyServer) handleIPPolicyPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", 403)
		return
	}
	if _, ok := p.getAuthFromCookie(r); !ok {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), 302)
		return
	}
	if p.ipPolicyBackend() == nil {
		http.Error(w, "IP policy authority unavailable", 503)
		return
	}
	a := p.sharingOwner(w, r, true)
	if a == nil {
		return
	}
	endpoint := r.URL.Query().Get("endpoint")
	if endpoint != "" && !isValidDNSLabel(endpoint) {
		http.Error(w, "Invalid endpoint name", 400)
		return
	}
	in := &pb.IPPolicyRequest{Owner: a.ID, Endpoint: endpoint, Operation: "get"}
	data := ipPolicyPageData{Endpoint: endpoint, Saved: r.URL.Query().Get("saved") == "1"}
	responseStatus := 200
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		if !p.requireCSRFToken(w, r, "ip-policy:"+endpoint) {
			return
		}
		in.Operation = r.PostFormValue("action")
		if in.Operation != "set" && in.Operation != "delete" {
			http.Error(w, "Invalid policy action", 400)
			return
		}
		if in.Operation == "set" {
			in.AllowCidrs = strings.Fields(r.PostFormValue("allow_cidrs"))
			in.DenyCidrs = strings.Fields(r.PostFormValue("deny_cidrs"))
		}
		if _, err := p.ipPolicyBackend().IPPolicy(r.Context(), in); err != nil {
			if status.Code(err) != codes.InvalidArgument {
				writeIPPolicyError(w, err)
				return
			}
			data.Error = status.Convert(err).Message()
			data.Allow = r.PostFormValue("allow_cidrs")
			data.Deny = r.PostFormValue("deny_cidrs")
			responseStatus = 400
		} else {
			http.Redirect(w, r, "/account/ip-policy?"+url.Values{"endpoint": {endpoint}, "saved": {"1"}}.Encode(), 303)
			return
		}
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Use GET or POST", 405)
		return
	}
	in.Operation = "get"
	in.AllowCidrs = nil
	in.DenyCidrs = nil
	policy, err := p.ipPolicyBackend().IPPolicy(r.Context(), in)
	if err != nil {
		writeIPPolicyError(w, err)
		return
	}
	data.Inherited = policy.Inherited
	if data.Error == "" {
		data.Allow = strings.Join(policy.AllowCidrs, "\n")
		data.Deny = strings.Join(policy.DenyCidrs, "\n")
	}
	data.CSRF, err = p.createCSRFToken(r, "ip-policy:"+endpoint)
	if err != nil {
		http.Error(w, "Session unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(responseStatus)
	_ = ipPolicyPage.Execute(w, data)
}
