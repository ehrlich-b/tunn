package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	qrcode "github.com/skip2/go-qrcode"
	"google.golang.org/grpc/status"
)

const appDevicesCSRFAction = "/api/app-devices"

// Enrollment resolves a live publisher and the immutable sharing generation.
// No offline hostname or capability can create a credential.
func (p *ProxyServer) appEnrollmentScope(ctx context.Context, host string) (appDevice, *TunnelConnection, *storage.Account, error) {
	if host == "" || host != requestHostname(host) || strings.ContainsAny(host, "/:?#@ \\\r\n") || len(host) > 253 || p.domains == nil {
		return appDevice{}, nil, nil, appProblem(400, "Enter an exact app hostname")
	}
	binding, err := p.domains.Route(ctx, &domainpb.Domain{Name: host})
	if err != nil {
		return appDevice{}, nil, nil, appProblem(appDomainStatus(err), "App hostname authority unavailable")
	}
	if binding == nil || !strings.HasPrefix(binding.Name, "*.") {
		return appDevice{}, nil, nil, appProblem(403, "Only a reserved wildcard app supports device credentials")
	}
	t, exists := p.tunnelServer.GetTunnel(binding.Tunnel)
	if !exists {
		for _, client := range p.nodeClients {
			out, e := client.FindTunnel(ctx, &internalpb.FindTunnelRequest{TunnelId: binding.Tunnel})
			if e == nil && out.Found {
				t = &TunnelConnection{TunnelID: binding.Tunnel, AccountID: out.AccountId, CreatorEmail: out.CreatorEmail, ResourceID: out.ResourceId, TargetURL: out.EndpointKind, AllowedEmails: out.AllowedEmails}
				break
			}
		}
	}
	if t == nil {
		return appDevice{}, nil, nil, appProblem(503, "App publisher is offline")
	}
	owner, err := p.currentTunnelAccount(ctx, t)
	if err != nil {
		return appDevice{}, nil, nil, err
	}
	if owner == nil || owner.ID != binding.Owner || owner.OperationalState != "active" || t.ResourceID == "" {
		return appDevice{}, nil, nil, appProblem(403, "App publisher, namespace or resource is unavailable")
	}
	if _, err = p.webResource(ctx, t); err != nil {
		return appDevice{}, nil, nil, err
	}
	return appDevice{Host: host, Namespace: binding.CnameTarget, Publisher: owner.ID, Endpoint: t.TunnelID, Resource: t.ResourceID}, t, owner, nil
}

func appDomainStatus(err error) int {
	// Match routing's authority-denial distinctions without exposing proof metadata.
	switch status.Code(err).String() {
	case "PermissionDenied", "NotFound", "FailedPrecondition":
		return 403
	default:
		return 503
	}
}

func (p *ProxyServer) browserAppDeviceAccount(w http.ResponseWriter, r *http.Request) (*storage.Account, string, bool) {
	session, ok := p.accountSession(r)
	if !ok {
		if r.URL.Path == "/account/app-devices" {
			http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape("https://"+p.loginAuthority()+r.URL.RequestURI()), 302)
		} else {
			http.Error(w, "Browser sign-in required", 401)
		}
		return nil, "", false
	}
	account, err := p.sessionAccount(r, session)
	if err != nil {
		appAuthenticationError(w, 503)
		return nil, "", false
	}
	if account == nil || account.OperationalState != "active" {
		appAuthenticationError(w, 403)
		return nil, "", false
	}
	email, _ := session["email"].(string)
	return account, email, true
}

func (p *ProxyServer) invitationAccess(ctx context.Context, i *appInvitation) error {
	scope, t, owner, err := p.appEnrollmentScope(ctx, i.Host)
	if err != nil {
		return err
	}
	if scope.Namespace != i.Namespace || scope.Resource != i.Resource || scope.Publisher != i.Publisher || scope.Endpoint != i.Endpoint {
		return appProblem(403, "App scope changed; create a new invitation")
	}
	r := &http.Request{Host: i.Host, Header: make(http.Header)}
	r = r.WithContext(ctx)
	if code := p.appDeviceScopeAccess(r, i.appDevice, owner, t); code != 200 {
		return appProblem(code, "Invitation account or app permission is no longer valid")
	}
	return nil
}

func appJSONInput(w http.ResponseWriter, r *http.Request, out any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		http.Error(w, "Invalid device request", 400)
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "Invalid device request", 400)
		return false
	}
	return true
}
func appDeviceHTTPError(w http.ResponseWriter, err error) {
	code := appStatus(err)
	if code == 429 {
		w.Header().Set("Retry-After", "5")
	}
	message := "App device authority unavailable"
	if code != 503 {
		message = err.Error()
	}
	writeOAuthJSON(w, code, map[string]any{"error": message})
}

func (p *ProxyServer) handleAppDevices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	_, proto := p.forwardingPeer(r)
	if !p.isPlatformHost(r.Host) || proto != "https" {
		http.Error(w, "App devices require the trusted HTTPS login origin", 403)
		return
	}
	if _, explicit, _ := appCredential(r); explicit {
		appAuthenticationError(w, 401)
		return
	}
	if r.URL.Path == "/api/app-devices/script" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, appDevicesJS)
		return
	}
	if p.appDevices == nil {
		p.loginNodeMu.RLock()
		addr := p.loginNodeHTTPAddr
		p.loginNodeMu.RUnlock()
		if addr != "" && r.Header.Get("Tunn-App-Devices-Forwarded") == "" {
			clone := r.Clone(r.Context())
			clone.Header = r.Header.Clone()
			clone.Header.Set("Tunn-App-Devices-Forwarded", "1")
			p.proxyToNode(w, clone, addr, "")
			return
		}
		appAuthenticationError(w, 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if r.URL.Path == "/pair/app-device" && r.Method == "GET" {
		p.renderAppDevices(w, appDevicesPageData{Phone: true, Authority: "https://" + p.loginAuthority()})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/app-devices")
	if r.Method == "POST" && path == "/claims" {
		if !p.requireAuthOrigin(w, r, true) {
			return
		}
		source, _ := p.forwardingPeer(r)
		if err := p.appDevices.admitClaimSource(ctx, source); err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		var in struct {
			Invitation string `json:"invitation"`
			Challenge  string `json:"code_challenge"`
			Method     string `json:"code_challenge_method"`
			Name       string `json:"name"`
			Host       string `json:"hostname"`
		}
		if !appJSONInput(w, r, &in) {
			return
		}
		if in.Method != "S256" {
			http.Error(w, "S256 is required", 400)
			return
		}
		i, err := p.appDevices.claim(ctx, in.Invitation, in.Challenge, in.Name, in.Host)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		if err = p.invitationAccess(ctx, i); err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		writeOAuthJSON(w, 201, i)
		return
	}
	if r.Method == "POST" && strings.HasPrefix(path, "/claims/") && strings.HasSuffix(path, "/redeem") {
		if !p.requireAuthOrigin(w, r, true) {
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/claims/"), "/redeem")
		var in struct {
			Verifier  string `json:"code_verifier"`
			Host      string `json:"hostname"`
			Phrase    string `json:"phrase"`
			Confirmed bool   `json:"confirmed"`
		}
		if !appJSONInput(w, r, &in) {
			return
		}
		i, err := p.appDevices.invitation(ctx, "claim", id)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		if err = p.invitationAccess(ctx, i); err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		d, secret, err := p.appDevices.redeem(ctx, id, in.Verifier, in.Host, in.Phrase, in.Confirmed)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		writeOAuthJSON(w, 201, map[string]any{"access_token": secret, "token_type": "Bearer", "expires_at": d.Expires, "device": d})
		return
	}
	account, email, ok := p.browserAppDeviceAccount(w, r)
	if !ok {
		return
	}
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", 400)
			return
		}
		if !p.requireCSRFToken(w, r, appDevicesCSRFAction) {
			return
		}
	}
	host := r.URL.Query().Get("host")
	if r.Method == "POST" {
		host = r.PostForm.Get("hostname")
	}
	if r.Method == "POST" && path == "/invitations" {
		scope, t, owner, err := p.appEnrollmentScope(ctx, host)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		scope.Account = account.ID
		scope.Email = email
		if code := p.appDeviceScopeAccess((&http.Request{Host: host}).WithContext(ctx), scope, owner, t); code != 200 {
			appAuthenticationError(w, code)
			return
		}
		i, secret, err := p.appDevices.invite(ctx, scope)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		// Fragment values are never transmitted by QR navigation or referrers.
		qrURL := "https://" + p.loginAuthority() + "/pair/app-device#invitation=" + url.QueryEscape(secret) + "&hostname=" + url.QueryEscape(host)
		png, err := qrcode.Encode(qrURL, qrcode.Medium, 256)
		if err != nil {
			appAuthenticationError(w, 503)
			return
		}
		writeOAuthJSON(w, 201, map[string]any{"invitation": secret, "id": i.ID, "hostname": host, "expires_at": i.Expires, "authority": "https://" + p.loginAuthority(), "qr_png": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
		return
	}
	if r.Method == "GET" && strings.HasPrefix(path, "/invitations/") {
		i, err := p.appDevices.invitation(ctx, "id", strings.TrimPrefix(path, "/invitations/"))
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		if i.Account != account.ID || !strings.EqualFold(i.Email, email) {
			appAuthenticationError(w, 403)
			return
		}
		writeOAuthJSON(w, 200, i)
		return
	}
	if r.Method == "POST" && strings.HasPrefix(path, "/claims/") && strings.HasSuffix(path, "/approve") {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/claims/"), "/approve")
		i, err := p.appDevices.invitation(ctx, "claim", id)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		if i.Account != account.ID || !strings.EqualFold(i.Email, email) || r.PostForm.Get("confirmed") != "true" || host != i.Host || r.PostForm.Get("phrase") != i.Phrase {
			appAuthenticationError(w, 403)
			return
		}
		if err = p.invitationAccess(ctx, i); err == nil {
			err = p.appDevices.approve(ctx, i)
		}
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		writeOAuthJSON(w, 200, map[string]bool{"approved": true})
		return
	}
	if host != "" && (host != requestHostname(host) || strings.ContainsAny(host, "/:?#@ \\\r\n") || len(host) > 253) {
		http.Error(w, "Enter an exact app hostname", 400)
		return
	}
	owner := false
	canEnroll := false
	var ownerErr error
	if host != "" {
		owner, ownerErr = p.appDeviceManagementOwner(ctx, host, account.ID)
		scope, t, publisher, err := p.appEnrollmentScope(ctx, host)
		if err == nil {
			scope.Account = account.ID
			scope.Email = email
			canEnroll = p.appDeviceScopeAccess((&http.Request{Host: host}).WithContext(ctx), scope, publisher, t) == 200
		}
	}
	if r.Method == "POST" && (path == "/revoke" || path == "/revoke-all") {
		if host == "" {
			http.Error(w, "Hostname required", 400)
			return
		}
		requestedScope := r.PostForm.Get("scope")
		if requestedScope != "" && requestedScope != "self" && requestedScope != "hostname" {
			http.Error(w, "Invalid revoke scope", 400)
			return
		}
		if requestedScope == "self" {
			owner = false
		} else if ownerErr != nil {
			appDeviceHTTPError(w, ownerErr)
			return
		} else if requestedScope == "hostname" && !owner {
			appAuthenticationError(w, 403)
			return
		}
		id := r.PostForm.Get("device_id")
		if path == "/revoke-all" {
			id = ""
		} else if id == "" {
			http.Error(w, "Device required", 400)
			return
		}
		committed, err := p.appDevices.revoke(ctx, host, account.ID, id, owner)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		writeOAuthJSON(w, 200, map[string]any{"revoked_at": committed, "hostname": host})
		return
	}
	if r.Method == "GET" && (path == "" || r.URL.Path == "/account/app-devices") {
		devices, err := p.appDevices.list(ctx, host, account.ID, owner)
		if err != nil {
			appDeviceHTTPError(w, err)
			return
		}
		if r.URL.Path != "/account/app-devices" {
			writeOAuthJSON(w, 200, map[string]any{"devices": devices, "owner": owner})
			return
		}
		csrf, err := p.createCSRFToken(r, appDevicesCSRFAction)
		if err != nil {
			appAuthenticationError(w, 503)
			return
		}
		p.renderAppDevices(w, appDevicesPageData{Host: host, Email: email, Devices: devices, CSRF: csrf, Owner: owner, CanEnroll: canEnroll, Authority: "https://" + p.loginAuthority()})
		return
	}
	http.NotFound(w, r)
}

// Management ownership is durable hostname authority, independent of whether
// its publisher is connected. A requested hostname-wide revoke never narrows.
func (p *ProxyServer) appDeviceManagementOwner(ctx context.Context, host, account string) (bool, error) {
	if p.domains == nil || p.storage == nil || !p.storage.Available() {
		return false, appProblem(503, "Hostname authority unavailable")
	}
	binding, err := p.domains.Route(ctx, &domainpb.Domain{Name: host})
	if err != nil {
		return false, appProblem(appDomainStatus(err), "Hostname authority unavailable")
	}
	if binding == nil || !strings.HasPrefix(binding.Name, "*.") {
		return false, appProblem(403, "Wildcard app hostname required")
	}
	owner, err := p.storage.GetAccount(ctx, binding.Owner)
	if err != nil {
		return false, err
	}
	if owner == nil || owner.OperationalState != "active" {
		return false, appProblem(403, "Hostname owner unavailable")
	}
	return owner.ID == account, nil
}

type appDevicesPageData struct {
	Host, Email, CSRF, Authority string
	Devices                      []appDevice
	Owner, CanEnroll, Phone      bool
}

var appDevicesTemplate = template.Must(template.New("app-devices").Funcs(template.FuncMap{
	"date": func(ms int64) string {
		if ms == 0 {
			return "Not used yet"
		}
		return time.UnixMilli(ms).UTC().Format("Jan 2, 2006 15:04 UTC")
	},
	"expired": func(ms int64) bool { return ms <= time.Now().UnixMilli() },
}).Parse(appDevicesHTML))

func (p *ProxyServer) renderAppDevices(w http.ResponseWriter, data appDevicesPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := appDevicesTemplate.Execute(w, data); err != nil {
		_ = fmt.Errorf("render app devices: %w", err)
	}
}
