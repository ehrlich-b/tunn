package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type appDeviceAuth struct {
	Device appDevice
	Digest []byte
	Source string
	Lease  string
}
type appDeviceAuthKey struct{}
type appAdmissionKey struct{}
type appPrecheckedKey struct{}
type appPrecheckedDevice struct {
	Device appDevice
	Digest []byte
	Source string
}

// Admission has one total deadline, carried as metadata so the established
// request/stream does not inherit its two-second lifetime.
func appAuthorityContext(r *http.Request) (context.Context, context.CancelFunc) {
	if ctx, _ := r.Context().Value(appAdmissionKey{}).(context.Context); ctx != nil {
		return ctx, func() {}
	}
	return context.WithTimeout(r.Context(), 2*time.Second)
}

func (p *ProxyServer) prepareAppCredential(w http.ResponseWriter, r *http.Request, ctx context.Context) bool {
	secret, explicit, malformed := appCredential(r)
	if !explicit {
		return true
	}
	for _, value := range appHeaderValues(r.Header, "Authorization") {
		_, appBearer := appBearer(value)
		_, appBasic := appBasic(value)
		if !appBearer && !appBasic && p.isPlatformAuthorization(value) {
			malformed = true
		}
	}
	source, proto := p.forwardingPeer(r)
	if proto != "https" {
		appAuthenticationError(w, 403)
		return false
	}
	in := &internalpb.AppDeviceCheckRequest{Operation: "resolve", TokenSha256: appDigest(secret), Source: source, Hostname: requestHostname(r.Host)}
	if malformed {
		// Syntax alone cannot authenticate. Authority failure must not turn a
		// malformed credential into a different principal or cookie fallback.
		in.Operation = "failure"
		out, err := p.checkAppDevice(ctx, in)
		code := 401
		if err == nil && out.Status == 429 {
			code = 429
		}
		appAuthenticationError(w, code)
		return false
	}
	out, err := p.checkAppDevice(ctx, in)
	if err != nil {
		appAuthenticationError(w, 503)
		return false
	}
	if out.Status != 200 {
		appAuthenticationError(w, int(out.Status))
		return false
	}
	var d appDevice
	if err = json.Unmarshal(out.DeviceJson, &d); err != nil {
		appAuthenticationError(w, 503)
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), appPrecheckedKey{}, &appPrecheckedDevice{d, in.TokenSha256, source}))
	return true
}

// Header names can be supplied with noncanonical casing by internal callers.
// Count every field instead of letting Header.Get hide a duplicate.
func appHeaderValues(h http.Header, name string) []string {
	var out []string
	for key, values := range h {
		if strings.EqualFold(key, name) {
			out = append(out, values...)
		}
	}
	return out
}
func appBasic(value string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "Basic") {
		return "", false
	}
	decoded, _ := base64.StdEncoding.DecodeString(parts[1])
	user, password, _ := strings.Cut(string(decoded), ":")
	return password, user == "tunn-app"
}

func validAppBasic(value string) bool {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	user, _, colon := strings.Cut(string(decoded), ":")
	return err == nil && colon && user == "tunn-app"
}
func appBearer(value string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) >= 2 && strings.EqualFold(parts[0], "Bearer") && strings.HasPrefix(parts[1], "tunn_app_") {
		return parts[1], true
	}
	return "", false
}
func appCredential(r *http.Request) (secret string, explicit, malformed bool) {
	dedicated := appHeaderValues(r.Header, "Tunn-Authorization")
	auth := appHeaderValues(r.Header, "Authorization")
	count := 0
	if len(dedicated) > 0 {
		explicit = true
		if len(dedicated) != 1 {
			malformed = true
		}
		for _, value := range dedicated {
			if len(strings.Fields(value)) != 2 {
				malformed = true
			}
			token, ok := appBearer(value)
			if !ok {
				malformed = true
			}
			secret = token
			count++
		}
	}
	for _, value := range auth {
		token, ok := appBearer(value)
		if !ok {
			token, ok = appBasic(value)
			if ok && !validAppBasic(value) {
				malformed = true
			}
		}
		if ok {
			if len(strings.Fields(value)) != 2 {
				malformed = true
			}
			explicit = true
			count++
			secret = token
			if len(auth) != 1 {
				malformed = true
			}
		}
	}
	if count > 1 {
		malformed = true
	}
	if explicit && (!strings.HasPrefix(secret, "tunn_app_") || len(secret) != len("tunn_app_")+43 || !validAppChallenge(strings.TrimPrefix(secret, "tunn_app_"))) {
		malformed = true
	}
	return
}

func isAppCredentialAttempt(r *http.Request) bool {
	for _, name := range []string{"Authorization", "Tunn-Authorization"} {
		for _, value := range appHeaderValues(r.Header, name) {
			_, bearer := appBearer(value)
			_, basic := appBasic(value)
			if bearer || basic {
				return true
			}
		}
	}
	return false
}

func stripAppCredential(r *http.Request) {
	for key, values := range r.Header {
		if strings.EqualFold(key, "Tunn-Authorization") {
			delete(r.Header, key)
			continue
		}
		if strings.EqualFold(key, "Authorization") {
			var kept []string
			for _, value := range values {
				_, bearer := appBearer(value)
				_, basic := appBasic(value)
				if !bearer && !basic {
					kept = append(kept, value)
				}
			}
			delete(r.Header, key)
			if len(kept) > 0 {
				r.Header[key] = kept
			}
		}
	}
}

func appAuthenticationError(w http.ResponseWriter, code int) {
	if code == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tunn-app", error="invalid_token"`)
		w.Header().Add("WWW-Authenticate", `Basic realm="tunn-app", charset="UTF-8"`)
	}
	if code == 429 {
		w.Header().Set("Retry-After", "60")
	}
	http.Error(w, http.StatusText(code), code)
}

func (s *LoginNodeDBServer) AppDeviceCheck(ctx context.Context, in *internalpb.AppDeviceCheckRequest) (*internalpb.AppDeviceCheckResponse, error) {
	if s.appDevices == nil {
		return nil, status.Error(codes.Unavailable, "app device authority unavailable")
	}
	out, err := s.appDevices.check(ctx, in)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "app device authority check failed")
	}
	return out, nil
}
func (p *ProxyServer) checkAppDevice(ctx context.Context, in *internalpb.AppDeviceCheckRequest) (*internalpb.AppDeviceCheckResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if p.appDevices != nil {
		return p.appDevices.check(ctx, in)
	}
	p.loginNodeMu.RLock()
	conn := p.loginNodeConn
	p.loginNodeMu.RUnlock()
	if conn == nil {
		return nil, storage.ErrNotAvailable
	}
	return internalpb.NewLoginNodeDBClient(conn).AppDeviceCheck(ctx, in)
}

func appDeviceSession(d appDevice) jwt.MapClaims {
	return jwt.MapClaims{"account_id": d.Account, "email": d.Email, "provider": "app_device", "email_verified": true, "exp": float64(d.Expires / 1000)}
}

func (p *ProxyServer) appDeviceScopeAccess(r *http.Request, d appDevice, owner *storage.Account, t *TunnelConnection) int {
	if d.Host != requestHostname(r.Host) || t.ResourceID == "" || d.Resource != t.ResourceID || d.Endpoint != t.TunnelID || owner == nil || d.Publisher != owner.ID {
		return 403
	}
	if p.domains == nil {
		return 503
	}
	binding, err := p.domains.Route(r.Context(), &domainpb.Domain{Name: d.Host})
	if err != nil {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.NotFound, codes.FailedPrecondition:
			return 403
		default:
			return 503
		}
	}
	if binding == nil || !strings.HasPrefix(binding.Name, "*.") || binding.CnameTarget != d.Namespace || binding.Owner != owner.ID || binding.Tunnel != t.TunnelID {
		return 403
	}
	backend := p.sharingBackend()
	if backend == nil {
		return 503
	}
	resources, err := backend.Sharing(r.Context(), &meterpb.SharingRequest{Operation: "list", Owner: owner.ID})
	if err != nil {
		return 503
	}
	live := false
	for _, resource := range resources.Resources {
		if resource.Id == d.Resource && resource.Endpoint == d.Endpoint && resource.Owner == owner.ID {
			live = true
			break
		}
	}
	if !live {
		return 403
	}
	_, code := p.appAccountAccess(r, appDeviceSession(d), owner, t)
	return code
}

func (p *ProxyServer) appRouteFailure(w http.ResponseWriter, r *http.Request, routeErr error) {
	if r.Context().Value(appPrecheckedKey{}) != nil {
		appAuthenticationError(w, appDomainStatus(routeErr))
		return
	}
	secret, explicit, malformed := appCredential(r)
	if !explicit {
		domainHTTPError(w, routeErr)
		return
	}
	source, _ := p.forwardingPeer(r)
	op := "resolve"
	if malformed {
		op = "failure"
	}
	out, err := p.checkAppDevice(r.Context(), &internalpb.AppDeviceCheckRequest{Operation: op, TokenSha256: appDigest(secret), Source: source, Hostname: requestHostname(r.Host)})
	code := appDomainStatus(routeErr)
	if err != nil {
		code = 503
	} else if out.Status != 200 {
		code = int(out.Status)
	}
	if malformed && code != 429 && code != 503 {
		code = 401
	}
	appAuthenticationError(w, code)
}

func (p *ProxyServer) authorizeAppDevice(w http.ResponseWriter, r *http.Request, owner *storage.Account, t *TunnelConnection, secret string, malformed bool) (jwt.MapClaims, bool) {
	ctx, cancel := appAuthorityContext(r)
	defer cancel()
	if r.Context().Value(appPrecheckedKey{}) == nil && !p.prepareAppCredential(w, r, ctx) {
		return nil, false
	}
	pre, _ := r.Context().Value(appPrecheckedKey{}).(*appPrecheckedDevice)
	if pre == nil {
		appAuthenticationError(w, 401)
		return nil, false
	}
	stripAppCredential(r)
	d, source := pre.Device, pre.Source
	in := &internalpb.AppDeviceCheckRequest{Operation: "resolve", TokenSha256: pre.Digest, Source: source, Hostname: requestHostname(r.Host)}
	if code := p.appDeviceScopeAccess(r.WithContext(ctx), d, owner, t); code != 200 {
		if code == 403 {
			in.Operation = "failure"
			failed, err := p.checkAppDevice(ctx, in)
			if err != nil {
				code = 503
			} else if failed.Status == 429 {
				code = 429
			}
		}
		appAuthenticationError(w, code)
		return nil, false
	}
	lease, err := randomOAuthValue("al_")
	if err != nil {
		appAuthenticationError(w, 503)
		return nil, false
	}
	in.Operation = "acquire"
	in.LeaseId = lease
	out, err := p.checkAppDevice(ctx, in)
	if err != nil {
		appAuthenticationError(w, 503)
		return nil, false
	}
	if out.Status != 200 {
		appAuthenticationError(w, int(out.Status))
		return nil, false
	}
	// A verified merge can commit between resolve and admission. Emit the
	// canonical surviving UUID, still requiring the originating mailbox.
	account, err := p.sessionAccount(r.WithContext(ctx), appDeviceSession(d))
	if err != nil {
		appAuthenticationError(w, 503)
		return nil, false
	}
	if account == nil {
		appAuthenticationError(w, 403)
		return nil, false
	}
	d.Account = account.ID
	auth := &appDeviceAuth{Device: d, Digest: in.TokenSha256, Source: source, Lease: lease}
	*r = *r.WithContext(context.WithValue(r.Context(), appDeviceAuthKey{}, auth))
	return appDeviceSession(d), true
}

func (p *ProxyServer) releaseAppDevice(r *http.Request) {
	auth, _ := r.Context().Value(appDeviceAuthKey{}).(*appDeviceAuth)
	if auth == nil {
		return
	}
	// Transport teardown must not wait another authority deadline after the
	// watchdog cancels. A failed release is recovered by the 5-second lease TTL.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 100*time.Millisecond)
	defer cancel()
	_, _ = p.checkAppDevice(ctx, &internalpb.AppDeviceCheckRequest{Operation: "release", TokenSha256: auth.Digest, Source: auth.Source, Hostname: auth.Device.Host, DeviceId: auth.Device.ID, LeaseId: auth.Lease})
}

func (p *ProxyServer) recheckAppDevice(ctx context.Context, r *http.Request, t *TunnelConnection, auth *appDeviceAuth) bool {
	out, err := p.checkAppDevice(ctx, &internalpb.AppDeviceCheckRequest{Operation: "renew", TokenSha256: auth.Digest, Source: auth.Source, Hostname: auth.Device.Host, DeviceId: auth.Device.ID, LeaseId: auth.Lease})
	if err != nil || out.Status != 200 {
		return false
	}
	owner, err := p.currentTunnelAccount(ctx, t)
	return err == nil && p.appDeviceScopeAccess(r.WithContext(ctx), auth.Device, owner, t) == 200
}
