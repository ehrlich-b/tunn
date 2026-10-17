package host

import (
	"context"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type publisherStopReason string

const (
	publisherClientStop    publisherStopReason = "client stop"
	publisherTransportLoss publisherStopReason = "transport loss"
	publisherTimeout       publisherStopReason = "keepalive timeout"
	publisherEviction      publisherStopReason = "relay eviction"
)

type publisherStop struct {
	reason publisherStopReason
	detail string
}

// Record the first terminal event, before teardown cancels any other work.
// Client EOF, GracefulStop and client cancellation are clean stops. Only loss,
// timeout or eviction without a preceding client stop is an outage.
func (conn *TunnelConnection) endRegistration(err error) {
	ended := &publisherStop{reason: publisherTransportLoss, detail: "Publisher connection lost"}
	switch {
	case err == nil, errors.Is(err, context.Canceled), status.Code(err) == codes.Canceled:
		ended.reason, ended.detail = publisherClientStop, ""
	case errors.Is(err, context.DeadlineExceeded), status.Code(err) == codes.DeadlineExceeded:
		ended.reason, ended.detail = publisherTimeout, "Publisher keepalive timed out"
	case status.Code(err) == codes.Unauthenticated:
		ended.reason, ended.detail = publisherEviction, "Invalid or expired token. Run tunn login to refresh."
	case status.Code(err) == codes.Aborted, status.Code(err) == codes.PermissionDenied, status.Code(err) == codes.InvalidArgument:
		ended.reason, ended.detail = publisherEviction, err.Error()
	default:
		if err != nil {
			ended.detail = err.Error()
		}
	}
	if err != nil && conn.Stream != nil {
		if transport, ok := conn.Stream.Context().Value(publisherTransportKey{}).(*publisherTransportState); ok {
			if lost := transport.stop.Load(); lost != nil {
				ended = lost
			}
		}
	}
	conn.stop.CompareAndSwap(nil, ended)
}

func (s *TunnelServer) reportAvailability(conn *TunnelConnection, operation, lastError string) error {
	backend, ok := s.storage.(storage.TunnelAlerts)
	if !ok || conn.AccountID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := backend.TunnelAlert(ctx, &internalpb.TunnelAlertRequest{Operation: operation, AccountId: conn.AccountID, Tunnel: conn.TunnelID, Session: conn.alertSession, LastError: lastError})
	if err != nil {
		common.LogError("tunnel availability report failed", "tunnel_id", conn.TunnelID, "operation", operation, "error", err)
	}
	return err
}

func (s *TunnelServer) availabilityHeartbeats(ctx context.Context, conn *TunnelConnection, up bool) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			operation := "heartbeat"
			if !up {
				operation = "up"
			}
			if s.reportAvailability(conn, operation, "") == nil {
				up = true
			}
		}
	}
}

// Never attribute an unauthenticated probe to a tunnel. Only a token with a
// verified signature and the owning account can explain a rejected reconnect.
func (s *TunnelServer) reportExpiredPublisher(ctx context.Context, tunnel, raw string) {
	backend, ok := s.storage.(storage.TunnelAlerts)
	if !ok || s.cfg.JWTSecret == "" {
		return
	}
	claims := jwt.MapClaims{}
	p := jwt.Parser{SkipClaimsValidation: true, ValidMethods: []string{"HS256"}}
	token, err := p.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) { return []byte(s.cfg.JWTSecret), nil })
	if err != nil || !token.Valid {
		return
	}
	var email string
	if claims["type"] == "device_access" {
		exp, _ := claims["exp"].(float64)
		email, _, _, err = deviceIdentity(claims, time.Unix(int64(exp)-1, 0))
	} else {
		// Signature and purpose still matter; only expiry is relaxed for a
		// diagnosis. This token is never accepted for publishing or settings.
		claims["exp"] = float64(time.Now().Add(time.Minute).Unix())
		email, err = accountIdentityEmail(claims)
	}
	if err != nil {
		return
	}
	id, _ := claims["account_id"].(string)
	var a *storage.Account
	if id != "" {
		a, err = s.storage.GetAccount(ctx, id)
	} else {
		a, err = s.storage.GetAccountByEmail(ctx, email)
	}
	if err != nil || a == nil {
		return
	}
	_, err = backend.TunnelAlert(ctx, &internalpb.TunnelAlertRequest{Operation: "error", AccountId: a.ID, Tunnel: tunnel, LastError: "Invalid or expired token. Run tunn login to refresh."})
	if err != nil {
		common.LogError("publisher failure report failed", "tunnel_id", tunnel, "error", err)
	}
}

func (p *ProxyServer) deliverTunnelAlerts(ctx context.Context) error {
	local, ok := p.storage.(*storage.LocalStorage)
	if !ok || p.emailSender == nil {
		return nil
	}
	alerts, err := local.ClaimTunnelAlerts(ctx)
	if err != nil {
		return err
	}
	for _, a := range alerts {
		state := "offline"
		if a.Recovery {
			state = "recovered"
		}
		body := fmt.Sprintf("<h2>Tunnel %s %s</h2><p>Offline since: %s (UTC).</p>", html.EscapeString(a.Tunnel), state, a.Since.UTC().Format(time.RFC3339))
		if a.Recovery {
			body += "<p>The publisher is connected again.</p>"
		}
		if a.LastError != "" {
			body += "<p>Last relay error: " + html.EscapeString(a.LastError) + "</p>"
		}
		body += "<p>Check this tunnel on its publishing machine:</p><pre>tunn status</pre><p>If the login expired, refresh it and restart your saved publisher command:</p><pre>TUNN_SERVER_ADDR=" + html.EscapeString(p.config.Domain) + ":443 tunn login</pre><p><a href=\"https://" + html.EscapeString(p.config.Domain) + "/account/tunnel-alerts\">Manage tunnel alerts</a></p>"
		subject := "tunn: " + a.Tunnel + " " + state
		if sender, ok := p.emailSender.(interface {
			SendContext(context.Context, string, string, string) error
		}); ok {
			err = sender.SendContext(ctx, a.Email, subject, body)
		} else {
			err = p.emailSender.Send(a.Email, subject, body)
		}
		if err != nil {
			common.LogError("tunnel alert delivery failed", "tunnel_id", a.Tunnel, "error", err)
		} else if err = local.DeliveredTunnelAlert(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

func (p *ProxyServer) tunnelAlertLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if err := p.deliverTunnelAlerts(ctx); err != nil {
			common.LogError("tunnel alert sweep failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

const tunnelAlertSettingsPath = "/account/tunnel-alerts"

func (p *ProxyServer) handleTunnelAlertSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Invalid account host", 403)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	claims, ok := p.accountSession(r)
	if !ok {
		http.Redirect(w, r, "/auth/login?return_to=/account/tunnel-alerts", 302)
		return
	}
	a, err := p.sessionAccount(r, claims)
	if err != nil || a == nil {
		http.Error(w, "Account unavailable", 503)
		return
	}
	if a.OperationalState != "active" {
		http.Error(w, "Account suspended", 403)
		return
	}
	backend, ok := p.storage.(storage.TunnelAlerts)
	if !ok {
		http.Error(w, "Alert settings unavailable", 503)
		return
	}
	req := &internalpb.TunnelAlertRequest{Operation: "settings", AccountId: a.ID}
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if !p.requireCSRFToken(w, r, tunnelAlertSettingsPath) {
			return
		}
		threshold, err := strconv.ParseInt(r.PostForm.Get("threshold_seconds"), 10, 64)
		if err != nil || threshold < 1 || threshold > 604800 {
			http.Error(w, "Threshold must be 1 to 604800 seconds", 400)
			return
		}
		req.Operation = "save_settings"
		req.Enabled = r.PostForm.Get("enabled") == "on"
		req.OnGracefulStop = r.PostForm.Get("on_graceful_stop") == "on"
		req.ThresholdSeconds = threshold
	}
	settings, err := backend.TunnelAlert(r.Context(), req)
	if err != nil {
		http.Error(w, "Alert settings unavailable", 503)
		return
	}
	if r.Method == "POST" {
		http.Redirect(w, r, tunnelAlertSettingsPath, 303)
		return
	}
	csrf, err := p.createCSRFToken(r, tunnelAlertSettingsPath)
	if err != nil {
		http.Error(w, "Settings unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tunnelAlertSettingsTemplate.Execute(w, struct {
		Settings *internalpb.TunnelAlertResponse
		CSRF     string
	}{settings, csrf})
}

var tunnelAlertSettingsTemplate = template.Must(template.New("tunnel-alerts").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Tunnel alerts</title><h1>Tunnel alerts</h1><p>Email me when a previously connected reserved tunnel stays offline, and when it recovers. At most one email per tunnel per hour; recovery can wait for that window. Relay failures are detected after 90 seconds without a heartbeat, followed by your threshold. Checks run every 30 seconds.</p><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><p><label><input type="checkbox" name="enabled" {{if .Settings.Enabled}}checked{{end}}> Email alerts for my account</label></p><p><label>Offline threshold (seconds) <input type="number" name="threshold_seconds" min="1" max="604800" value="{{.Settings.ThresholdSeconds}}" required></label></p><p><label><input type="checkbox" name="on_graceful_stop" {{if .Settings.OnGracefulStop}}checked{{end}}> Also alert after a clean publisher shutdown</label></p><button>Save</button></form><p><a href="/account">Account</a></p></html>`))
