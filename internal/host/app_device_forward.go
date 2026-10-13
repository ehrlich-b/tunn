package host

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

const appRelayDeadline = "Tunn-Relay-Admission-Deadline"
const appRelayAdmissionID = "Tunn-Relay-Admission-Id"
const appRelayAdmissionSignature = "Tunn-Relay-Admission-Signature"
const appRelayAdmitted = "Tunn-Relay-Admitted"

func (p *ProxyServer) appRelaySignature(host, peer, proto, deadline, id, purpose string) string {
	if p.config == nil || p.config.NodeSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(p.config.NodeSecret))
	fmt.Fprintf(mac, "tunn-app-admission-v1\n%s\n%s\n%s\n%s\n%s\n%s", host, peer, proto, deadline, id, purpose)
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *ProxyServer) trustedAppAdmission(r *http.Request) bool {
	peer, proto := p.forwardingPeer(r)
	deadline, id := r.Header.Get(appRelayDeadline), r.Header.Get(appRelayAdmissionID)
	if deadline == "" || id == "" || len(id) > 80 {
		return false
	}
	expected := p.appRelaySignature(r.Host, peer, proto, deadline, id, "request")
	return expected != "" && hmac.Equal([]byte(expected), []byte(r.Header.Get(appRelayAdmissionSignature)))
}

func (p *ProxyServer) appAdmissionDeadline(r *http.Request) time.Time {
	deadline := time.Now().Add(2 * time.Second)
	if p.trustedAppAdmission(r) {
		if ms, err := strconv.ParseInt(r.Header.Get(appRelayDeadline), 10, 64); err == nil {
			upstream := time.UnixMilli(ms)
			if upstream.Before(deadline) {
				deadline = upstream
			}
		}
	}
	return deadline
}

// An authenticated early response releases frontend admission timing before
// the upstream application starts. It imposes no lifetime on app responses.
func (p *ProxyServer) signalAppAdmission(w http.ResponseWriter, r *http.Request) {
	if !p.trustedAppAdmission(r) {
		return
	}
	peer, proto := p.forwardingPeer(r)
	w.Header().Set(appRelayAdmitted, r.Header.Get(appRelayAdmissionID))
	w.Header().Set(appRelayAdmissionSignature, p.appRelaySignature(r.Host, peer, proto, r.Header.Get(appRelayDeadline), r.Header.Get(appRelayAdmissionID), "admitted"))
	w.WriteHeader(http.StatusEarlyHints)
	w.Header().Del(appRelayAdmitted)
	w.Header().Del(appRelayAdmissionSignature)
}

func (p *ProxyServer) remoteAppTunnel(ctx context.Context, endpoint string) (*TunnelConnection, error) {
	for _, client := range p.nodeClients {
		found, err := client.FindTunnel(ctx, &internalpb.FindTunnelRequest{TunnelId: endpoint})
		if err == nil && found.Found {
			return &TunnelConnection{TunnelID: endpoint, AccountID: found.AccountId, CreatorEmail: found.CreatorEmail, ResourceID: found.ResourceId, TargetURL: found.EndpointKind, AllowedEmails: found.AllowedEmails}, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("publisher authority unavailable")
}

func (p *ProxyServer) forwardedAppAllowed(ctx context.Context, r *http.Request) bool {
	pre, _ := r.Context().Value(appPrecheckedKey{}).(*appPrecheckedDevice)
	if pre != nil {
		out, err := p.checkAppDevice(ctx, &internalpb.AppDeviceCheckRequest{Operation: "watch", TokenSha256: pre.Digest, Source: pre.Source, Hostname: requestHostname(r.Host)})
		if err != nil || out.Status != 200 {
			return false
		}
		t, err := p.remoteAppTunnel(ctx, pre.Device.Endpoint)
		if err != nil {
			return false
		}
		owner, err := p.currentTunnelAccount(ctx, t)
		return err == nil && p.appDeviceScopeAccess(r.WithContext(ctx), pre.Device, owner, t) == 200
	}
	// Browser streams retain the same UUID/mailbox/ACL/domain checks too.
	binding, err := p.domains.Route(ctx, &domainpb.Domain{Name: requestHostname(r.Host)})
	if err != nil || binding == nil {
		return false
	}
	t, err := p.remoteAppTunnel(ctx, binding.Tunnel)
	if err != nil {
		return false
	}
	owner, err := p.currentTunnelAccount(ctx, t)
	session, valid := p.accountSession(r)
	_, code := p.appAccountAccess(r.WithContext(ctx), session, owner, t)
	expected, _ := r.Context().Value(domainOwnerKey{}).(string)
	return err == nil && valid && code == 200 && owner != nil && binding.Owner == expected && binding.Owner == owner.ID && binding.Tunnel == t.TunnelID
}

func (p *ProxyServer) watchForwardedApp(r *http.Request) (*http.Request, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, stop := context.WithTimeout(ctx, 2*time.Second)
				allowed := p.forwardedAppAllowed(check, r)
				stop()
				if !allowed {
					cancel()
					return
				}
			}
		}
	}()
	return r.WithContext(ctx), cancel
}

// ReverseProxy owns upgrade sockets. Independent cancellation interrupts a
// blocked downstream writer without needing to observe upstream EOF first.
type appForwardWriter struct {
	http.ResponseWriter
	ctx     context.Context
	mu      sync.Mutex
	conn    net.Conn
	started atomic.Bool
}

func (w *appForwardWriter) WriteHeader(code int) {
	if code >= 200 || code == 101 {
		w.started.Store(true)
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *appForwardWriter) Write(body []byte) (int, error) {
	w.started.Store(true)
	if w.ctx.Err() != nil {
		w.abort()
		return 0, w.ctx.Err()
	}
	return w.ResponseWriter.Write(body)
}

func (w *appForwardWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *appForwardWriter) Flush()                      { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *appForwardWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffer, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.mu.Lock()
		w.conn = conn
		w.mu.Unlock()
		if w.ctx.Err() != nil {
			closeUpgradedConnection(conn)
		}
	}
	return conn, buffer, err
}
func (w *appForwardWriter) abort() {
	w.mu.Lock()
	conn := w.conn
	w.mu.Unlock()
	if !w.started.Load() && conn == nil {
		return
	}
	controller := http.NewResponseController(w.ResponseWriter)
	_ = controller.SetReadDeadline(time.Now())
	_ = controller.SetWriteDeadline(time.Now())
	if conn != nil {
		closeUpgradedConnection(conn)
	}
}

type appForwardAdmission struct {
	deadline  time.Time
	id, proof string
	cancel    context.CancelFunc
	timer     *time.Timer
}

func (a *appForwardAdmission) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints && h.Get(appRelayAdmitted) == a.id && hmac.Equal([]byte(h.Get(appRelayAdmissionSignature)), []byte(a.proof)) {
			a.timer.Stop()
		}
		return nil
	}}
}
