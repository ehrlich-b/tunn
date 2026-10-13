package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	ipb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type forwardPermissionProbeKey struct{}
type permissionProbeWriter struct{ header http.Header }

func (w permissionProbeWriter) Header() http.Header         { return w.header }
func (w permissionProbeWriter) WriteHeader(int)             {}
func (w permissionProbeWriter) Write(b []byte) (int, error) { return len(b), nil }

// Internal node authentication protects this read-only admission check. It
// shares the ingress validators without dispatching or charging a request.
func (s *InternalServer) CheckForwardedPermission(ctx context.Context, in *ipb.ForwardedPermissionRequest) (*ipb.ForwardedPermissionResponse, error) {
	if s.proxy == nil {
		return nil, status.Error(codes.Unavailable, "permission service unavailable")
	}
	if !isValidDNSLabel(in.TunnelId) || len(in.Host) > 255 || len(in.Path) > 4096 || len(in.Method) > 16 || len(in.Headers) > 8 || !strings.HasPrefix(in.Path, "/") {
		return nil, status.Error(codes.InvalidArgument, "invalid permission request")
	}
	allowed := false
	r, err := http.NewRequestWithContext(context.WithValue(ctx, forwardPermissionProbeKey{}, &allowed), in.Method, "https://"+in.Host+in.Path, nil)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid permission request")
	}
	r.Host = in.Host
	r.RemoteAddr = net.JoinHostPort(in.Peer, "0")
	if in.Scheme == "https" {
		r.TLS = &tls.ConnectionState{}
	}
	for k, v := range in.Headers {
		if len(v) > 8192 {
			return nil, status.Error(codes.InvalidArgument, "invalid permission request")
		}
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "Tunn-Authorization", "Cookie", "Origin", "Upgrade", "Connection":
			r.Header.Set(k, v)
		default:
			return nil, status.Error(codes.InvalidArgument, "invalid permission header")
		}
	}
	p := s.proxy
	if p.customerHost(r.Host) {
		if p.domains == nil {
			return &ipb.ForwardedPermissionResponse{}, nil
		}
		binding, err := p.domains.Route(ctx, &domainpb.Domain{Name: requestHostname(r.Host)})
		if err != nil || binding == nil || binding.Tunnel != in.TunnelId {
			return &ipb.ForwardedPermissionResponse{}, nil
		}
		r = r.WithContext(context.WithValue(r.Context(), domainOwnerKey{}, binding.Owner))
		if strings.HasPrefix(binding.Name, "*.") {
			return nil, status.Error(codes.Unimplemented, "App streams use the app permission service")
		}
	}
	_ = p.proxyToLocal(permissionProbeWriter{make(http.Header)}, r, in.TunnelId)
	return &ipb.ForwardedPermissionResponse{Allowed: allowed}, nil
}

// A stream deadline interrupts only the current HTTP/2 or HTTP/3 response.
// Hijacked transports belong solely to this upgraded request.
type forwardedPermissionWriter struct {
	http.ResponseWriter
	mu       sync.Mutex
	hijacked net.Conn
	stopped  bool
}

func (w *forwardedPermissionWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *forwardedPermissionWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, b, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	w.hijacked = c
	stopped := w.stopped
	w.mu.Unlock()
	if stopped {
		_ = c.Close()
	}
	return c, b, nil
}
func (w *forwardedPermissionWriter) interrupt() {
	w.mu.Lock()
	w.stopped = true
	c := w.hijacked
	w.mu.Unlock()
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now())
	if c != nil {
		_ = c.Close()
	}
}
func (p *ProxyServer) checkForwardedPermission(ctx context.Context, in *ipb.ForwardedPermissionRequest, nodeAddr string) bool {
	// Node maps use internal RPC addresses; FindTunnel binds the HTTP destination.
	for _, client := range p.nodeClients {
		found, err := client.FindTunnel(ctx, &ipb.FindTunnelRequest{TunnelId: in.TunnelId})
		if err != nil || found == nil || !found.Found || found.NodeAddress != nodeAddr {
			continue
		}
		out, err := client.CheckForwardedPermission(ctx, in)
		return err == nil && out != nil && out.Allowed
	}
	return false
}
func (p *ProxyServer) watchForwardedPermission(w http.ResponseWriter, r *http.Request, nodeAddr, tunnelID string) (*http.Request, http.ResponseWriter, func()) {
	ctx, cancel := context.WithCancelCause(r.Context())
	writer := &forwardedPermissionWriter{ResponseWriter: w}
	peer, scheme := p.forwardingPeer(r)
	in := &ipb.ForwardedPermissionRequest{TunnelId: tunnelID, Host: r.Host, Path: r.URL.RequestURI(), Method: r.Method, Peer: peer, Scheme: scheme, Headers: map[string]string{}}
	for _, name := range []string{"Authorization", "Tunn-Authorization", "Cookie", "Origin", "Upgrade", "Connection"} {
		if v := r.Header.Get(name); v != "" {
			in.Headers[name] = v
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, stop := context.WithTimeout(ctx, 2*time.Second)
				allowed := p.checkForwardedPermission(check, in, nodeAddr)
				stop()
				if !allowed {
					cancel(&webPermissionError{"permission_revoked_or_unavailable"})
					writer.interrupt()
					return
				}
			}
		}
	}()
	return r.WithContext(ctx), writer, func() { cancel(nil); <-done }
}
