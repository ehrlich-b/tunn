package host

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/domains"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type domainOwnerKey struct{}

func requestHostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
func (p *ProxyServer) customerHost(host string) bool {
	name := requestHostname(host)
	if name == "" || name == strings.ToLower(p.Domain) || name == "www."+strings.ToLower(p.Domain) {
		return false
	}
	if p.config != nil && p.isPlatformHost(host) {
		return false
	}
	return extractTunnelID(name, strings.ToLower(p.Domain)) == ""
}
func (p *ProxyServer) domainCertificate(base tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := requestHostname(hello.ServerName)
		if name == "" || name == p.Domain || name == "www."+p.Domain || domains.ValidLabel(extractTunnelID(name, p.Domain)) {
			return &base, nil
		}
		if p.domains == nil {
			return nil, fmt.Errorf("customer certificates unavailable")
		}
		parent := hello.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		pair, err := p.domains.Certificate(ctx, &pb.Domain{Name: name})
		if err != nil {
			return nil, fmt.Errorf("customer certificate unavailable: %w", err)
		}
		cert, err := tls.X509KeyPair(pair.CertificatePem, pair.KeyPem)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
}
func domainHTTPError(w http.ResponseWriter, err error) {
	code := http.StatusServiceUnavailable
	message := "Domain service unavailable"
	switch status.Code(err) {
	case codes.InvalidArgument:
		code = 400
		message = status.Convert(err).Message()
	case codes.PermissionDenied:
		code = 403
		message = status.Convert(err).Message()
	case codes.NotFound:
		code = 404
		message = "Domain not found"
	case codes.AlreadyExists:
		code = 409
		message = "Domain already claimed"
	case codes.FailedPrecondition:
		code = 409
		message = status.Convert(err).Message()
	case codes.ResourceExhausted:
		code = 429
		message = status.Convert(err).Message()
	case codes.Aborted:
		code = 409
		message = "Domain claim changed; retry"
	}
	http.Error(w, message, code)
}
func (p *ProxyServer) handleDomainsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Owner API requires the relay origin", 403)
		return
	}
	if p.domains == nil {
		http.Error(w, "Custom domains are not configured", 503)
		return
	}
	email, _, capability, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{})
	if !ok || capability {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tunn-owner"`)
		http.Error(w, "Owner authentication required", 401)
		return
	}
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Account service unavailable", 503)
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), common.NormalizeEmail(email))
	if err != nil {
		http.Error(w, "Account service unavailable", 503)
		return
	}
	if account == nil || account.ID == "" {
		http.Error(w, "Owner account required", 403)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/domains")
	var out any
	switch {
	case path == "" && r.Method == http.MethodGet:
		out, err = p.domains.List(r.Context(), &pb.Owner{Owner: account.ID})
	case path == "" && r.Method == http.MethodPost:
		var input struct {
			Name   string `json:"name"`
			Tunnel string `json:"tunnel"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil {
			http.Error(w, "Invalid domain binding", 400)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			http.Error(w, "Invalid domain binding", 400)
			return
		}
		out, err = p.domains.Add(r.Context(), &pb.Domain{Name: input.Name, Tunnel: input.Tunnel, Owner: account.ID})
	case strings.HasPrefix(path, "/"):
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		if len(parts) == 1 && r.Method == http.MethodDelete {
			_, err = p.domains.Delete(r.Context(), &pb.Domain{Name: parts[0], Owner: account.ID})
			if err == nil {
				w.WriteHeader(204)
				return
			}
		}
		if len(parts) == 2 && parts[1] == "verify" && r.Method == http.MethodPost {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
			defer cancel()
			out, err = p.domains.Verify(ctx, &pb.Domain{Name: parts[0], Owner: account.ID})
		}
		if out == nil && err == nil {
			http.NotFound(w, r)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Unsupported domain operation", 405)
		return
	}
	if err != nil {
		domainHTTPError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if path == "" && r.Method == http.MethodPost {
		w.WriteHeader(201)
	}
	_ = json.NewEncoder(w).Encode(out)
}

// HTTP-01 must be reachable on port 80 on every anycast relay. The application
// serves only authority-issued tokens, never a publisher's challenge response.
func (p *ProxyServer) http01Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		const prefix = "/.well-known/acme-challenge/"
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, prefix) || p.domains == nil {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)
		if token == "" || strings.Contains(token, "/") || len(token) > 256 {
			http.NotFound(w, r)
			return
		}
		out, err := p.domains.Challenge(r.Context(), &pb.ChallengeRequest{Name: requestHostname(r.Host), Token: token})
		if err != nil {
			if status.Code(err) == codes.NotFound {
				http.NotFound(w, r)
			} else {
				http.Error(w, "Challenge authority unavailable", 503)
			}
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, out.Body)
	})
}
func (p *ProxyServer) startHTTP01Server(ctx context.Context) error {
	server := &http.Server{Addr: p.config.HTTP01Addr, Handler: p.http01Handler(), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { <-ctx.Done(); _ = server.Close() }()
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
