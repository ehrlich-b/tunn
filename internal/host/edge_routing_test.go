package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/domains"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEdgeHostRoutingNormalizesAuthority(t *testing.T) {
	p, _, _, _ := meteringRelay(t, false, "publisher health")
	owner := relayJWT(t, p, "owner@example.com")
	for _, tc := range []struct {
		host string
		code int
		body string
	}{
		{"tunn.test", 200, "ok"}, {"TUNN.TEST:443", 200, "ok"}, {"www.tunn.test", 200, "ok"},
		{"api.tunn.test", 200, "publisher health"}, {"API.TUNN.TEST:443", 200, "publisher health"},
		{"api.tunn.test.", 200, "publisher health"}, {"api.tunn.test.:443", 200, "publisher health"},
		{"api.tunn.test.example.com", 404, ""}, {"not-tunn.test", 404, ""},
		{"api.other.test", 404, ""}, {"nested.api.tunn.test", 503, ""},
	} {
		t.Run(tc.host, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://tunn.test/health", nil)
			r.Host = tc.host
			r.Header.Set("Authorization", "Bearer "+owner)
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, r)
			if rec.Code != tc.code || tc.body != "" && rec.Body.String() != tc.body {
				t.Fatalf("host %s: %d %q, want %d %q", tc.host, rec.Code, rec.Body, tc.code, tc.body)
			}
		})
	}
}

type edgeChallengeBackend struct {
	domains.Backend
	err error
}

func (b edgeChallengeBackend) Challenge(_ context.Context, request *pb.ChallengeRequest) (*pb.ChallengeResponse, error) {
	if b.err != nil {
		return nil, b.err
	}
	if request.Name != "work.example.com" || request.Token != "current-token" {
		return nil, status.Error(codes.NotFound, "missing fixture challenge")
	}
	return &pb.ChallengeResponse{Body: "current-token.account-proof"}, nil
}

func TestEdgeHTTP01MethodHostAndAuthority(t *testing.T) {
	for _, tc := range []struct {
		method, host, path string
		backendErr         error
		code               int
	}{
		{"GET", "work.example.com", "/.well-known/acme-challenge/current-token", nil, 200},
		{"GET", "WORK.EXAMPLE.COM.:80", "/.well-known/acme-challenge/current-token?ignored=1", nil, 200},
		{"POST", "work.example.com", "/.well-known/acme-challenge/current-token", nil, 404},
		{"HEAD", "work.example.com", "/.well-known/acme-challenge/current-token", nil, 404},
		{"GET", "other.example.com", "/.well-known/acme-challenge/current-token", nil, 404},
		{"GET", "work.example.com", "/.well-known/acme-challenge/wrong-token", nil, 404},
		{"GET", "work.example.com", "/.well-known/acme-challenge/", nil, 404},
		{"GET", "work.example.com", "/.well-known/acme-challenge/current-token/extra", nil, 404},
		{"GET", "work.example.com", "/.well-known/acme-challenge/current-token%2fextra", nil, 404},
		{"GET", "work.example.com", "/health", nil, 404},
		{"GET", "work.example.com", "/.well-known/acme-challenge/current-token", status.Error(codes.Unavailable, "fixture unavailable"), 503},
	} {
		t.Run(fmt.Sprintf("%s %s%s/%d", tc.method, tc.host, tc.path, tc.code), func(t *testing.T) {
			p := &ProxyServer{domains: edgeChallengeBackend{err: tc.backendErr}}
			r := httptest.NewRequest(tc.method, "http://work.example.com"+tc.path, nil)
			r.Host = tc.host
			rec := httptest.NewRecorder()
			p.http01Handler().ServeHTTP(rec, r)
			if rec.Code != tc.code || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("HTTP01: %d %s headers=%v", rec.Code, rec.Body, rec.Header())
			}
			if tc.code == 200 && (rec.Body.String() != "current-token.account-proof" || rec.Header().Get("Content-Type") != "text/plain") {
				t.Fatalf("challenge response changed: %s %v", rec.Body, rec.Header())
			}
			if tc.code != 200 && strings.Contains(rec.Body.String(), "account-proof") {
				t.Fatal("failed HTTP01 response disclosed proof")
			}
		})
	}
}

func edgeTLSFiles(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"tunn.test", "*.tunn.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	certFile, keyFile := filepath.Join(root, "fullchain.pem"), filepath.Join(root, "privkey.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for path, data := range map[string][]byte{certFile: certPEM, keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture trust root invalid")
	}
	return certFile, keyFile, pool
}

func TestEdgeTLSLoadingRejectsInvalidMaterial(t *testing.T) {
	for _, kind := range []string{"missing certificate", "missing key", "malformed certificate", "malformed key", "mismatched key"} {
		t.Run(kind, func(t *testing.T) {
			certFile, keyFile, _ := edgeTLSFiles(t)
			var err error
			switch kind {
			case "missing certificate":
				err = os.Remove(certFile)
			case "missing key":
				err = os.Remove(keyFile)
			case "malformed certificate":
				err = os.WriteFile(certFile, []byte("invalid PEM"), 0600)
			case "malformed key":
				err = os.WriteFile(keyFile, []byte("invalid PEM"), 0600)
			case "mismatched key":
				_, keyFile, _ = edgeTLSFiles(t)
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{Environment: config.EnvProd, Domain: "tunn.test", CertFile: certFile, KeyFile: keyFile}
			if _, err := NewProxyServer(cfg); err == nil || !strings.Contains(err.Error(), "failed to load TUNN_CERT_FILE/TUNN_KEY_FILE") {
				t.Fatalf("public TLS accepted invalid material or unclear error: %v", err)
			}
			if _, err := createInternalTLSConfig(cfg); err == nil || !strings.Contains(err.Error(), "failed to load server cert") {
				t.Fatalf("internal TLS accepted invalid material or unclear error: %v", err)
			}
		})
	}
}

func TestEdgeTLSLoadedCertificateNegotiatesHTTP(t *testing.T) {
	certFile, keyFile, pool := edgeTLSFiles(t)
	p, err := NewProxyServer(&config.Config{Environment: config.EnvProd, Domain: "tunn.test", CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer p.grpcServer.Stop()
	defer p.internalGRPCServer.Stop()
	for _, protocol := range []string{"h2", "http/1.1"} {
		t.Run(protocol, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = a.Close() }()
			defer func() { _ = b.Close() }()
			_ = a.SetDeadline(time.Now().Add(3 * time.Second))
			_ = b.SetDeadline(time.Now().Add(3 * time.Second))
			server := tls.Server(a, p.tlsConfig)
			client := tls.Client(b, &tls.Config{ServerName: "api.tunn.test", RootCAs: pool, NextProtos: []string{protocol}})
			done := make(chan error, 1)
			go func() { done <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if state := client.ConnectionState(); state.NegotiatedProtocol != protocol || state.PeerCertificates[0].VerifyHostname("api.tunn.test") != nil {
				t.Fatalf("loaded TLS state: %+v", state)
			}
		})
	}
	selectCertificate := p.domainCertificate(p.tlsConfig.Certificates[0])
	for _, name := range []string{"", "tunn.test", "www.tunn.test", "api.tunn.test", "API.TUNN.TEST."} {
		if _, err := selectCertificate(&tls.ClientHelloInfo{ServerName: name}); err != nil {
			t.Fatalf("platform certificate %q unavailable without domain authority: %v", name, err)
		}
	}
	for _, name := range []string{"work.example.com", "nested.api.tunn.test", "api.tunn.test.example.com"} {
		if _, err := selectCertificate(&tls.ClientHelloInfo{ServerName: name}); err == nil {
			t.Fatalf("customer/nested hostname %q selected wildcard certificate", name)
		}
	}
}
