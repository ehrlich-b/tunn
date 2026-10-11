package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc"
)

type hostDomainDNS struct{ target string }

func (d *hostDomainDNS) LookupCNAME(context.Context, string) (string, error) { return d.target, nil }

type hostDomainIssuer func(context.Context, string, domains.PresentChallenge) ([]byte, []byte, error)

func (f hostDomainIssuer) Issue(ctx context.Context, name string, p domains.PresentChallenge) ([]byte, []byte, error) {
	return f(ctx, name, p)
}
func domainProxyFixture(t *testing.T) (*ProxyServer, *domains.Registry, *hostDomainDNS) {
	t.Helper()
	p, _, _, _ := meteringRelay(t, false, "origin-content")
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO accounts(id,primary_email,plan,created_at) VALUES('ad38bf44-0c4a-40ce-bdee-2d8579bf63cc','owner@example.com','pro',1)`); err != nil {
		t.Fatal(err)
	}
	dns := new(hostDomainDNS)
	registry, err := domains.New(db, p.Domain, []byte("01234567890123456789012345678901"), dns, hostDomainIssuer(func(ctx context.Context, name string, present domains.PresentChallenge) ([]byte, []byte, error) {
		cleanup, err := present(ctx, "http01-token", "http01-token.proof")
		if err != nil {
			return nil, nil, err
		}
		defer cleanup()
		rec := httptest.NewRecorder()
		p.http01Handler().ServeHTTP(rec, httptest.NewRequest("GET", "http://"+name+"/.well-known/acme-challenge/http01-token", nil))
		if rec.Code != 200 || rec.Body.String() != "http01-token.proof" {
			t.Fatalf("HTTP01=%d %s", rec.Code, rec.Body)
		}
		for _, url := range []string{"http://other.example.com/.well-known/acme-challenge/http01-token", "http://" + name + "/.well-known/acme-challenge/incorrect"} {
			rec = httptest.NewRecorder()
			p.http01Handler().ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
			if rec.Code != 404 {
				t.Fatal(rec.Code)
			}
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		now := time.Now()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
		if err != nil {
			return nil, nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	p.domains = registry
	return p, registry, dns
}
func TestDomainAPIAndRoutingOwnEveryPath(t *testing.T) {
	p, registry, dns := domainProxyFixture(t)
	handler := p.createHandler()
	owner := relayJWT(t, p, "owner@example.com")
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://tunn.test"+path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}
	if rec := call("POST", "/api/domains", "", `{"name":"work.example.com","tunnel":"site"}`); rec.Code != 401 {
		t.Fatal(rec.Code)
	}
	if rec := call("POST", "/api/domains", owner, `{"name":"work.example.com","tunnel":"site","owner":"two"}`); rec.Code != 400 {
		t.Fatal(rec.Code)
	}
	rec := call("POST", "/api/domains", owner, `{"name":"work.example.com","tunnel":"site"}`)
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	d := new(domainpb.Domain)
	if err := json.Unmarshal(rec.Body.Bytes(), d); err != nil {
		t.Fatal(err)
	}
	dns.target = d.CnameTarget
	rec = call("POST", "/api/domains/work.example.com/verify", owner, "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Bind the fixture publisher to the same reserved endpoint and account.
	tunnel, _ := p.tunnelServer.GetTunnel("api")
	delete(p.tunnelServer.tunnels, "api")
	tunnel.TunnelID = "site"
	p.tunnelServer.tunnels["site"] = tunnel
	for _, path := range []string{"/account", "/api/domains", "/auth/login", "/health"} {
		r := httptest.NewRequest("GET", "https://work.example.com"+path, nil)
		r.Header.Set("Authorization", "Bearer "+owner)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code != 200 || rec.Body.String() != "origin-content" {
			t.Fatalf("customer path %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "https://work.example.com/account", nil))
	if rec.Code != 401 || rec.Header().Get("Location") != "" {
		t.Fatal("private custom domain must challenge bearer auth", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "https://unknown.example.com/account", nil))
	if rec.Code != 404 {
		t.Fatal("unknown host got platform UI", rec.Code)
	}
	originalOwner := tunnel.AccountID
	tunnel.AccountID = "other-account"
	r := httptest.NewRequest("GET", "https://work.example.com/", nil)
	r.Header.Set("Authorization", "Bearer "+owner)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Fatal("domain routed to other owner", rec.Code)
	}
	tunnel.AccountID = originalOwner
	if rec := call("GET", "/api/domains", relayJWT(t, p, "stranger@example.com"), ""); rec.Code != 200 || strings.Contains(rec.Body.String(), d.Name) {
		t.Fatal("domain list leaked", rec.Code, rec.Body)
	}
	if _, err := registry.Delete(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != 404 {
		t.Fatal("deleted domain routed", rec.Code)
	}
}
func TestDomainSNICertificateHandshakeAndAuthorityFailure(t *testing.T) {
	p, registry, dns := domainProxyFixture(t)
	d, err := registry.Add(context.Background(), &domainpb.Domain{Name: "work.example.com", Tunnel: "site", Owner: "ad38bf44-0c4a-40ce-bdee-2d8579bf63cc"})
	if err != nil {
		t.Fatal(err)
	}
	dns.target = d.CnameTarget
	if _, err := registry.Verify(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	pair, err := registry.Certificate(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pair.CertificatePem, pair.KeyPem)
	if err != nil {
		t.Fatal(err)
	}
	root := x509.NewCertPool()
	if !root.AppendCertsFromPEM(pair.CertificatePem) {
		t.Fatal("fixture root")
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	server := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{cert}, GetCertificate: p.domainCertificate(cert), NextProtos: []string{"h2", "http/1.1"}})
	client := tls.Client(b, &tls.Config{ServerName: d.Name, RootCAs: root, NextProtos: []string{"h2"}})
	result := make(chan error, 1)
	go func() { result <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if state := client.ConnectionState(); state.NegotiatedProtocol != "h2" || len(state.PeerCertificates) != 1 || state.PeerCertificates[0].DNSNames[0] != d.Name {
		t.Fatal(state)
	}
	p.domains = &domains.Remote{Connection: func() *grpc.ClientConn { return nil }}
	if _, err := p.domainCertificate(cert)(&tls.ClientHelloInfo{ServerName: d.Name}); err == nil {
		t.Fatal("authority outage fell back to wildcard certificate")
	}
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, httptest.NewRequest("GET", "https://work.example.com/", nil))
	if rec.Code != 503 {
		t.Fatal(rec.Code)
	}
}
