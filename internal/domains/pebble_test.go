package domains

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"golang.org/x/net/dns/dnsmessage"
)

// Opt-in local acceptance test; ordinary offline suites exercise fake-directory
// protocol/decision tests. The accompanying script starts only a test CA.
func TestPebbleWildcardHTTP01(t *testing.T) {
	directory := os.Getenv("TUNN_PEBBLE_DIRECTORY")
	if directory == "" {
		t.Skip("run scripts/test-apps-pebble.sh for real local ACME")
	}
	dns, err := net.ListenPacket("udp", "127.0.0.1:28053")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	response := func(buf []byte) []byte {
		var m dnsmessage.Message
		if m.Unpack(buf) != nil {
			return nil
		}
		m.Header.Response = true
		m.Header.Authoritative = true
		for _, q := range m.Questions {
			if q.Type == dnsmessage.TypeA {
				m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
			}
		}
		data, _ := m.Pack()
		return data
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = dns.WriteTo(response(buf[:n]), peer)
		}
	}()
	tcpDNS, err := net.Listen("tcp", "127.0.0.1:28053")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpDNS.Close()
	go func() {
		for {
			conn, err := tcpDNS.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				buf := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				data := response(buf)
				binary.BigEndian.PutUint16(length[:], uint16(len(data)))
				_, _ = conn.Write(append(length[:], data...))
			}()
		}
	}()
	r, _, d := wildcardFixture(t)
	r.now = time.Now
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(os.Getenv("TUNN_PEBBLE_ROOT"))
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		t.Fatal("Pebble HTTPS trust root missing", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 30 * time.Second}
	if err := r.ConfigureACME(directory, "test@example.invalid", client); err != nil {
		t.Fatal(err)
	}

	originalIssuer := r.issuer
	r.issuer = issuerFunc(func(ctx context.Context, name string, p PresentChallenge) ([]byte, []byte, error) {
		cert, key, err := originalIssuer.Issue(ctx, name, p)
		if err != nil {
			t.Logf("Pebble ACME error: %v", err)
		}
		return cert, key, err
	})
	listener, err := net.Listen("tcp", "127.0.0.1:25002")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := strings.TrimPrefix(req.URL.Path, "/.well-known/acme-challenge/")
		out, err := r.Challenge(req.Context(), &pb.ChallengeRequest{Name: func() string {
			host, _, err := net.SplitHostPort(req.Host)
			if err == nil {
				return host
			}
			return req.Host
		}(), Token: token})
		if err != nil {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write([]byte(out.Body))
	})}
	go server.Serve(listener)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	pair, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pair.CertificatePem, pair.KeyPem)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("dashboard.apps.ehrlich.dev"); err != nil {
		t.Fatal(err)
	}
	cached, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"})
	if err != nil || string(cached.CertificatePem) != string(pair.CertificatePem) {
		t.Fatal("certificate not reused", err)
	}
	t.Logf("Pebble issued %s via real HTTP-01; expires %s", leaf.DNSNames[0], leaf.NotAfter.UTC())
}
