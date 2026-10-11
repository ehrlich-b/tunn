package domains

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
)

// The fake directory verifies JWS signatures, obtains HTTP-01 through another
// relay's shared authority, and signs the actual CSR. It never opens a socket.
type fakeDirectory struct {
	t          *testing.T
	authority  *Registry
	account    *ecdsa.PublicKey
	ca         *ecdsa.PrivateKey
	nonce      int
	issued     int
	authorized bool
	name       string
	cert       []byte
	async      bool
	fail       bool
}

func (f *fakeDirectory) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "acme.invalid" {
		return nil, fmt.Errorf("unexpected network destination %s", r.URL)
	}
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, r)
	return rec.Result(), nil
}
func (f *fakeDirectory) payload(r *http.Request) []byte {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	var jws struct{ Protected, Payload, Signature string }
	if err := json.Unmarshal(raw, &jws); err != nil {
		f.t.Fatal(err)
	}
	protected, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		f.t.Fatal(err)
	}
	var header struct {
		URL   string                `json:"url"`
		Alg   string                `json:"alg"`
		Nonce string                `json:"nonce"`
		KID   string                `json:"kid"`
		JWK   struct{ X, Y string } `json:"jwk"`
	}
	if err := json.Unmarshal(protected, &header); err != nil {
		f.t.Fatal(err)
	}
	if header.URL != r.URL.String() || header.Alg != "ES256" || header.Nonce == "" {
		f.t.Fatalf("invalid JWS header %s", protected)
	}
	key := f.account
	if header.KID == "" {
		x, _ := base64.RawURLEncoding.DecodeString(header.JWK.X)
		y, _ := base64.RawURLEncoding.DecodeString(header.JWK.Y)
		key = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if f.account != nil && (key.X.Cmp(f.account.X) != 0 || key.Y.Cmp(f.account.Y) != 0) {
			f.t.Fatal("ACME account key changed after restart")
		}
		f.account = key
	} else if header.KID != "https://acme.invalid/account/1" {
		f.t.Fatal("unknown account")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(jws.Signature)
	hash := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if len(sig) != 64 || key == nil || !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		f.t.Fatal("invalid ACME signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		f.t.Fatal(err)
	}
	return payload
}
func (f *fakeDirectory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", f.nonce))
	w.Header().Set("Content-Type", "application/json")
	const origin = "https://acme.invalid"
	if r.URL.Path == "/directory" {
		_ = json.NewEncoder(w).Encode(map[string]any{"newNonce": origin + "/nonce", "newAccount": origin + "/account", "newOrder": origin + "/order", "meta": map[string]string{"termsOfService": origin + "/terms"}})
		return
	}
	if r.URL.Path == "/nonce" {
		w.WriteHeader(200)
		return
	}
	payload := f.payload(r)
	if f.fail {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"fake failure"}`)
		return
	}
	switch r.URL.Path {
	case "/account":
		w.Header().Set("Location", origin+"/account/1")
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"status":"valid"}`)
	case "/order":
		var request struct {
			Identifiers []struct{ Type, Value string }
		}
		if err := json.Unmarshal(payload, &request); err != nil {
			f.t.Fatal(err)
		}
		if len(request.Identifiers) != 1 || request.Identifiers[0].Type != "dns" {
			f.t.Fatal("unexpected identifiers")
		}
		f.cert = nil
		f.name = request.Identifiers[0].Value
		f.authorized = false
		w.Header().Set("Location", origin+"/order/1")
		w.WriteHeader(201)
		f.order(w, "pending")
	case "/auth/1":
		state := "pending"
		if f.authorized {
			state = "valid"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": state, "identifier": map[string]string{"type": "dns", "value": f.name}, "challenges": []map[string]string{{"type": "http-01", "url": origin + "/challenge/1", "token": "fake-http01-token", "status": state}}})
	case "/challenge/1":
		out, err := f.authority.Challenge(r.Context(), &pb.ChallengeRequest{Name: f.name, Token: "fake-http01-token"})
		if err != nil || !strings.HasPrefix(out.Body, "fake-http01-token.") {
			f.t.Fatalf("HTTP-01 unavailable on other relay: %v %v", out, err)
		}
		f.authorized = true
		_, _ = io.WriteString(w, `{"type":"http-01","url":"https://acme.invalid/challenge/1","token":"fake-http01-token","status":"valid"}`)
	case "/order/1":
		w.Header().Set("Location", origin+"/order/1")
		state := "ready"
		if f.async && len(f.cert) > 0 {
			state = "valid"
		}
		f.order(w, state)
	case "/finalize/1":
		if !f.authorized {
			f.t.Fatal("finalized unverified identifier")
		}
		var input struct{ CSR string }
		if err := json.Unmarshal(payload, &input); err != nil {
			f.t.Fatal(err)
		}
		der, err := base64.RawURLEncoding.DecodeString(input.CSR)
		if err != nil {
			f.t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != f.name {
			f.t.Fatal("invalid CSR")
		}
		if f.ca == nil {
			f.ca, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				f.t.Fatal(err)
			}
		}
		f.issued++
		now := f.authority.now()
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(f.issued)), DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		signed, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, f.ca)
		if err != nil {
			f.t.Fatal(err)
		}
		f.cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed})
		if f.async {
			f.order(w, "processing")
		} else {
			w.Header().Set("Location", origin+"/order/1")
			f.order(w, "valid")
		}
	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(f.cert)
	default:
		f.t.Fatalf("unexpected ACME path %s", r.URL.Path)
	}
}
func (f *fakeDirectory) order(w http.ResponseWriter, state string) {
	_ = json.NewEncoder(w).Encode(map[string]any{"status": state, "identifiers": []map[string]string{{"type": "dns", "value": f.name}}, "authorizations": []string{"https://acme.invalid/auth/1"}, "finalize": "https://acme.invalid/finalize/1", "certificate": "https://acme.invalid/cert/1"})
}

func TestFakeACMEDirectoryIssueRenewAndRestart(t *testing.T) {
	r, dns, db := domainFixture(t, nil)
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = d.CnameTarget + "."
	other, err := New(db, r.base, fixtureKey, dns, nil)
	if err != nil {
		t.Fatal(err)
	}
	other.now = r.now
	fake := &fakeDirectory{t: t, authority: other}
	if err := r.ConfigureACME("https://acme.invalid/directory", "operator@example.com", &http.Client{Transport: fake}); err != nil {
		t.Fatal(err)
	}
	ready, err := r.Verify(context.Background(), d)
	if err != nil || ready.State != "ready" || fake.issued != 1 {
		t.Fatalf("%v %v", ready, err)
	}
	pair, err := r.Certificate(context.Background(), d)
	if err != nil || len(pair.KeyPem) == 0 {
		t.Fatalf("%v %v", pair, err)
	}
	if _, err := r.Challenge(context.Background(), &pb.ChallengeRequest{Name: d.Name, Token: "fake-http01-token"}); err == nil {
		t.Fatal("completed challenge retained")
	}
	var encrypted []byte
	if err := db.QueryRow(`SELECT key FROM custom_domains WHERE name=?`, d.Name).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "PRIVATE KEY") || string(encrypted) == string(pair.KeyPem) {
		t.Fatal("unencrypted domain key")
	}
	restarted, err := New(db, r.base, fixtureKey, dns, nil)
	if err != nil {
		t.Fatal(err)
	}
	later := r.now().Add(61 * 24 * time.Hour)
	restarted.now = func() time.Time { return later }
	other.now = restarted.now
	if err := restarted.ConfigureACME("https://acme.invalid/directory", "operator@example.com", &http.Client{Transport: fake}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	renewed, err := restarted.Route(context.Background(), d)
	if err != nil || fake.issued != 2 || renewed.CertificateExpires <= ready.CertificateExpires {
		t.Fatalf("%v %v count=%d", renewed, err, fake.issued)
	}
	// An ACME outage preserves a still-valid certificate while DNS remains proven.
	later = later.Add(61 * 24 * time.Hour)
	fake.fail = true
	if err := restarted.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Route(context.Background(), d); err != nil {
		t.Fatal("valid certificate lost during ACME outage", err)
	}
	later = later.Add(31 * 24 * time.Hour)
	if _, err := restarted.Certificate(context.Background(), d); err == nil {
		t.Fatal("expired certificate served")
	}
	// A wrong at-rest key cannot decrypt account or domain keys.
	wrong, err := New(db, r.base, make([]byte, 32), dns, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.ConfigureACME("https://acme.invalid/directory", "operator@example.com", &http.Client{Transport: fake}); err == nil {
		t.Fatal("wrong encryption key accepted")
	}
}

func TestACMEProcessingWithoutLocationResumesOriginalOrder(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = d.CnameTarget
	directory := &fakeDirectory{t: t, authority: r, async: true}
	if err := r.ConfigureACME("https://acme.invalid/directory", "operator@example.com", &http.Client{Transport: directory}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Verify(context.Background(), d); err != nil || directory.issued != 1 {
		t.Fatalf("order finalization lost: issued=%d err=%v", directory.issued, err)
	}
}
