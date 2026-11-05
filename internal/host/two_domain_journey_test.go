package host

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	tunn "github.com/ehrlich-b/tunn/sdk"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/net/publicsuffix"
)

const twoDomainOwner = "owner@example.test"

var twoDomainHosts = []string{"grafana.apps.example.test", "dash.apps.example.test"}

// The child runs the production daemon, including TLS, HTTP/2, QUIC, internal
// RPC, SQLite, domain routing and permission checks. Only external Google, DNS
// and certificate issuance are fixtures. No production binary gains test hooks.
func TestTwoDomainDaemonProcess(t *testing.T) {
	dir := os.Getenv("TUNN_TWO_DOMAIN_PROCESS")
	if dir == "" {
		t.Skip("subprocess helper for TestTwoDomainLoginJourney")
	}
	var cfg config.Config
	twoDomainReadJSON(t, filepath.Join(dir, "config.json"), &cfg)
	p, err := NewProxyServer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	local := p.storage.(*storage.LocalStorage)
	if _, err := store.DB().Exec(`CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')`); err != nil {
		t.Fatal(err)
	}
	owner, err := local.FindOrCreateGoogleIdentity(context.Background(), "fixture-subject:"+twoDomainOwner, twoDomainOwner, "example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.UpdatePlan(context.Background(), owner.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	provider := googleFixtureTransport(t, p, true)
	p.googleHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == googleTokenURL {
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			code := strings.SplitN(r.Form.Get("code"), "|", 2)
			digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if len(code) != 2 || code[1] != base64.RawURLEncoding.EncodeToString(digest[:]) {
				return nil, fmt.Errorf("Google fixture refused PKCE mismatch")
			}
			r.Form.Set("code", code[0])
		}
		return provider.Transport.RoundTrip(r)
	})}
	registry, err := domains.New(store.DB(), cfg.Domain, []byte(strings.Repeat("d", 32)), twoDomainDNS{dir}, hostDomainIssuer(func(ctx context.Context, name string, present domains.PresentChallenge) ([]byte, []byte, error) {
		cleanup, err := present(ctx, "fixture-http01", "fixture-http01.proof")
		if err != nil {
			return nil, nil, err
		}
		defer cleanup()
		req, err := http.NewRequestWithContext(ctx, "GET", "http://"+cfg.HTTP01Addr+"/.well-known/acme-challenge/fixture-http01", nil)
		if err != nil {
			return nil, nil, err
		}
		req.Host = name
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
		defer client.CloseIdleConnections()
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "fixture-http01.proof" {
			return nil, nil, fmt.Errorf("HTTP-01 failed for %s", name)
		}
		cert, err := os.ReadFile(filepath.Join(dir, name+".pem"))
		if err != nil {
			return nil, nil, err
		}
		key, err := os.ReadFile(filepath.Join(dir, name+".key"))
		return cert, key, err
	}))
	if err != nil {
		t.Fatal(err)
	}
	p.domains, p.domainRegistry = registry, registry
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	p.tlsConfig.GetCertificate = p.domainCertificate(cert)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// A private fixture control pipe invokes the same durable transition used by
	// tunn admin suspend. It is not an HTTP endpoint or an authentication bypass.
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if scanner.Text() != "revoke" {
				continue
			}
			_, err := local.OperationsStore().Transition(ctx, accountOperationsAdmin(t, owner.ID), owner.ID, "suspended", "two app fixture revocation", 0)
			if err != nil {
				t.Error(err)
				cancel()
				return
			}
			if err := os.WriteFile(filepath.Join(dir, "revoked"), []byte("suspended"), 0600); err != nil {
				t.Error(err)
				cancel()
				return
			}
		}
		cancel()
	}()
	if err := p.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type twoDomainDNS struct{ dir string }

func (d twoDomainDNS) LookupCNAME(_ context.Context, name string) (string, error) {
	data, err := os.ReadFile(filepath.Join(d.dir, "dns.json"))
	if err != nil {
		return "", err
	}
	var records map[string]string
	if err := json.Unmarshal(data, &records); err != nil {
		return "", err
	}
	if value := records[name]; value != "" {
		return value, nil
	}
	return "", fmt.Errorf("no fixture DNS record for %s", name)
}
func twoDomainReadJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}
func twoDomainWriteJSON(t *testing.T, path string, data any) {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func twoDomainTLS(t *testing.T, dir, name string, pool *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture certificate")
	}
	for path, data := range map[string][]byte{name + ".pem": certPEM, name + ".key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})} {
		if err := os.WriteFile(filepath.Join(dir, path), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTwoDomainLoginJourney(t *testing.T) {
	dir := t.TempDir()
	pool := x509.NewCertPool()
	for _, name := range append([]string{"tunn.test"}, twoDomainHosts...) {
		twoDomainTLS(t, dir, name, pool)
	}
	cfg := config.Config{Environment: config.EnvProd, Domain: "tunn.test", PublicAddr: "tunn.test:443", CertFile: filepath.Join(dir, "tunn.test.pem"), KeyFile: filepath.Join(dir, "tunn.test.key"), HTTP2Addr: opsFreeTCP(t), HTTP3Addr: "127.0.0.1:0", InternalGRPCPort: "127.0.0.1:0", HTTP01Addr: opsFreeTCP(t), LoginNode: true, DBPath: filepath.Join(dir, "tunn.sqlite"), JWTSecret: "fixture-two-domain-signing-secret", WellKnownKey: "fixture-publisher-key", GoogleClientID: "fixture-id", GoogleClientSecret: "fixture-secret"}
	cfg.IdentityKeysFile = filepath.Join(dir, "identity.json")
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	twoDomainWriteJSON(t, cfg.IdentityKeysFile, map[string]any{"active": "fixture", "keys": []map[string]string{{"kid": "fixture", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(pub), "d": base64.RawURLEncoding.EncodeToString(key.Seed())}}})
	twoDomainWriteJSON(t, filepath.Join(dir, "config.json"), cfg)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestTwoDomainDaemonProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "TUNN_TWO_DOMAIN_PROCESS="+dir)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan struct{})
	var processErr error
	go func() {
		processErr = cmd.Wait()
		close(processDone)
	}()
	t.Cleanup(func() {
		input.Close()
		<-processDone
		if processErr != nil {
			data, _ := os.ReadFile(logFile.Name())
			t.Errorf("daemon process: %v\n%s", processErr, data)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if host != "tunn.test" && host != twoDomainHosts[0] && host != twoDomainHosts[1] {
			return nil, fmt.Errorf("fixture refuses network to %s", host)
		}
		return (&net.Dialer{}).DialContext(ctx, network, cfg.HTTP2Addr)
	}}
	defer transport.CloseIdleConnections()
	management := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(10 * time.Second)
	lastProbe := "not attempted"
	for {
		select {
		case <-processDone:
			data, _ := os.ReadFile(logFile.Name())
			t.Fatalf("daemon exited before readiness: %v; last probe: %s\n%s", processErr, lastProbe, data)
		default:
		}
		resp, err := management.Get("https://tunn.test/readyz")
		if err == nil {
			resp.Body.Close()
			lastProbe = resp.Status
			if resp.StatusCode == 200 {
				break
			}
		} else {
			lastProbe = err.Error()
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(logFile.Name())
			t.Fatalf("daemon readiness timed out; last probe: %s\n%s", lastProbe, data)
		}
		time.Sleep(20 * time.Millisecond)
	}
	ownerToken := createTestJWT(twoDomainOwner, cfg.JWTSecret)
	api := func(method, path, body string, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, "https://tunn.test"+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := management.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, resp.StatusCode, want, data)
		}
		return data
	}
	var claim domainpb.Domain
	for _, name := range []string{"grafana", "dash"} {
		data := api("POST", "/api/domains", fmt.Sprintf(`{"name":"*.apps.example.test","tunnel":%q}`, name), 201)
		if err := json.Unmarshal(data, &claim); err != nil {
			t.Fatal(err)
		}
	}
	// Verification must fail until the operator publishes the exact returned proof.
	api("POST", "/api/domains/*.apps.example.test/verify", "", 409)
	twoDomainWriteJSON(t, filepath.Join(dir, "dns.json"), map[string]string{"*.apps.example.test": claim.CnameTarget})
	data := api("POST", "/api/domains/*.apps.example.test/verify", "", 200)
	if err := json.Unmarshal(data, &claim); err != nil || claim.State != "ready" || len(claim.AppNames) != 2 {
		t.Fatalf("verified namespace and two apps: %s", data)
	}
	t.Log("one daemon process: verified *.apps.example.test with grafana and dash; missing DNS proof refused")
	var deliveries [2]atomic.Int64
	for index, label := range []string{"grafana", "dash"} {
		var binding struct {
			Tunnel string `json:"tunnel"`
		}
		data := api("POST", "/api/domains/publisher", fmt.Sprintf(`{"name":%q}`, label+".apps.example.test"), 200)
		if err := json.Unmarshal(data, &binding); err != nil || binding.Tunnel == "" {
			t.Fatalf("publisher lookup: %s", data)
		}
		publisher, err := tunn.PublishHandler(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deliveries[index].Add(1)
			if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
				t.Error("platform credential reached app")
			}
			token, err := identityForTwoDomain(r.Header.Get("X-Tunn-Identity"), pub, twoDomainHosts[index])
			if err != nil || token != twoDomainOwner || r.Header.Get("X-Tunn-User-Email") != twoDomainOwner {
				t.Errorf("app identity: %q %v", token, err)
			}
			fmt.Fprintf(w, "%s dashboard %s", label, r.URL.RequestURI())
		}), tunn.Options{Name: binding.Tunnel, ServerAddr: cfg.HTTP2Addr, Credentials: tunn.Credentials{AuthToken: ownerToken, TunnelKey: cfg.WellKnownKey}, TLSConfig: &tls.Config{RootCAs: pool, ServerName: "tunn.test", MinVersion: tls.VersionTLS12}, ConnectTimeout: 5 * time.Second, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := publisher.Close(); err != nil {
				t.Error(err)
			}
		})
		ready, stop := context.WithTimeout(ctx, 5*time.Second)
		_, err = publisher.WaitReady(ready)
		stop()
		if err != nil {
			t.Fatal(err)
		}
	}
	newBrowser := func() *http.Client {
		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Client{Transport: transport, Timeout: 5 * time.Second, Jar: jar, CheckRedirect: management.CheckRedirect}
	}
	// A browser-like cookie jar follows only real redirects. Consent is the single
	// mocked front-channel step; the daemon still validates state and PKCE.
	browse := func(browser *http.Client, target string) (int, string) {
		t.Helper()
		for hop := 0; hop < 12; hop++ {
			req, _ := http.NewRequest("GET", target, nil)
			req.Header.Set("Accept", "text/html")
			resp, err := browser.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 302 {
				return resp.StatusCode, string(data)
			}
			next, err := resp.Location()
			if err != nil {
				t.Fatal(err)
			}
			target = next.String()
		}
		t.Fatal("SSO redirect loop")
		return 0, ""
	}
	signIn := func(browser *http.Client, page, email string) {
		t.Helper()
		link := regexp.MustCompile(`href="(/auth/google\?[^"]+)"`).FindStringSubmatch(page)
		if len(link) != 2 {
			t.Fatal("login page has no Google link")
		}
		resp, err := browser.Get("https://tunn.test" + html.UnescapeString(link[1]))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		consent, err := resp.Location()
		if err != nil || consent.Host != "accounts.google.com" || consent.Query().Get("code_challenge_method") != "S256" {
			t.Fatal("missing Google consent / PKCE")
		}
		q := consent.Query()
		if q.Get("redirect_uri") != "https://tunn.test/auth/google/callback" {
			t.Fatal("wrong callback")
		}
		callback := q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {email + "|" + q.Get("code_challenge")}}.Encode()
		status, body := browse(browser, callback)
		want := 200
		if email != twoDomainOwner {
			want = 403
		}
		if status != want {
			t.Fatalf("Google callback journey: %d want %d: %s", status, want, body)
		}
	}
	owner := newBrowser()
	status, page := browse(owner, "https://"+twoDomainHosts[0]+"/report?q=1")
	if status != 200 || deliveries[0].Load() != 0 {
		t.Fatal("anonymous request reached app")
	}
	signIn(owner, page, twoDomainOwner)
	for index, host := range twoDomainHosts {
		status, body := browse(owner, "https://"+host+"/report?q=1")
		if status != 200 || body != []string{"grafana", "dash"}[index]+" dashboard /report?q=1" {
			t.Fatalf("one login to %s: %d %s", host, status, body)
		}
	}
	// No second provider interaction: both ordinary host cookies now work directly.
	for _, host := range twoDomainHosts {
		resp, err := owner.Get("https://" + host + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("repeat app access: %d", resp.StatusCode)
		}
	}
	t.Log("one verified Google sign-in reached both distinct dashboards; repeat requests needed no provider redirect; TLS hostnames and signed per-host identities verified")
	before := [2]int64{deliveries[0].Load(), deliveries[1].Load()}
	stranger := newBrowser()
	_, page = browse(stranger, "https://"+twoDomainHosts[0]+"/")
	signIn(stranger, page, "stranger@example.test")
	for _, host := range twoDomainHosts {
		status, _ := browse(stranger, "https://"+host+"/")
		if status != 403 {
			t.Fatalf("stranger at %s: %d", host, status)
		}
	}
	if before != [2]int64{deliveries[0].Load(), deliveries[1].Load()} {
		t.Fatal("stranger reached publisher")
	}
	t.Log("signed-in stranger refused with 403 on both apps; zero publisher deliveries")
	// Platform sign-out does not visit either app host. Retain both original
	// cookies and prove that their next requests cannot reach a publisher.
	resp, err := owner.Get("https://tunn.test/auth/logout")
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("logout confirmation: %v %d", err, resp.StatusCode)
	}
	form := url.Values{"csrf_token": {securityFormToken(t, string(confirmation))}}
	post, err := http.NewRequest("POST", "https://tunn.test/auth/logout", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://tunn.test")
	resp, err = owner.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	for _, host := range twoDomainHosts {
		target, _ := url.Parse("https://" + host + "/")
		found := false
		for _, c := range owner.Jar.Cookies(target) {
			if c.Name == appCookie {
				found = true
			}
		}
		if !found {
			t.Fatal("logout removed an app cookie instead of revoking it")
		}
		req, _ := http.NewRequest("GET", target.String(), nil)
		req.Header.Set("Accept", "text/html")
		resp, err = owner.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		location, locationErr := resp.Location()
		if resp.StatusCode != 302 || locationErr != nil || location.Scheme != "https" || location.Hostname() != "tunn.test" || location.Path != "/auth/domain" || location.Query().Get("request") == "" {
			t.Fatalf("old cookie at %s after logout: %d", host, resp.StatusCode)
		}
	}
	if before != [2]int64{deliveries[0].Load(), deliveries[1].Load()} {
		t.Fatal("logged-out cookie reached a publisher")
	}
	resp, err = stranger.Get("https://tunn.test/auth/logout")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("logout affected another user's platform session")
	}
	t.Log("platform logout immediately refused retained cookies on both app hosts; zero publisher deliveries; other user's session retained")
	// Rejected host cookies have been cleared. A retry starts SSO just as
	// it would for a visitor without a cookie.
	for _, host := range twoDomainHosts {
		req, err := http.NewRequest("GET", "https://"+host+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		resp, err = owner.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		location, locationErr := resp.Location()
		if resp.StatusCode != 302 || locationErr != nil || location.Scheme != "https" || location.Hostname() != "tunn.test" || location.Path != "/auth/domain" || location.Query().Get("request") == "" {
			t.Fatal("signed-out app sign-in", resp.StatusCode)
		}
	}
	// Obtain a new platform session and both new app cookies through real SSO.
	_, page = browse(owner, "https://"+twoDomainHosts[0]+"/")
	signIn(owner, page, twoDomainOwner)
	for _, host := range twoDomainHosts {
		status, _ := browse(owner, "https://"+host+"/")
		if status != 200 {
			t.Fatalf("new login at %s: %d", host, status)
		}
	}
	before = [2]int64{deliveries[0].Load(), deliveries[1].Load()}
	t.Log("signing in again restored access to both app hosts")
	if _, err := io.WriteString(input, "revoke\n"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "revoked")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revocation timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, host := range twoDomainHosts {
		target, _ := url.Parse("https://" + host + "/")
		cookies := owner.Jar.Cookies(target)
		found := false
		for _, cookie := range cookies {
			if cookie.Name == appCookie {
				found = true
			}
		}
		if !found {
			t.Fatal("revocation check lost app cookie")
		}
		resp, err := owner.Get(target.String())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("revoked account at %s: %d", host, resp.StatusCode)
		}
	}
	if before != [2]int64{deliveries[0].Load(), deliveries[1].Load()} {
		t.Fatal("revoked request reached publisher")
	}
	t.Log("one durable account suspension ended access to both apps despite retained app cookies; zero publisher deliveries")
}

func identityForTwoDomain(raw string, key ed25519.PublicKey, host string) (string, error) {
	token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid identity assertion: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if !claims.VerifyAudience(host, true) || claims["iss"] != "https://tunn.test:443" || claims["email_verified"] != true || claims["provider"] != "google" || claims["sub"] != claims["account_id"] || claims["account_id"] == "" {
		return "", fmt.Errorf("wrong app identity claims")
	}
	email, _ := claims["email"].(string)
	return email, nil
}
