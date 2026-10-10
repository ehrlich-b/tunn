package hostmode

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/client"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHostClientRegistrationPrivacy(t *testing.T) {
	c, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	a := API{Server: "127.0.0.1:8443", Token: "test-token", Client: &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://127.0.0.1:8443/api/hosts" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("incorrect authenticated registry request")
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"target", "allow", "command", "tools", "18789", "8080", "owner@example.com"} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("registration leaked %s", secret)
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"reserved":true}`)), Header: make(http.Header)}, nil
	})}}
	if err := a.Register(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func TestHostClientListing(t *testing.T) {
	a := API{Server: "127.0.0.1:8443", Token: "test-token", Client: &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.Body != nil {
			t.Fatal("hosts listing is not read-only")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"name":"gpu-box","online":true,"last_seen":"2026-10-10T12:00:00Z","tunnels":[{"name":"gpu-http","kind":"http","url":"https://gpu-http.host.test","online":true,"last_seen":"2026-10-10T12:00:00Z"}]}]`)), Header: make(http.Header)}, nil
	})}}
	m, err := a.Hosts(context.Background())
	if err != nil || len(m) != 1 || !m[0].Online || m[0].Tunnels[0].Name != "gpu-http" {
		t.Fatalf("hosts = %v %v", m, err)
	}
}

func TestHostHealth(t *testing.T) {
	c, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHealth(c)
	check := func(path string, code int) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != code {
			t.Fatalf("%s status = %d", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "8080") || strings.Contains(w.Body.String(), "owner@example.com") {
			t.Fatal("health leaks target or allow-list")
		}
	}
	check("/healthz", 200)
	check("/health", 503)
	for _, endpoint := range c.Tunnels {
		h.Set(endpoint.Name, true)
	}
	check("/readyz", 200)
	h.Set("gpu-http", false)
	check("/readyz", 503)
	check("/other", 404)
}

func TestHostRuntimeTokensSurviveRestart(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", t.TempDir())
	p, err := endpointToken("gpu-http")
	if err != nil {
		t.Fatal(err)
	}
	old, err := client.LoadEndpointToken("gpu-http")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := endpointToken("gpu-http")
	if err != nil || p != p2 {
		t.Fatal("token path changed")
	}
	now, err := client.LoadEndpointToken("gpu-http")
	if err != nil || old != now {
		t.Fatal("token rotated during restart")
	}
	rotated, _, err := client.RotateEndpointToken("gpu-http")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpointToken("gpu-http"); err != nil {
		t.Fatal(err)
	}
	now, _ = client.LoadEndpointToken("gpu-http")
	if now != rotated {
		t.Fatal("restart lost explicit token rotation")
	}
	if err := os.WriteFile(p, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := endpointToken("gpu-http"); err == nil {
		t.Fatal("corrupt credential was silently replaced")
	}
}

func TestOpenClawScaffold(t *testing.T) {
	var b bytes.Buffer
	err := OpenClaw(context.Background(), OpenClawOptions{Name: "gpu-claw", Domain: "host.test", ConfigPath: "/tmp/host.yaml", RenderQR: func(ctx context.Context, url string, out io.Writer, png string) error {
		if url != "https://gpu-claw.host.test" {
			t.Fatal(url)
		}
		_, err := io.WriteString(out, "fixture-qr")
		return err
	}, Probe: func(ctx context.Context, addr string) error {
		if addr != "127.0.0.1:18789" {
			t.Fatal(addr)
		}
		return nil
	}}, &b)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"https://gpu-claw.host.test", "tunn-websocket", "1.", "2.", "3.", "URL only", "fixture-qr"} {
		if !strings.Contains(b.String(), expected) {
			t.Fatalf("missing %q", expected)
		}
	}
	if err := OpenClaw(context.Background(), OpenClawOptions{Name: "gpu-claw", Gateway: "http://192.0.2.1:18789"}, &b); err == nil {
		t.Fatal("remote gateway probe allowed")
	}
}

func TestHostClientHTTPError(t *testing.T) {
	a := API{Server: "127.0.0.1:8443", Token: "test-token", Client: &http.Client{Transport: fixtureTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("secret")), Header: make(http.Header)}, nil
	})}}
	_, err := a.Hosts(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("registry response body leaked")
	}
}
