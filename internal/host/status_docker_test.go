//go:build client_image

package host

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
)

// Run explicitly after building the candidate image. All identities, TLS keys,
// databases, listeners and containers belong to this disposable local fixture.
func TestStatusDockerClientPrivateForwardingAndStop(t *testing.T) {
	image := os.Getenv("TUNN_TEST_CLIENT_IMAGE")
	if image == "" {
		t.Fatal("set TUNN_TEST_CLIENT_IMAGE to the locally built candidate image")
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "container app "+r.URL.RequestURI())
	}))
	defer app.Close()
	p, client, db := opsProxy(t)
	p.config.WellKnownKey = "fixture-key"
	ledger, err := metering.New(db, metering.WithAccountPlans())
	if err != nil {
		t.Fatal(err)
	}
	p.meter = ledger
	p.tunnelServer.sharing = ledger
	if _, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "fixture"); err != nil {
		t.Fatal(err)
	}
	cancel, done := opsStart(t, p)
	defer func() { cancel(); _ = opsWaitStopped(t, done) }()
	opsWaitHealth(t, p, client, "/healthz", 200)
	token := createTestJWT("owner@example.com", p.config.JWTSecret)
	run := func(args ...string) string {
		t.Helper()
		ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Env = append(os.Environ(), "TUNN_SECRET="+token)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("container fixture command failed: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	cid := run("run", "-d", "--network", "host", "-e", "TUNN_ENV=dev", "-e", "TUNN_SERVER_ADDR="+p.HTTP2Addr, "-e", "TUNN_WELL_KNOWN_KEY=fixture-key", "-e", "TUNN_SECRET", image, "http", app.URL, "--name", "container-fixture")
	defer run("rm", "-f", cid)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := p.tunnelServer.GetTunnel("container-fixture"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("container did not register: %s", run("logs", cid))
		}
		time.Sleep(10 * time.Millisecond)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(auth bool) (int, string) {
		t.Helper()
		r, _ := http.NewRequest("GET", "https://"+p.HTTP2Addr+"/from-container?fixture=1", nil)
		r.Host = "container-fixture.tunn.test"
		if auth {
			r.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if code, _ := request(false); code != 302 {
		t.Fatal("Docker quickstart did not retain private default", code)
	}
	if code, body := request(true); code != 200 || body != "container app /from-container?fixture=1" {
		t.Fatal("container did not forward to the host application", code, body)
	}
	run("stop", "--timeout", "5", cid)
	if code := run("inspect", "--format", "{{.State.ExitCode}}", cid); code != "0" {
		t.Fatal("client stop exit code", code)
	}
	t.Log("local image: registered, anonymous denied, owner forwarded, SIGTERM exit 0")
}
