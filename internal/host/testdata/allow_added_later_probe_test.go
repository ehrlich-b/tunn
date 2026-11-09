package host

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// This wire probe is overlaid by the external reproduction runner. It starts
// the actual CLI executable against a loopback TLS relay and HTTP origin.
func TestAllowAddedLaterCLIProbe(t *testing.T) {
	for _, tc := range []struct{ name, target, visitor string }{
		{"email", "b@x", "b@x"},
		{"hyphen email", "-alex@example.com", "-alex@example.com"},
		{"domain", "@example.com", "b@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) { probeAllowAddedLater(t, tc.target, tc.visitor) })
	}
}

func probeAllowAddedLater(t *testing.T, target, visitor string) {
	f := newMCPOAuthFixture(t)
	p := f.p
	p.tunnelServer.sharing = p.meter.(metering.SharingBackend)
	gs := grpc.NewServer()
	pb.RegisterTunnelServiceServer(gs, p.tunnelServer)
	relay := httptest.NewUnstartedServer(p.createHTTP2Router(p.createHandler()))
	relay.EnableHTTP2 = true
	relay.StartTLS()
	p.config.PublicAddr = relay.Listener.Addr().String()
	t.Cleanup(func() { gs.Stop(); relay.Close() })
	// createHTTP2Router dispatches gRPC through p.grpcServer.
	p.grpcServer = gs
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "private app") }))
	defer origin.Close()
	token := relayJWT(t, p, "owner@example.com")
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "token"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("TUNN_ALLOW_BINARY")
	if binary == "" {
		t.Fatal("TUNN_ALLOW_BINARY required")
	}
	var repairCommand []string
	start := func(allow string, rejected bool) func() {
		t.Helper()
		dir := t.TempDir()
		stdoutPath, stderrPath := filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
		stdout, err := os.Create(stdoutPath)
		if err != nil {
			t.Fatal(err)
		}
		defer stdout.Close()
		stderr, err := os.Create(stderrPath)
		if err != nil {
			t.Fatal(err)
		}
		defer stderr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, binary, "--insecure", "http", origin.URL, "--name", "preview", "--secret", token, "--tunnel-key", p.config.WellKnownKey, "--allow", allow)
		cmd.Env = append(os.Environ(), "TUNN_SERVER_ADDR="+relay.Listener.Addr().String(), "TUNN_CONFIG_DIR="+configDir, "TUNN_ENV=dev", "TUNN_PUBLIC_MODE=false")
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stopped, logged := false, false
		stop := func() {
			if logged {
				return
			}
			logged = true
			if !stopped {
				_ = cmd.Process.Signal(os.Interrupt)
				<-done
				stopped = true
			}
			cancel()
			out, _ := os.ReadFile(stdoutPath)
			errs, _ := os.ReadFile(stderrPath)
			t.Logf("tunn http ORIGIN --name preview --allow %s\nstdout:\n%sstderr:\n%s", allow, out, errs)
		}
		t.Cleanup(stop)
		deadline := time.After(10 * time.Second)
		for {
			out, _ := os.ReadFile(stdoutPath)
			if !rejected && strings.Contains(string(out), "allowed") {
				return stop
			}
			select {
			case err := <-done:
				stopped = true
				errs, _ := os.ReadFile(stderrPath)
				if !rejected || err == nil || !strings.Contains(string(errs), target+" is not allowed") || !strings.Contains(string(errs), "tunn share --server "+relay.Listener.Addr().String()+" --insecure -- preview "+target) || strings.Contains(string(out), "allowed") {
					t.Fatalf("unexpected exit %v: stdout=%s stderr=%s", err, out, errs)
				}
				for _, line := range strings.Split(string(errs), "\n") {
					if strings.HasPrefix(line, "tunn share ") {
						repairCommand = strings.Fields(line)[1:]
					}
				}
				return stop
			case <-deadline:
				t.Fatal("publisher did not settle")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	request := func(email string, want int) {
		t.Helper()
		req, _ := http.NewRequest("GET", relay.URL+"/", nil)
		req.Host = "preview.tunn.test"
		req.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, email)})
		res, err := relay.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		t.Logf("local edge GET / as %s: HTTP %d (body bytes=%d)", email, res.StatusCode, len(body))
		if res.StatusCode != want {
			t.Fatalf("HTTP %d, want %d", res.StatusCode, want)
		}
	}
	stop := start("a@x", false)
	request("a@x", 200)
	request(visitor, 403)
	stop()
	after := os.Getenv("TUNN_ALLOW_EXPECT") == "after"
	stop = start("a@x,"+target, after)
	if !after {
		request(visitor, 403)
	}
	stop()
	if after {
		share := exec.Command(binary, repairCommand...)
		share.Env = append(os.Environ(), "TUNN_CONFIG_DIR="+configDir)
		if output, err := share.CombinedOutput(); err != nil {
			t.Fatalf("printed share command: %v: %s", err, output)
		}
		t.Logf("printed tunn share preview %s command succeeded as the owner", target)
		stop = start("a@x,"+target, false)
		request(visitor, 200)
		request("unlisted@other.example", 403)
		stop()
		r, err := p.meter.(metering.SharingBackend).Sharing(context.Background(), &mp.SharingRequest{Operation: "get", Owner: f.tunnel.AccountID, Endpoint: "preview"})
		if err != nil || len(r.Resources[0].People) != 2 {
			t.Fatalf("grants=%v err=%v", r, err)
		}
	}
}
