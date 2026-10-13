package host

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// Opt-in gate: make test-js-sdk-contract builds the Node package first.
// Missing Node, denied loopback, and missing build artifacts fail this gate.
func TestJavaScriptSDKRelay(t *testing.T) {
	consumer := os.Getenv("TUNN_JS_SDK_CONSUMER")
	if consumer == "" {
		t.Skip("run make test-js-sdk-contract for Node relay acceptance")
	}
	consumer, err := filepath.Abs(consumer)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"handler", "origin"} {
		for _, wire := range []string{"streaming", "buffered"} {
			for _, exposure := range []string{"private", "public", "email", "endpoint", "bad-auth", "bad-key"} {
				t.Run(mode+"/"+wire+"/"+exposure, func(t *testing.T) {
					f := newMCPOAuthFixture(t)
					p := f.p
					p.tunnelServer.sharing = p.meter.(metering.SharingBackend)
					gs := grpc.NewServer()
					var implementation pb.TunnelServiceServer = p.tunnelServer
					if wire == "buffered" {
						implementation = &sdkBufferedRelay{p.tunnelServer}
					}
					pb.RegisterTunnelServiceServer(gs, implementation)
					p.grpcServer = gs
					relay := httptest.NewUnstartedServer(p.createHTTP2Router(p.createHandler()))
					relay.EnableHTTP2 = true
					relay.StartTLS()
					defer relay.Close()
					defer gs.Stop()
					credentials := map[string]any{"authToken": relayJWT(t, p, "owner@example.com"), "tunnelKey": p.config.WellKnownKey}
					options := map[string]any{"mode": mode, "name": "node-fixture", "serverAddr": relay.Listener.Addr().String(), "relayCA": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw})), "credentials": credentials, "connectTimeoutMs": 2000, "reconnect": map[string]int{"maxAttempts": 0}}
					switch exposure {
					case "public":
						options["public"] = true
					case "email":
						options["allowedEmails"] = []string{"alice@example.com"}
					case "endpoint":
						credentials["endpointToken"] = "tunn_ep_node-fixture"
					case "bad-auth":
						credentials["authToken"] = "not-a-jwt"
					case "bad-key":
						credentials["tunnelKey"] = "invalid-key"
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, "node", consumer)
					stdin, err := cmd.StdinPipe()
					if err != nil {
						t.Fatal(err)
					}
					stdout, err := cmd.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					// No remote strings/credentials in failure output. Fixture stderr is discarded.
					cmd.Stderr = io.Discard
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					joined := false
					defer func() {
						stdin.Close()
						if !joined {
							_ = cmd.Process.Kill()
							_ = cmd.Wait()
						}
					}()
					if err := json.NewEncoder(stdin).Encode(options); err != nil {
						t.Fatal(err)
					}
					scanner := bufio.NewScanner(stdout)
					if !scanner.Scan() {
						t.Fatal("Node did not return a registration result")
					}
					var result struct {
						Ready  string `json:"ready"`
						Error  string `json:"error"`
						Closed bool   `json:"closed"`
					}
					if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
						t.Fatal("invalid Node result")
					}
					if strings.HasPrefix(exposure, "bad-") {
						if result.Error != "registration_rejected" {
							t.Fatalf("auth category: %s", result.Error)
						}
						if err := cmd.Wait(); err != nil {
							t.Fatal(err)
						}
						joined = true
						return
					}
					if result.Ready != "https://node-fixture.tunn.test" {
						t.Fatalf("readiness missing: %s", result.Error)
					}
					registered, ok := p.tunnelServer.GetTunnel("node-fixture")
					if !ok || registered.CreatorEmail != "owner@example.com" || registered.TargetURL != "http" || registered.ResourceID == "" {
						t.Fatal("publisher identity/resource authority missing")
					}
					if registered.Supports("websocket-v1") || registered.Supports(deviceReauthCapability) {
						t.Fatal("Node advertised unsupported transports")
					}
					client := relay.Client()
					client.Timeout = 3 * time.Second
					client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
					open := func(email, endpoint string) (*http.Response, []byte) {
						t.Helper()
						req, _ := http.NewRequest("POST", relay.URL+"/mcp?fixture=1", strings.NewReader("input"))
						req.Host = "node-fixture.tunn.test"
						req.Header.Set("Authorization", "Bearer application-fixture")
						if email != "" {
							req.AddCookie(securityCookie(t, p, email))
						}
						if endpoint != "" {
							req.Header.Set("Tunn-Authorization", "Bearer "+endpoint)
						}
						res, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(res.Body)
						res.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
						return res, body
					}
					anonymous, _ := open("", "")
					if exposure == "public" {
						if anonymous.StatusCode != 200 {
							t.Fatalf("public admission: %d", anonymous.StatusCode)
						}
					} else if anonymous.StatusCode != 401 {
						t.Fatalf("anonymous private admission: %d", anonymous.StatusCode)
					}
					stranger, _ := open("stranger@example.com", "")
					if exposure != "public" && stranger.StatusCode != 403 {
						t.Fatalf("stranger admission: %d", stranger.StatusCode)
					}
					recipient, _ := open("alice@example.com", "")
					wantRecipient := 403
					if exposure == "email" || exposure == "public" {
						wantRecipient = 200
					}
					if recipient.StatusCode != wantRecipient {
						t.Fatalf("recipient admission: %d", recipient.StatusCode)
					}
					endpoint := ""
					email := "owner@example.com"
					if exposure == "endpoint" {
						bad, _ := open("", "tunn_ep_wrong")
						if bad.StatusCode != 401 {
							t.Fatalf("wrong endpoint bearer: %d", bad.StatusCode)
						}
						endpoint, email = "tunn_ep_node-fixture", ""
					}
					response, body := open(email, endpoint)
					if response.StatusCode != 200 {
						t.Fatalf("owner/endpoint status: %d", response.StatusCode)
					}
					var echoed map[string]string
					if err := json.Unmarshal(body, &echoed); err != nil {
						t.Fatal(err)
					}
					want := map[string]string{"method": "POST", "path": "/mcp?fixture=1", "auth": "Bearer application-fixture", "tunnAuth": "", "body": "input"}
					if !reflect.DeepEqual(echoed, want) {
						t.Fatal("application request fidelity mismatch")
					}
					if !reflect.DeepEqual(response.Header.Values("Set-Cookie"), []string{"first=a,b=c", "second=d"}) {
						t.Fatal("cookie field multiplicity lost")
					}
					if !reflect.DeepEqual(response.Trailer.Values("X-Final"), []string{"first", "second"}) {
						t.Fatalf("response trailers lost: %v", response.Trailer)
					}
					if exposure == "email" {
						owner := relayJWT(t, p, "owner@example.com")
						if w := sharingCall(t, p, "DELETE", "node-fixture", owner, `{"email":"alice@example.com"}`); w.Code != 200 {
							t.Fatal("share revocation failed")
						}
						revoked, _ := open("alice@example.com", "")
						if revoked.StatusCode != 403 {
							t.Fatal("revoked recipient still admitted")
						}
					}
					if _, err := io.WriteString(stdin, "close\n"); err != nil {
						t.Fatal(err)
					}
					if !scanner.Scan() {
						t.Fatal("Node did not join shutdown")
					}
					if err := json.Unmarshal(scanner.Bytes(), &result); err != nil || !result.Closed {
						t.Fatal("Node shutdown failed")
					}
					if err := cmd.Wait(); err != nil {
						t.Fatal(err)
					}
					joined = true
					deadline := time.Now().Add(time.Second)
					for time.Now().Before(deadline) {
						if _, ok := p.tunnelServer.GetTunnel("node-fixture"); !ok {
							return
						}
						time.Sleep(time.Millisecond)
					}
					t.Fatal("publisher remained registered after close")
				})
			}
		}
	}
}
