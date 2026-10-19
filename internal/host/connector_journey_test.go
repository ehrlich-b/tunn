package host

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/mcpbridge"
	"github.com/ehrlich-b/tunn/internal/mcpcheck"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestConnectorJourneyOAuthToolsAndRevocation(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "relay.sqlite")
	db, err := store.OpenLocal(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	f := newMCPOAuthFixtureWithDB(t, db)
	prepareMCPAuthorityFixture(t, f)
	attachConnectorEcho(t, f)
	// Real TLS requests to disposable loopback; certificate verification stays on.
	server := httptest.NewTLSServer(f.p.createHandler())
	t.Cleanup(func() { server.Close() })
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.TLSClientConfig.ServerName = "example.com" // httptest certificate SAN
	address := strings.TrimPrefix(server.URL, "https://")
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	defer transport.CloseIdleConnections()
	// Close all HTTP handlers before replacing store pointers. Each reopening
	// reconstructs both OAuth registrations and the grant authority from disk.
	restart := func() {
		t.Helper()
		server.Close()
		transport.CloseIdleConnections()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := store.OpenLocal(databasePath)
		if err != nil {
			t.Fatal(err)
		}
		db = reopened
		t.Cleanup(func() { reopened.Close() })
		registry, err := newMCPOAuthStore(db)
		if err != nil {
			t.Fatal(err)
		}
		ledger, err := metering.New(db)
		if err != nil {
			t.Fatal(err)
		}
		f.p.storage = storage.NewLocalStorage(db)
		f.p.tunnelServer.storage = f.p.storage
		f.p.mcpOAuth, f.p.meter = registry, ledger
		server = httptest.NewTLSServer(f.p.createHandler())
		address = strings.TrimPrefix(server.URL, "https://")
	}
	checker := mcpcheck.New(transport)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	d, err := checker.Discover(ctx, "https://tools.tunn.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("PASS HTTPS private challenge, canonical resource, public client metadata and S256")
	var clientID string
	token, err := checker.Authenticate(ctx, d, func(link string) {
		u, err := url.Parse(link)
		if err != nil {
			t.Error(err)
			return
		}
		clientID = u.Query().Get("client_id")
		client := &specMCPClient{f: f, authorize: d.Authorize, query: u.Query()}
		client.login(t)
		page := f.request("GET", link, "", "", "", client.cookie)
		if page.Code != 200 || !strings.Contains(page.Body.String(), "Allow tunn connector-check to use tools tools?") {
			t.Errorf("consent page status %d", page.Code)
			return
		}
		form := url.Values{"authorization": {hiddenMCPField(t, page.Body.String(), "authorization")}, "csrf_token": {hiddenMCPField(t, page.Body.String(), "csrf_token")}, "decision": {"allow"}}
		response := f.request("POST", d.Authorize, form.Encode(), "application/x-www-form-urlencoded", "", client.cookie)
		if response.Code != 302 {
			t.Errorf("consent status %d", response.Code)
			return
		}
		callback := response.Header().Get("Location")
		parsed, _ := url.Parse(callback)
		if !strings.HasPrefix(callback, u.Query().Get("redirect_uri")+"?") || parsed.Hostname() != "127.0.0.1" {
			t.Error("callback left local fixture")
			return
		}
		// Only the checked loopback callback is followed; no external redirect GET.
		result, err := http.Get(callback)
		if err != nil {
			t.Error(err)
			return
		}
		result.Body.Close()
		if result.StatusCode != 200 {
			t.Errorf("callback status %d", result.StatusCode)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("PASS local email fixture, DCR, browser consent, loopback state/issuer, S256 token exchange")
	opts := mcpcheck.ToolOptions{Expected: []string{"echo"}, Call: "echo", Deny: "hidden_echo", Arguments: json.RawMessage(`{"text":"through the checker"}`)}
	report, err := checker.CheckTools(ctx, d, token, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Called || !report.Denied || len(report.Names) != 1 || report.Names[0] != "echo" {
		t.Fatalf("incomplete report: %#v", report)
	}
	// The fixture child advertises hidden_echo but exits if it receives its call.
	// Successful denial therefore proves both list filtering and no child call.
	t.Log("PASS initialize, exact filtered tools/list, harmless echo, hidden tool -32001 denial before child")
	if _, err := checker.CheckTools(ctx, d, token, mcpcheck.ToolOptions{Expected: []string{"echo", "hidden_echo"}}); err == nil {
		t.Fatal("accepted mismatched expected tools")
	}
	t.Log("PASS wrong expected tool set rejected")
	restart()
	if client, err := f.p.mcpOAuth.client(ctx, clientID); err != nil || client.Name != "tunn connector-check" {
		t.Fatal("OAuth registration lost on store reopening")
	}
	if _, err := checker.CheckTools(ctx, d, token, opts); err != nil {
		t.Fatalf("grant lost on store reopening: %v", err)
	}
	t.Log("PASS disk SQLite registration and active grant persist across close/reopen")
	owner := relayJWT(t, f.p, "owner@example.com")
	revoked := f.request("DELETE", "https://tunn.test/api/mcp/clients?tunnel=tools&client_id="+url.QueryEscape(clientID), "", "", owner, nil)
	if revoked.Code != 204 {
		t.Fatalf("revocation status %d", revoked.Code)
	}
	if _, err := checker.CheckTools(ctx, d, token, opts); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("revoked token accepted: %v", err)
	}
	t.Log("PASS revoked token rejected on next request")
	restart()
	if _, err := checker.CheckTools(ctx, d, token, opts); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("revoked token accepted after store reopening: %v", err)
	}
	t.Log("PASS durable revocation still rejects token after close/reopen")
}

func attachConnectorEcho(t *testing.T, f *mcpOAuthFixture) {
	t.Helper()
	t.Setenv("TUNN_MCP_OAUTH_HELPER", "1")
	bridge, err := mcpbridge.StartStdioHandler(context.Background(), []string{os.Args[0], "-test.run=^TestMCPOAuthStdioHelper$"}, io.Discard, mcpbridge.Options{AllowedTools: []string{"echo"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := bridge.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	f.tunnel.Stream.(*meteringFixtureStream).hook = func(message *pb.TunnelMessage) error {
		if request := message.GetHttpRequest(); request != nil {
			f.forwarded++
			local := httptest.NewRequest(request.Method, request.Path, bytes.NewReader(request.Body))
			for k, v := range request.Headers {
				local.Header.Set(k, v)
			}
			if local.Header.Get("Authorization") != "" || local.Header.Get("Cookie") != "" {
				t.Error("credentials reached child")
			}
			w := httptest.NewRecorder()
			bridge.ServeHTTP(w, local)
			headers := map[string]string{}
			for k := range w.Header() {
				headers[k] = w.Header().Get(k)
			}
			f.tunnel.pendingMu.RLock()
			ch := f.tunnel.pendingRequests[request.ConnectionId]
			f.tunnel.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: request.ConnectionId, StatusCode: int32(w.Code), Headers: headers, Body: w.Body.Bytes()}
		}
		return nil
	}
}
