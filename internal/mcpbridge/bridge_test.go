package mcpbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_MCP_HELPER") == "1" {
		runMCPHelperProcess()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestBridgeMCPFlow(t *testing.T) {
	bridge := startTestBridge(t)

	discover := postMCP(t, bridge, "", "application/json", `{
		"jsonrpc":"2.0","id":"discover","method":"server/discover","params":{}
	}`)
	defer func() { _ = discover.Body.Close() }()
	if discover.StatusCode != http.StatusOK {
		t.Fatalf("server/discover status = %d, want legacy method error: %s", discover.StatusCode, readBody(t, discover.Body))
	}
	if body := readBody(t, discover.Body); !strings.Contains(body, `"code":-32601`) {
		t.Fatalf("server/discover did not return a fallback-compatible method error: %s", body)
	}

	initialize := postMCP(t, bridge, "", "application/json", `{
		"jsonrpc":"2.0","id":1,"method":"initialize",
		"params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}
	}`)
	defer func() { _ = initialize.Body.Close() }()
	if initialize.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200: %s", initialize.StatusCode, readBody(t, initialize.Body))
	}
	sessionID := initialize.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("initialize response has no Mcp-Session-Id")
	}
	if got := initialize.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("initialize Content-Type = %q, want application/json", got)
	}

	initialized := postMCP(t, bridge, sessionID, "application/json", `{
		"jsonrpc":"2.0","method":"notifications/initialized"
	}`)
	_ = initialized.Body.Close()
	if initialized.StatusCode != http.StatusAccepted {
		t.Fatalf("initialized status = %d, want 202", initialized.StatusCode)
	}

	missingSession := postMCP(t, bridge, "", "application/json", `{
		"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}
	}`)
	_ = missingSession.Body.Close()
	if missingSession.StatusCode != http.StatusNotFound {
		t.Fatalf("missing session status = %d, want 404", missingSession.StatusCode)
	}

	list := postMCP(t, bridge, sessionID, "application/json", `{
		"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}
	}`)
	defer func() { _ = list.Body.Close() }()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("tools/list status = %d, want 200: %s", list.StatusCode, readBody(t, list.Body))
	}
	var listResponse struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(list.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(listResponse.Result.Tools) != 1 || listResponse.Result.Tools[0].Name != "echo" {
		t.Fatalf("tools/list returned %#v, want echo tool", listResponse.Result.Tools)
	}
}

func TestBridgeOfficialGoSDKClient(t *testing.T) {
	bridge := startTestBridge(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "tunn-interop-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             bridge.URL() + "/mcp",
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	if err != nil {
		t.Fatalf("official MCP client Connect: %v", err)
	}
	defer func() { _ = session.Close() }()
	if got := session.InitializeResult().ProtocolVersion; got != modernProtocolVersion {
		t.Fatalf("official MCP client negotiated %q, want %s", got, modernProtocolVersion)
	}

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("official MCP client ListTools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo" {
		t.Fatalf("official MCP client tools = %#v, want echo", tools.Tools)
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"text": "hello"},
	})
	if err != nil {
		t.Fatalf("official MCP client CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("official MCP tool returned error: %#v", result)
	}
}

func TestBridgeModernHeadersAndSessionlessCalls(t *testing.T) {
	bridge := startTestBridge(t)
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	post := func(method, name, body string) *http.Response {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, bridge.URL()+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
		request.Header.Set("Mcp-Method", method)
		if name != "" {
			request.Header.Set("Mcp-Name", name)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	discover := post("server/discover", "", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+meta+`}}`)
	if discover.StatusCode != http.StatusOK || discover.Header.Get("Mcp-Session-Id") != "" {
		t.Fatalf("discover status = %d, session = %q", discover.StatusCode, discover.Header.Get("Mcp-Session-Id"))
	}
	if body := readBody(t, discover.Body); !strings.Contains(body, modernProtocolVersion) {
		t.Fatalf("discover did not advertise current protocol: %s", body)
	}
	_ = discover.Body.Close()

	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + meta + `}}`
	list := post("tools/list", "", listBody)
	if list.StatusCode != http.StatusOK || !strings.Contains(readBody(t, list.Body), `"echo"`) {
		t.Fatal("modern tools/list failed")
	}
	_ = list.Body.Close()

	callBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"},` + meta + `}}`
	badName := post("tools/call", "wrong", callBody)
	if badName.StatusCode != http.StatusBadRequest || !strings.Contains(readBody(t, badName.Body), `"code":-32020`) {
		t.Fatal("mismatched Mcp-Name was not rejected")
	}
	_ = badName.Body.Close()
	call := post("tools/call", "echo", callBody)
	if call.StatusCode != http.StatusOK || !strings.Contains(readBody(t, call.Body), `"hello"`) {
		t.Fatal("modern tools/call failed")
	}
	_ = call.Body.Close()

	request, err := http.NewRequest(http.MethodPost, bridge.URL()+"/mcp", strings.NewReader(listBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/call")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(readBody(t, response.Body), `"code":-32020`) {
		t.Fatal("mismatched Mcp-Method was not rejected")
	}
	_ = response.Body.Close()

	request, err = http.NewRequest(http.MethodPost, bridge.URL()+"/mcp", strings.NewReader(listBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("browser Origin status = %d, want 403", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestBridgeCarriesFiniteSSENotifications(t *testing.T) {
	bridge := startTestBridge(t)
	sessionID := initializeTestBridge(t, bridge)

	response := postMCP(t, bridge, sessionID, "application/json, text/event-stream", `{
		"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}
	}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("tools/call status = %d, want 200: %s", response.StatusCode, readBody(t, response.Body))
	}
	if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	body := readBody(t, response.Body)
	if strings.Count(body, "event: message") != 2 {
		t.Fatalf("SSE body has wrong event count: %s", body)
	}
	if !strings.Contains(body, `"method":"notifications/progress"`) || !strings.Contains(body, `"id":"call-1"`) {
		t.Fatalf("SSE body is missing notification or response: %s", body)
	}
}

func TestBridgeRejectsChildRequestsWithoutDeadlock(t *testing.T) {
	bridge := startTestBridge(t)
	sessionID := initializeTestBridge(t, bridge)

	response := postMCP(t, bridge, sessionID, "application/json", `{
		"jsonrpc":"2.0","id":7,"method":"test/server-request","params":{}
	}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("server-request status = %d, want 200: %s", response.StatusCode, readBody(t, response.Body))
	}
	if body := readBody(t, response.Body); !strings.Contains(body, `"rejected":true`) {
		t.Fatalf("child did not receive explicit rejection: %s", body)
	}
}

func TestBridgeEnforcesLocalToolAllowList(t *testing.T) {
	bridge := startTestBridgeWithOptions(t, Options{AllowedTools: []string{"safe-tool"}})
	sessionID := initializeTestBridge(t, bridge)

	list := postMCP(t, bridge, sessionID, "application/json", `{
		"jsonrpc":"2.0","id":20,"method":"tools/list","params":{}
	}`)
	defer func() { _ = list.Body.Close() }()
	if body := readBody(t, list.Body); !strings.Contains(body, `"tools":[]`) {
		t.Fatalf("tools/list was not filtered: %s", body)
	}

	call := postMCP(t, bridge, sessionID, "application/json", `{
		"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"echo","arguments":{"text":"secret"}}
	}`)
	defer func() { _ = call.Body.Close() }()
	body := readBody(t, call.Body)
	if call.StatusCode != http.StatusOK || !strings.Contains(body, `"code":-32001`) {
		t.Fatalf("denied tools/call response = %d %s", call.StatusCode, body)
	}
}

func TestBridgeValidatesHTTPEnvelope(t *testing.T) {
	bridge := startTestBridge(t)

	request, err := http.NewRequest(http.MethodPost, bridge.URL()+"/mcp", strings.NewReader("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "text/plain")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong content type status = %d, want 415", response.StatusCode)
	}
}

func TestBridgeTimesOut(t *testing.T) {
	// Keep process startup and network scheduling out of the deadline check.
	// synctest advances the real handler's clock only once it is blocked
	// waiting for the child response, regardless of host load.
	synctest.Test(t, func(t *testing.T) {
		bridge := &Bridge{
			outputs:        make(chan childOutput, 1),
			requestTimeout: defaultRequestTimeout,
		}
		neverWritten := false
		bridge.stdin = lifecycleWriteFunc(func(message []byte) (int, error) {
			var request envelope
			if err := json.Unmarshal(message, &request); err != nil {
				t.Fatalf("decode child request: %v", err)
			}
			switch request.Method {
			case "initialize":
				bridge.outputs <- childOutput{message: []byte(fmt.Sprintf(
					`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}}`,
					request.ID))}
			case "test/never":
				neverWritten = true // The child accepts the call but never replies.
			default:
				t.Fatalf("unexpected child method: %q", request.Method)
			}
			return len(message), nil
		})

		initialize := httptest.NewRecorder()
		bridge.ServeHTTP(initialize, lifecycleRequest(context.Background(), `{
			"jsonrpc":"2.0","id":1,"method":"initialize",
			"params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}
		}`))
		if initialize.Code != http.StatusOK {
			t.Fatalf("initialize status = %d, want 200: %s", initialize.Code, initialize.Body)
		}
		sessionID := initialize.Header().Get("Mcp-Session-Id")
		if sessionID == "" {
			t.Fatal("initialize response has no Mcp-Session-Id")
		}

		bridge.requestTimeout = 30 * time.Millisecond
		request := lifecycleRequest(context.Background(), `{
			"jsonrpc":"2.0","id":99,"method":"test/never","params":{}
		}`)
		request.Header.Set("Mcp-Session-Id", sessionID)
		response := httptest.NewRecorder()
		start := time.Now()
		bridge.ServeHTTP(response, request)
		if !neverWritten {
			t.Fatal("timeout request never reached the child")
		}
		if elapsed := time.Since(start); elapsed != bridge.requestTimeout {
			t.Fatalf("timeout after %s, want %s", elapsed, bridge.requestTimeout)
		}
		if response.Code != http.StatusGatewayTimeout {
			t.Fatalf("timeout status = %d, want 504: %s", response.Code, response.Body)
		}
		var message struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &message); err != nil {
			t.Fatalf("decode timeout response: %v", err)
		}
		if message.JSONRPC != "2.0" || message.ID != 99 || message.Error.Code != -32603 || message.Error.Message != "local MCP request timed out" {
			t.Fatalf("uncorrelated or incorrect timeout error: %s", response.Body)
		}
	})
}

func TestBridgeClosesInheritedStdoutOnCancellation(t *testing.T) {
	// The descendant holds stdout after its parent exits. Keep it alive until
	// cleanup so EOF cannot hide a reader that cancellation failed to stop.
	for _, cancelParent := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent-cancel-%t", cancelParent), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var pid bytes.Buffer
			bridge, err := StartStdioHandler(ctx, []string{"sh", "-c", "sleep 30 2>/dev/null & echo $! >&2"}, &pid, Options{})
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-bridge.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("child did not exit")
			}
			childPID, err := strconv.Atoi(strings.TrimSpace(pid.String()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if process, err := os.FindProcess(childPID); err == nil {
					_ = process.Kill()
				}
			})
			if cancelParent {
				cancel()
			} else {
				closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := bridge.Close(closeCtx); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-bridge.readerDone:
			case <-time.After(time.Second):
				t.Fatal("stdout reader did not stop")
			}
		})
	}
}

func TestBridgeReportsChildExit(t *testing.T) {
	bridge := startTestBridge(t)
	sessionID := initializeTestBridge(t, bridge)

	response := postMCP(t, bridge, sessionID, "application/json", `{
		"jsonrpc":"2.0","id":10,"method":"test/exit","params":{}
	}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exit response status = %d, want 200", response.StatusCode)
	}

	select {
	case <-bridge.Done():
		if err := bridge.Wait(); err != nil {
			t.Fatalf("helper exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Bridge.Done did not report child exit")
	}
}

func TestBridgeFailsRequestWhenChildExits(t *testing.T) {
	bridge := startTestBridge(t)
	sessionID := initializeTestBridge(t, bridge)

	response := postMCP(t, bridge, sessionID, "application/json", `{
		"jsonrpc":"2.0","id":11,"method":"test/exit-now","params":{}
	}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("child exit status = %d, want 502: %s", response.StatusCode, readBody(t, response.Body))
	}
}

func startTestBridge(t *testing.T) *Bridge {
	return startTestBridgeWithOptions(t, Options{})
}

func startTestBridgeWithOptions(t *testing.T, options Options) *Bridge {
	t.Helper()
	t.Setenv("GO_WANT_MCP_HELPER", "1")
	ctx, cancel := context.WithCancel(context.Background())
	bridge, err := StartWithOptions(ctx, []string{os.Args[0]}, os.Stderr, options)
	if err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
		defer closeCancel()
		if err := bridge.Close(closeCtx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return bridge
}

func initializeTestBridge(t *testing.T, bridge *Bridge) string {
	t.Helper()
	response := postMCP(t, bridge, "", "application/json", `{
		"jsonrpc":"2.0","id":1,"method":"initialize",
		"params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}
	}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d: %s", response.StatusCode, readBody(t, response.Body))
	}
	return response.Header.Get("Mcp-Session-Id")
}

func postMCP(t *testing.T, bridge *Bridge, sessionID, accept, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, bridge.URL()+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", accept)
	if sessionID != "" {
		request.Header.Set("Mcp-Session-Id", sessionID)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	return response
}

func readBody(t *testing.T, reader io.Reader) string {
	t.Helper()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// runMCPHelperProcess becomes the stdio MCP child in subprocesses launched by
// startTestBridge. It intentionally implements only the messages needed here.
func runMCPHelperProcess() {
	scanner := bufio.NewScanner(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	write := func(message string) {
		_, _ = fmt.Fprintln(writer, message)
		_ = writer.Flush()
	}

	for scanner.Scan() {
		message := append([]byte(nil), scanner.Bytes()...)
		var request envelope
		if json.Unmarshal(message, &request) != nil {
			continue
		}

		switch request.Method {
		case "initialize":
			write(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}}`, request.ID))
		case "notifications/initialized":
		case "tools/list":
			write(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"echo text","inputSchema":{"type":"object"}}]}}`, request.ID))
		case "tools/call":
			write(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p","progress":1,"total":1}}`)
			write(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"hello"}]}}`, request.ID))
		case "test/server-request":
			write(`{"jsonrpc":"2.0","id":"child-1","method":"roots/list","params":{}}`)
			if !scanner.Scan() {
				return
			}
			rejection := scanner.Bytes()
			rejected := bytes.Contains(rejection, []byte(`"code":-32601`))
			write(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"rejected":%t}}`, request.ID, rejected))
		case "test/never":
		case "test/exit":
			write(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"exiting":true}}`, request.ID))
			return
		case "test/exit-now":
			return
		default:
			if hasID(request.ID) {
				write(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, request.ID))
			}
		}
	}
}

func TestBridgeCloseUnusedConnection(t *testing.T) {
	bridge := startTestBridge(t)
	address, err := url.Parse(bridge.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", address.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Second)
	for {
		bridge.httpConnMu.Lock()
		accepted := len(bridge.httpNewConns) > 0
		bridge.httpConnMu.Unlock()
		if accepted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not accept speculative connection")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := bridge.Close(ctx); err != nil {
		t.Fatal("unused connection delayed shutdown", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("unused connection leaked", err)
	}
}
