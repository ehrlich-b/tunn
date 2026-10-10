package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func inspectContractEvent(i *Inspector, body string, complete bool) InspectionEvent {
	capture := i.begin("POST", "/hook", map[string]string{"Content-Type": "text/plain"})
	_, _ = capture.Write([]byte(body))
	if complete {
		capture.complete()
	}
	return capture.finishReason(202, 2, "complete")
}
func inspectContractAction(t *testing.T, i *Inspector, id uint64) string {
	t.Helper()
	action, err := i.prepare(id)
	if err != nil {
		t.Fatal(err)
	}
	return action
}
func inspectContractAPI(i *Inspector, method, path string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:4040"+path, body)
	r.Header.Set("X-Tunn-Inspector-Token", i.token)
	w := httptest.NewRecorder()
	i.ServeHTTP(w, r)
	return w
}
func inspectContractInspector() *Inspector {
	i := NewInspector(&ServeClient{TargetURL: "http://original.test:8080"})
	i.host = "127.0.0.1:4040"
	i.token = "fixture-session"
	return i
}

func TestInspectContractMetadataSentinels(t *testing.T) {
	i := inspectContractInspector()
	const secret = "TOKEN_SENTINEL_8e7f"
	headers := map[string]string{"Authorization": "Bearer " + secret, "Cookie": "session=" + secret, "Proxy-Authorization": secret, "X-Api-Key": secret, "X-Webhook-Signature": secret, "Content-Type": "text/plain"}
	c := i.beginConnection("correlation-1", "http", "POST", "/hook?ToKeN="+secret+"&custom="+secret, headers)
	_, _ = c.Write([]byte("BODY_SENTINEL_9a2c"))
	c.complete()
	c.finish(202, 2, "")
	headers["Authorization"] = "changed"
	e := i.list()[0]
	if e.Replayable || !e.Reconstructable || e.BodyCaptured || len(e.Body) != 0 || !e.QueryRedacted || len(e.RedactedHeaders) != 5 || e.ConnectionID != "correlation-1" || e.TerminalReason != "complete" {
		t.Fatalf("unsafe metadata: %+v", e)
	}
	for _, endpoint := range []string{"/api/events", "/api/export"} {
		w := inspectContractAPI(i, "GET", endpoint, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "BODY_SENTINEL") || strings.Contains(w.Body.String(), "Qk9EWV9TRU5USU5FTA") {
			t.Fatalf("sentinel leak at %s: %s", endpoint, w.Body.String())
		}
	}
	e.Headers["Authorization"] = "external-mutation"
	if i.list()[0].Headers["Authorization"] != redacted {
		t.Fatal("snapshot changed retained headers")
	}
}
func TestInspectContractBodyBoundariesAndCompletion(t *testing.T) {
	for _, n := range []int{0, inspectBodyLimit - 1, inspectBodyLimit, inspectBodyLimit + 1} {
		for _, complete := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/complete=%v", n, complete), func(t *testing.T) {
				i := NewInspectorWithBodyCapture(&ServeClient{}, true)
				e := inspectContractEvent(i, strings.Repeat("a", n), complete)
				if len(e.Body) != min(n, inspectBodyLimit) || e.RequestBytes != int64(n) || e.Truncated != (n > inspectBodyLimit) || e.BodyComplete != complete || e.Replayable != (complete && n <= inspectBodyLimit) {
					t.Fatalf("boundary state: bytes=%d captured=%d complete=%v replayable=%v", e.RequestBytes, len(e.Body), e.BodyComplete, e.Replayable)
				}
			})
		}
	}
	i := inspectContractInspector()
	c := i.begin("POST", "/hook", nil)
	r := &inspectionReader{reader: strings.NewReader("partial"), capture: c}
	_, _ = r.Read(make([]byte, 3))
	c.finish(502, 0, "failure")
	c.finish(502, 0, "failure")
	if len(i.list()) != 1 || i.list()[0].BodyComplete || i.snapshot().ActiveStreams != 0 {
		t.Fatal("partial or duplicate completion admitted")
	}
}
func TestInspectContractEvictionAndConcurrentCaptures(t *testing.T) {
	i := inspectContractInspector()
	first := inspectContractEvent(i, "", true)
	_ = inspectContractAction(t, i, first.ID)
	var workers sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 30; n++ {
				inspectContractEvent(i, "small fixture", true)
			}
		}()
	}
	workers.Wait()
	events := i.list()
	seen := map[uint64]bool{}
	for _, e := range events {
		if seen[e.ID] {
			t.Fatal("duplicate event ID")
		}
		seen[e.ID] = true
	}
	m := i.snapshot()
	if len(events) != 50 || events[0].ID != 12 || events[49].ID != 61 || m.Completed != 61 || m.HistoryEvictions != 11 || m.ActiveStreams != 0 {
		t.Fatalf("history=%d metrics=%+v", len(events), m)
	}
	if _, err := i.prepare(first.ID); err == nil {
		t.Fatal("evicted event admitted")
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if len(i.actions) != 0 {
		t.Fatal("evicted action retained")
	}
}

type inspectContractDelivery struct{ method, path, host, authorization, cookie, body, address string }

// A real HTTP transport over net.Pipe: no TCP listener, DNS, or network service.
func inspectContractTarget(deliveries chan<- inspectContractDelivery, status int, hold <-chan struct{}, fail bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		local, peer := net.Pipe()
		go func() {
			defer peer.Close()
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-ctx.Done():
					_ = peer.Close()
				case <-done:
				}
			}()
			r, err := http.ReadRequest(bufio.NewReader(peer))
			if err != nil {
				return
			}
			body, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				return
			}
			if deliveries != nil {
				deliveries <- inspectContractDelivery{r.Method, r.URL.RequestURI(), r.Host, r.Header.Get("Authorization"), r.Header.Get("Cookie"), string(body), address}
			}
			if hold != nil {
				select {
				case <-hold:
				case <-ctx.Done():
					return
				}
			}
			if fail {
				return
			}
			response := &http.Response{StatusCode: status, Status: fmt.Sprintf("%d fixture", status), ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {"text/plain"}, "Location": {"http://redirect.test/elsewhere"}}, Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2, Close: true}
			_ = response.Write(peer)
		}()
		return local, nil
	}
}
func TestInspectContractReconstructionAndOriginalTarget(t *testing.T) {
	deliveries := make(chan inspectContractDelivery, 2)
	client := &ServeClient{TargetURL: "http://original.test:8080", DialContext: inspectContractTarget(deliveries, 202, nil, false)}
	i := NewInspector(client)
	client.TargetURL = "http://changed.test:9090"
	c := i.begin("POST", "/hook?token=secret", map[string]string{"Authorization": "Bearer secret", "Cookie": "session=secret", "Host": "application.test", "Content-Type": "text/plain"})
	_, _ = c.Write([]byte("body"))
	c.complete()
	c.finish(202, 2, "")
	id := i.list()[0].ID
	action := inspectContractAction(t, i, id)
	if _, err := i.replay(context.Background(), id, inspectionReplayInput{Action: action}); err == nil {
		t.Fatal("unavailable fields silently replayed")
	}
	path := "/hook?token=secret"
	body := []byte("body")
	input := inspectionReplayInput{Action: action, Path: &path, Headers: map[string]string{"Authorization": "Bearer secret", "Cookie": "session=secret", "Host": "application.test", "Content-Type": "text/plain"}, Body: &body}
	badPath := "//elsewhere.test/hook?token=secret"
	bad := input
	bad.Path = &badPath
	if _, err := i.replay(context.Background(), id, bad); err == nil {
		t.Fatal("target override accepted")
	}
	redactionMarker := "/hook?token=%5bredacted%5d"
	bad = input
	bad.Path = &redactionMarker
	if _, err := i.replay(context.Background(), id, bad); err == nil {
		t.Fatal("encoded redaction marker dispatched")
	}
	wrongBody := []byte("wrong-length")
	bad = input
	bad.Body = &wrongBody
	if _, err := i.replay(context.Background(), id, bad); err == nil {
		t.Fatal("unavailable body byte count changed")
	}
	e, err := i.replay(context.Background(), id, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery := <-deliveries
	if delivery.address != "original.test:8080" || delivery.path != path || delivery.body != "body" || delivery.authorization != "Bearer secret" || delivery.cookie != "session=secret" || delivery.host != "application.test" || e.ID == 0 || e.ReplayOf != id || e.Status != 202 || e.ResponseBytes != 2 || e.TerminalReason != "complete" {
		t.Fatalf("dispatch=%+v result=%+v", delivery, e)
	}
	if _, err := i.replay(context.Background(), id, input); err == nil {
		t.Fatal("consumed action reused")
	}
	if i.snapshot().ReplayDispatches != 1 {
		t.Fatal("invalid reconstruction counted as a dispatch")
	}
}
func TestInspectContractDoubleClickCancelAndFailure(t *testing.T) {
	for _, mode := range []string{"double-click", "cancel", "failure"} {
		t.Run(mode, func(t *testing.T) {
			deliveries := make(chan inspectContractDelivery, 2)
			hold := make(chan struct{})
			i := NewInspectorWithBodyCapture(&ServeClient{TargetURL: "http://target.test", DialContext: inspectContractTarget(deliveries, 200, hold, mode == "failure"), HTTPTimeout: time.Second}, true)
			e := inspectContractEvent(i, "body", true)
			input := inspectionReplayInput{Action: inspectContractAction(t, i, e.ID)}
			other := inspectContractEvent(i, "body", true)
			otherInput := inspectionReplayInput{Action: inspectContractAction(t, i, other.ID)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var result InspectionEvent
			var replayErr error
			done := make(chan struct{})
			go func() { defer close(done); result, replayErr = i.replay(ctx, e.ID, input) }()
			select {
			case <-deliveries:
			case <-time.After(2 * time.Second):
				t.Fatal("replay did not reach fixture")
			}
			if mode == "double-click" {
				if _, err := i.replay(ctx, other.ID, otherInput); err == nil {
					t.Fatal("parallel replay exceeded the process admission bound")
				}
				if _, err := i.replay(ctx, e.ID, input); err == nil {
					t.Fatal("double click dispatched twice")
				}
				if _, err := i.prepare(e.ID); err == nil {
					t.Fatal("prepared another action during dispatch")
				}
			}
			if mode == "cancel" {
				cancel()
			} else {
				close(hold)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("replay did not terminate")
			}
			if mode == "cancel" {
				close(hold)
			}
			want := "complete"
			if mode == "cancel" {
				want = "canceled"
			}
			if mode == "failure" {
				want = "target_error"
			}
			if result.TerminalReason != want || result.ID == 0 || (replayErr == nil) != (mode == "double-click") || i.snapshot().ActiveStreams != 0 || i.snapshot().ReplayDispatches != 1 {
				t.Fatalf("result=%+v err=%v metrics=%+v", result, replayErr, i.snapshot())
			}
			select {
			case <-deliveries:
				t.Fatal("duplicate dispatch")
			default:
			}
		})
	}
	i := inspectContractInspector()
	e := inspectContractEvent(i, "", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := i.replay(ctx, e.ID, inspectionReplayInput{Action: inspectContractAction(t, i, e.ID)}); err == nil || i.snapshot().ReplayDispatches != 0 {
		t.Fatal("pre-dispatch cancel admitted")
	}
}
func TestInspectContractReplayHTTPResultAndRedirect(t *testing.T) {
	for _, status := range []int{202, 409, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			i := NewInspector(&ServeClient{TargetURL: "http://target.test", DialContext: inspectContractTarget(nil, status, nil, false)})
			e := inspectContractEvent(i, "", true)
			result, err := i.replay(context.Background(), e.ID, inspectionReplayInput{Action: inspectContractAction(t, i, e.ID)})
			if err != nil || result.Status != status || result.ResponseBytes != 2 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

type inspectContractBrokenWriter struct{ header http.Header }

func (w inspectContractBrokenWriter) Header() http.Header { return w.header }
func (w inspectContractBrokenWriter) WriteHeader(int)     {}
func (w inspectContractBrokenWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture export disconnect")
}
func TestInspectContractExportDropAndBodyPrivacy(t *testing.T) {
	i := NewInspectorWithBodyCapture(&ServeClient{}, true)
	i.host = "127.0.0.1:4040"
	i.token = "fixture-session"
	e := inspectContractEvent(i, "BODY_SENTINEL", true)
	if string(e.Body) != "BODY_SENTINEL" {
		t.Fatal("explicit capture lost payload")
	}
	w := inspectContractAPI(i, "GET", "/api/export", nil)
	if strings.Contains(w.Body.String(), "Qk9EWV9TRU5USU5FTA") {
		t.Fatal("export included captured body")
	}
	r := httptest.NewRequest("GET", "http://"+i.host+"/api/export", nil)
	r.Header.Set("X-Tunn-Inspector-Token", i.token)
	i.ServeHTTP(inspectContractBrokenWriter{make(http.Header)}, r)
	if i.snapshot().ExportDrops != 1 {
		t.Fatalf("export drops=%d", i.snapshot().ExportDrops)
	}
}
func TestInspectContractUnsupportedAndBoundedMetadata(t *testing.T) {
	i := NewInspectorWithBodyCapture(&ServeClient{}, true)
	for _, protocol := range []string{"sse", "websocket", "tcp"} {
		c := i.beginConnection("stream", protocol, "GET", "/stream", nil)
		_, _ = c.Write([]byte("SECRET_FRAME"))
		c.complete()
		c.finishReason(200, 12, "canceled")
		e := i.list()[len(i.list())-1]
		if len(e.Body) != 0 || e.BodyCaptured || e.Replayable || e.Reconstructable || e.RequestBytes != 12 {
			t.Fatalf("unsupported state: %+v", e)
		}
	}
	c := i.begin("GET", "/"+strings.Repeat("x", 2048), map[string]string{"X-Secret": strings.Repeat("s", 2048)})
	c.complete()
	c.finish(200, 0, "")
	if !i.list()[3].MetadataTruncated || i.list()[3].Reconstructable {
		t.Fatal("incomplete metadata replay admitted")
	}
}
func TestInspectContractAPIAdmission(t *testing.T) {
	i := inspectContractInspector()
	e := inspectContractEvent(i, "", true)
	for _, test := range []struct{ host, token, origin string }{{"evil.test", i.token, ""}, {i.host, "", ""}, {i.host, i.token, "https://evil.test"}} {
		r := httptest.NewRequest("POST", "http://"+test.host+"/api/events/1/prepare", nil)
		r.Header.Set("X-Tunn-Inspector-Token", test.token)
		r.Header.Set("Origin", test.origin)
		w := httptest.NewRecorder()
		i.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("invalid API admission=%d", w.Code)
		}
	}
	for _, payload := range []string{`{}`, `{"action":"nope"}`, `{"action":"nope","unknown":1}`, `{"action":"nope"} {}`} {
		w := inspectContractAPI(i, "POST", fmt.Sprintf("/api/events/%d/replay", e.ID), strings.NewReader(payload))
		if w.Code < 400 || i.snapshot().ReplayDispatches != 0 {
			t.Fatalf("invalid dispatch=%d", w.Code)
		}
	}
}
func TestInspectContractMetricsObserveWithoutLabels(t *testing.T) {
	i := inspectContractInspector()
	i.denied()
	i.denied()
	i.reconnected()
	c := i.begin("GET", "/customer/path", nil)
	if i.snapshot().ActiveStreams != 1 {
		t.Fatal("active stream missing")
	}
	c.complete()
	c.finish(200, 0, "")
	encoded, _ := json.Marshal(i.snapshot())
	if strings.Contains(string(encoded), "customer") || i.snapshot().DeniedAdmissions != 2 || i.snapshot().Reconnects != 1 || i.snapshot().ActiveStreams != 0 {
		t.Fatalf("metrics=%s", encoded)
	}
}

func TestInspectContractReplayResponseTerminals(t *testing.T) {
	for _, mode := range []string{"response_error", "response_limit"} {
		t.Run(mode, func(t *testing.T) {
			client := &ServeClient{TargetURL: "http://target.test"}
			client.DialContext = func(context.Context, string, string) (net.Conn, error) {
				local, peer := net.Pipe()
				go func() {
					defer peer.Close()
					request, err := http.ReadRequest(bufio.NewReader(peer))
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, request.Body)
					_ = request.Body.Close()
					content, length := "ok", 3
					if mode == "response_limit" {
						content = strings.Repeat("x", inspectResponseLimit+1)
						length = len(content)
					}
					_, _ = fmt.Fprintf(peer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", length, content)
				}()
				return local, nil
			}
			i := NewInspector(client)
			e := inspectContractEvent(i, "", true)
			result, err := i.replay(context.Background(), e.ID, inspectionReplayInput{Action: inspectContractAction(t, i, e.ID)})
			if err == nil || result.TerminalReason != mode || result.Status != 200 || i.snapshot().ActiveStreams != 0 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}
func TestInspectContractAPIReplayResult(t *testing.T) {
	i := NewInspector(&ServeClient{TargetURL: "http://target.test", DialContext: inspectContractTarget(nil, 409, nil, false)})
	i.host = "127.0.0.1:4040"
	i.token = "fixture-session"
	e := inspectContractEvent(i, "", true)
	prepared := inspectContractAPI(i, "POST", fmt.Sprintf("/api/events/%d/prepare", e.ID), nil)
	var action struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(prepared.Body.Bytes(), &action); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(inspectionReplayInput{Action: action.Action})
	w := inspectContractAPI(i, "POST", fmt.Sprintf("/api/events/%d/replay", e.ID), strings.NewReader(string(input)))
	var result InspectionEvent
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || result.Status != 409 || result.ReplayOf != e.ID || result.ID == 0 {
		t.Fatalf("API result=%s err=%v", w.Body.String(), err)
	}
	w = inspectContractAPI(i, "POST", fmt.Sprintf("/api/events/%d/replay", e.ID), strings.NewReader(string(input)))
	if w.Code != 409 || i.snapshot().ReplayDispatches != 1 {
		t.Fatal("API duplicated a consumed action")
	}
}

func TestInspectContractDeclaredLengthCompletion(t *testing.T) {
	for _, size := range []int{3, 4, 5} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			i := NewInspectorWithBodyCapture(&ServeClient{}, true)
			c := i.begin("POST", "/hook", nil)
			c.expectLength(4)
			reader := &inspectionReader{reader: strings.NewReader(strings.Repeat("a", size)), capture: c}
			buffer := make([]byte, size)
			if _, err := io.ReadFull(reader, buffer); err != nil {
				t.Fatal(err)
			}
			// A response can complete without another request-body read for EOF.
			c.finish(202, 2, "")
			e := i.list()[0]
			if e.BodyComplete != (size == 4) || e.Replayable != (size == 4) {
				t.Fatalf("declared-length state: %+v", e)
			}
		})
	}
	i := NewInspectorWithBodyCapture(&ServeClient{}, true)
	c := i.begin("POST", "/hook", nil)
	c.expectLength(4)
	_, _ = io.Copy(io.Discard, &inspectionReader{reader: strings.NewReader("abc"), capture: c})
	c.finish(202, 2, "")
	if i.list()[0].Replayable || i.list()[0].BodyComplete {
		t.Fatal("early EOF made a short body replayable")
	}
}

func TestInspectContractHTTPUpgradeAndConnectUnsupported(t *testing.T) {
	for _, test := range []struct{ method, upgrade, protocol string }{{"GET", "websocket", "websocket"}, {"GET", "h2c", "unsupported"}, {"CONNECT", "", "tcp"}} {
		t.Run(test.protocol, func(t *testing.T) {
			i := NewInspectorWithBodyCapture(&ServeClient{}, true)
			c := i.begin(test.method, "/stream", map[string]string{"Upgrade": test.upgrade})
			_, _ = c.Write([]byte("FRAME_SENTINEL"))
			c.complete()
			c.finish(200, 0, "")
			e := i.list()[0]
			if e.Protocol != test.protocol || e.Reconstructable || e.BodyCaptured || len(e.Body) > 0 {
				t.Fatalf("unsupported HTTP state: %+v", e)
			}
		})
	}
}

func TestInspectContractHeaderCountBoundary(t *testing.T) {
	for _, count := range []int{64, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			headers := make(map[string]string, count)
			for n := 0; n < count; n++ {
				headers[fmt.Sprintf("X-Field-%02d", n)] = "HEADER_SENTINEL"
			}
			i := NewInspector(&ServeClient{})
			c := i.begin("GET", "/hook", headers)
			c.complete()
			c.finish(200, 0, "")
			e := i.list()[0]
			if len(e.Headers) != 64 || e.MetadataTruncated != (count == 65) || e.Reconstructable != (count == 64) {
				t.Fatalf("header boundary: count=%d kept=%d truncated=%v reconstructable=%v", count, len(e.Headers), e.MetadataTruncated, e.Reconstructable)
			}
			for _, value := range e.Headers {
				if value != redacted {
					t.Fatal("custom header value persisted")
				}
			}
		})
	}
}
