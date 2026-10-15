package host

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ehrlich-b/tunn/internal/testutil/httpconformance"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Reflect the additive field so this regression also runs on the old schema.
func TestRepeatedApplicationRequestHeaders(t *testing.T) {
	stream := &mockWebProxyStream{}
	tunnel := &TunnelConnection{Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse), Capabilities: map[string]bool{"http-request-headers-v1": true}}
	respondToForwardedRequest(t, stream, tunnel)
	request := httptest.NewRequest(http.MethodGet, "https://app.tunn.test/a", nil)
	request.Header["X-Application"] = []string{"first, literal", "second"}
	request.Header["Cookie"] = []string{"tunn_auth=secret; app=one", "other=two"}
	if err := (&ProxyServer{}).proxyHTTPOverGRPC(httptest.NewRecorder(), request, tunnel); err != nil {
		t.Fatal(err)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	message := stream.sentMsgs[0].GetHttpRequest().ProtoReflect()
	field := message.Descriptor().Fields().ByName("header_fields")
	if field == nil {
		t.Fatal("request header_fields absent: repeated application fields flattened into legacy map")
	}
	var got []string
	fields := message.Get(field).List()
	for i := 0; i < fields.Len(); i++ {
		entry := fields.Get(i).Message()
		name := entry.Get(entry.Descriptor().Fields().ByName("name")).String()
		if name == "X-Application" {
			got = append(got, entry.Get(entry.Descriptor().Fields().ByName("value")).String())
		}
	}
	if !reflect.DeepEqual(got, []string{"first, literal", "second"}) {
		t.Fatalf("repeated application fields = %q", got)
	}
}

func TestRequestHeadersLegacyNegotiation(t *testing.T) {
	for _, capable := range []bool{false, true} {
		for _, repeated := range []bool{false, true} {
			t.Run(fmt.Sprintf("capable=%t/repeated=%t", capable, repeated), func(t *testing.T) {
				request := httptest.NewRequest("GET", "https://app.tunn.test/a", nil)
				request.Header["X-App"] = []string{"first"}
				if repeated {
					request.Header.Add("X-App", "second")
				}
				request.Header["Cookie"] = []string{"a=1", "tunn_auth=secret; b=2"}
				request.Header.Set("Connection", "X-Hop")
				request.Header.Set("X-Hop", "secret")
				recorder := httptest.NewRecorder()
				legacy, fields, ok := (&ProxyServer{}).negotiatedRequestHeaders(recorder, request, &TunnelConnection{Capabilities: map[string]bool{"http-request-headers-v1": capable}})
				if !ok || (len(fields) > 0) != capable || legacy["Cookie"] != "a=1; b=2" || legacy["X-Hop"] != "" {
					t.Fatalf("negotiation: %t %v %v", ok, legacy, fields)
				}
				if repeated && legacy["X-App"] != "first, second" {
					t.Fatalf("legacy fallback: %v", legacy)
				}
			})
		}
	}
}

func TestRequestHeadersRelayRejectsSingletons(t *testing.T) {
	for _, key := range []string{"Host", "Authorization", "Content-Length", "Sec-WebSocket-Key"} {
		request := httptest.NewRequest("GET", "https://app.tunn.test/a", nil)
		request.Header[key] = []string{"0", "0"}
		stream := &mockWebProxyStream{}
		recorder := httptest.NewRecorder()
		if err := (&ProxyServer{}).proxyHTTPOverGRPC(recorder, request, &TunnelConnection{Stream: stream, Capabilities: map[string]bool{"http-stream-v1": true}}); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != 400 || len(stream.sentMsgs) != 0 {
			t.Fatalf("%s dispatched before rejection: status %d", key, recorder.Code)
		}
	}
}

func requestHeadersOrigin(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Values("X-App"); !reflect.DeepEqual(got, []string{"first, literal", "second"}) {
			t.Errorf("origin repeated headers: %q", got)
		}
		if r.Header.Get("Cookie") != "a=1; b=2" || r.Header.Get("Tunn-Authorization") != "" || r.Header.Get("X-Hop") != "" || r.Header.Get("Authorization") != "Bearer application" {
			t.Errorf("origin headers: %v", r.Header)
		}
		w.WriteHeader(204)
	})
}

func TestRequestHeadersAcrossGoPublishers(t *testing.T) {
	for _, mode := range []string{"handler", "origin", "cli"} {
		for _, wire := range []httpconformance.Mode{httpconformance.Streaming, httpconformance.Buffered} {
			t.Run(fmt.Sprintf("%s/%s", mode, wire), func(t *testing.T) {
				stack := startSDKContractStack(t, mode, sdkResponseContract{Handler: requestHeadersOrigin(t), Mode: wire})
				if !stack.tunnel.Supports("http-request-headers-v1") {
					t.Fatal("request capability not advertised")
				}
				req, _ := http.NewRequest("GET", stack.relay.URL+"/http", nil)
				req.Host = "websocket-fixture.tunn.test"
				req.Header = http.Header{"X-App": {"first, literal", "second"}, "Cookie": {"a=1", "tunn_auth=secret; b=2"}, "Authorization": {"Bearer application"}, "Tunn-Authorization": {"Bearer " + sdkEndpointToken}, "Connection": {"X-Hop"}, "X-Hop": {"secret"}}
				transport := stack.relay.Client().Transport.(*http.Transport).Clone()
				transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
				transport.Protocols = new(http.Protocols)
				transport.Protocols.SetHTTP1(true)
				defer transport.CloseIdleConnections()
				response, err := (&http.Client{Transport: transport}).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != 204 {
					t.Fatalf("status %d", response.StatusCode)
				}
			})
		}
	}
}

func TestRequestHeadersAcrossWebSocketPublishers(t *testing.T) {
	for _, mode := range []string{"handler", "origin", "cli"} {
		t.Run(mode, func(t *testing.T) {
			fixture := &webSocketFixture{closes: make(chan []byte, 16)}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Values("X-App"); !reflect.DeepEqual(got, []string{"first, literal", "second"}) {
					t.Errorf("WebSocket request fields: %q", got)
				}
				if r.Header.Get("Cookie") != "a=1; b=2" || r.Header.Get("Tunn-Authorization") != "" {
					t.Errorf("WebSocket private headers: %v", r.Header)
				}
				fixture.ServeHTTP(w, r)
			})
			stack := startSDKContractStack(t, mode, sdkResponseContract{Handler: handler, Mode: httpconformance.Streaming})
			headers := http.Header{"X-App": {"first, literal", "second"}, "Cookie": {"a=1", "b=2"}, "Tunn-Authorization": {"Bearer " + sdkEndpointToken}}
			conn, reader := mustWebSocket(t, stack.webSocketStack, "/echo", headers)
			defer conn.Close()
			_, err := conn.Write(fixtureFrame(1, true, true, []byte("repeated request")))
			if err != nil {
				t.Fatal(err)
			}
			expectWireFrame(t, reader, 1, []byte("repeated request"))
			_, _ = conn.Write(fixtureFrame(8, true, true, []byte{3, 232}))
			expectWireFrame(t, reader, 8, []byte{3, 232})
		})
	}
}
