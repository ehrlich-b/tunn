package host

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/testutil/httpconformance"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// The upstream reference is an actual net/http handler and the downstream is
// another real HTTP consumer. The production relay reconstructs serialized
// metadata using its existing fixture stream; neither side uses a Recorder.
func TestHTTPFidelityRelayConformance(t *testing.T) {
	for _, scenario := range httpconformance.Scenarios() {
		response, body, err := responseFailureMemoryResponse(t, scenario.Handler)
		if err != nil {
			t.Fatal(err)
		}
		want := httpconformance.Observation{Status: response.StatusCode, Header: response.Header, Trailer: response.Trailer, Body: body, Terminals: 1}
		legacy, fields := common.EncodeHTTPResponseHeaders(response.Header)
		// A nonempty list must suppress even map-only stale metadata.
		if scenario.Name == "cookies" {
			legacy["X-Map-Only"] = "stale"
		}
		var trailers []*pb.HttpHeader
		var names []string
		for name, values := range response.Trailer {
			names = append(names, name)
			for _, value := range values {
				trailers = append(trailers, &pb.HttpHeader{Name: name, Value: value})
			}
		}
		for _, cell := range httpconformance.Cells() {
			if scenario.Trailers && !cell.Exact() {
				continue
			}
			t.Run(scenario.Name+"/"+cell.String(), func(t *testing.T) {
				// Precompute on the test goroutine: fixture callbacks only route.
				buffered := httpconformance.WireResponse(t, &pb.HttpResponse{StatusCode: int32(response.StatusCode), Headers: legacy, HeaderFields: fields, Body: []byte(body), TrailerNames: names, Trailers: trailers}, httpconformance.Cell{Publisher: cell.Publisher, Relay: cell.Relay, Mode: httpconformance.Buffered}).(*pb.HttpResponse)
				head := httpconformance.WireResponse(t, &pb.HttpResponseHead{StatusCode: int32(response.StatusCode), Headers: legacy, HeaderFields: fields, TrailerNames: names}, httpconformance.Cell{Publisher: cell.Publisher, Relay: cell.Relay, Mode: httpconformance.Streaming}).(*pb.HttpResponseHead)
				stream := &meteringFixtureStream{}
				tunnel := &TunnelConnection{TunnelID: "api", Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse), Capabilities: map[string]bool{common.CapabilityHTTPResponseTrailersV1: cell.Exact()}}
				if cell.Mode == httpconformance.Streaming {
					tunnel.Capabilities[common.CapabilityHTTPStreamV1] = true
				}
				cfg := webproxyTestConfig()
				cfg.Domain = "tunn.test"
				server := NewTunnelServer(cfg, nil, nil, nil)
				server.tunnels["api"] = tunnel
				proxy := &ProxyServer{config: cfg, Domain: cfg.Domain, tunnelServer: server}
				stream.hook = func(message *pb.TunnelMessage) error {
					if request := message.GetHttpRequest(); request != nil {
						tunnel.pendingMu.RLock()
						ch := tunnel.pendingRequests[request.ConnectionId]
						tunnel.pendingMu.RUnlock()
						ch <- buffered
					}
					if open := message.GetConnectionOpen(); open != nil {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: head}}})
						if body != "" {
							tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: []byte(body)}}})
						}
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId, Trailers: trailers}}})
					}
					return nil
				}
				res, gotBody, readErr := responseFailureMemoryResponse(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxy.handleWebProxy(w, r) }))
				if res == nil {
					t.Fatal(readErr)
				}
				got := httpconformance.Observation{Status: res.StatusCode, Header: res.Header, Trailer: res.Trailer, Body: gotBody, ReadErr: readErr, Terminals: 1}
				expected := want
				if !cell.Exact() {
					expected = httpconformance.LegacyWireExpectation(want)
					if scenario.Name == "cookies" {
						// Literal legacy loss: the valid comma inside the first
						// cookie becomes a spurious third cookie, in this order.
						expected.Header["Set-Cookie"] = []string{"first=one", "fragment=two; Path=/", "second=three; Path=/"}
						expected.Header.Set("X-Map-Only", "stale")
					}
				}
				httpconformance.Assert(t, got, expected)
			})
		}
	}
}

// Force buffered response selection at registration, without mutating a live
// connection's capabilities. Used only by the ordinary-host exported SDK gate.
type responseBufferedRegistration struct {
	pb.TunnelService_EstablishTunnelServer
}

func (s responseBufferedRegistration) Recv() (*pb.TunnelMessage, error) {
	message, err := s.TunnelService_EstablishTunnelServer.Recv()
	if err == nil && message.GetRegisterClient() != nil {
		reg := message.GetRegisterClient()
		var capabilities []string
		for _, capability := range reg.Capabilities {
			if capability != common.CapabilityHTTPStreamV1 {
				capabilities = append(capabilities, capability)
			}
		}
		reg.Capabilities = capabilities
	}
	return message, err
}

func TestSDKResponseConformance(t *testing.T) {
	for _, mode := range []httpconformance.Mode{httpconformance.Buffered, httpconformance.Streaming} {
		for _, scenario := range httpconformance.Scenarios() {
			t.Run(string(mode)+"/"+scenario.Name, func(t *testing.T) {
				reference, body, err := responseFailureMemoryResponse(t, scenario.Handler)
				if err != nil {
					t.Fatal(err)
				}
				stack := startSDKContractStack(t, "handler", sdkResponseContract{Handler: scenario.Handler, Mode: mode})
				request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, stack.relay.URL+"/", nil)
				request.Host = "websocket-fixture.tunn.test"
				request.Header.Set("Tunn-Authorization", "Bearer "+sdkEndpointToken)
				res, err := stack.relay.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				got := httpconformance.Read(res)
				want := httpconformance.Observation{Status: reference.StatusCode, Header: reference.Header, Trailer: reference.Trailer, Body: body, Terminals: 1}
				httpconformance.Assert(t, got, want)
				if !strings.HasPrefix(stack.tunnelSDK.URL(), "https://websocket-fixture.") {
					t.Fatal("SDK registration identity changed")
				}
			})
		}
	}
}

func TestSDKResponseControllerConformance(t *testing.T) {
	report := make(chan error, 1)
	stack := startSDKContractStack(t, "handler", sdkResponseContract{Handler: httpconformance.ControllerHandler(report), Mode: httpconformance.Streaming})
	request, _ := http.NewRequest(http.MethodGet, stack.relay.URL+"/", nil)
	request.Host = "websocket-fixture.tunn.test"
	request.Header.Set("Tunn-Authorization", "Bearer "+sdkEndpointToken)
	response, err := stack.relay.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	got := httpconformance.Read(response)
	if err = waitResponseSignal(t, report); err != nil {
		t.Fatal(err)
	}
	if got.Status != 202 || got.Body != "abc" || got.ReadErr != nil {
		t.Fatalf("exported handler controller response=%+v", got)
	}
}
