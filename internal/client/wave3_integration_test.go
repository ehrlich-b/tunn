package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestIntegrationSDKInspectionKeepsLocalTransport(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			var calls atomic.Int32
			client := &ServeClient{
				TargetURL: "http://sdk-handler.invalid", LocalTLSConfig: &tls.Config{ServerName: "original.test"},
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("relay dialer must not reach the handler")
				},
				LocalDialContext: func(context.Context, string, string) (net.Conn, error) {
					local, peer := net.Pipe()
					go func() {
						defer func() { _ = peer.Close() }()
						r, err := httpReadFixtureRequest(peer)
						if err != nil {
							return
						}
						if r != "/hook" {
							return
						}
						calls.Add(1)
						_, _ = io.WriteString(peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
					}()
					return local, nil
				},
			}
			client.Inspector = NewInspector(client)
			client.LocalTLSConfig.ServerName = "changed.test"
			if client.Inspector.target.LocalTLSConfig.ServerName != "original.test" {
				t.Fatal("inspection shared mutable SDK TLS configuration")
			}
			if streaming {
				client.handleStreamingHTTPRequest(context.Background(), inspectContractSender{}, &pb.ConnectionOpen{ConnectionId: "sdk-stream", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/hook", ContentLength: 0}}, strings.NewReader(""))
			} else {
				client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "sdk-buffered", Method: "GET", Path: "/hook"})
			}
			events := client.Inspector.list()
			if len(events) != 1 || events[0].Status != 200 || !events[0].Replayable {
				t.Fatalf("SDK inspection capture: %v", events)
			}
			result, err := client.Inspector.replay(context.Background(), events[0].ID, inspectionReplayInput{Action: inspectContractAction(t, client.Inspector, events[0].ID)})
			if err != nil || result.Status != 200 || calls.Load() != 2 {
				t.Fatalf("replay lost local SDK transport: %v %v calls=%d", result, err, calls.Load())
			}
		})
	}
}

func httpReadFixtureRequest(peer net.Conn) (string, error) {
	r, err := http.ReadRequest(bufio.NewReader(peer))
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Body.Close() }()
	_, err = io.Copy(io.Discard, r.Body)
	return r.URL.RequestURI(), err
}

func TestIntegrationSSHInspectionKeepsEmbeddedHTTPTransport(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			var calls atomic.Int32
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/mcp" {
					return nil, errors.New("unexpected embedded handler path")
				}
				calls.Add(1)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2, Request: r}, nil
			})
			s := &ServeClient{TargetURL: "http://ssh-stdio.invalid", HTTPTransport: transport, LocalDialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("embedded SSH handler must not dial a socket")
			}}
			s.Inspector = NewInspector(s)
			if streaming {
				s.handleStreamingHTTPRequest(context.Background(), inspectContractSender{}, &pb.ConnectionOpen{ConnectionId: "stdio-stream", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "GET", Path: "/mcp", ContentLength: 0}}, strings.NewReader(""))
			} else {
				s.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "stdio-buffered", Method: "GET", Path: "/mcp"})
			}
			// The replay snapshot retains the handler selected at publication.
			s.HTTPTransport = nil
			events := s.Inspector.Events()
			if len(events) != 1 || events[0].Status != 200 || !events[0].Replayable {
				t.Fatalf("embedded capture=%v", events)
			}
			result, err := s.Inspector.Replay(context.Background(), events[0].ID)
			if err != nil || result.Status != 200 || calls.Load() != 2 {
				t.Fatalf("embedded replay=%v %v calls=%d", result, err, calls.Load())
			}
			if streaming {
				s.HTTPTransport = transport
				s.handleStreamingHTTPRequest(context.Background(), inspectContractSender{}, &pb.ConnectionOpen{ConnectionId: "stdio-unread", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/mcp", ContentLength: 1}}, strings.NewReader("x"))
				incomplete := s.Inspector.Events()[2]
				if incomplete.BodyComplete || incomplete.Reconstructable {
					t.Fatal("embedded handler made an unread nonempty body replayable")
				}
			}
		})
	}
}

func TestIntegrationMCPOAuthInspectionRedactsCaptureAndReconstruction(t *testing.T) {
	const token = "tunn_mcp_inspection_integration_sentinel"
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			client := &ServeClient{TargetURL: "http://sdk-handler.invalid", LocalDialContext: func(context.Context, string, string) (net.Conn, error) {
				local, peer := net.Pipe()
				go func() {
					defer func() { _ = peer.Close() }()
					_, _ = httpReadFixtureRequest(peer)
					_, _ = io.WriteString(peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				}()
				return local, nil
			}}
			client.Inspector = NewInspectorWithBodyCapture(client, true)
			client.Inspector.host, client.Inspector.token = "127.0.0.1:4040", "session-fixture"
			body := `{"access_token":"` + token + `"}`
			headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json; credential=" + token}
			if streaming {
				client.handleStreamingHTTPRequest(context.Background(), inspectContractSender{}, &pb.ConnectionOpen{ConnectionId: "oauth-stream", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/mcp", Headers: headers, ContentLength: int64(len(body))}}, strings.NewReader(body))
			} else {
				client.handleHttpRequest(&mockEstablishTunnelClient{}, &pb.HttpRequest{ConnectionId: "oauth-buffered", Method: "POST", Path: "/mcp", Headers: headers, Body: []byte(body)})
			}
			event := client.Inspector.list()[0]
			if event.Status != 200 || event.BodyCaptured || len(event.Body) != 0 || event.Replayable || len(event.RedactedHeaders) != 2 {
				t.Fatalf("OAuth capture retained credential data: %+v", event)
			}
			for _, path := range []string{"/api/events", "/api/export"} {
				w := inspectContractAPI(client.Inspector, "GET", path, nil)
				if w.Code != 200 || strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), base64.StdEncoding.EncodeToString([]byte(body))) {
					t.Fatalf("OAuth credential appeared at %s: %s", path, w.Body)
				}
			}
			action := inspectContractAction(t, client.Inspector, event.ID)
			if _, err := client.Inspector.replay(context.Background(), event.ID, inspectionReplayInput{Action: action, Headers: headers, Body: byteSlicePointer([]byte(body))}); err == nil {
				t.Fatal("OAuth credential reconstruction reached local replay")
			}
		})
	}
}

func byteSlicePointer(value []byte) *[]byte { return &value }
