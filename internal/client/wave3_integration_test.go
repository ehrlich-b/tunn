package client

import (
	"bufio"
	"context"
	"crypto/tls"
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
						defer peer.Close()
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
	defer r.Body.Close()
	_, err = io.Copy(io.Discard, r.Body)
	return r.URL.RequestURI(), err
}
