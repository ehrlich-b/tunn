package client

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
	"github.com/ehrlich-b/tunn/internal/testnet"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

var dogfoodProxyMemory = flag.Bool("dogfood-proxy-memory", false, "run the HTTP proxy TLS/gRPC fixture over in-memory sockets")

type proxyTunnelFixture struct {
	pb.UnimplementedTunnelServiceServer
}

func (*proxyTunnelFixture) EstablishTunnel(stream grpc.BidiStreamingServer[pb.TunnelMessage, pb.TunnelMessage]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://fixture.tunn.test"}}}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// Every socket stays on loopback. The relay hostname deliberately cannot be
// resolved: successful login, HTTP/2 CONNECT and gRPC require the HTTP proxy.
func TestDogfoodProxyLoginAndHTTP2Control(t *testing.T) {
	for _, proxyEnv := range []string{"HTTPS_PROXY", "ALL_PROXY"} {
		t.Run(proxyEnv, func(t *testing.T) {
			for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
				t.Setenv(key, "")
			}
			grpcServer := grpc.NewServer()
			defer grpcServer.Stop()
			pb.RegisterTunnelServiceServer(grpcServer, &proxyTunnelFixture{})
			var requests atomic.Int64
			relayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.ProtoMajor != 2 {
					t.Errorf("relay connection = %s, want HTTP/2", r.Proto)
				}
				if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
					grpcServer.ServeHTTP(w, r)
					return
				}
				if r.Method == "CONNECT" {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					var ping [4]byte
					if _, err := io.ReadFull(r.Body, ping[:]); err == nil {
						_, _ = w.Write(ping[:])
						w.(http.Flusher).Flush()
					}
					<-r.Context().Done()
					return
				}
				switch r.URL.Path {
				case "/api/device/code":
					_, _ = io.WriteString(w, `{"device_code":"device-fixture","user_code":"ABC-123","expires_in":600,"interval":1}`)
				case "/api/device/token":
					_, _ = io.WriteString(w, `{"access_token":"fixture-jwt"}`)
				case "/api/usage":
					_, _ = io.WriteString(w, `{"events":[]}`)
				default:
					http.NotFound(w, r)
				}
			})
			var relay *httptest.Server
			var relayMemory *testnet.Listener
			if *dogfoodProxyMemory {
				relayMemory = testnet.NewListener()
				relay = &httptest.Server{Listener: relayMemory, Config: &http.Server{Handler: relayHandler}}
			} else {
				relay = httptest.NewUnstartedServer(relayHandler)
			}
			relay.EnableHTTP2 = true
			relay.StartTLS()
			defer relay.Close()
			var connects atomic.Int64
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.Host != "unresolvable.invalid:443" {
					http.Error(w, "unexpected proxy destination", 400)
					return
				}
				connects.Add(1)
				var upstream net.Conn
				var err error
				if relayMemory != nil {
					upstream, err = relayMemory.Dial()
				} else {
					upstream, err = net.DialTimeout("tcp", relay.Listener.Addr().String(), time.Second)
				}
				if err != nil {
					http.Error(w, "fixture unavailable", 502)
					return
				}
				defer upstream.Close()
				downstream, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer downstream.Close()
				_, _ = io.WriteString(downstream, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
				_, _ = io.Copy(downstream, upstream)
				_ = downstream.Close()
				<-done
			})
			var proxy *httptest.Server
			var proxyMemory *testnet.Listener
			if *dogfoodProxyMemory {
				proxyMemory = testnet.NewListener()
				proxy = &httptest.Server{Listener: proxyMemory, Config: &http.Server{Handler: proxyHandler}}
				proxy.Start()
			} else {
				proxy = httptest.NewServer(proxyHandler)
			}
			defer proxy.Close()
			t.Setenv(proxyEnv, proxy.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			transport := relaytransport.Transport(true)
			var memoryDial func(context.Context, string, string) (net.Conn, error)
			if proxyMemory != nil {
				memoryDial = func(_ context.Context, _, address string) (net.Conn, error) {
					if address != proxyMemory.Addr().String() {
						t.Errorf("dialed %s instead of proxy", address)
					}
					return proxyMemory.Dial()
				}
				transport.DialContext = memoryDial
			}
			defer transport.CloseIdleConnections()
			hc := &http.Client{Transport: transport}
			login := &LoginClient{ServerAddr: "unresolvable.invalid:443", Insecure: true, HTTPClient: hc}
			code, err := login.requestDeviceCode(ctx)
			if err != nil {
				t.Fatal(err)
			}
			token, err := login.checkToken(ctx, code.DeviceCode)
			if err != nil || token.AccessToken != "fixture-jwt" {
				t.Fatalf("proxied login = %v %v", token, err)
			}
			secureTransport := relaytransport.Transport(false)
			if memoryDial != nil {
				secureTransport.DialContext = memoryDial
			}
			defer secureTransport.CloseIdleConnections()
			secure := &LoginClient{ServerAddr: login.ServerAddr, HTTPClient: &http.Client{Transport: secureTransport}}
			if _, err := secure.requestDeviceCode(ctx); err == nil {
				t.Fatal("default login trusted an unverified relay certificate")
			}
			management := &ManagementClient{ServerURL: login.ServerAddr, OwnerToken: "fixture-jwt", HTTPClient: hc}
			if _, err := management.Call(ctx, "GET", "", "usage", nil); err != nil {
				t.Fatal(err)
			}
			serveCtx, stopServe := context.WithCancel(ctx)
			limit := 0
			registered := false
			serve := &ServeClient{ServerAddr: login.ServerAddr, Insecure: true, Quiet: true, ReconnectLimit: &limit, OnRegistered: func(string) { registered = true; stopServe() }}
			if memoryDial != nil {
				serve.DialContext = relaytransport.Dialer(memoryDial)
			}
			err = serve.Run(serveCtx)
			stopServe()
			if !registered || !errors.Is(err, context.Canceled) {
				t.Fatalf("proxied gRPC registration = %v, %v", registered, err)
			}
			local, app := net.Pipe()
			defer app.Close()
			connectCtx, stopConnect := context.WithCancel(ctx)
			finished := make(chan error, 1)
			connect := &ConnectClient{EndpointURL: "https://" + login.ServerAddr + common.TCPConnectPath}
			go func() { finished <- connect.handleConnection(connectCtx, hc, local) }()
			if err := app.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			go func() { _, _ = app.Write([]byte("ping")) }()
			var echo [4]byte
			if _, err := io.ReadFull(app, echo[:]); err != nil || !bytes.Equal(echo[:], []byte("ping")) {
				stopConnect()
				t.Fatalf("proxied HTTP/2 CONNECT = %q %v", echo, err)
			}
			stopConnect()
			_ = app.Close()
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("CONNECT did not stop")
			}
			if connects.Load() < 3 || requests.Load() != 5 {
				t.Fatalf("proxy connects=%d relay requests=%d", connects.Load(), requests.Load())
			}
		})
	}
}
