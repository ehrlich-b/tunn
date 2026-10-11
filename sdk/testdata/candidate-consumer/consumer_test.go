//go:build candidatefixture

// This independent importer uses only exported SDK and wire types. The memory
// dial seam is fixture-only; the normal exported API retains its native gate.
package consumer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	tunn "github.com/ehrlich-b/tunn/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

const call = `{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"sum","arguments":{"values":[2,3,5]}}}`
const firstResult = `{"jsonrpc":"2.0","id":19,"result":{"content":[{"type":"text","text":"10"}]}}` + "\n"

type relay struct {
	pb.UnimplementedTunnelServiceServer
	mode     string
	observed chan observation
}
type observation struct {
	body    []byte
	status  int
	headers http.Header
	err     error
}

func (r *relay) EstablishTunnel(stream pb.TunnelService_EstablishTunnelServer) (err error) {
	var got observation
	delivered := false
	defer func() {
		if !delivered {
			got.err = err
			r.observed <- got
		}
	}()
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	reg := message.GetRegisterClient()
	if reg == nil {
		return errors.New("no SDK registration")
	}
	if err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterResponse{RegisterResponse: &pb.RegisterResponse{Success: true, PublicUrl: "https://" + reg.TunnelId + ".consumer.test", Capabilities: []string{"http-stream-v1", "connection-stream-v1", "http-response-trailers-v1"}}}}); err != nil {
		return err
	}
	if r.mode == "buffered" {
		err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_HttpRequest{HttpRequest: &pb.HttpRequest{ConnectionId: "task", Method: "POST", Path: "/mcp", Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(call)}}})
	} else {
		for _, m := range []*pb.TunnelMessage{
			{Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: &pb.ConnectionOpen{ConnectionId: "task", Protocol: "http", HttpRequest: &pb.HttpRequestHead{Method: "POST", Path: "/mcp", Headers: map[string]string{"Content-Type": "application/json"}, ContentLength: int64(len(call))}}}},
			{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: "task", Data: []byte(call)}}},
			{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: "task"}}},
		} {
			if err = stream.Send(m); err != nil {
				return err
			}
		}
	}
	if err != nil {
		return err
	}
	for {
		m, e := stream.Recv()
		if e != nil {
			return e
		}
		if response := m.GetHttpResponse(); response != nil {
			got.status = int(response.StatusCode)
			got.body = response.Body
			got.headers = decode(response.Headers, response.HeaderFields)
			delivered = true
			r.observed <- got
		}
		if accept := m.GetConnectionAccept(); accept != nil {
			if !accept.Success || accept.HttpResponse == nil {
				return errors.New("stream rejected")
			}
			got.status = int(accept.HttpResponse.StatusCode)
			got.headers = decode(accept.HttpResponse.Headers, accept.HttpResponse.HeaderFields)
		}
		if data := m.GetConnectionData(); data != nil {
			got.body = append(got.body, data.Data...)
			if len(got.body) >= len(firstResult) && !delivered {
				delivered = true
				r.observed <- got
			}
		}
	}
}
func decode(legacy map[string]string, fields []*pb.HttpHeader) http.Header {
	h := make(http.Header)
	if len(fields) > 0 {
		for _, f := range fields {
			h.Add(f.Name, f.Value)
		}
	} else {
		for k, v := range legacy {
			h.Set(k, v)
		}
	}
	return h
}
func taskHandler(cancelled chan<- struct{}, block bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(r.Body)
		if e != nil || string(b) != call {
			http.Error(w, "invalid input", 400)
			return
		}
		var request struct {
			Params struct {
				Name      string
				Arguments struct{ Values []int }
			}
		}
		if json.Unmarshal(b, &request) != nil || request.Params.Name != "sum" {
			http.Error(w, "invalid tool", 400)
			return
		}
		sum := 0
		for _, value := range request.Params.Arguments.Values {
			sum += value
		}
		if sum != 10 {
			http.Error(w, "invalid sum", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		http.SetCookie(w, &http.Cookie{Name: "one", Value: "one,two", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "two", Value: "three", Path: "/"})
		_, _ = io.WriteString(w, firstResult)
		_ = http.NewResponseController(w).Flush()
		if block {
			<-r.Context().Done()
			close(cancelled)
		}
	})
}
func TestIndependentSDKUsefulResultAndCancellation(t *testing.T) {
	for _, mode := range []string{"buffered", "streamed"} {
		t.Run(mode, func(t *testing.T) {
			key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"consumer.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if e != nil {
				t.Fatal(e)
			}
			parsed, e := x509.ParseCertificate(der)
			if e != nil {
				t.Fatal(e)
			}
			roots := x509.NewCertPool()
			roots.AddCert(parsed)
			listener := bufconn.Listen(1 << 20)
			gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})))
			fixture := &relay{mode: mode, observed: make(chan observation, 1)}
			pb.RegisterTunnelServiceServer(gs, fixture)
			served := make(chan struct{})
			go func() { defer close(served); _ = gs.Serve(listener) }()
			defer func() { gs.Stop(); _ = listener.Close(); <-served }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cancelled := make(chan struct{})
			block := mode == "streamed"
			publisher, e := tunn.CandidateFixturePublishHandler(ctx, taskHandler(cancelled, block), tunn.Options{Name: "second-consumer", ServerAddr: "consumer.test:443", TLSConfig: &tls.Config{RootCAs: roots, ServerName: "consumer.test", MinVersion: tls.VersionTLS12}, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}, ConnectTimeout: time.Second}, func(ctx context.Context, _, _ string) (net.Conn, error) { return listener.DialContext(ctx) })
			if e != nil {
				t.Fatal(e)
			}
			closePublisher := sync.OnceFunc(func() {
				if e := publisher.Close(); e != nil {
					t.Error(e)
				}
			})
			defer closePublisher()
			if _, e = publisher.WaitReady(ctx); e != nil {
				t.Fatal(e)
			}
			var got observation
			select {
			case got = <-fixture.observed:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			oracle := httptest.NewRecorder()
			taskHandler(nil, false).ServeHTTP(oracle, httptest.NewRequest("POST", "http://oracle.invalid/mcp", strings.NewReader(call)))
			if got.err != nil || got.status != oracle.Code || string(got.body) != oracle.Body.String() || string(got.body) != firstResult || !reflect.DeepEqual(got.headers.Values("Set-Cookie"), oracle.Header().Values("Set-Cookie")) {
				t.Fatalf("%s SDK/direct complete bytes differ: %+v / %s", mode, got, oracle.Body)
			}
			closePublisher()
			if block {
				select {
				case <-cancelled:
				case <-ctx.Done():
					t.Fatal("SDK handler did not observe cancellation after first complete result")
				}
			}
			closed := 0
			for event := range publisher.Events() {
				if event.State == tunn.Closed {
					closed++
				}
			}
			if closed != 1 {
				t.Fatalf("terminal events=%d", closed)
			}
			t.Logf("independent %s consumer: %d exact JSON-RPC bytes; 2 cookies; 1 Closed; cancellation-after-result=%v", mode, len(got.body), block)
		})
	}
}
