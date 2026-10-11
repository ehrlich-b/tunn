package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Generates large bodies without allocating a 100+ MiB fixture.
type uploadBody struct {
	remaining int64
	read      int64
}

func (b *uploadBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > b.remaining {
		n = b.remaining
	}
	b.remaining -= n
	b.read += n
	return int(n), nil
}
func (*uploadBody) Close() error { return nil }

func assertUpload413(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get("Tunn-Limit-Reason") != "request_body_too_large" || !strings.Contains(w.Body.String(), "104857600 bytes (100 MiB)") {
		t.Fatalf("oversized response = %d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestDogfoodUploadRejectedAtEdge(t *testing.T) {
	// Includes a cached remote route: rejection must happen before any node dial.
	for _, remote := range []bool{false, true} {
		p := securityProxy(securityDB(t))
		if remote {
			p.tunnelCache["upload"] = "must-not-be-dialed.invalid:443"
		}
		body := &uploadBody{remaining: 200_000_000}
		r := httptest.NewRequest("POST", "https://upload.tunn.test/", body)
		r.ContentLength = body.remaining
		w := httptest.NewRecorder()
		p.handleWebProxy(w, r)
		assertUpload413(t, w)
		if body.read != 0 {
			t.Fatalf("edge read %d bytes before rejecting known length", body.read)
		}
	}
}

func TestDogfoodUploadMeteringRecords413(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		p, tunnel, ledger, stream := meteringRelay(t, streaming, "must not be served")
		body := &uploadBody{remaining: 200_000_000}
		r := httptest.NewRequest("POST", "https://api.tunn.test/", body)
		r.ContentLength = body.remaining
		r.Header.Set("Authorization", "Bearer "+relayJWT(t, p, "owner@example.com"))
		w := httptest.NewRecorder()
		p.handleWebProxy(w, r)
		assertUpload413(t, w)
		if body.read != 0 || len(stream.sentMsgs) != 0 {
			t.Fatal("oversized ingress reached publisher")
		}
		export, err := ledger.Export(context.Background(), &meterpb.ExportRequest{Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID})
		if err != nil || len(export.Events) != 1 {
			t.Fatalf("upload audit = %v %v", export, err)
		}
		event := export.Events[0]
		if event.Status != 413 || event.Reason != "request_body_too_large" || event.Forwarded || event.ContentLength != 200_000_000 || event.RequestBytes != 0 {
			t.Fatalf("oversized audit = %+v", event)
		}
	}
}

func TestDogfoodUploadLimitThroughTunnel(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, known := range []bool{false, true} {
			name := map[bool]string{false: "buffered", true: "streaming"}[streaming] + "/" + map[bool]string{false: "chunked", true: "known length"}[known]
			t.Run(name, func(t *testing.T) {
				var sent atomic.Int64
				tunnel := &TunnelConnection{Stream: &securityStream{onSend: func(m *pb.TunnelMessage) error {
					if m.GetConnectionData() != nil || m.GetHttpRequest() != nil {
						sent.Add(1)
					}
					return nil
				}}}
				if streaming {
					tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true}
				}
				body := &uploadBody{remaining: MaxBodySize + 1}
				r := httptest.NewRequest("POST", "https://upload.tunn.test/", body)
				r.ContentLength = -1
				if known {
					r.ContentLength = body.remaining
				}
				w := httptest.NewRecorder()
				err := (&ProxyServer{}).proxyHTTPOverGRPC(w, r, tunnel)
				var tooLarge *requestBodyTooLargeError
				if !errors.As(err, &tooLarge) {
					t.Fatalf("upload error = %v", err)
				}
				writeIngressError(w, err)
				assertUpload413(t, w)
				if known && (body.read != 0 || sent.Load() != 0) {
					t.Fatal("known oversized request was forwarded")
				}
				if !known && body.read != MaxBodySize+1 {
					t.Fatalf("size probe read %d bytes", body.read)
				}
				if !streaming && sent.Load() != 0 {
					t.Fatal("buffered oversized request was forwarded")
				}
			})
		}
	}
}

func TestDogfoodUploadStreamingBoundaryAndEarlyResponse(t *testing.T) {
	for _, size := range []int64{MaxBodySize - 1, MaxBodySize, MaxBodySize + 1} {
		for _, early := range []bool{false, true} {
			if !early && size > MaxBodySize {
				continue
			} // No response is needed for an oversized body.
			name := map[bool]string{false: "after upload", true: "early 200"}[early]
			t.Run(name+"/"+fmt.Sprint(size), func(t *testing.T) {
				var forwarded atomic.Int64
				var tunnel *TunnelConnection
				respond := func(id string) {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200}}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
				}
				tunnel = &TunnelConnection{Capabilities: map[string]bool{common.CapabilityHTTPStreamV1: true}}
				tunnel.Stream = &securityStream{onSend: func(m *pb.TunnelMessage) error {
					if data := m.GetConnectionData(); data != nil {
						forwarded.Add(int64(len(data.Data)))
					}
					if early && m.GetConnectionOpen() != nil {
						respond(m.GetConnectionOpen().ConnectionId)
					}
					if !early && m.GetConnectionHalfClose() != nil {
						respond(m.GetConnectionHalfClose().ConnectionId)
					}
					return nil
				}}
				body := &uploadBody{remaining: size}
				r := httptest.NewRequest("POST", "https://upload.tunn.test/", body)
				r.ContentLength = -1
				w := httptest.NewRecorder()
				err := (&ProxyServer{}).proxyHTTPOverGRPC(w, r, tunnel)
				if size > MaxBodySize {
					if err == nil || responseHasStarted(err) {
						t.Fatalf("early 200 hid oversized upload: %v", err)
					}
					writeIngressError(w, err)
					assertUpload413(t, w)
				} else if err != nil || w.Code != 200 || forwarded.Load() != size {
					t.Fatalf("allowed upload = %d %v, forwarded %d of %d bytes", w.Code, err, forwarded.Load(), size)
				}
			})
		}
	}
}
