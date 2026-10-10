package host

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type webSocketAccessKey struct{}

func closeUpgradedConnection(conn net.Conn) {
	// The WebSocket close handshake has its own frame. Close the underlying
	// transport promptly instead of waiting for a TLS close-notify write to
	// a client that may have stopped reading after that frame.
	if tlsConn, ok := conn.(interface{ NetConn() net.Conn }); ok {
		_ = tlsConn.NetConn().Close()
	} else {
		_ = conn.Close()
	}
}

func (p *ProxyServer) proxyWebSocketOverGRPC(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) error {
	id, err := generateConnectionID()
	if err != nil {
		return err
	}
	digest, _ := r.Context().Value(webSocketAccessKey{}).([]byte)
	pending, err := tunnel.addPendingAuthenticatedConnection(id, digest)
	if err != nil {
		return err
	}
	defer tunnel.removePendingConnection(id, pending)
	defer sendConnectionClose(tunnel.Stream.Context(), tunnel, id, "")
	if err := tunnel.SendMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionOpen{
		ConnectionOpen: &pb.ConnectionOpen{ConnectionId: id, Protocol: "websocket", SourceAddress: r.RemoteAddr,
			HttpRequest: &pb.HttpRequestHead{Method: r.Method, Path: r.URL.RequestURI(), Headers: p.forwardedHTTPHeaders(r)}},
	}}); err != nil {
		return err
	}
	if session := meterForRequest(r); session != nil {
		session.event.Forwarded = true
	}
	timer := time.NewTimer(streamResponseHeaderTimeout)
	defer timer.Stop()
	var head *pb.HttpResponseHead
	select {
	case event := <-pending.events:
		if event.accept == nil || !event.accept.Success || event.accept.HttpResponse == nil {
			return fmt.Errorf("local target rejected WebSocket upgrade")
		}
		head = event.accept.HttpResponse
	case <-pending.done:
		return fmt.Errorf("tunnel disconnected or token revoked before upgrade")
	case <-r.Context().Done():
		return r.Context().Err()
	case <-timer.C:
		return fmt.Errorf("timeout waiting for WebSocket upgrade")
	}
	if head.StatusCode != http.StatusSwitchingProtocols {
		if head.StatusCode < 200 || head.StatusCode > 599 {
			return fmt.Errorf("invalid upgrade rejection status")
		}
		var requestBytes atomic.Int64
		var responseBytes int64
		finished := true
		err := p.writeStreamingHTTPResponse(w, r, tunnel, pending, head, &requestBytes, &responseBytes, nil, &finished)
		if err != nil {
			return &responseStartedError{err}
		}
		return nil
	}
	headers := make(http.Header)
	copyApplicationResponseHeaders(headers, head.Headers)
	if !common.ValidWebSocketResponse(headers, r.Header.Get("Sec-WebSocket-Key")) {
		return fmt.Errorf("invalid WebSocket acceptance")
	}
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return fmt.Errorf("WebSocket ingress requires HTTP/1.1: %w", err)
	}
	// The upgrade bypasses WriteHeader, so preserve its admission metadata and
	// final status explicitly. Frame bytes belong to account bandwidth usage,
	// rather than HTTP body-byte budgets.
	for key, values := range w.Header() {
		if strings.HasPrefix(strings.ToLower(key), "tunn-") {
			headers[key] = append([]string(nil), values...)
		}
	}
	if writer, ok := w.(*meterResponseWriter); ok {
		writer.status, writer.started, writer.bodyMeter = http.StatusSwitchingProtocols, true, false
	}
	defer closeUpgradedConnection(conn)
	// Hijack retains the HTTP server's deadlines. An upgraded connection must
	// outlive those header/body limits; the publisher owns its idle timer.
	_ = conn.SetDeadline(time.Time{})
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-pending.done:
			closeUpgradedConnection(conn)
		case <-r.Context().Done():
			closeUpgradedConnection(conn)
		case <-watchDone:
		}
	}()
	if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return &responseStartedError{err}
	}
	if err := headers.Write(buffered); err != nil {
		return &responseStartedError{err}
	}
	if _, err := buffered.WriteString("\r\n"); err != nil {
		return &responseStartedError{err}
	}
	if err := buffered.Flush(); err != nil {
		return &responseStartedError{err}
	}
	var requestBytes atomic.Int64
	var responseBytes int64
	defer func() {
		if tunnel.AccountID != "" {
			p.RecordUsage(r.Context(), tunnel.AccountID, requestBytes.Load()+responseBytes)
		}
	}()
	inputDone := make(chan error, 1)
	go func() {
		// Read from the hijacker's buffer: frames can accompany the handshake.
		buffer := make([]byte, common.StreamChunkSize)
		for {
			n, readErr := buffered.Read(buffer)
			if n > 0 {
				requestBytes.Add(int64(n))
				if !tunnel.CheckRateLimit(n) {
					inputDone <- fmt.Errorf("WebSocket bandwidth limit exceeded")
					return
				}
				if err := tunnel.SendMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{
					ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: append([]byte(nil), buffer[:n]...)},
				}}); err != nil {
					inputDone <- err
					return
				}
			}
			if readErr != nil {
				inputDone <- readErr
				return
			}
		}
	}()
	for {
		select {
		case event := <-pending.events:
			switch {
			case event.data != nil:
				if !tunnel.CheckRateLimit(len(event.data)) {
					return &responseStartedError{fmt.Errorf("WebSocket bandwidth limit exceeded")}
				}
				responseBytes += int64(len(event.data))
				_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := conn.Write(event.data); err != nil {
					return &responseStartedError{err}
				}
			case event.halfClose, event.close != nil:
				return nil
			default:
				return &responseStartedError{fmt.Errorf("unexpected WebSocket stream metadata")}
			}
		case err := <-inputDone:
			if err == io.EOF {
				return nil
			}
			return &responseStartedError{err}
		case <-pending.done:
			return &responseStartedError{fmt.Errorf("WebSocket disconnected or token revoked")}
		case <-r.Context().Done():
			return &responseStartedError{r.Context().Err()}
		}
	}
}
