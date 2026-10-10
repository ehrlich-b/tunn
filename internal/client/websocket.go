package client

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type webSocketTunnelWriter struct {
	sender messageSender
	id     string
}

func (w webSocketTunnelWriter) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		n := min(len(data), common.StreamChunkSize)
		if err := w.sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{
			ConnectionData: &pb.ConnectionData{ConnectionId: w.id, Data: append([]byte(nil), data[:n]...)},
		}}); err != nil {
			return written, err
		}
		written += n
		data = data[n:]
	}
	return written, nil
}

type webSocketActivityReader struct {
	reader io.Reader
	last   *atomic.Int64
}

func (r webSocketActivityReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.last.Store(time.Now().UnixNano())
	}
	return n, err
}

type webSocketTargetConn struct{ net.Conn }

func (c webSocketTargetConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return c.Conn.Write(p)
}

func sendHTTPConnectionHead(sender messageSender, id string, status int, headers http.Header) error {
	values := make(map[string]string, len(headers))
	for key, value := range headers {
		values[key] = strings.Join(value, ", ")
	}
	return sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{
		ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true,
			HttpResponse: &pb.HttpResponseHead{StatusCode: int32(status), Headers: values}},
	}})
}

func sendConnectionHalfClose(sender messageSender, id string) {
	_ = sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{
		ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id},
	}})
}

func sendUpstreamAuthRequired(sender messageSender, id string) {
	_ = sendHTTPConnectionHead(sender, id, http.StatusUnauthorized, http.Header{"Www-Authenticate": {`Bearer realm="upstream"`}})
	sendConnectionHalfClose(sender, id)
}

func (s *ServeClient) handleWebSocket(ctx context.Context, sender messageSender, open *pb.ConnectionOpen, input io.Reader) {
	head, id := open.HttpRequest, open.ConnectionId
	options := common.DefaultWebSocketOptions()
	if s.WebSocket != nil {
		options = *s.WebSocket
	}
	if err := options.Validate(); err != nil {
		sendConnectionRejection(sender, id, err.Error())
		return
	}
	request, err := http.NewRequestWithContext(ctx, head.Method, s.targetURL(head.Path), nil)
	if err != nil {
		sendConnectionRejection(sender, id, "invalid local WebSocket target")
		return
	}
	for key, value := range head.Headers {
		request.Header.Set(key, value)
	}
	request.Host = request.Header.Get("Host")
	request.Header.Del("Host")
	// Compression would require limiting inflated messages. Negotiate the base
	// protocol only so fragmentation cannot bypass the actual message limit.
	request.Header.Del("Sec-WebSocket-Extensions")
	if !common.ValidWebSocketRequest(request) {
		sendConnectionRejection(sender, id, "invalid WebSocket upgrade")
		return
	}
	if s.RequireUpstreamAuth && strings.TrimSpace(request.Header.Get("Authorization")) == "" {
		sendUpstreamAuthRequired(sender, id)
		return
	}
	timeout := s.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	var targetMu sync.Mutex
	var targetConn net.Conn
	defer func() {
		targetMu.Lock()
		defer targetMu.Unlock()
		if targetConn != nil {
			_ = targetConn.Close()
		}
	}()
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: s.SkipLocalTLSVerify},
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if s.TargetNetwork == "unix" {
				network, address = "unix", s.DialAddress
			}
			dial := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext
			if s.DialContext != nil {
				dial = s.DialContext
			}
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			targetMu.Lock()
			targetConn = conn
			targetMu.Unlock()
			return webSocketTargetConn{conn}, nil
		},
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		sendConnectionRejection(sender, id, "failed to reach local WebSocket target")
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusSwitchingProtocols {
		if err := sendHTTPConnectionHead(sender, id, response.StatusCode, response.Header); err != nil {
			return
		}
		n, err := io.Copy(webSocketTunnelWriter{sender, id}, io.LimitReader(response.Body, MaxResponseBodySize+1))
		if err == nil && n <= MaxResponseBodySize {
			sendConnectionHalfClose(sender, id)
		} else {
			_ = sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{
				ConnectionClose: &pb.ConnectionClose{ConnectionId: id, ErrorMessage: "failed to stream local WebSocket rejection"},
			}})
		}
		return
	}
	upstream, duplex := response.Body.(io.ReadWriteCloser)
	// Close the raw transport before Body.Close sends a TLS close-notify.
	// A peer may stop reading after its WebSocket closing frame; waiting for
	// another TLS write would unnecessarily retain the connection slot.
	defer func() {
		targetMu.Lock()
		defer targetMu.Unlock()
		if targetConn != nil {
			_ = targetConn.Close()
		}
	}()
	if !duplex || !common.ValidWebSocketResponse(response.Header, request.Header.Get("Sec-WebSocket-Key")) {
		sendConnectionRejection(sender, id, "invalid local WebSocket handshake")
		return
	}
	if selected := response.Header.Get("Sec-WebSocket-Protocol"); selected != "" {
		offered := false
		for _, protocol := range strings.Split(request.Header.Get("Sec-WebSocket-Protocol"), ",") {
			if strings.TrimSpace(protocol) == selected {
				offered = true
			}
		}
		if !offered {
			sendConnectionRejection(sender, id, "local target selected an unrequested WebSocket subprotocol")
			return
		}
	}
	if err := sendHTTPConnectionHead(sender, id, response.StatusCode, response.Header); err != nil {
		return
	}
	s.runWebSocket(ctx, sender, id, input, upstream, options)
}

func (s *ServeClient) runWebSocket(ctx context.Context, sender messageSender, id string, input io.Reader, upstream io.ReadWriteCloser, options common.WebSocketOptions) {
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = upstream.Close()
		case <-watchDone:
		}
	}()
	defer func() {
		_ = sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{
			ConnectionClose: &pb.ConnectionClose{ConnectionId: id},
		}})
	}()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	toLocal := &common.WebSocketFrameWriter{Writer: upstream}
	toRemote := &common.WebSocketFrameWriter{Writer: webSocketTunnelWriter{sender, id}}
	incoming, outgoing := make(chan error, 1), make(chan error, 1)
	go func() {
		incoming <- toLocal.CopyFrames(webSocketActivityReader{input, &last}, true, options.MaxMessageSize)
	}()
	go func() {
		outgoing <- toRemote.CopyFrames(webSocketActivityReader{upstream, &last}, false, options.MaxMessageSize)
	}()

	var idleTimer *time.Timer
	var idle <-chan time.Time
	if options.IdleTimeout > 0 {
		idleTimer = time.NewTimer(options.IdleTimeout)
		idle = idleTimer.C
		defer idleTimer.Stop()
	}
	var keepalive <-chan time.Time
	if options.KeepaliveInterval > 0 {
		ticker := time.NewTicker(options.KeepaliveInterval)
		defer ticker.Stop()
		keepalive = ticker.C
	}
	var closing <-chan time.Time
	incomingClosed, outgoingClosed := false, false
	var closeTimer *time.Timer
	defer func() {
		if closeTimer != nil {
			closeTimer.Stop()
		}
	}()
	closeWithCode := func(code uint16) {
		payload := make([]byte, 2)
		binary.BigEndian.PutUint16(payload, code)
		_ = toRemote.TryControl(8, payload, false)
		// A rejected upstream frame may still be blocked in a payload write.
		// Close that transport on return instead of waiting for it to read a
		// generated close frame. Normal peer close frames remain bidirectional.
	}
	failed := func(err error) {
		if errors.Is(err, common.ErrWebSocketMessageTooLarge) {
			closeWithCode(1009)
		} else if errors.Is(err, common.ErrWebSocketProtocol) {
			closeWithCode(1002)
		}
	}
	for {
		select {
		case err := <-outgoing:
			failed(err)
			if err != nil || incomingClosed {
				sendConnectionHalfClose(sender, id)
				return
			}
			outgoingClosed = true
			outgoing = nil
			keepalive = nil
			closeTimer = time.NewTimer(5 * time.Second)
			closing = closeTimer.C
		case err := <-incoming:
			if err != nil {
				failed(err)
				return
			}
			if outgoingClosed {
				sendConnectionHalfClose(sender, id)
				return
			}
			incomingClosed = true
			// Preserve the upstream's closing reply after a client close frame.
			incoming = nil
			keepalive = nil
			closeTimer = time.NewTimer(5 * time.Second)
			closing = closeTimer.C
		case <-idle:
			remaining := options.IdleTimeout - time.Since(time.Unix(0, last.Load()))
			if remaining > 0 {
				idleTimer.Reset(remaining)
				continue
			}
			closeWithCode(1001)
			sendConnectionHalfClose(sender, id)
			return
		case <-keepalive:
			// Generated pings do not extend idle time; received frames (including
			// pong) do. Both public and upstream legs stay active through proxies.
			if err := toRemote.TryControl(9, []byte("tunn"), false); err != nil {
				return
			}
			if err := toLocal.TryControl(9, []byte("tunn"), true); err != nil {
				return
			}
		case <-closing:
			return
		case <-ctx.Done():
			return
		}
	}
}
