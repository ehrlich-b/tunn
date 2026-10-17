package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/inspection"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Each stream buffers at most 512 KiB plus one chunk being drained. The
// shared receiver must never wait for an origin to consume its upload.
const inboundQueueChunks = 16

type requestTimingKey struct{}

// Completion metadata outlives the origin connection, but never the stream.
type requestTiming struct {
	completion   chan *pb.ConnectionClose
	streamDone   <-chan struct{}
	manager      *inboundConnectionManager
	connectionID string
}

func (t *requestTiming) remove() {
	t.manager.mu.Lock()
	if t.manager.timings[t.connectionID] == t {
		delete(t.manager.timings, t.connectionID)
	}
	t.manager.mu.Unlock()
}

func (t *requestTiming) finish(record func(*pb.ConnectionClose)) {
	t.manager.workers.Add(1)
	go func() {
		defer t.manager.workers.Done()
		defer t.remove()
		var closed *pb.ConnectionClose
		select {
		case closed = <-t.completion:
		case <-t.streamDone:
			// Prefer a completion already received before stream shutdown.
			select {
			case closed = <-t.completion:
			default:
			}
		}
		record(closed)
	}()
}

type inboundConnection struct {
	bodyWriter  *io.PipeWriter
	cancel      context.CancelFunc
	closeOnce   sync.Once
	input       chan []byte
	done        <-chan struct{}
	inputError  chan error
	inputMu     sync.Mutex
	inputClosed bool
}

func (c *inboundConnection) stop(err error) {
	c.closeOnce.Do(func() {
		_ = c.bodyWriter.CloseWithError(err)
		c.cancel()
	})
}

type inboundConnectionManager struct {
	workers     sync.WaitGroup
	mu          sync.RWMutex
	connections map[string]*inboundConnection
	timings     map[string]*requestTiming
	slots       chan struct{}
}

func newInboundConnectionManager() *inboundConnectionManager {
	return newInboundConnectionManagerWithLimit(common.MaxConcurrentConnections)

}

func newInboundConnectionManagerWithLimit(limit int) *inboundConnectionManager {
	return &inboundConnectionManager{
		connections: make(map[string]*inboundConnection),
		timings:     make(map[string]*requestTiming),
		slots:       make(chan struct{}, limit),
	}
}

func (m *inboundConnectionManager) open(ctx context.Context, client *ServeClient, sender messageSender, open *pb.ConnectionOpen) {
	valid := open != nil && open.ConnectionId != ""
	endpointProtocol := client.EndpointProtocol
	if endpointProtocol == "" {
		endpointProtocol = "http"
	}
	if valid {
		valid = open.Protocol == endpointProtocol || (endpointProtocol == "http" && (open.Protocol == "websocket" || open.Protocol == common.HTTPOriginReplayProtocol))
		if open.Protocol == "http" || open.Protocol == "websocket" || open.Protocol == common.HTTPOriginReplayProtocol {
			valid = valid && open.HttpRequest != nil
		}
	}
	if !valid {
		client.Inspector.denied()
		connectionID := ""
		if open != nil {
			connectionID = open.ConnectionId
		}
		sendConnectionRejection(sender, connectionID, "unsupported or malformed connection open")
		return
	}
	select {
	case m.slots <- struct{}{}:
	default:
		client.Inspector.denied()
		sendConnectionRejection(sender, open.ConnectionId, "endpoint connection limit reached")
		return
	}

	bodyReader, bodyWriter := io.Pipe()
	connectionCtx, cancel := context.WithCancel(ctx)
	var timing *requestTiming
	if open.RequestTiming && client.Inspector != nil && (open.Protocol == "http" || open.Protocol == common.HTTPOriginReplayProtocol) {
		timing = &requestTiming{completion: make(chan *pb.ConnectionClose, 1), streamDone: ctx.Done(), manager: m, connectionID: open.ConnectionId}
		connectionCtx = context.WithValue(connectionCtx, requestTimingKey{}, timing)
	}
	connection := &inboundConnection{
		bodyWriter: bodyWriter, cancel: cancel,
		input: make(chan []byte, inboundQueueChunks), done: connectionCtx.Done(),
		inputError: make(chan error, 1),
	}
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		defer func() {
			select {
			case err := <-connection.inputError:
				_ = sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{
					ConnectionClose: &pb.ConnectionClose{ConnectionId: open.ConnectionId, ErrorMessage: err.Error()},
				}})
			default:
			}
		}()
		for {
			select {
			case data, ok := <-connection.input:
				if !ok {
					_ = bodyWriter.Close()
					return
				}
				if _, err := bodyWriter.Write(data); err != nil {
					return
				}
			case <-connectionCtx.Done():
				return
			}
		}
	}()

	m.mu.Lock()
	if m.connections[open.ConnectionId] != nil || m.timings[open.ConnectionId] != nil {
		client.Inspector.denied()
		m.mu.Unlock()
		<-m.slots
		_ = bodyReader.Close()
		connection.stop(fmt.Errorf("duplicate connection ID"))
		sendConnectionRejection(sender, open.ConnectionId, "duplicate connection ID")
		return
	}
	m.connections[open.ConnectionId] = connection
	if timing != nil {
		m.timings[open.ConnectionId] = timing
	}
	m.mu.Unlock()

	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		defer func() {
			_ = bodyReader.Close()
			m.remove(open.ConnectionId, connection)
		}()
		switch open.Protocol {
		case "http", common.HTTPOriginReplayProtocol:
			client.handleStreamingHTTPRequest(connectionCtx, sender, open, bodyReader)
		case "tcp":
			client.handleStreamingTCP(connectionCtx, sender, open.ConnectionId, bodyReader)
		case "websocket":
			client.handleWebSocket(connectionCtx, sender, open, bodyReader)
		}
	}()
}

func (s *ServeClient) handleStreamingTCP(ctx context.Context, sender messageSender, connectionID string, input io.Reader) {
	inputCloser, _ := input.(io.Closer)
	status, reason := 0, "target_error"
	var capture *inspectionCapture
	if s.Inspector != nil {
		capture = s.Inspector.beginConnection(connectionID, "tcp", "CONNECT", "/", nil)
		input = &inspectionReader{reader: input, capture: capture}
		defer func() {
			if ctx.Err() != nil {
				reason = "canceled"
			}
			capture.finishReason(status, -1, reason)
		}()
	}
	targetNetwork := s.TargetNetwork
	if targetNetwork == "" {
		targetNetwork = "tcp"
	}
	dial := (&net.Dialer{}).DialContext
	if s.DialContext != nil {
		dial = s.DialContext
	}
	connection, err := dial(ctx, targetNetwork, s.TargetURL)
	if err != nil {
		sendConnectionRejection(sender, connectionID, "failed to reach local TCP target")
		return
	}
	closeConnection := func() {
		_ = connection.Close()
		if inputCloser != nil {
			_ = inputCloser.Close()
		}
	}
	var workers sync.WaitGroup
	stopWatcher := make(chan struct{})
	defer func() {
		close(stopWatcher)
		closeConnection()
		workers.Wait()
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		select {
		case <-ctx.Done():
			closeConnection()
		case <-stopWatcher:
		}
	}()

	if err := sender.Send(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionAccept{
			ConnectionAccept: &pb.ConnectionAccept{ConnectionId: connectionID, Success: true},
		},
	}); err != nil {
		reason = "relay_error"
		return
	}

	uploadDone := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(uploadDone)
		if _, err := io.Copy(connection, input); err != nil {
			closeConnection()
			return
		}
		if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
		}
	}()

	status, reason = http.StatusOK, "complete"
	buffer := make([]byte, common.StreamChunkSize)
	for {
		n, readErr := connection.Read(buffer)
		if capture != nil {
			capture.response(n)
		}
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			if err := sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionData{
					ConnectionData: &pb.ConnectionData{ConnectionId: connectionID, Data: chunk},
				},
			}); err != nil {
				reason = "relay_error"
				return
			}
		}
		if readErr == io.EOF {
			reason = "peer_closed"
			if err := sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionHalfClose{
					ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: connectionID},
				},
			}); err != nil {
				reason = "relay_error"
				return
			}
			// Origin EOF ends only the response direction. Keep accepting
			// uploads until their EOF, or until cancellation closes both I/Os.
			<-uploadDone
			return
		}
		if readErr != nil {
			reason = "response_error"
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionClose{
					ConnectionClose: &pb.ConnectionClose{ConnectionId: connectionID, ErrorMessage: "failed to read local TCP target"},
				},
			})
			return
		}
	}
}

// enqueue copies transport buffers before returning to the receiver. EOF and
// writes share the lock so a concurrent half-close cannot send on a closed queue.
func (c *inboundConnection) enqueue(data []byte) error {
	c.inputMu.Lock()
	defer c.inputMu.Unlock()
	if c.inputClosed || len(data) == 0 {
		return nil
	}
	select {
	case <-c.done:
		return nil
	default:
	}
	if len(data) > common.StreamChunkSize {
		return fmt.Errorf("oversized inbound transport chunk")
	}
	select {
	case c.input <- append([]byte(nil), data...):
		return nil
	default:
		return fmt.Errorf("inbound stream queue overflow")
	}
}

func (m *inboundConnectionManager) write(connectionID string, data []byte) {
	connection := m.get(connectionID)
	if connection == nil {
		return
	}
	if err := connection.enqueue(data); err != nil {
		// Report the close from the drain worker, never from the receiver.
		select {
		case connection.inputError <- err:
		default:
		}
		connection.stop(err)
		m.remove(connectionID, connection)
	}
}

func (m *inboundConnectionManager) halfClose(connectionID string) {
	connection := m.get(connectionID)
	if connection != nil {
		connection.inputMu.Lock()
		defer connection.inputMu.Unlock()
		if !connection.inputClosed {
			connection.inputClosed = true
			close(connection.input)
		}
	}
}

func (m *inboundConnectionManager) complete(closed *pb.ConnectionClose) {
	m.mu.Lock()
	if timing := m.timings[closed.ConnectionId]; timing != nil {
		timing.completion <- closed
		delete(m.timings, closed.ConnectionId)
	}
	m.mu.Unlock()
	m.close(closed.ConnectionId, closed.ErrorMessage)
}

func (m *inboundConnectionManager) close(connectionID, message string) {
	connection := m.get(connectionID)
	if connection == nil {
		return
	}
	err := io.EOF
	if message != "" {
		err = fmt.Errorf("remote connection closed: %s", message)
	}
	connection.stop(err)
	m.remove(connectionID, connection)
}

func (m *inboundConnectionManager) get(connectionID string) *inboundConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connections[connectionID]
}

func (m *inboundConnectionManager) remove(connectionID string, connection *inboundConnection) {
	removed := false
	m.mu.Lock()
	if m.connections[connectionID] == connection {
		delete(m.connections, connectionID)
		removed = true
	}
	m.mu.Unlock()
	if removed {
		<-m.slots
	}
	connection.stop(io.EOF)
}

func (m *inboundConnectionManager) closeAll(err error) {
	m.mu.Lock()
	for connectionID, timing := range m.timings {
		timing.completion <- nil
		delete(m.timings, connectionID)
	}
	connections := make([]*inboundConnection, 0, len(m.connections))
	for connectionID, connection := range m.connections {
		delete(m.connections, connectionID)
		connections = append(connections, connection)
	}
	m.mu.Unlock()
	for _, connection := range connections {
		<-m.slots
		connection.stop(err)
	}
}

func (s *ServeClient) handleStreamingHTTPRequest(ctx context.Context, sender messageSender, open *pb.ConnectionOpen, body io.Reader) {
	head := open.HttpRequest
	var capture *inspectionCapture
	if s.Inspector != nil {
		capture = s.Inspector.beginConnection(open.ConnectionId, "http", head.Method, head.Path, head.Headers)
		capture.expectLength(head.ContentLength)
		body = &inspectionReader{reader: body, capture: capture}
	}
	status, responseBytes, reason := http.StatusBadGateway, int64(0), "target_error"
	if capture != nil {
		defer func() {
			if timing, ok := ctx.Value(requestTimingKey{}).(*requestTiming); ok {
				if reason == "complete" {
					// Do not retain origin capacity while the visitor downloads.
					timing.finish(func(closed *pb.ConnectionClose) {
						if closed == nil {
							reason = "canceled"
						} else {
							if closed.ErrorMessage != "" {
								reason = "relay_error"
							}
							if v := closed.Timing; v != nil {
								capture.mu.Lock()
								capture.event.Timing = inspection.NewTiming(v.OriginTtfbUs, v.OriginTotalUs, v.RelayTtfbUs, v.RelayTotalUs)
								capture.mu.Unlock()
							}
						}
						capture.finishReason(status, responseBytes, reason)
					})
					return
				}
				timing.remove()
			}
			if ctx.Err() != nil {
				reason = "canceled"
			}
			capture.finishReason(status, responseBytes, reason)
		}()
	}
	request, err := http.NewRequestWithContext(ctx, head.Method, s.targetURL(head.Path), body)
	if err != nil {
		sendConnectionRejection(sender, open.ConnectionId, "failed to create local HTTP request")
		return
	}
	request.Header, err = common.DecodeHTTPRequestHeaders(head.Headers, head.HeaderFields, head.ContentLength, false)
	if err != nil {
		sendConnectionRejection(sender, open.ConnectionId, "invalid request headers")
		return
	}
	request.Host = request.Header.Get("Host")
	request.Header.Del("Host")
	if s.RequireUpstreamAuth && strings.TrimSpace(request.Header.Get("Authorization")) == "" {
		status, reason = http.StatusUnauthorized, "auth_required"
		s.Inspector.denied()
		sendUpstreamAuthRequired(sender, open.ConnectionId)
		return
	}
	request.ContentLength = head.ContentLength

	transport, closePool := s.originHTTPTransport(ctx)
	defer closePool()
	httpClient := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	// Uploads can wait on the visitor. Charge the app only after the full
	// request has reached the origin, and exclude relay response backpressure.
	var timingMu sync.Mutex
	var originStart, firstResponseByte time.Time
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				timingMu.Lock()
				originStart = time.Now()
				timingMu.Unlock()
			}
		},
		GotFirstResponseByte: func() {
			timingMu.Lock()
			firstResponseByte = time.Now()
			timingMu.Unlock()
		},
	}))
	response, err := httpClient.Do(request)
	var originTTFB, originTotal time.Duration
	timingMu.Lock()
	// A response before upload completion has no meaningful post-upload app split.
	originTimingKnown := !originStart.IsZero() && !firstResponseByte.IsZero() && !firstResponseByte.Before(originStart)
	if originTimingKnown {
		originTTFB = firstResponseByte.Sub(originStart)
		originTotal = time.Since(originStart)
	}
	timingMu.Unlock()
	if err != nil {
		common.LogDebug("streaming target failed", "error", err)
		sendConnectionRejection(sender, open.ConnectionId, "failed to reach local target")
		return
	}
	defer func() { _ = response.Body.Close() }()
	status = response.StatusCode
	reason = "complete"
	if capture != nil && strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		capture.setProtocol("sse")
	}

	if response.StatusCode == http.StatusSwitchingProtocols {
		reason = "response_error"
		sendConnectionRejection(sender, open.ConnectionId, "HTTP protocol upgrades require the WebSocket transport")
		return
	}
	trailerNames, err := s.responseTrailerNames(response, head.Method)
	if err != nil {
		reason = "response_error"
		sendConnectionRejection(sender, open.ConnectionId, err.Error())
		return
	}
	headers, fields := common.EncodeHTTPResponseHeaders(response.Header)
	if err := sender.Send(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionAccept{
			ConnectionAccept: &pb.ConnectionAccept{
				ConnectionId: open.ConnectionId,
				Success:      true,
				HttpResponse: &pb.HttpResponseHead{
					StatusCode:    int32(response.StatusCode),
					Headers:       headers,
					HeaderFields:  fields,
					TrailerNames:  trailerNames,
					OriginTtfbUs:  originTTFB.Microseconds(),
					OriginTotalUs: originTotal.Microseconds(),
				},
			},
		},
	}); err != nil {
		reason = "relay_error"
		return
	}

	if !common.HTTPResponseHasBody(head.Method, response.StatusCode) {
		if err := sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId}}}); err != nil {
			reason = "relay_error"
		}
		return
	}
	buffer := make([]byte, common.StreamChunkSize)
	for {
		readStart := time.Now()
		n, readErr := response.Body.Read(buffer)
		if originTimingKnown {
			originTotal += time.Since(readStart)
		}
		if n > 0 {
			responseBytes += int64(n)
			chunk := append([]byte(nil), buffer[:n]...)
			if err := sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionData{
					ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: chunk},
				},
			}); err != nil {
				reason = "relay_error"
				return
			}
		}
		if readErr == io.EOF {
			trailers, trailerErr := s.responseTrailerFields(response, trailerNames)
			if trailerErr != nil {
				reason = "response_error"
				_ = sender.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: open.ConnectionId, ErrorMessage: trailerErr.Error()}}})
				return
			}
			if err := sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionHalfClose{
					ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId, Trailers: trailers, OriginTotalUs: originTotal.Microseconds()},
				},
			}); err != nil {
				reason = "relay_error"
			}
			return
		}
		if readErr != nil {
			reason = "response_error"
			_ = sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionClose{
					ConnectionClose: &pb.ConnectionClose{ConnectionId: open.ConnectionId, ErrorMessage: "failed to read local response"},
				},
			})
			return
		}
	}
}

func sendConnectionRejection(sender messageSender, connectionID, message string) {
	_ = sender.Send(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionAccept{
			ConnectionAccept: &pb.ConnectionAccept{
				ConnectionId: connectionID,
				Success:      false,
				ErrorMessage: message,
			},
		},
	})
}
