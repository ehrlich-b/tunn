package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type inboundConnection struct {
	bodyWriter *io.PipeWriter
	cancel     context.CancelFunc
	closeOnce  sync.Once
	input      chan []byte // Bounded WebSocket queue; a slow socket cannot stall the control receiver
	done       <-chan struct{}
}

func (c *inboundConnection) stop(err error) {
	c.closeOnce.Do(func() {
		_ = c.bodyWriter.CloseWithError(err)
		c.cancel()
	})
}

type inboundConnectionManager struct {
	mu          sync.RWMutex
	connections map[string]*inboundConnection
	slots       chan struct{}
}

func newInboundConnectionManager() *inboundConnectionManager {
	return newInboundConnectionManagerWithLimit(common.MaxConcurrentConnections)

}

func newInboundConnectionManagerWithLimit(limit int) *inboundConnectionManager {
	return &inboundConnectionManager{
		connections: make(map[string]*inboundConnection),
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
		valid = open.Protocol == endpointProtocol || (endpointProtocol == "http" && open.Protocol == "websocket")
		if open.Protocol == "http" || open.Protocol == "websocket" {
			valid = valid && open.HttpRequest != nil
		}
	}
	if !valid {
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
		sendConnectionRejection(sender, open.ConnectionId, "endpoint connection limit reached")
		return
	}

	bodyReader, bodyWriter := io.Pipe()
	connectionCtx, cancel := context.WithCancel(ctx)
	connection := &inboundConnection{bodyWriter: bodyWriter, cancel: cancel}
	if open.Protocol == "websocket" {
		connection.input = make(chan []byte, 16)
		connection.done = connectionCtx.Done()
		go func() {
			for {
				select {
				case data := <-connection.input:
					if data == nil {
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
	}

	m.mu.Lock()
	if _, exists := m.connections[open.ConnectionId]; exists {
		m.mu.Unlock()
		<-m.slots
		_ = bodyReader.Close()
		connection.stop(fmt.Errorf("duplicate connection ID"))
		sendConnectionRejection(sender, open.ConnectionId, "duplicate connection ID")
		return
	}
	m.connections[open.ConnectionId] = connection
	m.mu.Unlock()

	go func() {
		defer func() {
			_ = bodyReader.Close()
			m.remove(open.ConnectionId, connection)
		}()
		switch open.Protocol {
		case "http":
			client.handleStreamingHTTPRequest(connectionCtx, sender, open, bodyReader)
		case "tcp":
			client.handleStreamingTCP(connectionCtx, sender, open.ConnectionId, bodyReader)
		case "websocket":
			client.handleWebSocket(connectionCtx, sender, open, bodyReader)
		}
	}()
}

func (s *ServeClient) handleStreamingTCP(ctx context.Context, sender messageSender, connectionID string, input io.Reader) {
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
	defer func() { _ = connection.Close() }()
	stopWatcher := make(chan struct{})
	defer close(stopWatcher)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopWatcher:
		}
	}()

	if err := sender.Send(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionAccept{
			ConnectionAccept: &pb.ConnectionAccept{ConnectionId: connectionID, Success: true},
		},
	}); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(connection, input)
		if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
		}
	}()

	buffer := make([]byte, common.StreamChunkSize)
	for {
		n, readErr := connection.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			if err := sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionData{
					ConnectionData: &pb.ConnectionData{ConnectionId: connectionID, Data: chunk},
				},
			}); err != nil {
				return
			}
		}
		if readErr == io.EOF {
			_ = sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionHalfClose{
					ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: connectionID},
				},
			})
			return
		}
		if readErr != nil {
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

func (m *inboundConnectionManager) write(connectionID string, data []byte) {
	connection := m.get(connectionID)
	if connection == nil {
		return
	}
	if connection.input != nil {
		if len(data) > common.StreamChunkSize {
			connection.stop(fmt.Errorf("oversized WebSocket transport chunk"))
			return
		}
		select {
		case connection.input <- data:
		case <-connection.done:
		}
		return
	}
	if _, err := connection.bodyWriter.Write(data); err != nil {
		connection.stop(err)
	}
}

func (m *inboundConnectionManager) halfClose(connectionID string) {
	connection := m.get(connectionID)
	if connection != nil {
		if connection.input != nil {
			select {
			case connection.input <- nil:
			case <-connection.done:
			}
		} else {
			_ = connection.bodyWriter.Close()
		}
	}
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
		capture = s.Inspector.begin(head.Method, head.Path, head.Headers)
		body = &inspectionReader{reader: body, capture: capture}
	}
	status, responseBytes, failure := http.StatusBadGateway, int64(0), "failed to forward"
	if capture != nil {
		defer func() { capture.finish(status, responseBytes, failure) }()
	}
	request, err := http.NewRequestWithContext(ctx, head.Method, s.targetURL(head.Path), body)
	if err != nil {
		sendConnectionRejection(sender, open.ConnectionId, "failed to create local HTTP request")
		return
	}
	for key, value := range head.Headers {
		request.Header.Set(key, value)
	}
	request.Host = request.Header.Get("Host")
	request.Header.Del("Host")
	if s.RequireUpstreamAuth && strings.TrimSpace(request.Header.Get("Authorization")) == "" {
		sendUpstreamAuthRequired(sender, open.ConnectionId)
		return
	}
	request.ContentLength = head.ContentLength

	timeout := s.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.SkipLocalTLSVerify,
		},
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: timeout,
	}
	if s.DialContext != nil {
		transport.DialContext = s.DialContext
	}
	if s.TargetNetwork == "unix" {
		dialAddress := s.DialAddress
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", dialAddress)
		}
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}
	response, err := httpClient.Do(request)
	if err != nil {
		common.LogDebug("streaming target failed", "error", err)
		sendConnectionRejection(sender, open.ConnectionId, "failed to reach local target")
		return
	}
	defer func() { _ = response.Body.Close() }()
	status = response.StatusCode
	failure = ""

	headers := make(map[string]string, len(response.Header))
	for key, values := range response.Header {
		headers[key] = strings.Join(values, ", ")
	}
	if err := sender.Send(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionAccept{
			ConnectionAccept: &pb.ConnectionAccept{
				ConnectionId: open.ConnectionId,
				Success:      true,
				HttpResponse: &pb.HttpResponseHead{
					StatusCode: int32(response.StatusCode),
					Headers:    headers,
				},
			},
		},
	}); err != nil {
		return
	}

	buffer := make([]byte, common.StreamChunkSize)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			responseBytes += int64(n)
			chunk := append([]byte(nil), buffer[:n]...)
			if err := sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionData{
					ConnectionData: &pb.ConnectionData{ConnectionId: open.ConnectionId, Data: chunk},
				},
			}); err != nil {
				return
			}
		}
		if readErr == io.EOF {
			_ = sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionHalfClose{
					ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: open.ConnectionId},
				},
			})
			return
		}
		if readErr != nil {
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
