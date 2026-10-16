package host

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type connectionEvent struct {
	accept        *pb.ConnectionAccept
	data          []byte
	halfClose     bool
	trailers      []*pb.HttpHeader
	originTotalUS int64
	close         *pb.ConnectionClose
}

type pendingConnection struct {
	timing       *pb.RequestTiming // Owned only by the HTTP response goroutine.
	events       chan connectionEvent
	done         chan struct{}
	closeOnce    sync.Once
	accessDigest []byte // Immutable after publication; empty for cookie/public connections
}

func newPendingConnection() *pendingConnection {
	return &pendingConnection{
		events: make(chan connectionEvent, 16),
		done:   make(chan struct{}),
	}
}

func (p *pendingConnection) stop() {
	p.closeOnce.Do(func() { close(p.done) })
}

func connectionMessageID(msg *pb.TunnelMessage) (string, connectionEvent) {
	switch message := msg.Message.(type) {
	case *pb.TunnelMessage_ConnectionAccept:
		return message.ConnectionAccept.ConnectionId, connectionEvent{accept: message.ConnectionAccept}
	case *pb.TunnelMessage_ConnectionData:
		return message.ConnectionData.ConnectionId, connectionEvent{data: message.ConnectionData.Data}
	case *pb.TunnelMessage_ConnectionHalfClose:
		return message.ConnectionHalfClose.ConnectionId, connectionEvent{halfClose: true, trailers: message.ConnectionHalfClose.Trailers, originTotalUS: message.ConnectionHalfClose.OriginTotalUs}
	case *pb.TunnelMessage_ConnectionClose:
		return message.ConnectionClose.ConnectionId, connectionEvent{close: message.ConnectionClose}
	default:
		return "", connectionEvent{}
	}
}

func (t *TunnelConnection) addPendingConnection(connectionID string) (*pendingConnection, error) {
	return t.addPendingAuthenticatedConnection(connectionID, nil)
}

func (t *TunnelConnection) addPendingAuthenticatedConnection(connectionID string, digest []byte) (*pendingConnection, error) {
	pending := newPendingConnection()
	pending.accessDigest = append([]byte(nil), digest...)
	// Hold auth through publication so a concurrent rotation cannot miss a
	// socket authorized against the old token immediately before opening.
	t.authMu.RLock()
	defer t.authMu.RUnlock()
	if len(digest) > 0 && !bytes.Equal(digest, t.AccessTokenSHA256) {
		return nil, fmt.Errorf("endpoint token was revoked before upgrade")
	}
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	if t.pendingStreams == nil {
		t.pendingStreams = make(map[string]*pendingConnection)
	}
	if len(t.pendingStreams) >= common.MaxConcurrentConnections {
		return nil, fmt.Errorf("endpoint connection limit reached")
	}
	if _, exists := t.pendingStreams[connectionID]; exists {
		return nil, fmt.Errorf("connection %s is already pending", connectionID)
	}
	t.pendingStreams[connectionID] = pending
	return pending, nil
}

func (t *TunnelConnection) removePendingConnection(connectionID string, pending *pendingConnection) {
	t.pendingMu.Lock()
	if t.pendingStreams[connectionID] == pending {
		delete(t.pendingStreams, connectionID)
	}
	t.pendingMu.Unlock()
	pending.stop()
}

func (t *TunnelConnection) routeConnectionMessage(msg *pb.TunnelMessage) {
	connectionID, event := connectionMessageID(msg)
	if connectionID == "" {
		return
	}

	t.pendingMu.RLock()
	pending := t.pendingStreams[connectionID]
	t.pendingMu.RUnlock()
	if pending == nil {
		return
	}

	select {
	case pending.events <- event:
	case <-pending.done:
	case <-t.Stream.Context().Done():
	}
}

func (t *TunnelConnection) closePendingConnections() {
	t.pendingMu.Lock()
	pending := make([]*pendingConnection, 0, len(t.pendingStreams))
	for connectionID, connection := range t.pendingStreams {
		delete(t.pendingStreams, connectionID)
		pending = append(pending, connection)
	}
	t.pendingMu.Unlock()

	for _, connection := range pending {
		connection.stop()
	}
}

func sendConnectionClose(ctx context.Context, tunnel *TunnelConnection, connectionID, message string) {
	if ctx.Err() != nil {
		return
	}
	cleanup, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	_ = tunnel.SendMessageContext(cleanup, &pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionClose{
			ConnectionClose: &pb.ConnectionClose{
				ConnectionId: connectionID,
				ErrorMessage: message,
			},
		},
	})
}
