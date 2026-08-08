package host

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func (p *ProxyServer) proxyTCPOverGRPC(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) error {
	connectionID, err := generateConnectionID()
	if err != nil {
		return fmt.Errorf("failed to generate connection ID: %w", err)
	}
	pending, err := tunnel.addPendingConnection(connectionID)
	if err != nil {
		return err
	}
	defer tunnel.removePendingConnection(connectionID, pending)
	defer sendConnectionClose(r.Context(), tunnel, connectionID, "")

	// HTTP/1 servers otherwise may consume the entire request body before they
	// permit response writes. CONNECT needs both directions concurrently.
	_ = http.NewResponseController(w).EnableFullDuplex()

	if err := tunnel.SendMessage(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionOpen{
			ConnectionOpen: &pb.ConnectionOpen{
				ConnectionId:  connectionID,
				Protocol:      "tcp",
				SourceAddress: r.RemoteAddr,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to open TCP connection: %w", err)
	}

	var requestBytes atomic.Int64
	requestResult := make(chan requestBodyResult, 1)
	go func() {
		_, err := streamConnectionInput(r.Body, tunnel, connectionID, &requestBytes, 0)
		requestResult <- requestBodyResult{err: err}
	}()

	timer := time.NewTimer(streamResponseHeaderTimeout)
	defer timer.Stop()
	for {
		select {
		case event := <-pending.events:
			if event.accept == nil {
				if event.close != nil {
					return connectionCloseError(event.close)
				}
				return fmt.Errorf("TCP data arrived before connection acceptance")
			}
			if !event.accept.Success {
				return fmt.Errorf("local TCP target rejected connection: %s", event.accept.ErrorMessage)
			}
			return p.writeTCPStream(w, r, tunnel, pending, &requestBytes, requestResult)

		case result := <-requestResult:
			if result.err != nil {
				return result.err
			}
		case <-pending.done:
			return fmt.Errorf("tunnel disconnected before TCP connection acceptance")
		case <-r.Context().Done():
			return r.Context().Err()
		case <-timer.C:
			return fmt.Errorf("timeout waiting for local TCP connection")
		}
	}
}

func (p *ProxyServer) writeTCPStream(
	w http.ResponseWriter,
	r *http.Request,
	tunnel *TunnelConnection,
	pending *pendingConnection,
	requestBytes *atomic.Int64,
	requestResult <-chan requestBodyResult,
) error {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	var responseBytes int64
	defer func() {
		if tunnel.AccountID != "" {
			p.RecordUsage(r.Context(), tunnel.AccountID, requestBytes.Load()+responseBytes)
		}
	}()

	for {
		select {
		case event := <-pending.events:
			switch {
			case event.data != nil:
				if !tunnel.CheckRateLimit(len(event.data)) {
					return &responseStartedError{err: fmt.Errorf("bandwidth rate limit exceeded")}
				}
				responseBytes += int64(len(event.data))
				if _, err := w.Write(event.data); err != nil {
					return &responseStartedError{err: fmt.Errorf("write TCP response: %w", err)}
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			case event.halfClose:
				return nil
			case event.close != nil:
				if event.close.ErrorMessage == "" {
					return nil
				}
				return &responseStartedError{err: connectionCloseError(event.close)}
			case event.accept != nil:
				return &responseStartedError{err: fmt.Errorf("duplicate TCP connection acceptance")}
			}

		case result := <-requestResult:
			if result.err != nil {
				return &responseStartedError{err: result.err}
			}
			requestResult = nil
		case <-pending.done:
			return &responseStartedError{err: fmt.Errorf("tunnel disconnected during TCP stream")}
		case <-r.Context().Done():
			return &responseStartedError{err: r.Context().Err()}
		}
	}
}
