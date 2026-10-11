package host

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

const streamResponseHeaderTimeout = 30 * time.Second

type requestBodyResult struct {
	err error
}

// proxyStreamingHTTPOverGRPC carries HTTP metadata and body chunks on the
// connection-oriented data path. Unlike the legacy path, the response may
// remain open indefinitely for SSE and MCP standalone event streams.
func (p *ProxyServer) proxyStreamingHTTPOverGRPC(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) error {
	connectionID, err := requestConnectionID(r)
	if err != nil {
		return fmt.Errorf("failed to generate connection ID: %w", err)
	}

	pending, err := tunnel.addPendingConnection(connectionID)
	if err != nil {
		return err
	}
	defer tunnel.removePendingConnection(connectionID, pending)
	defer sendConnectionClose(tunnel.Stream.Context(), tunnel, connectionID, "")

	open := &pb.ConnectionOpen{
		ConnectionId:  connectionID,
		Protocol:      "http",
		SourceAddress: r.RemoteAddr,
		HttpRequest: &pb.HttpRequestHead{
			Method:        r.Method,
			Path:          r.URL.RequestURI(),
			Headers:       p.forwardedHTTPHeaders(r),
			ContentLength: r.ContentLength,
		},
	}
	if err := tunnel.SendMessage(&pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: open},
	}); err != nil {
		return fmt.Errorf("failed to open streamed HTTP connection: %w", err)
	}

	if s := meterForRequest(r); s != nil {
		s.event.Forwarded = true
	}
	defer func() { _ = r.Body.Close() }()
	var requestBytes atomic.Int64
	requestResult := make(chan requestBodyResult, 1)
	go func() {
		_, err := streamConnectionInput(r.Body, tunnel, connectionID, &requestBytes, MaxBodySize)
		requestResult <- requestBodyResult{err: err}
	}()

	headerTimer := time.NewTimer(streamResponseHeaderTimeout)
	defer headerTimer.Stop()

	var responseBytes int64
	requestFinished := false
	for {
		select {
		case event := <-pending.events:
			if event.accept == nil {
				if event.close != nil {
					return connectionCloseError(event.close)
				}
				return fmt.Errorf("streamed HTTP response data arrived before response metadata")
			}
			if !event.accept.Success {
				return fmt.Errorf("local target rejected connection: %s", event.accept.ErrorMessage)
			}
			if event.accept.HttpResponse == nil {
				return fmt.Errorf("streamed HTTP response has no metadata")
			}
			if event.accept.HttpResponse.StatusCode < 200 || event.accept.HttpResponse.StatusCode > 599 {
				return fmt.Errorf("local target returned invalid HTTP status %d", event.accept.HttpResponse.StatusCode)
			}
			if err := validateResponseTrailers(tunnel, event.accept.HttpResponse.TrailerNames, nil); err != nil {
				return err
			}
			var responseSize int64
			if common.HTTPResponseHasBody(r.Method, int(event.accept.HttpResponse.StatusCode)) {
				length, err := common.HTTPResponseContentLength(common.DecodeHTTPResponseHeaders(event.accept.HttpResponse.Headers, event.accept.HttpResponse.HeaderFields))
				if err != nil {
					return err
				}
				if length >= 0 {
					responseSize = length
				}
			}
			if err := checkMeteredResponse(r, responseSize); err != nil {
				return err
			}
			if err := p.writeStreamingHTTPResponse(w, r, tunnel, pending, event.accept.HttpResponse, &requestBytes, &responseBytes, requestResult, &requestFinished); err != nil {
				return &responseStartedError{err: err}
			}
			return nil

		case result := <-requestResult:
			requestFinished = true
			if result.err != nil {
				return result.err
			}

		case <-pending.done:
			return fmt.Errorf("tunnel disconnected before response metadata")
		case <-r.Context().Done():
			return r.Context().Err()
		case <-headerTimer.C:
			return fmt.Errorf("timeout waiting for streamed HTTP response headers")
		}
	}
}

func streamConnectionInput(body io.ReadCloser, tunnel *TunnelConnection, connectionID string, count *atomic.Int64, maxBytes int64) (int64, error) {
	defer func() { _ = body.Close() }()
	buffer := make([]byte, common.StreamChunkSize)
	for {
		n, err := body.Read(buffer)
		if n > 0 {
			current := count.Add(int64(n))
			if maxBytes > 0 && current > maxBytes {
				return current, fmt.Errorf("request body too large (max %d bytes)", maxBytes)
			}
			if !tunnel.CheckRateLimit(n) {
				return current, fmt.Errorf("bandwidth rate limit exceeded")
			}
			chunk := append([]byte(nil), buffer[:n]...)
			if sendErr := tunnel.SendMessage(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionData{
					ConnectionData: &pb.ConnectionData{ConnectionId: connectionID, Data: chunk},
				},
			}); sendErr != nil {
				return current, fmt.Errorf("failed to stream HTTP request body: %w", sendErr)
			}
		}
		if err == io.EOF {
			if sendErr := tunnel.SendMessage(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionHalfClose{
					ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: connectionID},
				},
			}); sendErr != nil {
				return count.Load(), fmt.Errorf("failed to half-close HTTP request: %w", sendErr)
			}
			return count.Load(), nil
		}
		if err != nil {
			return count.Load(), fmt.Errorf("failed to read HTTP request body: %w", err)
		}
	}
}

func (p *ProxyServer) writeStreamingHTTPResponse(
	w http.ResponseWriter,
	r *http.Request,
	tunnel *TunnelConnection,
	pending *pendingConnection,
	head *pb.HttpResponseHead,
	requestBytes *atomic.Int64,
	responseBytes *int64,
	requestResult <-chan requestBodyResult,
	requestFinished *bool,
) error {
	expected := int64(-1)
	if common.HTTPResponseHasBody(r.Method, int(head.StatusCode)) {
		var err error
		expected, err = common.HTTPResponseContentLength(common.DecodeHTTPResponseHeaders(head.Headers, head.HeaderFields))
		if err != nil {
			return err
		}
	}
	copyApplicationResponseHeaderFields(w.Header(), head.Headers, head.HeaderFields)
	if common.HTTPResponseHasBody(r.Method, int(head.StatusCode)) {
		declareResponseTrailers(w.Header(), head.TrailerNames)
	}
	if meterForRequest(r) != nil && r.Method != http.MethodHead && head.StatusCode != 204 && head.StatusCode != 304 {
		// HTTP/1 trailers require chunked framing. The upstream length was already
		// checked, but a concurrent upload/revocation may still terminate egress.
		w.Header().Del("Content-Length")
		w.Header().Add("Trailer", "Tunn-Limit-Reason")
	}
	w.WriteHeader(int(head.StatusCode))
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	defer func() {
		if tunnel.AccountID != "" && meterForRequest(r) == nil {
			p.RecordUsage(r.Context(), tunnel.AccountID, requestBytes.Load()+*responseBytes)
		}
	}()

	if !common.HTTPResponseHasBody(r.Method, int(head.StatusCode)) {
		return nil
	}
	for {
		select {
		case event := <-pending.events:
			switch {
			case event.data != nil:
				if expected >= 0 && *responseBytes+int64(len(event.data)) > expected {
					return truncatedHTTPResponse(fmt.Errorf("response exceeds Content-Length"))
				}
				if !tunnel.CheckRateLimit(len(event.data)) {
					return fmt.Errorf("bandwidth rate limit exceeded")
				}
				*responseBytes += int64(len(event.data))
				if _, err := w.Write(event.data); err != nil {
					return fmt.Errorf("failed to write streamed HTTP response: %w", err)
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			case event.halfClose:
				if err := validateResponseTrailers(tunnel, head.TrailerNames, event.trailers); err != nil {
					return truncatedHTTPResponse(err)
				}
				if expected >= 0 && *responseBytes != expected {
					return truncatedHTTPResponse(io.ErrUnexpectedEOF)
				}
				writeResponseTrailers(w.Header(), event.trailers)
				return nil
			case event.close != nil:
				if event.close.ErrorMessage == "" {
					return truncatedHTTPResponse(io.ErrUnexpectedEOF)
				}
				return truncatedHTTPResponse(connectionCloseError(event.close))
			case event.accept != nil:
				return truncatedHTTPResponse(fmt.Errorf("local target sent duplicate HTTP response metadata"))
			}

		case result := <-requestResult:
			if !*requestFinished {
				*requestFinished = true
				if result.err != nil {
					return result.err
				}
			}
		case <-pending.done:
			return truncatedHTTPResponse(fmt.Errorf("tunnel disconnected during streamed HTTP response"))
		case <-r.Context().Done():
			return r.Context().Err()
		}
	}
}

func connectionCloseError(closed *pb.ConnectionClose) error {
	if closed.ErrorMessage == "" {
		return io.EOF
	}
	return fmt.Errorf("connection closed: %s", closed.ErrorMessage)
}
