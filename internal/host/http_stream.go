package host

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/inspection"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

type requestTimingCaptureKey struct{}

const streamResponseHeaderTimeout = 30 * time.Second

type requestBodyResult struct {
	err error
}

// All streaming upload owners share one close. HTTP/1 Body.Close can wait on
// a concurrent Read's lock and then drain more input, so interrupt the read
// first. HTTP/2 Body.Close already interrupts its stream without affecting the
// connection or response. Preserve HTTP/1 keep-alive when EOF was consumed.
type streamingHTTPRequestBody struct {
	io.ReadCloser
	controller    *http.ResponseController
	interruptRead bool
	sawEOF        atomic.Bool
	closeOnce     sync.Once
	closeErr      error
}

func (b *streamingHTTPRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.sawEOF.Store(true)
	}
	return n, err
}

func (b *streamingHTTPRequestBody) Close() error {
	b.closeOnce.Do(func() {
		if b.interruptRead && !b.sawEOF.Load() {
			_ = b.controller.SetReadDeadline(time.Now())
		}
		b.closeErr = b.ReadCloser.Close()
	})
	return b.closeErr
}

// proxyStreamingHTTPOverGRPC carries HTTP metadata and body chunks on the
// connection-oriented data path. Unlike the legacy path, the response may
// remain open indefinitely for SSE and MCP standalone event streams.
func (p *ProxyServer) proxyStreamingHTTPOverGRPC(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) (resultErr error) {
	started := time.Now()
	timing := &pb.RequestTiming{}
	headers, fields, ok := p.negotiatedRequestHeaders(w, r, tunnel)
	if !ok {
		return nil
	}
	if r.ContentLength > MaxBodySize {
		return &requestBodyTooLargeError{MaxBodySize}
	}
	connectionID, err := requestConnectionID(r)
	if err != nil {
		return fmt.Errorf("failed to generate connection ID: %w", err)
	}

	pending, err := tunnel.addPendingConnection(connectionID)
	if err != nil {
		return err
	}
	pending.timing = timing
	defer tunnel.removePendingConnection(connectionID, pending)
	defer func() {
		var result *pb.RequestTiming
		if resultErr == nil && timing.OriginTotalUs > 0 {
			timing.RelayTotalUs = time.Since(started).Microseconds()
			result = timing
			if capture, ok := r.Context().Value(requestTimingCaptureKey{}).(*inspection.Capture); ok {
				capture.SetTiming(inspection.NewTiming(timing.OriginTtfbUs, timing.OriginTotalUs, timing.RelayTtfbUs, timing.RelayTotalUs))
			}
		}
		cleanup, stop := context.WithTimeout(tunnel.Stream.Context(), 100*time.Millisecond)
		defer stop()
		message := ""
		if resultErr != nil {
			message = "HTTP delivery failed"
		}
		_ = tunnel.SendMessageContext(cleanup, &pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionClose{ConnectionClose: &pb.ConnectionClose{ConnectionId: connectionID, Timing: result, ErrorMessage: message}}})
	}()

	open := &pb.ConnectionOpen{
		ConnectionId:  connectionID,
		RequestTiming: tunnel.Supports(common.CapabilityRequestTimingV1),
		Protocol:      "http",
		SourceAddress: r.RemoteAddr,
		HttpRequest: &pb.HttpRequestHead{
			Method:        r.Method,
			Path:          r.URL.RequestURI(),
			Headers:       headers,
			HeaderFields:  fields,
			ContentLength: r.ContentLength,
		},
	}
	if _, replay := r.Context().Value(inspectorReplayKey{}).(*inspectorReplay); replay {
		open.Protocol = common.HTTPOriginReplayProtocol
	}
	if err := tunnel.SendMessageContext(r.Context(), &pb.TunnelMessage{
		Message: &pb.TunnelMessage_ConnectionOpen{ConnectionOpen: open},
	}); err != nil {
		return fmt.Errorf("failed to open streamed HTTP connection: %w", err)
	}

	if s := meterForRequest(r); s != nil {
		s.event.Forwarded = true
	}
	// The outer proxy cleanup and streamConnectionInput also close this body.
	// Share ownership so none can drain unfinished HTTP/1 input synchronously.
	body := &streamingHTTPRequestBody{ReadCloser: r.Body, controller: http.NewResponseController(w), interruptRead: r.ProtoMajor < 2}
	r.Body = body
	var requestBytes atomic.Int64
	requestResult := make(chan requestBodyResult, 1)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		_, err := streamConnectionInputContext(r.Context(), body, tunnel, connectionID, &requestBytes, MaxBodySize)
		requestResult <- requestBodyResult{err: err}
	}()
	defer func() {
		_ = body.Close()
		select {
		case <-requestDone:
		case <-r.Context().Done():
		}
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
				return &localTargetRejectedError{message: event.accept.ErrorMessage}
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
			timing.OriginTtfbUs = event.accept.HttpResponse.OriginTtfbUs
			timing.OriginTotalUs = event.accept.HttpResponse.OriginTotalUs
			timing.RelayTtfbUs = time.Since(started).Microseconds()
			firstEvent, err := waitStreamingHTTPResponseStart(r, pending, event.accept.HttpResponse, requestResult, &requestFinished, headerTimer.C)
			if err != nil {
				return err
			}
			if err := p.writeStreamingHTTPResponse(w, r, tunnel, pending, event.accept.HttpResponse, &requestBytes, &responseBytes, requestResult, &requestFinished, firstEvent); err != nil {
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

// An empty final success must not conceal an oversized unknown-length upload.
// A 202 acknowledges processing without asserting upload completion; it and
// non-success heads must reach callers that need them to decide how to proceed.
// For other successes, retain at most one event until upload EOF or a nonempty
// response chunk. After headers commit, upload failures abort the response.
func waitStreamingHTTPResponseStart(
	r *http.Request,
	pending *pendingConnection,
	head *pb.HttpResponseHead,
	requestResult <-chan requestBodyResult,
	requestFinished *bool,
	timeout <-chan time.Time,
) (*connectionEvent, error) {
	if *requestFinished {
		return nil, nil
	}
	if r.ContentLength >= 0 || head.StatusCode == http.StatusAccepted || head.StatusCode >= 300 {
		// An upload failure already known before headers still owns the status.
		select {
		case result := <-requestResult:
			*requestFinished = true
			return nil, result.err
		default:
			return nil, nil
		}
	}
	events := pending.events
	if !common.HTTPResponseHasBody(r.Method, int(head.StatusCode)) {
		events = nil
	}
	var firstEvent *connectionEvent
	for {
		select {
		case result := <-requestResult:
			*requestFinished = true
			return firstEvent, result.err
		case event := <-events:
			switch {
			case len(event.data) > 0:
				// Prefer an upload error already available before committing headers.
				select {
				case result := <-requestResult:
					*requestFinished = true
					return &event, result.err
				default:
					return &event, nil
				}
			case event.halfClose:
				firstEvent, events = &event, nil
			case event.close != nil:
				return nil, connectionCloseError(event.close)
			case event.accept != nil:
				return nil, fmt.Errorf("local target sent duplicate HTTP response metadata")
			}
		case <-pending.done:
			return nil, fmt.Errorf("tunnel disconnected before response body")
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for streamed HTTP request or response body")
		}
	}
}

func streamConnectionInput(body io.ReadCloser, tunnel *TunnelConnection, connectionID string, count *atomic.Int64, maxBytes int64) (int64, error) {
	return streamConnectionInputContext(tunnel.Stream.Context(), body, tunnel, connectionID, count, maxBytes)
}
func streamConnectionInputContext(ctx context.Context, body io.ReadCloser, tunnel *TunnelConnection, connectionID string, count *atomic.Int64, maxBytes int64) (int64, error) {
	// The caller owns body cleanup. Closing unfinished HTTP/1 input sets a
	// read deadline and can cancel Request.Context through net/http's read
	// loop. The response owner must receive the upload result first, so that
	// cancellation cannot replace a body-limit error with a generic 502.
	buffer := make([]byte, common.StreamChunkSize)
	for {
		readBuffer := buffer
		if maxBytes > 0 {
			remaining := maxBytes - count.Load() + 1
			if remaining < int64(len(readBuffer)) {
				readBuffer = readBuffer[:remaining]
			}
		}
		n, err := body.Read(readBuffer)
		if n > 0 {
			current := count.Add(int64(n))
			if maxBytes > 0 && current > maxBytes {
				return current, &requestBodyTooLargeError{maxBytes}
			}
			if !tunnel.CheckRateLimit(n) {
				return current, fmt.Errorf("bandwidth rate limit exceeded")
			}
			chunk := append([]byte(nil), buffer[:n]...)
			if sendErr := tunnel.SendMessageContext(ctx, &pb.TunnelMessage{
				Message: &pb.TunnelMessage_ConnectionData{
					ConnectionData: &pb.ConnectionData{ConnectionId: connectionID, Data: chunk},
				},
			}); sendErr != nil {
				return current, fmt.Errorf("failed to stream HTTP request body: %w", sendErr)
			}
		}
		if err == io.EOF {
			if sendErr := tunnel.SendMessageContext(ctx, &pb.TunnelMessage{
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
	firstEvent *connectionEvent,
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
	if body, ok := r.Body.(*streamingHTTPRequestBody); ok && r.ProtoMajor < 2 && r.ContentLength != 0 && !body.sawEOF.Load() {
		// Override upstream connection policy: cleanup may abandon this upload.
		// net/http must not reuse unread body bytes as another request when it
		// resets the read deadline after this handler returns.
		w.Header().Set("Connection", "close")
	}
	if common.HTTPResponseHasBody(r.Method, int(head.StatusCode)) {
		declareResponseTrailers(w.Header(), head.TrailerNames)
	}
	if meterForRequest(r) != nil && r.Method != http.MethodHead && head.StatusCode != 204 && head.StatusCode != 304 {
		// HTTP/1 trailers require chunked framing. The upstream length was already
		// checked, but a concurrent upload/revocation may still terminate egress.
		w.Header().Del("Content-Length")
		w.Header().Add("Trailer", "Tunn-Limit-Reason")
	}
	// HTTP/1 otherwise drains the remaining request body before writing a
	// response, recreating the upload/prefix deadlock at the net/http boundary.
	_ = http.NewResponseController(w).EnableFullDuplex()
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
		var event connectionEvent
		if firstEvent != nil {
			event, firstEvent = *firstEvent, nil
		} else {
			select {
			case event = <-pending.events:
			case result := <-requestResult:
				if !*requestFinished {
					*requestFinished = true
					if result.err != nil {
						return truncatedHTTPResponse(result.err)
					}
				}
				continue
			case <-pending.done:
				return truncatedHTTPResponse(fmt.Errorf("tunnel disconnected during streamed HTTP response"))
			case <-r.Context().Done():
				return truncatedHTTPResponse(r.Context().Err())
			}
		}
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
			if pending.timing != nil && event.originTotalUS > 0 {
				pending.timing.OriginTotalUs = event.originTotalUS
			}
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
	}
}

func connectionCloseError(closed *pb.ConnectionClose) error {
	if closed.ErrorMessage == "" {
		return io.EOF
	}
	return fmt.Errorf("connection closed: %s", closed.ErrorMessage)
}
