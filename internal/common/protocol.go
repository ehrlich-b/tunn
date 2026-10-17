package common

const (
	// CapabilityHTTPStreamV1 enables the connection-oriented HTTP data path.
	// Clients that omit it remain compatible with relays using buffered
	// HttpRequest and HttpResponse messages.
	CapabilityHTTPStreamV1           = "http-stream-v1"
	CapabilityRequestTimingV1        = "request-timing-v1"
	CapabilityConnectionStreamV1     = "connection-stream-v1"
	CapabilityWebSocketV1            = "websocket-v1"
	CapabilityHTTPResponseTrailersV1 = "http-response-trailers-v1"

	// CapabilityHTTPRequestHeadersV1 retains application request field boundaries.
	CapabilityHTTPRequestHeadersV1 = "http-request-headers-v1"

	// HTTP replay is separately negotiated: it uses the existing streamed
	// envelope but the publisher must never follow an origin redirect.
	CapabilityHTTPOriginReplayV1 = "http-origin-replay-v1"
	HTTPOriginReplayProtocol     = "http-replay"

	TCPConnectPath   = "/_tunn/connect"
	TCPConnectHeader = "Tunn-Protocol"
	TCPConnectValue  = "tcp/1"

	// StreamChunkSize keeps individual protobuf messages comfortably below
	// gRPC's default message limit while providing useful flow-control points.
	StreamChunkSize = 32 * 1024

	// MaxConcurrentConnections bounds logical streaming connections per
	// endpoint on both sides of the tunnel.
	MaxConcurrentConnections = 100
)
