package common

import (
	"fmt"
	"net/http"
	"strings"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/net/http/httpguts"
)

// EncodeHTTPRequestHeaders retains field boundaries and a Cookie-safe fallback.
func EncodeHTTPRequestHeaders(header http.Header) (map[string]string, []*pb.HttpHeader) {
	legacy, fields := EncodeHTTPResponseHeaders(header)
	if values := header.Values("Cookie"); len(values) > 0 {
		legacy["Cookie"] = strings.Join(values, "; ")
	}
	return legacy, fields
}

// DecodeHTTPRequestHeaders selects one whole representation, validates singleton
// framing before dispatch, and removes transport-owned and relay credentials.
// length is the envelope's body length, including -1 for a streamed unknown size.
func DecodeHTTPRequestHeaders(legacy map[string]string, fields []*pb.HttpHeader, length int64, websocket bool) (http.Header, error) {
	header := make(http.Header)
	add := func(name, value string) error {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("invalid request header")
		}
		header.Add(name, value)
		return nil
	}
	if len(fields) > 0 {
		for _, field := range fields {
			if field == nil {
				return nil, fmt.Errorf("invalid request header")
			}
			if err := add(field.Name, field.Value); err != nil {
				return nil, err
			}
		}
	} else {
		for name, value := range legacy {
			if err := add(name, value); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range []string{"Host", "Authorization", "Proxy-Authorization", "Content-Length", "Transfer-Encoding", "Expect", "Sec-WebSocket-Key", "Sec-WebSocket-Version"} {
		if len(header.Values(name)) > 1 {
			return nil, fmt.Errorf("repeated singleton request header")
		}
	}
	if length < -1 {
		return nil, fmt.Errorf("invalid request length")
	}
	if len(header.Values("Content-Length")) > 0 {
		n, err := HTTPResponseContentLength(header)
		if err != nil || n != length || len(header.Values("Transfer-Encoding")) > 0 {
			return nil, fmt.Errorf("invalid request framing")
		}
	}
	if values := header.Values("Transfer-Encoding"); len(values) > 0 && !strings.EqualFold(strings.TrimSpace(values[0]), "chunked") {
		return nil, fmt.Errorf("invalid request transfer encoding")
	}
	// Connection-nominated fields must be removed even when absent from the
	// standard hop-by-hop list. WebSocket's two upgrade fields are adapter-owned.
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name == "" || !httpguts.ValidHeaderFieldName(name) {
				return nil, fmt.Errorf("invalid Connection option")
			}
			if !websocket || !strings.EqualFold(name, "Upgrade") {
				header.Del(name)
			}
		}
	}
	for _, name := range []string{"Connection", "Upgrade", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Content-Length", "Tunn-Authorization"} {
		if websocket && (name == "Connection" || name == "Upgrade") {
			continue
		}
		header.Del(name)
	}
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "tunn-relay-") {
			header.Del(name)
		}
	}
	if values := header.Values("Cookie"); len(values) > 0 {
		header.Set("Cookie", strings.Join(values, "; "))
	}
	return header, nil
}
