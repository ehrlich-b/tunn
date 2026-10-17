// Package inspection shares the bounded metadata and reconstruction policy
// between the local viewer and the authenticated dashboard. It never dials.
package inspection

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	BodyLimit        = 64 * 1024
	EventLimit       = 50
	MetadataLimit    = 16 * 1024
	ReplayInputLimit = 128 * 1024
	Redacted         = "[redacted]"
)

// Event contains bounded, process-local debugging data. Body is only
// retained when explicitly enabled; arbitrary application payloads may be secret.
type Event struct {
	Timing            *Timing           `json:"timing,omitempty"`
	ID                uint64            `json:"id"`
	At                time.Time         `json:"at"`
	ConnectionID      string            `json:"connection_id"`
	Protocol          string            `json:"protocol"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	Headers           map[string]string `json:"headers"`
	Body              []byte            `json:"body,omitempty"`
	BodyCaptured      bool              `json:"body_captured"`
	BodyComplete      bool              `json:"body_complete"`
	QueryRedacted     bool              `json:"query_redacted"`
	RedactedHeaders   []string          `json:"redacted_headers,omitempty"`
	MetadataTruncated bool              `json:"metadata_truncated"`
	RequestBytes      int64             `json:"request_bytes"`
	ResponseBytes     int64             `json:"response_bytes"`
	Status            int               `json:"status"`
	DurationMS        int64             `json:"duration_ms"`
	TerminalReason    string            `json:"terminal_reason"`
	Error             string            `json:"error,omitempty"`
	Truncated         bool              `json:"truncated"`
	Replayable        bool              `json:"replayable"`
	Reconstructable   bool              `json:"reconstructable"`
	ReplayOf          uint64            `json:"replay_of,omitempty"`
}

// Request supplies only data the user deliberately reconstructs.
type Request struct {
	Path    *string           `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *[]byte           `json:"body,omitempty"`
}

func Credential(value string) bool {
	for _, prefix := range []string{"tunn_mcp_", "tunn_ep_", "tunn_gr_", "tunn_sk_", "tunn_app_", "tunn_inv_"} {
		if strings.Contains(value, prefix) {
			return true
		}
	}
	return false
}

func SafeHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Accept", "Accept-Encoding", "Content-Type", "Content-Length", "Host":
		return true
	}
	return false
}

func Path(path string) (string, bool, bool) {
	u, err := url.ParseRequestURI(path)
	if err != nil || Credential(path) || Credential(u.Path) || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u.IsAbs() || u.Fragment != "" || len(path) > 2048 {
		return "[unavailable path]", true, true
	}
	if u.RawQuery == "" {
		return path, false, false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return u.EscapedPath() + "?[unavailable query]", true, true
	}
	for key, values := range query {
		if len(key) > 128 || Credential(key) {
			return u.EscapedPath() + "?[unavailable query]", true, true
		}
		for j := range values {
			values[j] = Redacted
		}
		query[key] = values
	}
	clean := u.EscapedPath() + "?" + query.Encode()
	if len(clean) > MetadataLimit {
		return u.EscapedPath() + "?[unavailable query]", true, true
	}
	return clean, true, false
}

// Metadata discards raw header and query values before returning a snapshot.
func Metadata(id, method, path string, headers map[string]string) Event {
	path, queryRedacted, truncated := Path(path)
	if len(id) > 128 || Credential(id) {
		id = "[unavailable]"
	}
	if len(method) > 32 || Credential(method) {
		method = "[unavailable]"
		truncated = true
	}
	keys := make([]string, 0, min(len(headers), 64))
	if len(headers) > 64 {
		truncated = true
	}
	for key := range headers {
		if len(keys) == 64 {
			break
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	clean := make(map[string]string)
	var removed []string
	budget := len(path)
	for _, key := range keys {
		canonical := strings.Clone(http.CanonicalHeaderKey(key))
		value := headers[key]
		if len(key) > 128 || Credential(key) {
			truncated = true
			continue
		}
		if !SafeHeader(key) || Credential(value) {
			value = Redacted
			removed = append(removed, canonical)
		}
		budget += len(canonical) + len(value)
		if len(key) > 128 || len(value) > 1024 || len(clean) >= 64 || budget > MetadataLimit {
			truncated = true
			continue
		}
		if _, duplicate := clean[canonical]; duplicate {
			truncated = true
		}
		clean[canonical] = strings.Clone(value)
	}
	if len(removed) > 64 {
		removed = removed[:64]
		truncated = true
	}
	return Event{ConnectionID: strings.Clone(id), Method: strings.Clone(method),
		Path: strings.Clone(path), Headers: clean, QueryRedacted: queryRedacted,
		RedactedHeaders: removed, MetadataTruncated: truncated}
}

func Reconstruct(original Event, input Request) (string, map[string]string, []byte, error) {
	// Also validate old metadata: omitting a replacement must not bypass a
	// stricter credential filter introduced since the capture was recorded.
	if _, _, unsafe := Path(original.Path); unsafe {
		return "", nil, nil, errors.New("credential-bearing or unavailable path cannot replay")
	}
	path, headers, body := original.Path, original.Headers, original.Body
	if original.QueryRedacted {
		if input.Path == nil {
			return "", nil, nil, errors.New("reconstruct the request query explicitly")
		}
		clean, masked, bad := Path(*input.Path)
		if bad || !masked || clean != original.Path || strings.Contains(*input.Path, Redacted) || strings.Contains(*input.Path, url.QueryEscape(Redacted)) {
			return "", nil, nil, errors.New("reconstruction must preserve the original path and query fields")
		}
		query, _ := url.ParseQuery(strings.SplitN(*input.Path, "?", 2)[1])
		for _, values := range query {
			for _, value := range values {
				if strings.Contains(value, Redacted) || Credential(value) {
					return "", nil, nil, errors.New("reconstruct every redacted query value")
				}
			}
		}
		path = *input.Path
	} else if input.Path != nil && *input.Path != original.Path {
		return "", nil, nil, errors.New("request path cannot change")
	}
	if len(original.RedactedHeaders) > 0 && input.Headers == nil {
		return "", nil, nil, errors.New("reconstruct redacted headers explicitly")
	}
	if input.Headers != nil {
		headers = make(map[string]string, len(input.Headers))
		for key, value := range input.Headers {
			canonical := http.CanonicalHeaderKey(key)
			if _, exists := headers[canonical]; exists {
				return "", nil, nil, errors.New("duplicate reconstructed header")
			}
			if _, exists := original.Headers[canonical]; !exists || strings.Contains(value, Redacted) || strings.ContainsAny(value, "\r\n") || Credential(value) || len(value) > 1024 {
				return "", nil, nil, errors.New("invalid reconstructed header")
			}
			headers[canonical] = value
		}
		if len(headers) != len(original.Headers) {
			return "", nil, nil, errors.New("reconstruct every original header")
		}
		for key, value := range original.Headers {
			if SafeHeader(key) && headers[key] != value {
				return "", nil, nil, errors.New("captured representation headers cannot change")
			}
		}
	}
	if !original.BodyCaptured && original.RequestBytes > 0 && input.Body == nil {
		return "", nil, nil, errors.New("reconstruct the unavailable request body explicitly")
	}
	if input.Body != nil {
		body = *input.Body
	}
	if input.Body != nil && !original.BodyCaptured && int64(len(body)) != original.RequestBytes {
		return "", nil, nil, errors.New("reconstructed body must match the observed byte count")
	}
	if Credential(string(body)) {
		return "", nil, nil, errors.New("platform credentials cannot be replayed to the application")
	}
	if len(body) > BodyLimit {
		return "", nil, nil, errors.New("reconstructed body exceeds 64 KiB")
	}
	if original.BodyCaptured && input.Body != nil && string(body) != string(original.Body) {
		return "", nil, nil, errors.New("captured body cannot change")
	}
	return path, headers, body, nil
}
