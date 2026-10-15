package host

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

const relayForwardedFor = "Tunn-Relay-For"
const relayForwardedProto = "Tunn-Relay-Proto"
const relayForwardedSignature = "Tunn-Relay-Signature"

func (p *ProxyServer) forwardingSignature(host, peer, proto string) string {
	if p.config == nil || p.config.NodeSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(p.config.NodeSecret))
	_, _ = mac.Write([]byte(host + "\n" + peer + "\n" + proto))
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *ProxyServer) forwardingPeer(r *http.Request) (peer, proto string) {
	peer = r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	if addr, err := netip.ParseAddr(peer); err == nil {
		// A local interface zone is not part of a client's network address and
		// must not invalidate signed metadata at the next relay.
		peer = addr.WithZone("").String()
	}
	proto = "http"
	if r.TLS != nil {
		proto = "https"
	}
	// Only a relay possessing the cluster secret can preserve the first hop's
	// metadata. Public X-Forwarded-* and Forwarded headers are never trusted.
	forwardedPeer, forwardedProto := r.Header.Get(relayForwardedFor), r.Header.Get(relayForwardedProto)
	expected := p.forwardingSignature(r.Host, forwardedPeer, forwardedProto)
	if expected != "" && net.ParseIP(forwardedPeer) != nil && (forwardedProto == "http" || forwardedProto == "https") &&
		hmac.Equal([]byte(expected), []byte(r.Header.Get(relayForwardedSignature))) {
		peer, proto = forwardedPeer, forwardedProto
	}
	if ip := net.ParseIP(peer); ip != nil {
		peer = ip.String()
	}
	return peer, proto
}

func (p *ProxyServer) forwardedHTTPHeaderValues(r *http.Request) http.Header {
	headers := p.forwardedApplicationHeaders(r.Header)
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "tunn-authorization" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "tunn-relay-") {
			delete(headers, name)
		}
	}
	peer, proto := p.forwardingPeer(r)
	headers.Set("Host", r.Host)
	headers.Set("X-Forwarded-For", peer)
	headers.Set("X-Forwarded-Proto", proto)
	headers.Set("X-Forwarded-Host", r.Host)
	return headers
}

func (p *ProxyServer) forwardedHTTPHeaders(r *http.Request) map[string]string {
	legacy, _ := common.EncodeHTTPRequestHeaders(p.forwardedHTTPHeaderValues(r))
	return legacy
}

func (p *ProxyServer) forwardedApplicationHeaders(source http.Header) http.Header {
	headers := make(http.Header, len(source))
	for name, values := range source {
		if strings.EqualFold(name, "Tunn-Authorization") {
			continue
		}
		for _, value := range values {
			if strings.EqualFold(name, "Authorization") && p.isPlatformAuthorization(value) {
				continue
			}
			headers.Add(name, value)
		}
	}
	if values := headers.Values("Cookie"); len(values) > 0 {
		value := stripPlatformCookies(strings.Join(values, "; "))
		headers.Del("Cookie")
		if value != "" {
			headers.Set("Cookie", value)
		}
	}
	return headers
}

// Prepare both wire representations from the same sanitized request. Old
// publishers retain their historical comma-joined map contract; only capable
// publishers receive individual fields. Never expand a legacy joined value.
func (p *ProxyServer) negotiatedRequestHeaders(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) (map[string]string, []*pb.HttpHeader, bool) {
	_, raw := common.EncodeHTTPRequestHeaders(p.forwardedApplicationHeaders(r.Header))
	if _, err := common.DecodeHTTPRequestHeaders(nil, raw, r.ContentLength, common.IsWebSocketUpgrade(r.Header)); err != nil {
		http.Error(w, "Invalid request headers", http.StatusBadRequest)
		return nil, nil, false
	}
	legacy, fields := common.EncodeHTTPRequestHeaders(p.forwardedHTTPHeaderValues(r))
	headers, err := common.DecodeHTTPRequestHeaders(legacy, fields, r.ContentLength, common.IsWebSocketUpgrade(r.Header))
	if err != nil {
		http.Error(w, "Invalid request headers", http.StatusBadRequest)
		return nil, nil, false
	}
	legacy, fields = common.EncodeHTTPRequestHeaders(headers)
	if !tunnel.Supports(common.CapabilityHTTPRequestHeadersV1) {
		fields = nil
	}
	return legacy, fields, true
}
