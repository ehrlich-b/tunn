package host

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
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
	return peer, proto
}

func (p *ProxyServer) forwardedHTTPHeaders(r *http.Request) map[string]string {
	headers := p.forwardedRequestHeaders(r.Header)
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "tunn-authorization" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "tunn-relay-") {
			delete(headers, name)
		}
	}
	peer, proto := p.forwardingPeer(r)
	headers["Host"] = r.Host
	headers["X-Forwarded-For"] = peer
	headers["X-Forwarded-Proto"] = proto
	headers["X-Forwarded-Host"] = r.Host
	return headers
}
