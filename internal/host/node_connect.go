package host

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func removeRelayHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}

type relayFlushWriter struct{ http.ResponseWriter }

func (w relayFlushWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}

// ReverseProxy rejects CONNECT. HTTP/2 RoundTrip keeps the request upload and
// response download independent, retaining backpressure and cancellation.
func (p *ProxyServer) proxyConnectToNode(w http.ResponseWriter, r *http.Request, target *url.URL, peer, proto, tunnelID string) {
	_ = http.NewResponseController(w).EnableFullDuplex()
	req := r.Clone(r.Context())
	req.URL.Scheme, req.URL.Host = target.Scheme, target.Host
	req.RequestURI = ""
	removeRelayHopHeaders(req.Header)
	req.Header.Set(relayForwardedFor, peer)
	req.Header.Set(relayForwardedProto, proto)
	req.Header.Set(relayForwardedSignature, p.forwardingSignature(r.Host, peer, proto))
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: p.config.Insecure}, ForceAttemptHTTP2: true, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, "Relay connection unavailable", http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 503 {
		p.cacheMu.Lock()
		delete(p.tunnelCache, tunnelID)
		p.cacheMu.Unlock()
	}
	if response.StatusCode == 200 && response.ProtoMajor != 2 {
		http.Error(w, "Relay connection requires HTTP/2", http.StatusServiceUnavailable)
		return
	}
	removeRelayHopHeaders(response.Header)
	for name, values := range response.Header {
		w.Header()[name] = values
	}
	for name := range response.Trailer {
		w.Header().Add("Trailer", name)
	}
	w.WriteHeader(response.StatusCode)
	_ = http.NewResponseController(w).Flush()
	if _, err = io.Copy(relayFlushWriter{w}, response.Body); err != nil {
		panic(http.ErrAbortHandler)
	}
	for name, values := range response.Trailer {
		if len(values) > 0 {
			w.Header()[name] = values
		}
	}
}
