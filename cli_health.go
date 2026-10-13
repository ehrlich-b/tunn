package main

import (
	"context"
	"crypto/tls"
	"github.com/ehrlich-b/tunn/internal/client"
	"net"
	"net/http"
	"time"
)

// A HEAD request checks HTTP readiness without submitting application data.
func probeLocalApp(ctx context.Context, s *client.ServeClient) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	dial := s.LocalDialContext
	if dial == nil {
		dial = s.DialContext
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: s.SkipLocalTLSVerify}, ForceAttemptHTTP2: true}
	if s.LocalTLSConfig != nil {
		transport.TLSClientConfig = s.LocalTLSConfig.Clone()
	}
	if s.TargetNetwork == "unix" {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.DialAddress)
		}
	}
	defer transport.CloseIdleConnections()
	var rt http.RoundTripper = transport
	if s.HTTPTransport != nil {
		rt = s.HTTPTransport
	}
	h := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.TargetURL, nil)
	if err != nil {
		return err
	}
	response, err := h.Do(req)
	if err != nil {
		return err
	}
	return response.Body.Close()
}
