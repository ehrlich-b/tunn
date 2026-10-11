package relaytransport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(key, "")
	}
}

func TestProxyEnvironment(t *testing.T) {
	for _, test := range []struct {
		name, target, want string
		env                map[string]string
	}{
		{"HTTPS", "https://relay.invalid", "http://secure.invalid:8080", map[string]string{"HTTPS_PROXY": "http://secure.invalid:8080", "ALL_PROXY": "http://fallback.invalid:8080"}},
		{"HTTP", "http://relay.invalid", "http://plain.invalid:8080", map[string]string{"HTTP_PROXY": "http://plain.invalid:8080"}},
		{"ALL fallback", "https://relay.invalid", "socks5h://socks.invalid:1080", map[string]string{"ALL_PROXY": "socks5h://socks.invalid:1080"}},
		{"lowercase", "https://relay.invalid", "http://fallback.invalid:8080", map[string]string{"all_proxy": "http://fallback.invalid:8080"}},
		{"lowercase HTTPS", "https://relay.invalid", "http://secure.invalid:8080", map[string]string{"https_proxy": "http://secure.invalid:8080"}},
		{"NO_PROXY", "https://relay.invalid", "", map[string]string{"ALL_PROXY": "http://fallback.invalid:8080", "NO_PROXY": ".invalid"}},
		{"CIDR bypass", "https://192.0.2.1", "", map[string]string{"HTTPS_PROXY": "http://secure.invalid:8080", "no_proxy": "192.0.2.0/24"}},
		{"loopback bypass", "https://127.0.0.1:443", "", map[string]string{"ALL_PROXY": "http://fallback.invalid:8080"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearProxyEnv(t)
			for key, value := range test.env {
				t.Setenv(key, value)
			}
			u, _ := url.Parse(test.target)
			got, err := ProxyFromEnvironment(&http.Request{URL: u})
			if err != nil {
				t.Fatal(err)
			}
			value := ""
			if got != nil {
				value = got.String()
			}
			if value != test.want {
				t.Fatalf("proxy = %q, want %q", value, test.want)
			}
		})
	}
}

func TestProxyCONNECTDial(t *testing.T) {
	for _, status := range []int{200, 407} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			clearProxyEnv(t)
			t.Setenv("ALL_PROXY", "http://fixture:password@proxy.invalid:8080")
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			received := make(chan *http.Request, 1)
			go func() {
				req, err := http.ReadRequest(bufio.NewReader(remote))
				if err == nil {
					received <- req
					_, _ = fmt.Fprintf(remote, "HTTP/1.1 %d fixture\r\n\r\nhello", status)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := dialContext(ctx, "tcp", "relay.invalid:443", func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "proxy.invalid:8080" {
					t.Errorf("dial = %s %s; must only dial the proxy", network, address)
				}
				return local, nil
			})
			if status != 200 {
				if err == nil || !strings.Contains(err.Error(), "407") || strings.Contains(err.Error(), "password") {
					t.Fatalf("CONNECT error = %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				data := make([]byte, 5)
				if _, err := io.ReadFull(conn, data); err != nil || string(data) != "hello" {
					t.Fatalf("buffered tunnel bytes = %q, %v", data, err)
				}
			}
			select {
			case req := <-received:
				wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture:password"))
				if req.Method != "CONNECT" || req.Host != "relay.invalid:443" || req.Header.Get("Proxy-Authorization") != wantAuth {
					t.Fatalf("CONNECT request = %+v", req)
				}
			case <-ctx.Done():
				t.Fatal("proxy did not receive CONNECT")
			}
		})
	}
}

func TestProxyCONNECTCancellation(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
	local, remote := net.Pipe()
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(remote))
		cancel() // Cancel while the client awaits the proxy's CONNECT response.
	}()
	_, err := dialContext(ctx, "tcp", "relay.invalid:443", func(context.Context, string, string) (net.Conn, error) { return local, nil })
	if err == nil || ctx.Err() == nil {
		t.Fatalf("stalled CONNECT ignored cancellation: %v", err)
	}
}

func TestProxySOCKSRemoteDNS(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			clearProxyEnv(t)
			t.Setenv("ALL_PROXY", scheme+"://proxy.invalid:1080")
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			target := make(chan string, 1)
			go func() {
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(remote, greeting); err != nil {
					return
				}
				_, _ = remote.Write([]byte{5, 0})
				head := make([]byte, 5)
				if _, err := io.ReadFull(remote, head); err != nil {
					return
				}
				if head[3] != 3 {
					target <- "not a domain"
					return
				}
				name := make([]byte, int(head[4])+2)
				if _, err := io.ReadFull(remote, name); err != nil {
					return
				}
				target <- fmt.Sprintf("%s:%d", name[:len(name)-2], int(name[len(name)-2])*256+int(name[len(name)-1]))
				_, _ = remote.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := dialContext(ctx, "tcp", "unresolvable.invalid:443", func(_ context.Context, _, address string) (net.Conn, error) {
				if address != "proxy.invalid:1080" {
					t.Errorf("direct relay dial: %s", address)
				}
				return local, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			select {
			case got := <-target:
				if got != "unresolvable.invalid:443" {
					t.Fatalf("SOCKS target = %q", got)
				}
			case <-ctx.Done():
				t.Fatal("SOCKS proxy never received the hostname")
			}
		})
	}
}
