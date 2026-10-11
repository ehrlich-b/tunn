package host

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func edgeSSHSession(t *testing.T, c *ssh.Client, command string) (*ssh.Session, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	in, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start(command); err != nil {
		t.Fatal(err)
	}
	return session, in, bufio.NewReader(out)
}

func edgeSSHOffline(t *testing.T, p *ProxyServer, name string) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, ok := p.tunnelServer.GetTunnel(name); !ok {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("SSH endpoint %s retained after termination", name)
		}
	}
}

func TestSSHEdgeTerminationAndStdinEOF(t *testing.T) {
	for _, action := range []string{"signal", "control-C", "control-D", "disconnect", "stdin EOF"} {
		t.Run(action, func(t *testing.T) {
			p, c, _ := sshRelay(t, true)
			listener, err := c.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "still online") })}
			go func() { _ = upstream.Serve(listener) }()
			t.Cleanup(func() { _ = upstream.Close() })
			session, in, out := edgeSSHSession(t, c, "--name ssh-control --public")
			if line := sshLine(t, out); line != "https://ssh-control.tunn.test\n" {
				t.Fatal(line)
			}
			switch action {
			case "signal":
				err = session.Signal(ssh.SIGTERM)
			case "control-C":
				_, err = in.Write([]byte{3})
			case "control-D":
				_, err = in.Write([]byte{4})
			case "disconnect":
				err = c.Close()
			case "stdin EOF":
				err = in.Close()
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				p.createHandler().ServeHTTP(rec, httptest.NewRequest("GET", "https://ssh-control.tunn.test/health", nil))
				if rec.Code != 200 || rec.Body.String() != "still online" {
					t.Fatalf("stdin EOF stopped publication: %d %s", rec.Code, rec.Body)
				}
				err = session.Signal(ssh.SIGTERM)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- session.Wait() }()
			select {
			case err := <-done:
				if action != "disconnect" && err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("termination did not finish SSH session")
			}
			edgeSSHOffline(t, p, "ssh-control")
		})
	}
}

func TestSSHEdgeMCPCustomPath(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	observed := make(chan *http.Request, 1)
	session, out := sshForward(t, c, "mcp --name ssh-mcp-path --target http://localhost:3000/internal/mcp?server=1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	if line := sshLine(t, out); line != "https://ssh-mcp-path.tunn.test/mcp\n" {
		t.Fatal(line)
	}
	r := httptest.NewRequest("POST", "https://ssh-mcp-path.tunn.test/mcp?client=2", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+relayJWT(t, p, "owner@example.com"))
	rec := httptest.NewRecorder()
	p.createHandler().ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("MCP forwarding: %d %s", rec.Code, rec.Body)
	}
	select {
	case request := <-observed:
		if request.URL.Path != "/internal/mcp" || request.URL.Query().Get("server") != "1" || request.URL.Query().Get("client") != "2" || request.Method != "POST" {
			t.Fatalf("MCP request rewrite: %s %s", request.Method, request.URL)
		}
	case <-time.After(time.Second):
		t.Fatal("MCP request missed SSH upstream")
	}
	if tunnel, ok := p.tunnelServer.GetTunnel("ssh-mcp-path"); !ok || tunnel.TargetURL != "http" {
		t.Fatal("MCP registration did not redact local target")
	}
	_ = session.Signal(ssh.SIGINT)
	_ = session.Wait()
}

func TestSSHEdgeInvalidPublicationNeverRegisters(t *testing.T) {
	for _, command := range []string{
		"--name ssh-invalid --secret fixture-secret",
		"--name ssh-invalid --tunnel-key fixture-key",
		"--name ssh-invalid --target ftp://localhost:21",
		"--name ssh-invalid --target http://user:pass@localhost:8080",
		"--name ssh-invalid --target http://localhost:8080/#fragment",
		"tcp --name ssh-invalid --public",
		"tcp --name ssh-invalid --target http://localhost:8080",
		"unix --name ssh-invalid --as http --public",
		"mcp --name ssh-invalid --tools read_file",
	} {
		t.Run(command, func(t *testing.T) {
			p, c, _ := sshRelay(t, true)
			session, out := sshForward(t, c, command, http.NotFoundHandler())
			line := sshLine(t, out)
			if strings.HasPrefix(line, "https://") || strings.TrimSpace(line) == "" {
				t.Fatalf("invalid command published or lacked error: %q", line)
			}
			if err := session.Wait(); err == nil {
				t.Fatal("invalid publication returned successful exit status")
			}
			if _, ok := p.tunnelServer.GetTunnel("ssh-invalid"); ok {
				t.Fatal("invalid publication retained an endpoint")
			}
		})
	}
}

func TestSSHEdgeIndependentNamedForwards(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	channels := c.HandleChannelOpen("forwarded-tcpip")
	go func() {
		for incoming := range channels {
			go func(incoming ssh.NewChannel) {
				var destination struct {
					Address    string
					Port       uint32
					Origin     string
					OriginPort uint32
				}
				if err := ssh.Unmarshal(incoming.ExtraData(), &destination); err != nil {
					t.Error(err)
					return
				}
				channel, requests, err := incoming.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				defer channel.Close()
				go ssh.DiscardRequests(requests)
				request, err := http.ReadRequest(bufio.NewReader(channel))
				if err != nil {
					t.Error(err)
					return
				}
				_ = request.Body.Close()
				body := destination.Address + request.URL.Path
				_, _ = fmt.Fprintf(channel, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(incoming)
		}
	}()
	for _, name := range []string{"ssh-left", "ssh-right"} {
		ok, _, err := c.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
			Address string
			Port    uint32
		}{name, 80}))
		if !ok || err != nil {
			t.Fatalf("forward %s: %v %v", name, ok, err)
		}
	}
	session, _, out := edgeSSHSession(t, c, "--public")
	urls := make(map[string]bool)
	for lines := 0; lines < 8 && len(urls) < 2; lines++ {
		if line := sshLine(t, out); strings.HasPrefix(line, "https://") {
			urls[line] = true
		}
	}
	for _, name := range []string{"ssh-left", "ssh-right"} {
		if !urls["https://"+name+".tunn.test\n"] {
			t.Fatalf("missing named URL: %v", urls)
		}
	}
	request := func(name string) {
		t.Helper()
		rec := httptest.NewRecorder()
		p.createHandler().ServeHTTP(rec, httptest.NewRequest("GET", "https://"+name+".tunn.test/probe", nil))
		if rec.Code != 200 || rec.Body.String() != name+"/probe" {
			t.Fatalf("named route %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	request("ssh-left")
	request("ssh-right")
	ok, _, err := c.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(struct {
		Address string
		Port    uint32
	}{"ssh-left", 80}))
	if !ok || err != nil {
		t.Fatalf("cancel left: %v %v", ok, err)
	}
	if _, online := p.tunnelServer.GetTunnel("ssh-left"); online {
		t.Fatal("cancelled named endpoint remains online")
	}
	request("ssh-right")
	_ = session.Signal(ssh.SIGINT)
	_ = session.Wait()
	edgeSSHOffline(t, p, "ssh-right")
}
