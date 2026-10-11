package host

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHEdgeLocalHTTPSVerificationFlag(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run("skip="+strconv.FormatBool(skip), func(t *testing.T) {
			p, c, _ := sshRelay(t, true)
			listener, err := c.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			certFile, keyFile, _ := edgeTLSFiles(t)
			certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			upstream := &http.Server{ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.TLS == nil || r.URL.Path != "/probe" {
					t.Error("SSH HTTPS target lost TLS or request path")
				}
				_, _ = io.WriteString(w, "local HTTPS reached")
			})}
			go func() {
				_ = upstream.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}}))
			}()
			t.Cleanup(func() { _ = upstream.Close() })
			session, _, out := edgeSSHSession(t, c, "--name ssh-local-https --public --target https://localhost:8443 --skip-local-tls-verify="+strconv.FormatBool(skip))
			if line := sshLine(t, out); line != "https://ssh-local-https.tunn.test\n" {
				t.Fatal(line)
			}
			rec := httptest.NewRecorder()
			p.createHandler().ServeHTTP(rec, httptest.NewRequest("GET", "https://ssh-local-https.tunn.test/probe", nil))
			if skip {
				if rec.Code != 200 || rec.Body.String() != "local HTTPS reached" || calls.Load() != 1 {
					t.Fatalf("explicit TLS bypass: %d %s calls=%d", rec.Code, rec.Body, calls.Load())
				}
			} else if rec.Code != 502 || calls.Load() != 0 {
				t.Fatalf("untrusted local HTTPS accepted: %d %s calls=%d", rec.Code, rec.Body, calls.Load())
			}
			_ = session.Signal(ssh.SIGINT)
			_ = session.Wait()
		})
	}
}

func TestSSHEdgeRequiresApplicationAuthorization(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	observed := make(chan string, 1)
	session, out := sshForward(t, c, "--name ssh-upstream-auth --require-upstream-auth", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "application authorized")
	}))
	if line := sshLine(t, out); line != "https://ssh-upstream-auth.tunn.test\n" {
		t.Fatal(line)
	}
	for _, application := range []string{"", "Bearer app-fixture-token"} {
		r := httptest.NewRequest("GET", "https://ssh-upstream-auth.tunn.test/", nil)
		r.Header.Set("Tunn-Authorization", "Bearer "+relayJWT(t, p, "owner@example.com"))
		if application != "" {
			r.Header.Set("Authorization", application)
		}
		rec := httptest.NewRecorder()
		p.createHandler().ServeHTTP(rec, r)
		if application == "" {
			if rec.Code != 401 {
				t.Fatalf("missing application auth: %d %s", rec.Code, rec.Body)
			}
			select {
			case <-observed:
				t.Fatal("request missing app authorization reached target")
			default:
			}
		} else {
			if rec.Code != 200 || rec.Body.String() != "application authorized" {
				t.Fatalf("application auth: %d %s", rec.Code, rec.Body)
			}
			select {
			case value := <-observed:
				if value != application {
					t.Fatalf("app authorization changed: %q", value)
				}
			case <-time.After(time.Second):
				t.Fatal("application auth did not reach target")
			}
		}
	}
	_ = session.Signal(ssh.SIGINT)
	_ = session.Wait()
}
