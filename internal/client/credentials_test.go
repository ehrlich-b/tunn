package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func credentialFixture(t *testing.T) (*CredentialManager, *savedCredentials) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	state := &savedCredentials{Server: "https://relay.test", Access: "old-access", Refresh: "tunn_rt_old-secret", Device: "dev_fixture", Expires: time.Now().Add(5 * time.Minute)}
	path := filepath.Join(dir, credentialsFilename)
	if err := saveCredentialState(path, state); err != nil {
		t.Fatal(err)
	}
	return &CredentialManager{ServerAddr: state.Server, path: path}, state
}
func refreshFixtureResponse(r *http.Request, access, refresh string) *http.Response {
	body := fmt.Sprintf(`{"access_token":%q,"refresh_token":%q,"device_id":"dev_fixture","expires_in":300}`, access, refresh)
	return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func TestDurableClientExpirySkewAtomicAndConcurrentRefresh(t *testing.T) {
	m, state := credentialFixture(t)
	now := time.Unix(500000000, 0)
	m.now = func() time.Time { return now }
	state.Expires = now.Add(300 * time.Second)
	if err := saveCredentialState(m.path, state); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	transport := meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != "https://relay.test/api/device/refresh" || r.Method != "POST" {
			t.Error("unexpected refresh target")
		}
		var input map[string]string
		_ = json.NewDecoder(r.Body).Decode(&input)
		if input["refresh_token"] != state.Refresh || len(input["request_id"]) != 43 {
			t.Error("missing refresh binding")
		}
		return refreshFixtureResponse(r, "new-access-with-different-server-clock", "tunn_rt_new-secret"), nil
	})
	m.HTTPClient = &http.Client{Transport: transport}
	second := &CredentialManager{ServerAddr: m.ServerAddr, path: m.path, HTTPClient: m.HTTPClient, now: m.now}
	for _, manager := range []*CredentialManager{m, second} {
		token, err := manager.Token(context.Background(), false)
		if err != nil || token != state.Access {
			t.Fatal(token, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("refreshed too early")
	}
	now = now.Add(240 * time.Second)
	var workers sync.WaitGroup
	for _, manager := range []*CredentialManager{m, second} {
		workers.Add(1)
		go func(manager *CredentialManager) {
			defer workers.Done()
			token, err := manager.Token(context.Background(), true)
			if err != nil || token != "new-access-with-different-server-clock" {
				t.Error(token, err)
			}
		}(manager)
	}
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent refresh replayed old credential", calls.Load())
	}
	saved, err := readCredentialState(m.path)
	if err != nil || saved.Refresh != "tunn_rt_new-secret" || saved.Pending != "" || !saved.Expires.Equal(now.Add(300*time.Second)) {
		t.Fatal(saved, err)
	}
	for _, name := range []string{credentialsFilename, "token", "credentials.lock"} {
		info, err := os.Stat(filepath.Join(filepath.Dir(m.path), name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("credential permissions", name, err)
		}
	}
	info, _ := os.Stat(filepath.Dir(m.path))
	if info.Mode().Perm() != 0700 {
		t.Fatal("config directory permissions")
	}
}
func TestDurableClientLostResponseAndActionableFailure(t *testing.T) {
	m, _ := credentialFixture(t)
	var requests []string
	m.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		var input map[string]string
		_ = json.NewDecoder(r.Body).Decode(&input)
		requests = append(requests, input["request_id"])
		if len(requests) == 1 {
			return nil, fmt.Errorf("transport lost response with secret sentinel")
		}
		return refreshFixtureResponse(r, "new-access", "new-refresh"), nil
	})}
	_, err := m.Token(context.Background(), true)
	if err == nil || terminalCredentialError(err) || strings.Contains(err.Error(), "sentinel") {
		t.Fatal("network failure not actionable or leaked", err)
	}
	state, err := readCredentialState(m.path)
	if err != nil || state.Pending == "" {
		t.Fatal("pending request lost", err)
	}
	restarted := &CredentialManager{ServerAddr: m.ServerAddr, path: m.path, HTTPClient: m.HTTPClient}
	token, err := restarted.Token(context.Background(), false)
	if err != nil || token != "new-access" || requests[0] != requests[1] {
		t.Fatal("restart did not recover exact request", err)
	}
	restarted.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("secret sentinel")), Header: make(http.Header)}, nil
	})}
	_, err = restarted.Token(context.Background(), true)
	if err == nil || !terminalCredentialError(err) || !strings.Contains(err.Error(), "tunn login") || strings.Contains(err.Error(), "sentinel") {
		t.Fatal("revocation error not actionable", err)
	}
}
func TestDurableClientServerBindingAndRedirect(t *testing.T) {
	m, _ := credentialFixture(t)
	m.ServerAddr = "https://attacker.test"
	m.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(*http.Request) (*http.Response, error) {
		t.Error("credential sent to different server")
		return nil, fmt.Errorf("unexpected network")
	})}
	if _, err := m.Token(context.Background(), true); err == nil {
		t.Fatal("server mismatch accepted")
	}
	m.ServerAddr = "https://relay.test"
	var calls int
	m.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://attacker.test/stolen"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	if _, err := m.Token(context.Background(), true); err == nil || calls != 1 {
		t.Fatal("refresh followed redirect", calls, err)
	}
}
func TestDurableLoginAndLegacyReplacement(t *testing.T) {
	m, _ := credentialFixture(t)
	login := &LoginClient{ServerAddr: "relay.test"}
	if err := login.saveCredentials(&TokenResponse{AccessToken: "new", RefreshToken: "refresh", DeviceID: "dev_fixture", ExpiresIn: 300}); err != nil {
		t.Fatal(err)
	}
	state, err := readCredentialState(m.path)
	if err != nil || state.Server != "https://relay.test" {
		t.Fatal(err)
	}
	if err = login.saveCredentials(&TokenResponse{AccessToken: "legacy"}); err != nil {
		t.Fatal(err)
	}
	if _, err = readCredentialState(m.path); !os.IsNotExist(err) {
		t.Fatal("legacy login retained stale renewal", err)
	}
	token, manager, err := LoadTunnelToken(context.Background(), "relay.test", false)
	if err != nil || token != "legacy" || manager != nil {
		t.Fatal("legacy fallback failed", err)
	}
}

type durableLeaseSender struct{ sent func(*pb.TunnelMessage) error }

func (s durableLeaseSender) Send(m *pb.TunnelMessage) error { return s.sent(m) }
func TestDurableClientPublisherRefreshesFor48Hours(t *testing.T) {
	m, state := credentialFixture(t)
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	m.now = clock
	state.Expires = clock().Add(300 * time.Second)
	if err := saveCredentialState(m.path, state); err != nil {
		t.Fatal(err)
	}
	var rotations atomic.Int64
	m.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		n := rotations.Add(1)
		return refreshFixtureResponse(r, fmt.Sprintf("access-%d", n), fmt.Sprintf("refresh-%d", n)), nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var renewals int
	sender := durableLeaseSender{sent: func(msg *pb.TunnelMessage) error {
		reg := msg.GetRegisterClient()
		if reg == nil || reg.AuthToken == "" || reg.TunnelId != "" {
			t.Error("renewal mutated tunnel registration")
		}
		renewals++
		seconds.Add(240)
		if renewals == 720 {
			cancel()
		}
		return nil
	}}
	seconds.Add(240)
	publisher := &ServeClient{Credentials: m}
	if err := publisher.maintainDeviceLease(ctx, sender, state.Access, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if renewals != 720 || rotations.Load() != 720 {
		t.Fatal("publisher stopped renewing", renewals)
	}
}
func TestDurableConnect401RetriesBeforeReadingSSH(t *testing.T) {
	m, state := credentialFixture(t)
	var refreshes atomic.Int64
	m.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		refreshes.Add(1)
		return refreshFixtureResponse(r, "renewed-access", "renewed-refresh"), nil
	})}
	var attempts int
	var consumed atomic.Bool
	var uploaded string
	input := &durableSSHReader{read: func() { consumed.Store(true) }, Reader: strings.NewReader("SSH hello")}
	transport := meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			if consumed.Load() {
				t.Error("SSH bytes consumed before authorization")
			}
			if r.Header.Get("Tunn-Authorization") != "Bearer "+state.Access {
				t.Error("initial token missing")
			}
			return &http.Response{StatusCode: 401, Status: "401 Unauthorized", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		if r.Header.Get("Tunn-Authorization") != "Bearer renewed-access" {
			t.Error("forced renewal missing")
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: &durableResponseReader{body: r.Body, received: &uploaded}}, nil
	})
	connector := &ConnectClient{EndpointURL: "https://forge-ssh.relay.test/.well-known/tunn-connect", Credentials: m}
	var output strings.Builder
	if err := connector.connectStreams(context.Background(), &http.Client{Transport: transport}, input, &output); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || refreshes.Load() != 1 || uploaded != "SSH hello" || output.String() != "SSH reply" {
		t.Fatal(attempts, refreshes.Load(), uploaded, output.String())
	}
}

type durableSSHReader struct {
	io.Reader
	read func()
}

func (r *durableSSHReader) Read(p []byte) (int, error) { r.read(); return r.Reader.Read(p) }

type durableResponseReader struct {
	body     io.ReadCloser
	received *string
	read     bool
}

func (r *durableResponseReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	data, err := io.ReadAll(r.body)
	*r.received = string(data)
	if err != nil {
		return 0, err
	}
	return copy(p, "SSH reply"), nil
}
func (r *durableResponseReader) Close() error { return r.body.Close() }

func TestDurableCrossProcessRefresh(t *testing.T) {
	if os.Getenv("TUNN_REFRESH_CHILD") == "1" {
		dir := os.Getenv("TUNN_CONFIG_DIR")
		m := &CredentialManager{ServerAddr: "https://relay.test", path: filepath.Join(dir, credentialsFilename)}
		m.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
			f, err := os.OpenFile(filepath.Join(dir, "refresh-count"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return nil, err
			}
			_, err = f.WriteString("refresh\n")
			f.Close()
			if err != nil {
				return nil, err
			}
			return refreshFixtureResponse(r, "process-new", "process-refresh"), nil
		})}
		token, err := m.Token(context.Background(), false)
		if err != nil || token != "process-new" {
			t.Fatal("child refresh failed", err)
		}
		return
	}
	m, state := credentialFixture(t)
	state.Expires = time.Now().Add(-time.Hour)
	if err := saveCredentialState(m.path, state); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestDurableCrossProcessRefresh$")
			cmd.Env = append(os.Environ(), "TUNN_REFRESH_CHILD=1")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("child failed: %v: %s", err, output)
			}
		}()
	}
	workers.Wait()
	count, err := os.ReadFile(filepath.Join(filepath.Dir(m.path), "refresh-count"))
	if err != nil || string(count) != "refresh\n" {
		t.Fatal("processes reused rotating secret", string(count), err)
	}
}
