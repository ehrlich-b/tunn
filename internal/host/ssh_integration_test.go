package host

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ehrlich-b/tunn/internal/client"
)

func TestIntegrationSSHReplayRequiresCredentialSafeReconstruction(t *testing.T) {
	const token = "tunn_mcp_ssh_inspection_sentinel"
	p, c, dial := sshRelay(t, true)
	var requests atomic.Int32
	_, output := sshForward(t, c, "--name ssh-reconstruction --public --inspect --inspect-body", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	_ = sshLine(t, output)
	body := []byte(`{"token":"` + token + `"}`)
	r := httptest.NewRequest("POST", "https://ssh-reconstruction.tunn.test/mcp?tenant=application", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	headers := p.forwardedHTTPHeaders(r)
	w := httptest.NewRecorder()
	p.handleWebProxy(w, r)
	if w.Code != 200 {
		t.Fatalf("ingress=%d %s", w.Code, w.Body)
	}
	data := sshOwnerCommand(t, dial, "inspect ssh-reconstruction")
	var events []client.InspectionEvent
	if err := json.Unmarshal(data, &events); err != nil || len(events) != 1 {
		t.Fatalf("events=%s %v", data, err)
	}
	if strings.Contains(string(data), token) || events[0].BodyCaptured || events[0].Replayable || !events[0].Reconstructable || len(events[0].Body) != 0 {
		t.Fatalf("SSH inspection retained platform credentials: %s", data)
	}
	run := func(command string, request *client.InspectionReplayRequest) ([]byte, error) {
		t.Helper()
		session, err := dial().NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if request != nil {
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			session.Stdin = bytes.NewReader(payload)
		}
		return session.CombinedOutput(command)
	}
	if data, err := run("replay ssh-reconstruction 1", nil); err == nil || !strings.Contains(string(data), "reconstruct") {
		t.Fatalf("implicit reconstruction=%s %v", data, err)
	}
	path := r.URL.RequestURI()
	input := &client.InspectionReplayRequest{Path: &path, Headers: headers, Body: &body}
	if data, err := run("replay ssh-reconstruction 1 --request -", input); err == nil || strings.Contains(string(data), token) {
		t.Fatalf("credential reconstruction=%s %v", data, err)
	}
	if requests.Load() != 1 {
		t.Fatal("invalid reconstruction reached the target")
	}
	cleanBody := bytes.Repeat([]byte("x"), len(body))
	input.Body = &cleanBody
	if data, err := run("replay ssh-reconstruction 1 --request -", input); err != nil || !json.Valid(data) || requests.Load() != 2 {
		t.Fatalf("safe explicit replay=%s %v requests=%d", data, err, requests.Load())
	}
}
