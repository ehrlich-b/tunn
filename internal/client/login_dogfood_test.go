package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type loginRoundTripper func(*http.Request) (*http.Response, error)

func (f loginRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func loginJSON(v any) *http.Response {
	data, _ := json.Marshal(v)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}
}

func TestDogfoodLoginRenewsExpiredCode(t *testing.T) {
	for _, localExpiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "server expiry", true: "local expiry"}[localExpiry], func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TUNN_CONFIG_DIR", dir)
			var output bytes.Buffer
			codes, polls, opened := 0, 0, 0
			expiry := time.Now().Add(10 * time.Minute).Truncate(time.Second)
			l := &LoginClient{ServerAddr: "relay.invalid:443", Output: &output, OpenBrowser: func(string) { opened++ }}
			l.HTTPClient = &http.Client{Transport: loginRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/device/code" {
					if r.Method != http.MethodPost {
						t.Errorf("code request method = %s", r.Method)
					}
					codes++
					code := DeviceCodeResponse{DeviceCode: "first", UserCode: "ABC-123", VerificationURIComplete: "https://relay.invalid/login?code=ABC-123&device_code=private-device-secret", ExpiresIn: 600, Interval: 1, ExpiresAt: expiry.Unix()}
					if codes == 1 && localExpiry {
						code.ExpiresAt = time.Now().Add(-time.Second).Unix()
					}
					if codes == 2 {
						code.DeviceCode, code.UserCode, code.VerificationURIComplete = "second", "DEF-456", "https://relay.invalid/login?code=DEF-456&device_code=private-device-secret"
					}
					return loginJSON(code), nil
				}
				polls++
				if r.URL.Query().Get("code") == "first" {
					return loginJSON(TokenResponse{Error: "expired_token"}), nil
				}
				return loginJSON(TokenResponse{AccessToken: "private-fixture-token"}), nil
			})}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			if err := l.Run(ctx); err != nil {
				t.Fatal(err)
			}
			wantPolls := 2
			if localExpiry {
				wantPolls = 1
			}
			if codes != 2 || polls != wantPolls || opened != 2 {
				t.Fatalf("codes=%d polls=%d browsers=%d", codes, polls, opened)
			}
			data, err := os.ReadFile(filepath.Join(dir, "token"))
			if err != nil || string(data) != "private-fixture-token" {
				t.Fatalf("saved token = %q, %v", data, err)
			}
			for _, text := range []string{"ABC-123", "DEF-456", "Expires at: " + expiry.Local().Format("15:04:05 MST"), "Requesting a new code", "Signed in", "tunn 3000"} {
				if !strings.Contains(output.String(), text) {
					t.Errorf("output omitted %q: %s", text, output.String())
				}
			}
			if strings.Contains(output.String(), "private-fixture-token") || strings.Contains(output.String(), "private-device-secret") || strings.Contains(output.String(), "token_file") {
				t.Fatal("printed token")
			}
		})
	}
}

func TestDogfoodLoginCancellationDuringRequest(t *testing.T) {
	for _, polling := range []bool{false, true} {
		t.Run(map[bool]string{false: "code request", true: "token poll"}[polling], func(t *testing.T) {
			var output bytes.Buffer
			requests := 0
			l := &LoginClient{ServerAddr: "relay.invalid:443", Output: &output, OpenBrowser: func(string) {}}
			l.HTTPClient = &http.Client{Transport: loginRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests++
				if polling && r.URL.Path == "/api/device/code" {
					return loginJSON(DeviceCodeResponse{DeviceCode: "pending", UserCode: "ABC-123", ExpiresIn: 600, Interval: 1}), nil
				}
				<-r.Context().Done()
				return nil, r.Context().Err()
			})}
			duration := 20 * time.Millisecond
			if polling {
				duration = 1100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			if err := l.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation = %v", err)
			}
			want := 1
			if polling {
				want = 2
			}
			if requests != want {
				t.Fatalf("requests = %d, want %d; must not renew after cancellation", requests, want)
			}
		})
	}
}
