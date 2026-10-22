package client

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

const retrySecret = "private-device-code-fixture"
const retryToken = "private-access-token-fixture"
const retryBody = "private-raw-body-fixture"
const retryURL = "https://private.invalid/secret?token=" + retryToken

func retryResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type retryTimeoutReader struct{}

func (retryTimeoutReader) Read([]byte) (int, error) {
	return 0, &url.Error{Op: "read", URL: retryURL, Err: context.DeadlineExceeded}
}

type retryFixture struct {
	client                 *LoginClient
	output                 bytes.Buffer
	dir                    string
	codes, polls, browsers int
	times                  []time.Duration
	start                  time.Time
}

func newRetryFixture(t *testing.T, exchange func(*retryFixture, *http.Request) (*http.Response, error)) *retryFixture {
	t.Helper()
	f := &retryFixture{dir: t.TempDir(), start: time.Now()}
	t.Setenv(configDirectoryEnvironment, f.dir)
	for _, name := range []string{"token", credentialsFilename} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte("saved-unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.client = &LoginClient{ServerAddr: "relay.invalid", Output: &f.output, OpenBrowser: func(string) { f.browsers++ }}
	f.client.HTTPClient = &http.Client{Transport: loginRoundTripper(func(r *http.Request) (*http.Response, error) {
		f.unchanged(t)
		if r.URL.Path == "/api/device/code" {
			f.codes++
			code := retrySecret
			if f.codes > 1 {
				code = "replacement-fixture"
			}
			return loginJSON(DeviceCodeResponse{DeviceCode: code, UserCode: "ABCD-EFGH", VerificationURIComplete: "https://relay.invalid/login?code=ABCD-EFGH&private=" + retryToken, ExpiresIn: 120, Interval: 2}), nil
		}
		f.polls++
		f.times = append(f.times, time.Since(f.start))
		if f.codes == 1 && r.URL.Query().Get("code") != retrySecret {
			t.Fatal("changed code before expiry")
		}
		return exchange(f, r)
	})}
	return f
}

func (f *retryFixture) unchanged(t *testing.T) {
	t.Helper()
	for _, name := range []string{"token", credentialsFilename} {
		got, err := os.ReadFile(filepath.Join(f.dir, name))
		if err != nil || string(got) != "saved-unchanged" {
			t.Fatalf("saved credentials changed before success: %s, %v", name, err)
		}
	}
}

func retryNoSecrets(t *testing.T, diagnostic string) {
	t.Helper()
	for _, secret := range []string{retrySecret, retryToken, retryBody, retryURL, "private.invalid", "raw-error-fixture"} {
		if strings.Contains(diagnostic, secret) {
			t.Fatal("secret present in diagnostics")
		}
	}
}

func TestLoginPollRetryRecovery(t *testing.T) {
	for _, fault := range []string{"timeout", "body timeout", "502", "503", "429", "reset"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newRetryFixture(t, func(f *retryFixture, r *http.Request) (*http.Response, error) {
					switch f.polls {
					case 1:
						return loginJSON(TokenResponse{Error: "authorization_pending"}), nil
					case 2:
						switch fault {
						case "timeout":
							return nil, &url.Error{Op: "Get", URL: retryURL, Err: context.DeadlineExceeded}
						case "body timeout":
							resp := retryResponse(200, "")
							resp.Body = io.NopCloser(retryTimeoutReader{})
							return resp, nil
						case "reset":
							return nil, fmt.Errorf("%s: %w", retryURL, syscall.ECONNRESET)
						case "429":
							resp := retryResponse(429, retryBody)
							resp.Header.Set("Retry-After", "9")
							return resp, nil
						case "502":
							return retryResponse(502, retryBody), nil
						default:
							return retryResponse(503, retryBody), nil
						}
					}
					return loginJSON(TokenResponse{AccessToken: retryToken, RefreshToken: "private-refresh-token", DeviceID: "dev_fixture", ExpiresIn: 300}), nil
				})
				if err := f.client.Run(context.Background()); err != nil {
					t.Fatal(err)
				}
				last := 8 * time.Second
				if fault == "429" {
					last = 13 * time.Second
				}
				if fmt.Sprint(f.times) != fmt.Sprint([]time.Duration{2 * time.Second, 4 * time.Second, last}) {
					t.Fatalf("exchange times = %v", f.times)
				}
				if f.codes != 1 || f.browsers != 1 {
					t.Fatalf("codes=%d browsers=%d", f.codes, f.browsers)
				}
				if strings.Count(f.output.String(), "Retrying until this code expires; Ctrl+C to cancel.") != 1 {
					t.Fatal("missing bounded guidance")
				}
				retryNoSecrets(t, f.output.String())
				got, err := os.ReadFile(filepath.Join(f.dir, "token"))
				if err != nil || string(got) != retryToken {
					t.Fatal("valid token was not saved")
				}
				saved, err := readCredentialState(filepath.Join(f.dir, credentialsFilename))
				if err != nil || saved.Access != retryToken || saved.Refresh != "private-refresh-token" {
					t.Fatal("valid renewable credentials were not saved")
				}
			})
		})
	}
}

func TestLoginPollRetryBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newRetryFixture(t, func(f *retryFixture, _ *http.Request) (*http.Response, error) {
			if f.polls <= 6 {
				return retryResponse(503, retryBody), nil
			}
			if f.polls == 7 {
				return loginJSON(TokenResponse{Error: "authorization_pending"}), nil
			}
			return loginJSON(TokenResponse{AccessToken: retryToken}), nil
		})
		if err := f.client.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.codes != 2 {
			t.Fatal("expected local expiry to replace code")
		}
		if strings.Count(f.output.String(), "Retrying until") != 1 {
			t.Fatal("repeated recovery guidance")
		}
		if fmt.Sprint(f.times) != "[2s 6s 14s 30s 1m0s 1m30s 2m2s 2m4s]" {
			t.Fatalf("backoff/expiry times %v", f.times)
		}
	})
}

func TestLoginPollRetryServerIntervals(t *testing.T) {
	for _, interval := range []int{0, 45} {
		t.Run(fmt.Sprint(interval), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var times []time.Duration
				start := time.Now()
				calls := 0
				l := &LoginClient{ServerAddr: "relay.invalid", Output: io.Discard, HTTPClient: &http.Client{Transport: loginRoundTripper(func(*http.Request) (*http.Response, error) {
					calls++
					times = append(times, time.Since(start))
					if calls < 3 {
						return retryResponse(500, retryBody), nil
					}
					return loginJSON(TokenResponse{AccessToken: retryToken}), nil
				})}}
				_, err := l.pollForToken(context.Background(), &DeviceCodeResponse{DeviceCode: retrySecret, Interval: interval, ExpiresIn: 600})
				if err != nil {
					t.Fatal(err)
				}
				base := time.Duration(interval) * time.Second
				if base == 0 {
					base = 3 * time.Second
				}
				second := min(base*2, max(base, maxLoginBackoff))
				third := min(second*2, max(base, maxLoginBackoff))
				if fmt.Sprint(times) != fmt.Sprint([]time.Duration{base, base + second, base + second + third}) {
					t.Fatalf("server interval ignored: %v", times)
				}
			})
		})
	}
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		calls := 0
		l := &LoginClient{ServerAddr: "relay.invalid", HTTPClient: &http.Client{Transport: loginRoundTripper(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return loginJSON(TokenResponse{Error: "slow_down"}), nil
			}
			if time.Since(start) != 9*time.Second {
				t.Fatal("slow_down interval ignored")
			}
			return loginJSON(TokenResponse{AccessToken: retryToken}), nil
		})}}
		if _, err := l.pollForToken(context.Background(), &DeviceCodeResponse{DeviceCode: retrySecret, Interval: 2, ExpiresIn: 60}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLoginPollRetryCancellation(t *testing.T) {
	for _, stage := range []string{"wait", "request", "backoff"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f := newRetryFixture(t, func(f *retryFixture, r *http.Request) (*http.Response, error) {
					if stage == "request" {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					return retryResponse(503, retryBody), nil
				})
				duration := time.Second
				if stage != "wait" {
					duration = 3 * time.Second
				}
				go func() { time.Sleep(duration); cancel() }()
				if err := f.client.Run(ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel = %v", err)
				}
				if time.Since(f.start) != duration || f.codes != 1 || f.browsers != 1 {
					t.Fatal("cancellation did not exit promptly")
				}
				f.unchanged(t)
				retryNoSecrets(t, f.output.String())
			})
		})
	}
}

func TestLoginPollRetryTerminal(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		transport error
		want      string
	}{
		{"invalid grant", 400, `{"error":"invalid_grant"}`, nil, "invalid grant"},
		{"denial", 403, `{"error":"access_denied"}`, nil, "denied"},
		{"configuration", 400, `{"error":"invalid_client"}`, nil, "configuration"},
		{"unknown error", 400, `{"error":"` + retryBody + `"}`, nil, "rejected"},
		{"malformed success", 200, `{"access_token":"` + retryToken + `",`, nil, "invalid sign-in token response"},
		{"trailing data", 200, `{"access_token":"` + retryToken + `"} {"raw":"` + retryBody + `"}`, nil, "invalid sign-in token response"},
		{"empty success", 200, `{}`, nil, "no access token"},
		{"bad status with token", 401, `{"access_token":"` + retryToken + `"}`, nil, "status 401"},
		{"raw error", 403, retryBody, nil, "invalid sign-in token response"},
		{"TLS", 0, "", x509.UnknownAuthorityError{}, "configuration"},
		{"transport config", 0, "", errors.New(retryURL + " raw-error-fixture"), "configuration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newRetryFixture(t, func(*retryFixture, *http.Request) (*http.Response, error) {
					if tc.transport != nil {
						return nil, tc.transport
					}
					return retryResponse(tc.status, tc.body), nil
				})
				err := f.client.Run(context.Background())
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("terminal error = %v", err)
				}
				if f.codes != 1 || f.browsers != 1 || f.polls != 1 {
					t.Fatal("terminal failure retried")
				}
				f.unchanged(t)
				retryNoSecrets(t, err.Error()+f.output.String())
			})
		})
	}
}

func TestLoginPollRetryExpiry(t *testing.T) {
	for _, mode := range []string{"server", "local", "in flight"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newRetryFixture(t, func(f *retryFixture, r *http.Request) (*http.Response, error) {
					if f.codes > 1 {
						return loginJSON(TokenResponse{AccessToken: retryToken}), nil
					}
					if mode == "server" {
						if f.polls == 2 {
							return retryResponse(400, `{"error":"expired_token"}`), nil
						}
						return retryResponse(503, retryBody), nil
					}
					if mode == "in flight" {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					resp := retryResponse(503, retryBody)
					resp.Header.Set("Retry-After", "300")
					return resp, nil
				})
				if err := f.client.Run(context.Background()); err != nil {
					t.Fatal(err)
				}
				if f.codes != 2 || f.browsers != 2 {
					t.Fatal("actual expiry did not replace the code")
				}
				if !strings.Contains(f.output.String(), "Code expired. Requesting a new code.") {
					t.Fatal("missing expiry guidance")
				}
				retryNoSecrets(t, f.output.String())
			})
		})
	}
}

func TestLoginPollRetryDiagnostics(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	synctest.Test(t, func(t *testing.T) {
		f := newRetryFixture(t, func(*retryFixture, *http.Request) (*http.Response, error) { return nil, errors.New(retryURL) })
		err := f.client.Run(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		retryNoSecrets(t, logs.String()+f.output.String()+err.Error())
		f.client.ServerAddr = retryURL
		if err := f.client.Run(context.Background()); err == nil {
			t.Fatal("accepted private URL as configuration")
		} else {
			retryNoSecrets(t, err.Error()+logs.String())
		}
		f.client.ServerAddr = "relay.invalid"
		f.client.HTTPClient = &http.Client{Transport: loginRoundTripper(func(*http.Request) (*http.Response, error) { return retryResponse(500, retryBody), nil })}
		if err := f.client.Run(context.Background()); err == nil {
			t.Fatal("expected device request failure")
		} else {
			retryNoSecrets(t, err.Error())
		}
	})
}

func TestLoginPollRetrySlowRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newRetryFixture(t, func(f *retryFixture, _ *http.Request) (*http.Response, error) {
			if f.polls == 1 {
				time.Sleep(3 * time.Second)
				return retryResponse(503, retryBody), nil
			}
			return loginJSON(TokenResponse{AccessToken: retryToken}), nil
		})
		if err := f.client.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(f.times) != "[2s 9s]" {
			t.Fatalf("caught up after slow request: %v", f.times)
		}
	})
}

func TestLoginPollRetryInvalidConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newRetryFixture(t, func(*retryFixture, *http.Request) (*http.Response, error) {
			t.Fatal("configuration failure reached exchange")
			return nil, nil
		})
		t.Setenv(configDirectoryEnvironment, "relative/fixture")
		err := f.client.Run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "absolute path") {
			t.Fatalf("configuration failure=%v", err)
		}
		if f.codes != 0 || f.browsers != 0 {
			t.Fatal("configuration failure started login")
		}
		f.unchanged(t)
	})
}

func TestLoginPollRetryInvalidDurableSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newRetryFixture(t, func(*retryFixture, *http.Request) (*http.Response, error) {
			return loginJSON(TokenResponse{AccessToken: retryToken, RefreshToken: "private-refresh-token", ExpiresIn: 300}), nil
		})
		err := f.client.Run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "invalid durable login response") {
			t.Fatalf("malformed durable success=%v", err)
		}
		if f.polls != 1 || f.browsers != 1 {
			t.Fatal("malformed success retried")
		}
		f.unchanged(t)
		retryNoSecrets(t, err.Error()+f.output.String())
	})
}
