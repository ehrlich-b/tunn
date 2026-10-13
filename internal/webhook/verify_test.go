package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var fixtureNow = time.Unix(1700000000, 0)

func fixtureClock() time.Time { return fixtureNow }

const fixtureSecret = "webhook-fixture-secret"

func signedRequest(provider string, body []byte, stamp int64, secret string) *http.Request {
	r := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	raw := strconv.FormatInt(stamp, 10)
	prefix := ""
	switch provider {
	case "stripe", "hmac-sha256":
		prefix = raw + "."
	case "slack":
		prefix = "v0:" + raw + ":"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(prefix))
	_, _ = mac.Write(body)
	digest := hex.EncodeToString(mac.Sum(nil))
	switch provider {
	case "stripe":
		r.Header.Set("Stripe-Signature", "t="+raw+",v1="+digest)
	case "github":
		r.Header.Set("X-Hub-Signature-256", "sha256="+digest)
	case "slack":
		r.Header.Set("X-Slack-Request-Timestamp", raw)
		r.Header.Set("X-Slack-Signature", "v0="+digest)
	case "shopify":
		r.Header.Set("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	case "hmac-sha256":
		r.Header.Set("X-Webhook-Timestamp", raw)
		r.Header.Set("X-Webhook-Signature", "sha256="+digest)
	}
	return r
}
func fixturePolicy(t *testing.T, provider string) *Policy {
	t.Helper()
	p, err := Compile(&pb.WebhookPolicy{Provider: provider, Secret: []byte(fixtureSecret), ToleranceSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestWebhookProviders(t *testing.T) {
	body := []byte(" {\n\"text\": \"café\", \"n\":1}\n\x00\xff")
	for _, provider := range []string{"stripe", "github", "slack", "shopify", "hmac-sha256"} {
		t.Run(provider, func(t *testing.T) {
			p := fixturePolicy(t, provider)
			r := signedRequest(provider, body, fixtureNow.Unix(), fixtureSecret)
			if err := p.Verify(r, fixtureClock); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(body, got) {
				t.Fatal("raw body changed")
			}
			for _, mutation := range []string{"key", "body", "missing", "duplicate", "malformed"} {
				t.Run(mutation, func(t *testing.T) {
					r := signedRequest(provider, body, fixtureNow.Unix(), fixtureSecret)
					switch mutation {
					case "key":
						r = signedRequest(provider, body, fixtureNow.Unix(), "incorrect-fixture-key")
					case "body":
						r.Body = io.NopCloser(strings.NewReader("changed"))
					case "missing":
						r.Header = make(http.Header)
					case "duplicate":
						for k, v := range r.Header {
							r.Header.Add(k, v[0])
						}
					case "malformed":
						for k := range r.Header {
							r.Header.Set(k, "malformed")
						}
					}
					if err := p.Verify(r, fixtureClock); err == nil {
						t.Fatal("invalid delivery accepted")
					}
				})
			}
		})
	}
}
func TestWebhookKnownGitHubVector(t *testing.T) {
	p, err := Compile(&pb.WebhookPolicy{Provider: "github", Secret: []byte("It's a Secret to Everybody"), ToleranceSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader("Hello, World!"))
	r.Header.Set("X-Hub-Signature-256", "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
	if err := p.Verify(r, fixtureClock); err != nil {
		t.Fatal(err)
	}
}
func TestWebhookTimestampWindow(t *testing.T) {
	for _, provider := range []string{"stripe", "slack", "hmac-sha256"} {
		for _, offset := range []int64{-301, -300, 0, 300, 301} {
			t.Run(fmt.Sprintf("%s/%d", provider, offset), func(t *testing.T) {
				r := signedRequest(provider, []byte("raw"), fixtureNow.Unix()+offset, fixtureSecret)
				err := fixturePolicy(t, provider).Verify(r, fixtureClock)
				if (err == nil) != (offset >= -300 && offset <= 300) {
					t.Fatalf("offset %d: %v", offset, err)
				}
			})
		}
	}
	for _, stamp := range []string{"", "-1", "+1700000000", "NaN", "9999999999999999999", "1700000000 ", "1.7e9"} {
		t.Run(stamp, func(t *testing.T) {
			r := signedRequest("slack", nil, fixtureNow.Unix(), fixtureSecret)
			r.Header.Set("X-Slack-Request-Timestamp", stamp)
			if err := fixturePolicy(t, "slack").Verify(r, fixtureClock); err == nil {
				t.Fatal("invalid timestamp accepted")
			}
		})
	}
}

func TestWebhookConfiguredTimestampWindow(t *testing.T) {
	for _, provider := range []string{"stripe", "slack", "hmac-sha256"} {
		for _, tolerance := range []uint32{1, 60, 3600} {
			t.Run(fmt.Sprintf("%s/%ds", provider, tolerance), func(t *testing.T) {
				p, err := Compile(&pb.WebhookPolicy{Provider: provider, Secret: []byte(fixtureSecret), ToleranceSeconds: tolerance})
				if err != nil {
					t.Fatal(err)
				}
				limit := int64(tolerance)
				for _, offset := range []int64{-limit - 1, -limit, 0, limit, limit + 1} {
					r := signedRequest(provider, []byte("body"), fixtureNow.Unix()+offset, fixtureSecret)
					if err := p.Verify(r, fixtureClock); (err == nil) != (offset >= -limit && offset <= limit) {
						t.Fatalf("offset %d: %v", offset, err)
					}
				}
			})
		}
	}
}

type advancingBody struct {
	io.ReadCloser
	advance func()
}

func (b *advancingBody) Read(buf []byte) (int, error) {
	b.advance()
	return b.ReadCloser.Read(buf)
}

func TestWebhookFreshnessAfterBodyRead(t *testing.T) {
	for _, provider := range []string{"stripe", "slack", "hmac-sha256"} {
		for _, delay := range []time.Duration{0, time.Second, 2 * time.Second} {
			t.Run(fmt.Sprintf("%s/%s", provider, delay), func(t *testing.T) {
				p, err := Compile(&pb.WebhookPolicy{Provider: provider, Secret: []byte(fixtureSecret), ToleranceSeconds: 1})
				if err != nil {
					t.Fatal(err)
				}
				now := fixtureNow
				r := signedRequest(provider, []byte("body"), now.Unix(), fixtureSecret)
				r.Body = &advancingBody{ReadCloser: r.Body, advance: func() { now = fixtureNow.Add(delay) }}
				err = p.Verify(r, func() time.Time { return now })
				if (err == nil) != (delay <= time.Second) {
					t.Fatalf("freshness after upload: %v", err)
				}
			})
		}
	}
}
func TestWebhookStripeRotationAndAmbiguity(t *testing.T) {
	p := fixturePolicy(t, "stripe")
	r := signedRequest("stripe", nil, fixtureNow.Unix(), fixtureSecret)
	r.Header.Set("Stripe-Signature", r.Header.Get("Stripe-Signature")+",v1="+strings.Repeat("0", 64)+",v0=ignored")
	if err := p.Verify(r, fixtureClock); err != nil {
		t.Fatal(err)
	}
	r = signedRequest("stripe", nil, fixtureNow.Unix(), fixtureSecret)
	r.Header.Set("Stripe-Signature", r.Header.Get("Stripe-Signature")+",t=1700000000")
	if err := p.Verify(r, fixtureClock); err == nil {
		t.Fatal("duplicate timestamp accepted")
	}
}

type badBody struct{}

func (badBody) Read([]byte) (int, error) { return 0, errors.New(fixtureSecret) }
func (badBody) Close() error             { return nil }
func TestWebhookBoundedBodiesAndTransport(t *testing.T) {
	p := fixturePolicy(t, "github")
	for _, kind := range []string{"declared-size", "unknown-size", "read-failure", "connect", "upgrade", "oversized-header", "empty-body"} {
		t.Run(kind, func(t *testing.T) {
			r := signedRequest("github", nil, fixtureNow.Unix(), fixtureSecret)
			switch kind {
			case "declared-size":
				r.ContentLength = MaxBodySize + 1
				r.Body = badBody{}
			case "unknown-size":
				r.ContentLength = -1
				r.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", int(MaxBodySize+1))))
			case "read-failure":
				r.Body = badBody{}
			case "connect":
				r.Method = "CONNECT"
			case "upgrade":
				r.Header.Set("Upgrade", "websocket")
			case "oversized-header":
				r.Header.Set("X-Hub-Signature-256", strings.Repeat("x", 8193))
			}
			err := p.Verify(r, fixtureClock)
			if (err == nil) != (kind == "empty-body") {
				t.Fatalf("%s: %v", kind, err)
			}
			if err != nil && strings.Contains(err.Error(), fixtureSecret) {
				t.Fatal("secret leaked")
			}
		})
	}
	body := bytes.Repeat([]byte("a"), int(MaxBodySize))
	r := signedRequest("github", body, fixtureNow.Unix(), fixtureSecret)
	if err := p.Verify(r, fixtureClock); err != nil {
		t.Fatal("exact body limit rejected", err)
	}
	for i := 0; i < MaxConcurrentVerifications; i++ {
		p.slots <- struct{}{}
	}
	if err := p.Verify(signedRequest("github", nil, fixtureNow.Unix(), fixtureSecret), fixtureClock); err == nil {
		t.Fatal("capacity limit bypassed")
	}
}
func TestWebhookConfigAndRedaction(t *testing.T) {
	for _, config := range []*pb.WebhookPolicy{
		{Provider: "unknown", Secret: []byte(fixtureSecret), ToleranceSeconds: 300},
		{Provider: "github", Secret: []byte(fixtureSecret), ToleranceSeconds: 1},
		{Provider: "stripe", ToleranceSeconds: 300},
		{Provider: "stripe", Secret: bytes.Repeat([]byte("a"), 4097), ToleranceSeconds: 300},
		{Provider: "stripe", Secret: []byte(fixtureSecret), ToleranceSeconds: 0},
		{Provider: "stripe", Secret: []byte(fixtureSecret), ToleranceSeconds: 3601},
		{Provider: "stripe", Secret: []byte(fixtureSecret), ToleranceSeconds: ^uint32(0)},
	} {
		if _, err := Compile(config); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if p, err := Compile(nil); p != nil || err != nil {
		t.Fatal("absent policy changed behavior")
	}
	p := fixturePolicy(t, "github")
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, p), fixtureSecret) {
			t.Fatal("policy formatting exposed key")
		}
	}
	if err := ValidateOptions("slack", 1500*time.Millisecond); err == nil {
		t.Fatal("fractional seconds accepted")
	}
}
