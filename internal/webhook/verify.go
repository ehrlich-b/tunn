// Package webhook verifies signed deliveries without decoding or changing bodies.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

const Capability = "verify-webhook-v1"
const MaxBodySize int64 = 1 << 20
const MaxSecretSize = 4096
const MaxConcurrentVerifications = 100
const ReadTimeout = 10 * time.Second
const DefaultTolerance = 300 * time.Second

// Policy owns a private copy of the key; formatting never reveals it.
// The relay retains it only for the lifetime of the publishing connection.
type Policy struct {
	provider  string
	secret    []byte
	tolerance time.Duration
	slots     chan struct{}
}

// Keep body errors private while allowing ingress to preserve its existing
// quota and ledger-failure responses when a metered read is denied.
type bodyReadError struct{ cause error }

func (e *bodyReadError) Error() string { return "webhook body could not be read" }
func (e *bodyReadError) Unwrap() error { return e.cause }

func (p *Policy) String() string   { return "webhook policy (secret redacted)" }
func (p *Policy) GoString() string { return p.String() }

func ValidateOptions(provider string, tolerance time.Duration) error {
	switch provider {
	case "stripe", "github", "slack", "shopify", "hmac-sha256":
	default:
		return errors.New("unsupported webhook provider")
	}
	if tolerance < time.Second || tolerance > time.Hour || tolerance%time.Second != 0 {
		return errors.New("webhook tolerance must be whole seconds between 1s and 1h")
	}
	if (provider == "github" || provider == "shopify") && tolerance != DefaultTolerance {
		return errors.New("this provider does not sign a timestamp; custom tolerance is unsupported")
	}
	return nil
}

func Compile(config *pb.WebhookPolicy) (*Policy, error) {
	if config == nil {
		return nil, nil
	}
	tolerance := time.Duration(config.ToleranceSeconds) * time.Second
	if err := ValidateOptions(config.Provider, tolerance); err != nil {
		return nil, err
	}
	if len(config.Secret) == 0 || len(config.Secret) > MaxSecretSize {
		return nil, errors.New("webhook secret must contain 1–4096 bytes")
	}
	return &Policy{provider: config.Provider, secret: append([]byte(nil), config.Secret...), tolerance: tolerance, slots: make(chan struct{}, MaxConcurrentVerifications)}, nil
}

func single(h http.Header, name string) (string, error) {
	values := h.Values(name)
	if len(values) == 0 || len(values) == 1 && values[0] == "" {
		return "", errors.New("missing signature or timestamp header")
	}
	if len(values) != 1 || len(values[0]) > 8192 {
		return "", errors.New("ambiguous or oversized signature header")
	}
	return values[0], nil
}

func (p *Policy) timestamp(raw string, now time.Time) error {
	if raw == "" || len(raw) > 12 {
		return errors.New("invalid webhook timestamp")
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return errors.New("invalid webhook timestamp")
		}
	}
	stamp, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return errors.New("invalid webhook timestamp")
	}
	delta := now.Unix() - stamp // Unix seconds bounded by the input length above.
	seconds := int64(p.tolerance / time.Second)
	if delta > seconds || delta < -seconds {
		return errors.New("webhook timestamp outside tolerance")
	}
	return nil
}

func matches(signature string, base64Encoding bool, expected []byte) bool {
	var got []byte
	var err error
	if base64Encoding {
		got, err = base64.StdEncoding.DecodeString(signature)
	} else {
		got, err = hex.DecodeString(signature)
	}
	if err != nil || len(got) != sha256.Size {
		return false
	}
	return hmac.Equal(got, expected)
}

// Verify restores the exact body for the existing buffered/streaming adapters.
// It never opens an origin connection before verification completes.
func (p *Policy) Verify(r *http.Request, clock func() time.Time) error {
	if p == nil {
		return nil
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		return errors.New("webhook verification capacity reached")
	}
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		return errors.New("webhook endpoint does not support connection upgrades")
	}
	var signature, prefix, stamp string
	var candidates []string
	base64Encoding := false
	switch p.provider {
	case "stripe":
		raw, err := single(r.Header, "Stripe-Signature")
		if err != nil {
			return err
		}
		seenTimestamp := false
		for _, part := range strings.Split(raw, ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				return errors.New("malformed Stripe signature")
			}
			switch key {
			case "t":
				if seenTimestamp {
					return errors.New("ambiguous webhook timestamp")
				}
				seenTimestamp = true
				stamp = value
			case "v1":
				candidates = append(candidates, value)
			}
		}
		if err := p.timestamp(stamp, clock()); err != nil {
			return err
		}
		if len(candidates) == 0 {
			return errors.New("missing Stripe v1 signature")
		}
		prefix = stamp + "."
	case "slack", "hmac-sha256":
		signatureHeader, timestampHeader, marker := "X-Slack-Signature", "X-Slack-Request-Timestamp", "v0="
		if p.provider == "hmac-sha256" {
			signatureHeader, timestampHeader, marker = "X-Webhook-Signature", "X-Webhook-Timestamp", "sha256="
		}
		raw, err := single(r.Header, signatureHeader)
		if err != nil {
			return err
		}
		stamp, err = single(r.Header, timestampHeader)
		if err != nil {
			return err
		}
		if err := p.timestamp(stamp, clock()); err != nil {
			return err
		}
		if !strings.HasPrefix(raw, marker) {
			return errors.New("malformed webhook signature")
		}
		signature = strings.TrimPrefix(raw, marker)
		prefix = "v0:" + stamp + ":"
		if p.provider == "hmac-sha256" {
			prefix = stamp + "."
		}
	case "github":
		raw, err := single(r.Header, "X-Hub-Signature-256")
		if err != nil {
			return err
		}
		if !strings.HasPrefix(raw, "sha256=") {
			return errors.New("malformed webhook signature")
		}
		signature = strings.TrimPrefix(raw, "sha256=")
	case "shopify":
		var err error
		signature, err = single(r.Header, "X-Shopify-Hmac-Sha256")
		if err != nil {
			return err
		}
		base64Encoding = true
	}
	if r.ContentLength > MaxBodySize {
		return errors.New("webhook body exceeds 1 MiB")
	}
	body := []byte(nil)
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, MaxBodySize+1))
		_ = r.Body.Close()
		if err != nil {
			return &bodyReadError{cause: err}
		}
	}
	if int64(len(body)) > MaxBodySize {
		return errors.New("webhook body exceeds 1 MiB")
	}
	if len(candidates) == 0 {
		candidates = []string{signature}
	}
	matched := false
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte(prefix))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	for _, candidate := range candidates {
		if matches(candidate, base64Encoding, expected) {
			matched = true
		}
	}
	if !matched {
		return errors.New("webhook signature mismatch")
	}
	if stamp != "" {
		if err := p.timestamp(stamp, clock()); err != nil {
			return err
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}
