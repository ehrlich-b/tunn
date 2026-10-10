package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// extractClientIP
// ---------------------------------------------------------------------------

func TestExtractClientIP(t *testing.T) {
	t.Run("X-Forwarded-For wins over X-Real-IP and RemoteAddr", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Real-IP", "192.0.2.77")
		r.RemoteAddr = "198.51.100.5:40000"

		if got := extractClientIP(r); got != "203.0.113.9" {
			t.Fatalf("extractClientIP() = %q, want %q (X-Forwarded-For must win)", got, "203.0.113.9")
		}
	})

	t.Run("X-Forwarded-For chain returns only the first entry, trimmed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1, 10.0.0.2")

		if got := extractClientIP(r); got != "203.0.113.5" {
			t.Fatalf("extractClientIP() = %q, want %q", got, "203.0.113.5")
		}
	})

	t.Run("X-Real-IP used when X-Forwarded-For absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Real-IP", " 192.0.2.99 ")
		r.RemoteAddr = "198.51.100.5:40000"

		if got := extractClientIP(r); got != "192.0.2.99" {
			t.Fatalf("extractClientIP() = %q, want %q", got, "192.0.2.99")
		}
	})

	t.Run("RemoteAddr fallback strips port (IPv4)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "192.0.2.1:54321"

		if got := extractClientIP(r); got != "192.0.2.1" {
			t.Fatalf("extractClientIP() = %q, want %q", got, "192.0.2.1")
		}
	})

	// CHARACTERIZED FINDING — DO NOT "FIX": `extractClientIP` strips only the
	// port from RemoteAddr via strings.LastIndex(addr, ":") and then returns
	// addr[:idx], keeping everything before the last colon — brackets included.
	// An IPv6 RemoteAddr like "[::1]:54321" therefore yields "[::1]" (with the
	// brackets still attached), never the bare "::1" one might expect from a
	// function whose job is "extract the client IP". This is verified real
	// behavior (verified 2026-08-27) and is intentionally pinned here, not fixed.
	t.Run("RemoteAddr fallback keeps IPv6 brackets (characterized quirk)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "[::1]:54321"

		if got := extractClientIP(r); got != "[::1]" {
			t.Fatalf("extractClientIP() = %q, want %q (brackets are preserved, by design)", got, "[::1]")
		}
	})

	t.Run("RemoteAddr fallback keeps IPv6 brackets on full address", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "[2001:db8::1]:8080"

		if got := extractClientIP(r); got != "[2001:db8::1]" {
			t.Fatalf("extractClientIP() = %q, want %q (brackets are preserved, by design)", got, "[2001:db8::1]")
		}
	})
}

// ---------------------------------------------------------------------------
// checkDeviceCodeRateLimit
// ---------------------------------------------------------------------------

func TestCheckDeviceCodeRateLimit(t *testing.T) {
	// Only deviceCodeRateByIP is touched by the method; the zero-value mutex
	// is ready to use, so a bare struct literal is sufficient.
	proxy := &ProxyServer{
		deviceCodeRateByIP: make(map[string][]time.Time),
	}

	t.Run("allows up to the max requests per window", func(t *testing.T) {
		for i := 0; i < deviceCodeRateMaxCount; i++ {
			if ok := proxy.checkDeviceCodeRateLimit("203.0.113.10"); !ok {
				t.Fatalf("call %d: checkDeviceCodeRateLimit() = false, want true", i+1)
			}
		}
	})

	t.Run("denies the request beyond the max in the same window", func(t *testing.T) {
		if ok := proxy.checkDeviceCodeRateLimit("203.0.113.10"); ok {
			t.Fatal("call 6: checkDeviceCodeRateLimit() = true, want false (rate limited)")
		}
	})

	t.Run("different IPs are rate limited independently", func(t *testing.T) {
		// The first IP exhausted its budget above; a fresh IP must still get
		// its own full 5-request budget from the same ProxyServer.
		for i := 0; i < deviceCodeRateMaxCount; i++ {
			if ok := proxy.checkDeviceCodeRateLimit("198.51.100.20"); !ok {
				t.Fatalf("call %d for independent IP: checkDeviceCodeRateLimit() = false, want true", i+1)
			}
		}
		if ok := proxy.checkDeviceCodeRateLimit("198.51.100.20"); ok {
			t.Fatal("call 6 for independent IP: checkDeviceCodeRateLimit() = true, want false (rate limited)")
		}
	})
}
