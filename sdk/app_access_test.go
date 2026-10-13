package tunn

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAppDeviceQRTrustAndScopedHTTPWebSocketHeader(t *testing.T) {
	handle := "tunn_inv_" + strings.Repeat("A", 43)
	qr := "https://login.example.test/pair/app-device#invitation=" + handle + "&hostname=wing.apps.test"
	i, err := ParseAppInvitation("https://login.example.test", qr)
	if err != nil || i.Hostname != "wing.apps.test" || i.Handle != handle {
		t.Fatal("trusted invitation rejected")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", i, i), handle) {
		t.Fatal("invitation string leaks handle")
	}
	for _, bad := range []string{
		strings.Replace(qr, "login.example.test", "evil.example.test", 1),
		strings.Replace(qr, "https:", "http:", 1),
		strings.Replace(qr, "/pair/app-device", "/redirect", 1),
		strings.Replace(qr, "/pair/app-device#", "/pair/app-device?redirect=evil#", 1),
		qr + "&invitation=" + handle,
		strings.Replace(qr, "wing.apps.test", "wing.apps.test.evil:8443", 1),
		strings.Replace(qr, "https://", "https://user@", 1),
	} {
		if _, err := ParseAppInvitation("https://login.example.test", bad); err == nil {
			t.Fatal("untrusted or malformed QR accepted")
		}
	}
	credential := "tunn_app_" + strings.Repeat("A", 43)
	for _, ws := range []bool{false, true} {
		r, _ := http.NewRequest("GET", "https://wing.apps.test/phone", nil)
		r.Header.Set("Authorization", "Bearer upstream")
		if ws {
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "Upgrade")
		}
		if err := SetAppAuthorization(r, "wing.apps.test", credential); err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("Tunn-Authorization") != "Bearer "+credential || r.Header.Get("Authorization") != "Bearer upstream" {
			t.Fatal("scoped header lost upstream auth")
		}
	}
	for _, target := range []string{"http://wing.apps.test/", "https://other.apps.test/", "https://wing.apps.test.evil/", "https://user@wing.apps.test/"} {
		r, _ := http.NewRequest("GET", target, nil)
		if err := SetAppAuthorization(r, "wing.apps.test", credential); err == nil || r.Header.Get("Tunn-Authorization") != "" {
			t.Fatal("credential left scoped HTTPS transport")
		}
	}
	r := &http.Request{URL: &url.URL{Scheme: "https", Host: "wing.apps.test"}, Host: "other.apps.test", Header: make(http.Header)}
	if err := SetAppAuthorization(r, "wing.apps.test", credential); err == nil {
		t.Fatal("conflicting HTTP Host accepted")
	}
}

func TestAppDeviceHTTPClientRejectsCredentialRedirectsAndCookies(t *testing.T) {
	destinationHits := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationHits++; w.WriteHeader(200) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer origin.Close()
	client := AppDeviceHTTPClient(nil, time.Second)
	if client.Jar != nil {
		t.Fatal("app client inherited browser cookies")
	}
	request, _ := http.NewRequest("POST", origin.URL, strings.NewReader("disposable-fixture"))
	request.Header.Set("Tunn-Authorization", "Bearer fixture-only")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 302 || destinationHits != 0 {
		t.Fatal("app client followed credential-bearing redirect")
	}
}
