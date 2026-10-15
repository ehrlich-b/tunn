package client

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestWebSocketResponseCookieFields(t *testing.T) {
	cookies := []string{
		"session=one,two=three; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/; HttpOnly",
		"preference=dark; Path=/; SameSite=Lax",
	}
	for _, status := range []int{http.StatusSwitchingProtocols, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			sender := new(webReplaySender)
			if err := sendHTTPConnectionHead(sender, "cookies", status, http.Header{
				"Set-Cookie": cookies, "X-Application": {"first", "second"},
			}); err != nil {
				t.Fatal(err)
			}
			if len(sender.messages) != 1 {
				t.Fatalf("sent %d messages, want one acceptance", len(sender.messages))
			}
			accept := sender.messages[0].GetConnectionAccept()
			if accept.GetConnectionId() != "cookies" || !accept.GetSuccess() || accept.GetHttpResponse().GetStatusCode() != int32(status) {
				t.Fatalf("unexpected acceptance: %v", accept)
			}
			head := accept.HttpResponse
			var gotCookies, gotApplication []string
			for _, field := range head.HeaderFields {
				switch field.Name {
				case "Set-Cookie":
					gotCookies = append(gotCookies, field.Value)
				case "X-Application":
					gotApplication = append(gotApplication, field.Value)
				}
			}
			if !reflect.DeepEqual(gotCookies, cookies) {
				t.Errorf("cookie fields = %q, want %q", gotCookies, cookies)
			}
			if !reflect.DeepEqual(gotApplication, []string{"first", "second"}) {
				t.Errorf("application fields = %q", gotApplication)
			}
			if head.Headers["Set-Cookie"] != strings.Join(cookies, ", ") || head.Headers["X-Application"] != "first, second" {
				t.Errorf("legacy response map changed: %v", head.Headers)
			}
		})
	}
}
