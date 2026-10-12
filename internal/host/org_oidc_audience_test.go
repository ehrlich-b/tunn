package host

import (
	"github.com/golang-jwt/jwt/v4"
	"testing"
)

func TestReviewAdditionalUntrustedAudience(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	r, _ := f.begin(t, func(c jwt.MapClaims) {
		c["aud"] = []string{f.org.ClientID, "untrusted-application"}
		c["azp"] = f.org.ClientID
	}, "")
	w := f.finish(r)
	if w.Code != 403 {
		t.Fatalf("untrusted extra audience accepted: %d", w.Code)
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authCookieName {
			t.Fatal("rejected token created a session")
		}
	}
}
