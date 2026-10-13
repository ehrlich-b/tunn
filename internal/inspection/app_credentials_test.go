package inspection

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectionHistoryAppCredentialsAreSuppressed(t *testing.T) {
	for _, prefix := range []string{"tunn_app_", "tunn_inv_"} {
		secret := prefix + "synthetic-private-value"
		event := Metadata("connection", "GET", "/path/"+secret, map[string]string{"Host": "api.example.test", "Accept": secret})
		data, _ := json.Marshal(event)
		if strings.Contains(string(data), secret) || event.Path != "[unavailable path]" || event.Headers["Accept"] != Redacted {
			t.Fatal("credential survived metadata capture")
		}
		_, original := historyFixture(t)
		cleanPath := "/hooks?token=restored"
		body := []byte("data")
		headers := map[string]string{"Host": "api.example.test", "Content-Type": "application/json", "Authorization": "explicit", "X-Custom": "explicit"}
		normal := Request{Path: &cleanPath, Body: &body, Headers: headers}
		if _, _, _, err := Reconstruct(original, normal); err != nil {
			t.Fatal("normal reconstruction rejected", err)
		}
		path := "/hooks?token=" + secret
		if _, _, _, err := Reconstruct(original, Request{Path: &path, Body: &body, Headers: headers}); err == nil {
			t.Fatal("credential query reconstructed")
		}
		replacement := make(map[string]string)
		for k, v := range headers {
			replacement[k] = v
		}
		replacement["X-Custom"] = secret
		if _, _, _, err := Reconstruct(original, Request{Path: &cleanPath, Body: &body, Headers: replacement}); err == nil {
			t.Fatal("credential header reconstructed")
		}
		sensitive := []byte(secret)
		if _, _, _, err := Reconstruct(original, Request{Path: &cleanPath, Body: &sensitive, Headers: headers}); err == nil {
			t.Fatal("credential body reconstructed")
		}
	}
}
