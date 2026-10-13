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

func TestInspectionHistoryEncodedCredentialsNeverEnterMetadataOrReplay(t *testing.T) {
	for _, prefix := range []string{"tunn_app_", "tunn_inv_"} {
		secret := prefix + "synthetic-private-value"
		for _, path := range []string{"/path/%74" + secret[1:], "/hooks?%74" + secret[1:] + "=x"} {
			event := Metadata("connection", "GET", path, map[string]string{"Host": "api.example.test"})
			data, _ := json.Marshal(event)
			if strings.Contains(string(data), secret) || !event.MetadataTruncated {
				t.Fatal("encoded credential retained in metadata")
			}
			// Historical metadata may predate the stricter filter. Replay must not
			// assume an old path is safe merely because no replacement was provided.
			legacy := Event{Path: path, Headers: map[string]string{"Host": "api.example.test"}}
			if _, _, _, err := Reconstruct(legacy, Request{}); err == nil {
				t.Fatal("encoded historical path replayed")
			}
			legacy.QueryRedacted = strings.Contains(path, "?")
			if _, _, _, err := Reconstruct(legacy, Request{Path: &path}); err == nil {
				t.Fatal("encoded replacement replayed")
			}
		}
	}
	path := "/hooks?ordinary%20key=restored"
	event := Metadata("connection", "GET", path, map[string]string{"Host": "api.example.test"})
	if event.MetadataTruncated {
		t.Fatal("ordinary encoded key suppressed")
	}
	if _, _, _, err := Reconstruct(event, Request{Path: &path}); err != nil {
		t.Fatal("ordinary encoded query replay rejected", err)
	}
	path = "/ordinary/%61pp"
	event = Metadata("connection", "GET", path, map[string]string{"Host": "api.example.test"})
	if event.MetadataTruncated {
		t.Fatal("ordinary encoded path suppressed")
	}
	if _, _, _, err := Reconstruct(event, Request{}); err != nil {
		t.Fatal("ordinary encoded path replay rejected", err)
	}
}
