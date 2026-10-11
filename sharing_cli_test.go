package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/ehrlich-b/tunn/internal/client"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSharingCLICommandsAndExpiry(t *testing.T) {
	for _, command := range []string{"share", "unshare", "access"} {
		args := []string{"preview"}
		if command != "access" {
			args = append(args, "alice@example.com")
		}
		if command == "share" {
			args = append(args, "--expires", "1h")
		}
		o, err := parseSharing(command, args)
		if err != nil || o.Endpoint != "preview" {
			t.Fatal(o, err)
		}
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/sharing/preview" || r.Header.Get("Authorization") != "Bearer owner-token" {
				t.Error("lost owner authentication")
			}
			want := map[string]string{"share": "POST", "unshare": "DELETE", "access": "GET"}[command]
			if r.Method != want {
				t.Error("wrong verb")
			}
			body, _ := io.ReadAll(r.Body)
			if command == "share" && !strings.Contains(string(body), `"expires_at"`) {
				t.Error("expiry omitted")
			}
			io.WriteString(w, `{"resources":[]}`)
		}))
		o.Server = strings.TrimPrefix(server.URL, "https://")
		var out bytes.Buffer
		if err = executeSharing(context.Background(), command, o, "owner-token", server.Client(), &out); err != nil || !strings.Contains(out.String(), "resources") {
			t.Fatal(err, out.String())
		}
		server.Close()
	}
	for _, args := range [][]string{{}, {"preview"}, {"preview", "alice@example.com", "--expires", "-1h"}, {"preview", "alice@example.com", "extra"}} {
		if _, err := parseSharing("share", args); err == nil {
			t.Fatal("invalid sharing options accepted")
		}
	}
}

func TestWebPublisherEnrollmentContinuesOriginalCommand(t *testing.T) {
	for _, scenario := range []string{"saved", "new", "enrollment-denied", "save-failed"} {
		loads, enrollments := 0, 0
		load := func(ctx context.Context, server string, insecure bool) (string, *client.CredentialManager, error) {
			loads++
			if server != "relay.example:443" || insecure {
				t.Fatal("wrong enrollment authority")
			}
			if scenario == "saved" || loads == 2 && scenario == "new" {
				return "saved-device-token", nil, nil
			}
			return "", nil, errors.New("no usable credentials")
		}
		enroll := func(context.Context) error {
			enrollments++
			if scenario == "enrollment-denied" {
				return errors.New("denied")
			}
			return nil
		}
		token, _, err := loadOrEnrollWebPublisher(context.Background(), "relay.example:443", false, load, enroll)
		switch scenario {
		case "saved":
			if err != nil || loads != 1 || enrollments != 0 {
				t.Fatal("saved publisher prompted again")
			}
		case "new":
			if err != nil || token != "saved-device-token" || loads != 2 || enrollments != 1 {
				t.Fatal("enrollment did not resume publishing")
			}
		default:
			if err == nil || token != "" {
				t.Fatal("failed enrollment admitted publisher")
			}
		}
	}
}

func TestOIDCGroupShareCLI(t *testing.T) {
	for _, command := range []string{"share", "unshare"} {
		o, err := parseSharing(command, []string{"preview", "group:company:engineering"})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"email":"group:company:engineering"`) || r.Header.Get("Authorization") != "Bearer owner-token" {
				t.Error("CLI lost owner/group binding")
			}
			io.WriteString(w, `{"resources":[]}`)
		}))
		o.Server = strings.TrimPrefix(server.URL, "https://")
		if err := executeSharing(context.Background(), command, o, "owner-token", server.Client(), io.Discard); err != nil {
			t.Fatal(err)
		}
		server.Close()
	}
}
