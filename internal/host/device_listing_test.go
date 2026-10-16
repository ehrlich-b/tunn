package host

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/storage"
)

type deviceListingStorage struct {
	storage.Storage
	lookups int
}

func (s *deviceListingStorage) GetAccount(ctx context.Context, id string) (*storage.Account, error) {
	s.lookups++
	return s.Storage.GetAccount(ctx, id)
}

func (s *deviceListingStorage) GetAccountByEmail(ctx context.Context, email string) (*storage.Account, error) {
	s.lookups++
	return s.Storage.GetAccountByEmail(ctx, email)
}

func TestDeviceListingAccountScopedLookups(t *testing.T) {
	p := durableFixture(t)
	ctx := context.Background()
	old, err := p.storage.FindOrCreateByEmails(ctx, []string{"merged@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	oldCookie := emailSession(t, p, old.PrimaryEmail)
	owner, err := p.storage.GetAccountByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ownerCookie := emailSession(t, p, owner.PrimaryEmail)
	other, err := p.storage.FindOrCreateByEmails(ctx, []string{"other@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	merged, err := p.storage.FindOrCreateByEmails(ctx, []string{owner.PrimaryEmail, old.PrimaryEmail}, "test")
	if err != nil {
		t.Fatalf("merge: %v, %v", merged, err)
	}
	if merged.ID == old.ID {
		owner, old = old, owner
		oldCookie = ownerCookie
	}
	insert := func(id, account, email, purpose string, created, revoked int) {
		t.Helper()
		_, err := p.devices.db.Exec(`INSERT INTO durable_devices(id,email,name,digest,created,last_used,revoked,purpose,account_id) VALUES(?,?,?,?,?,?,?,?,?)`, id, email, id, []byte(id), created, created, revoked, purpose, account)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("dev_current", owner.ID, owner.PrimaryEmail, "publisher", 10, 0)
	insert("dev_merged", old.ID, old.PrimaryEmail, "management", 20, 0)
	insert("dev_revoked", old.ID, old.PrimaryEmail, "publisher", 30, 40)
	// Email is not the ownership authority, even when it matches the session.
	insert("dev_unbound", "unbound-credential", owner.PrimaryEmail, "publisher", 40, 0)
	cookies := []*http.Cookie{emailSession(t, p, owner.PrimaryEmail), oldCookie, securityCookie(t, p, owner.PrimaryEmail)}
	counted := &deviceListingStorage{Storage: p.storage}
	p.storage = counted
	for _, total := range []int{0, 1, 128} {
		t.Run(fmt.Sprintf("unrelated=%d", total), func(t *testing.T) {
			for i := 0; i < total; i++ {
				insert(fmt.Sprintf("dev_other_%d_%d", total, i), other.ID, owner.PrimaryEmail, "publisher", 50+i, 0)
			}
			for _, cookie := range cookies {
				counted.lookups = 0
				r := httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				p.handleDevices(w, r)
				if w.Code != http.StatusOK {
					t.Fatalf("listing: %d %s", w.Code, w.Body)
				}
				body := w.Body.String()
				previous := -1
				for _, id := range []string{"dev_revoked", "dev_merged", "dev_current"} {
					pos := strings.Index(body, "<code>"+id+"</code>")
					if pos <= previous {
						t.Errorf("missing or unordered device %s: %s", id, body)
					}
					previous = pos
				}
				if strings.Contains(body, "dev_other_") || strings.Contains(body, "dev_unbound") || strings.Count(body, "<form ") != 2 {
					t.Errorf("unexpected devices or revoke forms: %s", body)
				}
				if counted.lookups != 1 {
					t.Errorf("account lookups = %d, want 1 regardless of device count", counted.lookups)
				}
				t.Logf("unrelated devices added=%d, account lookups=%d", total, counted.lookups)
			}
		})
	}
}
