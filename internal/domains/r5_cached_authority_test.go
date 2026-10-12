package domains

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"modernc.org/sqlite"
)

// Schedule a committed revocation after Route authorizes the request and
// immediately before the certificate/key SELECT, without changing product code.
type r5Connector struct {
	path   string
	before func()
}

func (c *r5Connector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.path)
	if err != nil {
		return nil, err
	}
	return &r5Conn{Conn: conn, before: c.before}, nil
}

func (c *r5Connector) Driver() driver.Driver { return &sqlite.Driver{} }

type r5Conn struct {
	driver.Conn
	before func()
}

func (c *r5Conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(query, "SELECT certificate,key FROM custom_domains") && c.before != nil {
		before := c.before
		c.before = nil
		before()
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *r5Conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func TestR5ConcreteCachedKeyRechecksAuthority(t *testing.T) {
	for _, mutation := range []struct {
		name  string
		query string
	}{
		{"reservation", `UPDATE reserved_subdomains SET account_id='two' WHERE subdomain='site'`},
		{"entitlement", `UPDATE accounts SET plan='free' WHERE id='one'`},
		{"lease_and_state", `UPDATE custom_domains SET state='dns_verification_failed',verified_until=0 WHERE name='work.example.com'`},
		{"lease_expired", `UPDATE custom_domains SET verified_until=? WHERE name='work.example.com'`},
		{"state_cleared", `UPDATE custom_domains SET state='dns_verification_failed' WHERE name='work.example.com'`},
		{"certificate_expired", `UPDATE custom_domains SET not_after=? WHERE name='work.example.com'`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			r, dns, _ := domainFixture(t, nil)
			ctx := context.Background()
			claim := addDomain(t, r, "work.example.com", "site", "one")
			dns.records[claim.Name] = claim.CnameTarget
			cert, key := fakeCert(t, claim.Name, r.now())
			r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
				return cert, key, nil
			})
			if _, err := r.Verify(ctx, claim); err != nil {
				t.Fatal(err)
			}
			pair, err := r.Certificate(ctx, &pb.Domain{Name: claim.Name})
			if err != nil || pair == nil || !bytes.Equal(pair.CertificatePem, cert) || !bytes.Equal(pair.KeyPem, key) {
				t.Fatalf("authorized cached certificate: pair=%v err=%v", pair != nil, err)
			}
			path := filepath.Join(t.TempDir(), "authority.db")
			if _, err := r.db.Exec(`VACUUM INTO ?`, path); err != nil {
				t.Fatal(err)
			}
			writer, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			fired := false
			hook := func() {
				fired = true
				var args []any
				if strings.Contains(mutation.query, "?") {
					args = append(args, r.now().Unix())
				}
				result, err := writer.ExecContext(ctx, mutation.query, args...)
				if err != nil {
					t.Fatal(err)
				}
				if n, err := result.RowsAffected(); err != nil || n != 1 {
					t.Fatalf("revocation affected %d rows: %v", n, err)
				}
				t.Log("revocation committed after Route authorization and before certificate/key SELECT")
			}
			hooked := sql.OpenDB(&r5Connector{path: path, before: hook})
			defer hooked.Close()
			hooked.SetMaxOpenConns(1)
			r.db = hooked
			pair, err = r.Certificate(ctx, &pb.Domain{Name: claim.Name})
			if !fired {
				t.Fatal("key-read scheduling hook did not execute")
			}
			_, nextErr := r.Certificate(ctx, &pb.Domain{Name: claim.Name})
			if nextErr == nil {
				t.Fatal("subsequent routing failed to enforce revocation")
			}
			if pair != nil || status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "app reservation or domain authority changed" {
				t.Fatalf("cached key read after committed %s revocation: pair=%v err=%v; next lookup denies: %v", mutation.name, pair != nil, err, nextErr)
			}
		})
	}
}
