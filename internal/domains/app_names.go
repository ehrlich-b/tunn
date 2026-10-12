package domains

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// n and d must be bound to the same claim target by the calling query. Historical
// bindings retain their independent global reservation revocation predicate.
const appAuthority = `(n.legacy=0 OR EXISTS(SELECT 1 FROM reserved_subdomains s WHERE s.subdomain=n.tunnel AND s.account_id=d.owner))`

func reserveWildcardApp(ctx context.Context, tx *sql.Tx, parent, owner, label string, now time.Time) error {
	var target string
	if err := tx.QueryRowContext(ctx, `SELECT target FROM custom_domains WHERE name=? AND owner=?`, parent, owner).Scan(&target); err != nil {
		return status.Error(codes.PermissionDenied, "namespace must belong to the app owner")
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM namespace_app_names WHERE parent=? AND target=? AND label=?`, parent, target, label).Scan(&count); err != nil {
		return err
	}
	if count == 1 {
		return nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM namespace_app_names WHERE parent=? AND target=?`, parent, target).Scan(&count); err != nil {
		return err
	}
	if count >= store.MaxNamespaceAppNamesPro {
		return status.Errorf(codes.ResourceExhausted, "namespace %s app-name limit reached (Pro: %d names); delete the namespace to remove its names before adding another", parent, store.MaxNamespaceAppNamesPro)
	}
	// Reuse an explicitly owned global reservation without releasing it. Otherwise
	// generate an internal endpoint scoped to this claim, allowing equal labels in
	// different customers' namespaces and avoiding global auto-reservation.
	tunnel := label
	legacy := 0
	var globalOwner string
	err := tx.QueryRowContext(ctx, `SELECT account_id FROM reserved_subdomains WHERE subdomain=?`, label).Scan(&globalOwner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if globalOwner == owner {
		legacy = 1
	} else {
		token := make([]byte, 24)
		if _, err := rand.Read(token); err != nil {
			return err
		}
		tunnel = fmt.Sprintf("ns-%x", token)
		var occupied int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM reserved_subdomains WHERE subdomain=?`, tunnel).Scan(&occupied); err != nil {
			return err
		}
		if occupied != 0 {
			return status.Error(codes.Aborted, "publisher ID collision; retry adding the app name")
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO namespace_app_names(parent,target,label,tunnel,legacy,created_at) VALUES(?,?,?,?,?,?)`, parent, target, label, tunnel, legacy, now.Unix())
	return err
}

func (r *Registry) appNames(ctx context.Context, d *pb.Domain) error {
	if !strings.HasPrefix(d.Name, "*.") {
		return nil
	}
	d.AppNameLimit = store.MaxNamespaceAppNamesPro
	rows, err := r.db.QueryContext(ctx, `SELECT label,tunnel,legacy FROM namespace_app_names WHERE parent=? AND target=? ORDER BY label`, d.Name, d.CnameTarget)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		n := new(pb.AppName)
		if err := rows.Scan(&n.Label, &n.Tunnel, &n.Legacy); err != nil {
			return err
		}
		d.AppNames = append(d.AppNames, n)
	}
	return rows.Err()
}
func (r *Registry) managementRead(ctx context.Context, name string) (*pb.Domain, error) {
	d, err := r.read(ctx, name)
	if err != nil {
		return nil, err
	}
	if err = r.appNames(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}
