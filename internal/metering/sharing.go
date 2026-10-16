package metering

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/mcpauth"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// SharingBackend uses the same authenticated login-node connection as grants.
type SharingBackend interface {
	Sharing(context.Context, *pb.SharingRequest) (*pb.SharingResponse, error)
}

func (s *Store) initSharing() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS web_resources (
 endpoint TEXT PRIMARY KEY, owner TEXT NOT NULL, id TEXT UNIQUE NOT NULL, mode TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS web_resources_owner ON web_resources(owner);
 CREATE INDEX IF NOT EXISTS meter_grants_owner_endpoint ON meter_grants(owner,endpoint);
 CREATE TABLE IF NOT EXISTS sharing_audit (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, resource TEXT NOT NULL,
 actor TEXT NOT NULL, target TEXT NOT NULL, action TEXT NOT NULL,
 decided_at INTEGER NOT NULL, grant_id TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS sharing_audit_owner ON sharing_audit(owner,sequence);
 CREATE TABLE IF NOT EXISTS sharing_mutation_rate (owner TEXT PRIMARY KEY, minute INTEGER NOT NULL, count INTEGER NOT NULL);`)
	if err != nil {
		return err
	}
	// Old versions stored history as extra grant rows. Preserve the newest
	// decision (including revocation), move older decisions to bounded audit.
	return s.transaction(context.Background(), func(tx *sql.Tx) error {
		var merges int
		if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='account_merges'`).Scan(&merges); err != nil {
			return err
		}
		if merges != 0 {
			if _, err := tx.Exec(`UPDATE web_resources SET owner=COALESCE((SELECT account_id FROM account_merges WHERE old_id=web_resources.owner),owner)`); err != nil {
				return err
			}
		}
		// Repair ownership before testing for orphans so merged live resources
		// retain their current decisions, including revocations.
		if err := s.retireSharingGrants(context.Background(), tx, "resource-retired", `NOT EXISTS (
            SELECT 1 FROM web_resources r WHERE r.id=g.endpoint AND r.owner=g.owner)`); err != nil {
			return err
		}
		return s.retireSharingGrants(context.Background(), tx, "legacy-history", `EXISTS (
            SELECT 1 FROM meter_grants newer WHERE newer.owner=g.owner AND newer.endpoint=g.endpoint AND newer.rowid>g.rowid
            AND json_extract(CAST(newer.data AS TEXT),'$.consumer')=json_extract(CAST(g.data AS TEXT),'$.consumer'))`)
	})
}

// retireSharingGrants moves obsolete person/group decisions into bounded audit
// in the caller's transaction. Machine grants have an independent lifecycle.
// The predicates are internal SQL; request values are always bound arguments.
func (s *Store) retireSharingGrants(ctx context.Context, tx *sql.Tx, action, predicate string, args ...any) error {
	for {
		// Process one decision at a time to keep upgrade memory bounded. Rowid
		// order also preserves the order of historical decisions in the audit.
		var data []byte
		var id, owner, resource string
		err := tx.QueryRowContext(ctx, `SELECT g.id,g.owner,g.endpoint,g.data FROM meter_grants g
            WHERE (substr(json_extract(CAST(g.data AS TEXT),'$.consumer'),1,7)='person:'
                OR substr(json_extract(CAST(g.data AS TEXT),'$.consumer'),1,6)='group:')
            AND (`+predicate+`) ORDER BY g.rowid LIMIT 1`, args...).Scan(&id, &owner, &resource, &data)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		g := new(pb.Grant)
		if err = json.Unmarshal(data, g); err != nil {
			return err
		}
		g.Id, g.Owner, g.Endpoint = id, owner, resource
		if err = s.sharingAudit(ctx, tx, owner, resource, g.Consumer, action, g); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM meter_grants WHERE id=?`, id); err != nil {
			return err
		}
	}
}

func validPerson(email string, domain bool) bool {
	if domain && strings.HasPrefix(email, "@") {
		email = "person" + email
	}
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email && !strings.ContainsAny(email, " \r\n")
}

var resourceName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// A name reclaimed by another owner gets a fresh immutable resource ID. Same-owner
// reconnects retain permissions; registration never replays a revoked allow-list.
func (s *Store) Sharing(ctx context.Context, in *pb.SharingRequest) (*pb.SharingResponse, error) {
	in = proto.Clone(in).(*pb.SharingRequest)
	out := &pb.SharingResponse{}
	if in.Owner == "" || in.Operation != "list" && !resourceName.MatchString(in.Endpoint) {
		return nil, fmt.Errorf("invalid resource owner or name")
	}
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		in.Owner, err = canonicalOwner(tx, in.Owner)
		if err != nil {
			return err
		}
		if in.Operation == "share" || in.Operation == "unshare" || in.Operation == "register" {
			if err = s.sharingMutationAdmission(ctx, tx, in.Owner); err != nil {
				return err
			}
		}
		if in.Operation == "list" {
			rows, err := tx.QueryContext(ctx, `SELECT id,owner,endpoint,mode FROM web_resources WHERE owner=? AND mode<>'policy-only' ORDER BY endpoint`, in.Owner)
			if err != nil {
				return err
			}
			for rows.Next() {
				r := new(pb.WebResource)
				if err = rows.Scan(&r.Id, &r.Owner, &r.Endpoint, &r.Mode); err != nil {
					rows.Close()
					return err
				}
				out.Resources = append(out.Resources, r)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		} else {
			r := &pb.WebResource{Endpoint: in.Endpoint}
			err := tx.QueryRowContext(ctx, `SELECT id,owner,mode FROM web_resources WHERE endpoint=?`, in.Endpoint).Scan(&r.Id, &r.Owner, &r.Mode)
			fresh := errors.Is(err, sql.ErrNoRows) || err == nil && r.Owner != in.Owner
			if in.Operation == "register" {
				if len(in.InitialEmails) > s.maxResourcePeople {
					return ErrCapacity
				}
				if in.Mode != "private" && in.Mode != "public" && in.Mode != "legacy-public" && in.Mode != "policy-only" {
					return fmt.Errorf("invalid exposure")
				}
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				if fresh && err == nil {
					if err := mcpauth.Revoke(ctx, tx, r.Owner, r.Endpoint, "", ""); err != nil {
						return err
					}
					if err = s.retireSharingGrants(ctx, tx, "resource-retired", `g.endpoint=?`, r.Id); err != nil {
						return err
					}
				}
				if fresh {
					r.Id = uuid.NewString()
					r.Owner = in.Owner
				}
				if !fresh && in.Mode == "legacy-public" && r.Mode != "legacy-public" {
					return fmt.Errorf("legacy publisher cannot make a managed resource public; update tunn")
				}
				if fresh {
					var count int
					if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM web_resources`).Scan(&count); err != nil {
						return err
					}
					if count >= s.maxGrants {
						return ErrCapacity
					}
				}
				if fresh {
					var owned int
					if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM web_resources WHERE owner=?`, in.Owner).Scan(&owned); err != nil {
						return err
					}
					if owned >= s.maxOwnerResources {
						return ErrCapacity
					}
				}
				r.Mode = in.Mode
				if _, err = tx.ExecContext(ctx, `INSERT INTO web_resources(endpoint,owner,id,mode) VALUES(?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET owner=excluded.owner,id=excluded.id,mode=excluded.mode`, r.Endpoint, r.Owner, r.Id, r.Mode); err != nil {
					return err
				}
				if fresh || r.Mode == "policy-only" {
					for _, email := range in.InitialEmails {
						// Upgrade MCP permission metadata without restoring an existing decision.
						if !fresh {
							var existing int
							if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM meter_grants WHERE owner=? AND endpoint=? AND json_extract(CAST(data AS TEXT),'$.consumer')=?`, r.Owner, r.Id, sharingConsumer(normalizeSharingTarget(email))).Scan(&existing); err != nil {
								return err
							}
							if existing != 0 {
								continue
							}
						}

						if err = s.sharePerson(ctx, tx, r, normalizeSharingTarget(email), s.now().AddDate(100, 0, 0).UnixMilli(), true); err != nil {
							return err
						}
					}
				}
			} else {
				if err != nil || r.Owner != in.Owner || in.ResourceId != "" && in.ResourceId != r.Id {
					return fmt.Errorf("resource not found")
				}
				switch in.Operation {
				case "get":
				case "share":
					if r.Mode != "private" && r.Mode != "policy-only" {
						return fmt.Errorf("use a private resource to share with people")
					}
					if err = s.sharePerson(ctx, tx, r, normalizeSharingTarget(in.Email), in.ExpiresAt, false); err != nil {
						return err
					}
				case "unshare":
					if !validSharingTarget(normalizeSharingTarget(in.Email), true) {
						return fmt.Errorf("invalid email")
					}
					if err = s.revokePerson(ctx, tx, r, normalizeSharingTarget(in.Email)); err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported sharing operation")
				}
			}
			out.Resources = append(out.Resources, r)
		}
		for _, r := range out.Resources {
			rows, err := tx.QueryContext(ctx, `SELECT data FROM meter_grants WHERE owner=? AND endpoint=? ORDER BY id`, r.Owner, r.Id)
			if err != nil {
				return err
			}
			for rows.Next() {
				var data []byte
				if err = rows.Scan(&data); err != nil {
					rows.Close()
					return err
				}
				g := new(pb.Grant)
				if err = json.Unmarshal(data, g); err != nil {
					rows.Close()
					return err
				}
				g.TokenSha256 = nil
				r.People = append(r.People, g)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) revokePerson(ctx context.Context, tx *sql.Tx, r *pb.WebResource, email string) error {
	if err := mcpauth.Revoke(ctx, tx, r.Owner, r.Endpoint, "", email); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT data FROM meter_grants WHERE owner=? AND endpoint=?`, r.Owner, r.Id)
	if err != nil {
		return err
	}
	var grants []*pb.Grant
	for rows.Next() {
		var data []byte
		if err = rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		g := new(pb.Grant)
		if err = json.Unmarshal(data, g); err != nil {
			rows.Close()
			return err
		}
		if g.Consumer == sharingConsumer(email) {
			grants = append(grants, g)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, g := range grants {
		g.Revoked = true
		if err = s.sharingAudit(ctx, tx, r.Owner, r.Id, g.Consumer, "unshare", g); err != nil {
			return err
		}
		data, _ := json.Marshal(g)
		if _, err = tx.ExecContext(ctx, `UPDATE meter_grants SET data=? WHERE id=?`, data, g.Id); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) sharePerson(ctx context.Context, tx *sql.Tx, r *pb.WebResource, email string, expires int64, domain bool) error {
	if !validSharingTarget(email, domain) || expires <= s.now().UnixMilli() {
		return fmt.Errorf("verified email and future expiry required")
	}
	consumer := sharingConsumer(email)
	var data []byte
	err := tx.QueryRowContext(ctx, `SELECT data FROM meter_grants WHERE owner=? AND endpoint=? AND json_extract(CAST(data AS TEXT),'$.consumer')=?`, r.Owner, r.Id, consumer).Scan(&data)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var g *pb.Grant
	if err == nil {
		g = new(pb.Grant)
		if err = json.Unmarshal(data, g); err != nil {
			return err
		}
		// Renewal and re-sharing update the current decision in place, even when
		// the global cap is full. A revoked decision stays durable until re-shared.
		g.ExpiresAt, g.Revoked = expires, false
		data, err = json.Marshal(g)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE meter_grants SET expires=?,data=? WHERE id=?`, expires, data, g.Id)
	} else {
		if err = s.grantCapacity(ctx, tx, r.Owner, r.Id, true); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(uuid.NewString()))
		g = &pb.Grant{Id: uuid.NewString(), Owner: r.Owner, Endpoint: r.Id, Consumer: consumer, TokenSha256: digest[:], ExpiresAt: expires}
		data, err = json.Marshal(g)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO meter_grants(id,owner,endpoint,digest,expires,data) VALUES(?,?,?,?,?,?)`, g.Id, r.Owner, r.Id, digest[:], expires, data)
	}
	if err != nil {
		return err
	}
	return s.sharingAudit(ctx, tx, r.Owner, r.Id, consumer, "share", g)
}

func validSharingTarget(target string, domain bool) bool {
	return config.ValidOIDCGroupSubject(target) || validPerson(target, domain)
}

func sharingConsumer(target string) string {
	if config.ValidOIDCGroupSubject(target) {
		return target
	}
	return "person:" + target
}

func normalizeSharingTarget(target string) string {
	// Org/group IDs are opaque policy identifiers, not normalized email aliases.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(target)), "group:") {
		return target
	}
	return common.NormalizeEmail(target)
}
