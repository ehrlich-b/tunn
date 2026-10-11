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
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"github.com/google/uuid"
)

// SharingBackend uses the same authenticated login-node connection as grants.
type SharingBackend interface {
	Sharing(context.Context, *pb.SharingRequest) (*pb.SharingResponse, error)
}

func (s *Store) initSharing() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS web_resources (
 endpoint TEXT PRIMARY KEY, owner TEXT NOT NULL, id TEXT UNIQUE NOT NULL, mode TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS web_resources_owner ON web_resources(owner);`)
	return err
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
	out := &pb.SharingResponse{}
	if in.Owner == "" || in.Operation != "list" && !resourceName.MatchString(in.Endpoint) {
		return nil, fmt.Errorf("invalid resource owner or name")
	}
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		if in.Operation == "list" {
			rows, err := tx.QueryContext(ctx, `SELECT id,owner,endpoint,mode FROM web_resources WHERE owner=? ORDER BY endpoint`, in.Owner)
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
				if in.Mode != "private" && in.Mode != "public" && in.Mode != "legacy-public" {
					return fmt.Errorf("invalid exposure")
				}
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
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
					if count >= MaxGrants {
						return ErrCapacity
					}
				}
				r.Mode = in.Mode
				if _, err = tx.ExecContext(ctx, `INSERT INTO web_resources(endpoint,owner,id,mode) VALUES(?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET owner=excluded.owner,id=excluded.id,mode=excluded.mode`, r.Endpoint, r.Owner, r.Id, r.Mode); err != nil {
					return err
				}
				if fresh {
					for _, email := range in.InitialEmails {
						if err = s.sharePerson(ctx, tx, r, normalizeSharingTarget(email), time.Now().AddDate(100, 0, 0).UnixMilli(), true); err != nil {
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
					if r.Mode != "private" {
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
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM meter_grants`).Scan(&count); err != nil {
		return err
	}
	if count >= s.maxGrants {
		return ErrCapacity
	}
	if err := s.revokePerson(ctx, tx, r, email); err != nil {
		return err
	}
	id := uuid.NewString()
	digest := sha256.Sum256([]byte(uuid.NewString()))
	g := &pb.Grant{Id: id, Owner: r.Owner, Endpoint: r.Id, Consumer: sharingConsumer(email), TokenSha256: digest[:], ExpiresAt: expires}
	data, _ := json.Marshal(g)
	_, err := tx.ExecContext(ctx, `INSERT INTO meter_grants(id,owner,endpoint,digest,expires,data) VALUES(?,?,?,?,?,?)`, id, r.Owner, r.Id, digest[:], expires, data)
	return err
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
