package metering

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"

	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PolicyBackend is optional for legacy test adapters. Managed HTTP resources
// require it and fail closed when the authority does not implement the RPC.
type PolicyBackend interface {
	EndpointPolicy(context.Context, *pb.EndpointPolicyRequest) (*pb.EndpointPolicyResponse, error)
}

const MaxPolicyBuckets = 100000
const MaxEndpointPolicyBuckets = 1024

func (s *Store) initEndpointPolicy() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS endpoint_policies (
 resource TEXT PRIMARY KEY, data BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS endpoint_policy_buckets (
 resource TEXT NOT NULL, bucket TEXT NOT NULL, tokens REAL NOT NULL,
 updated INTEGER NOT NULL, rate INTEGER NOT NULL, burst INTEGER NOT NULL, expires INTEGER NOT NULL,
 PRIMARY KEY(resource,bucket));
 CREATE INDEX IF NOT EXISTS endpoint_policy_buckets_expiry ON endpoint_policy_buckets(expires);
 CREATE TRIGGER IF NOT EXISTS retire_endpoint_policy AFTER UPDATE OF id ON web_resources
 WHEN OLD.id<>NEW.id BEGIN
 DELETE FROM endpoint_policies WHERE resource=OLD.id;
 DELETE FROM endpoint_policy_buckets WHERE resource=OLD.id;
 END;
 CREATE TRIGGER IF NOT EXISTS delete_endpoint_policy AFTER DELETE ON web_resources BEGIN
 DELETE FROM endpoint_policies WHERE resource=OLD.id;
 DELETE FROM endpoint_policy_buckets WHERE resource=OLD.id;
 END;
 DELETE FROM endpoint_policies WHERE resource NOT IN (SELECT id FROM web_resources);
 DELETE FROM endpoint_policy_buckets WHERE resource NOT IN (SELECT id FROM web_resources);`)
	return err
}

func (s *Store) EndpointPolicy(ctx context.Context, in *pb.EndpointPolicyRequest) (*pb.EndpointPolicyResponse, error) {
	if in == nil || in.Owner == "" || len(in.Owner) > 254 || !resourceName.MatchString(in.Endpoint) {
		return nil, status.Error(codes.InvalidArgument, "invalid policy owner or endpoint")
	}
	var replacement []byte
	if in.Operation == "set" {
		p, err := trafficpolicy.Decode(in.PolicyJson)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		replacement, _ = json.Marshal(p)
	}
	out := &pb.EndpointPolicyResponse{}
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		owner, err := canonicalOwner(tx, in.Owner)
		if err != nil {
			return err
		}
		var resource string
		err = tx.QueryRowContext(ctx, `SELECT id FROM web_resources WHERE owner=? AND endpoint=?`, owner, in.Endpoint).Scan(&resource)
		if errors.Is(err, sql.ErrNoRows) {
			return status.Error(codes.NotFound, "endpoint not found")
		}
		if err != nil {
			return err
		}
		if in.ResourceId != "" && in.ResourceId != resource || in.Operation == "admit" && in.ResourceId == "" {
			return status.Error(codes.NotFound, "endpoint generation changed")
		}
		var data []byte
		err = tx.QueryRowContext(ctx, `SELECT data FROM endpoint_policies WHERE resource=?`, resource).Scan(&data)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if len(data) == 0 {
			data = []byte(`{"headers":{},"rate_limits":{}}`)
		}
		switch in.Operation {
		case "get":
		case "set", "clear":
			if err = s.sharingMutationAdmission(ctx, tx, owner); err != nil {
				return err
			}
			if in.Operation == "set" {
				data = replacement
				policy, _ := trafficpolicy.Decode(data)
				if err = s.updateEndpointPolicyBuckets(ctx, tx, resource, policy); err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_policies(resource,data) VALUES(?,?) ON CONFLICT(resource) DO UPDATE SET data=excluded.data`, resource, data)
			} else {
				data = []byte(`{"headers":{},"rate_limits":{}}`)
				_, err = tx.ExecContext(ctx, `DELETE FROM endpoint_policies WHERE resource=?`, resource)
				if err == nil {
					_, err = tx.ExecContext(ctx, `DELETE FROM endpoint_policy_buckets WHERE resource=?`, resource)
				}
			}
			if err != nil {
				return err
			}
		case "admit":
			auth := &pb.Decision{Allowed: true, Status: 200, Reason: "allowed"}
			suspended, err := operationallySuspended(tx, owner)
			if err != nil {
				return err
			}
			if suspended {
				deny(auth, "account_suspended", 403)
			}
			if in.GrantId != "" {
				g, err := grant(tx, in.GrantId)
				if errors.Is(err, sql.ErrNoRows) {
					deny(auth, "invalid_grant", 403)
				} else if err != nil {
					return err
				} else {
					checkGrant(g, &pb.Event{Owner: owner, Endpoint: in.Endpoint}, auth, s.now())
				}
			}
			if !auth.Allowed {
				out.Decision = auth
				break
			}
			p, err := trafficpolicy.Decode(data)
			if err != nil {
				return fmt.Errorf("stored policy is invalid: %w", err)
			}
			out.Decision, err = s.admitEndpointPolicy(ctx, tx, resource, in.ClientIp, p)
			if err != nil {
				return err
			}
		default:
			return status.Error(codes.InvalidArgument, "unsupported policy operation")
		}
		out.PolicyJson = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type policyBucket struct {
	key, reason          string
	tokens               float64
	updated, rate, burst int64
	fresh                bool
}

func (s *Store) admitEndpointPolicy(ctx context.Context, tx *sql.Tx, resource, peer string, p *trafficpolicy.Policy) (*pb.Decision, error) {
	decision := &pb.Decision{Allowed: true, Status: 200, Reason: "allowed"}
	now := s.now().UnixMilli()
	var buckets []policyBucket
	if p.RateLimits.PerIP != nil || p.RateLimits.PerAccount != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM endpoint_policy_buckets WHERE expires<=?`, now); err != nil {
			return nil, err
		}
	}
	load := func(key, reason string, limit *trafficpolicy.Limit) error {
		if limit == nil {
			return nil
		}
		b := policyBucket{key: key, reason: reason, tokens: float64(limit.Burst), updated: now, rate: limit.RequestsPerMinute, burst: limit.Burst}
		var oldRate, oldBurst int64
		err := tx.QueryRowContext(ctx, `SELECT tokens,updated,rate,burst FROM endpoint_policy_buckets WHERE resource=? AND bucket=?`, resource, key).Scan(&b.tokens, &b.updated, &oldRate, &oldBurst)
		if errors.Is(err, sql.ErrNoRows) {
			b.fresh = true
		} else if err != nil {
			return err
		} else {
			b.tokens = math.Min(float64(oldBurst), b.tokens+float64(max(0, now-b.updated))*float64(oldRate)/60000)
			b.tokens = math.Min(float64(limit.Burst), b.tokens)
			b.updated = max(now, b.updated)
		}
		if b.tokens < 1 {
			decision.Allowed = false
			decision.Status = 429
			decision.Reason = reason
			decision.RetryAfter = max(decision.RetryAfter, int64(math.Ceil((1-b.tokens)*60/float64(b.rate))))
		}
		buckets = append(buckets, b)
		return nil
	}
	if p.RateLimits.PerIP != nil {
		ip, err := netip.ParseAddr(peer)
		if err != nil || ip.Zone() != "" {
			return nil, status.Error(codes.InvalidArgument, "canonical client IP required")
		}
		digest := sha256.Sum256([]byte(ip.Unmap().String()))
		if err = load("ip:"+hex.EncodeToString(digest[:]), "policy_ip_rate", p.RateLimits.PerIP); err != nil {
			return nil, err
		}
	}
	if err := load("account", "policy_account_rate", p.RateLimits.PerAccount); err != nil {
		return nil, err
	}
	if !decision.Allowed || len(buckets) == 0 {
		return decision, nil
	}
	// Only fully refilled buckets can be discarded; eviction of debt would grant
	// extra traffic. Reject new IPs at capacity instead of weakening the limit.
	newBuckets := 0
	for _, b := range buckets {
		if b.fresh {
			newBuckets++
		}
	}
	if newBuckets > 0 {
		var total, endpoint int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_policy_buckets`).Scan(&total); err != nil {
			return nil, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_policy_buckets WHERE resource=?`, resource).Scan(&endpoint); err != nil {
			return nil, err
		}
		if total+newBuckets > s.maxPolicyBuckets || endpoint+newBuckets > s.maxEndpointPolicyBuckets {
			return &pb.Decision{Allowed: false, Status: 429, Reason: "policy_capacity", RetryAfter: 60}, nil
		}
	}
	for _, b := range buckets {
		b.tokens--
		expires := b.updated + int64(math.Ceil((float64(b.burst)-b.tokens)*60000/float64(b.rate)))
		if _, err := tx.ExecContext(ctx, `INSERT INTO endpoint_policy_buckets(resource,bucket,tokens,updated,rate,burst,expires) VALUES(?,?,?,?,?,?,?) ON CONFLICT(resource,bucket) DO UPDATE SET tokens=excluded.tokens,updated=excluded.updated,rate=excluded.rate,burst=excluded.burst,expires=excluded.expires`, resource, b.key, b.tokens, b.updated, b.rate, b.burst, expires); err != nil {
			return nil, err
		}
	}
	return decision, nil
}

// Settle debt at the old refill rate up to the configuration change, then apply
// the new rate from this instant. Repeated PUTs cannot refill an active bucket.
func (s *Store) updateEndpointPolicyBuckets(ctx context.Context, tx *sql.Tx, resource string, p *trafficpolicy.Policy) error {
	now := s.now().UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE endpoint_policy_buckets SET tokens=min(burst,tokens+max(0,?-updated)*rate/60000.0),updated=max(updated,?) WHERE resource=?`, now, now, resource); err != nil {
		return err
	}
	for _, kind := range []struct {
		predicate string
		limit     *trafficpolicy.Limit
	}{
		{"bucket='account'", p.RateLimits.PerAccount}, {"substr(bucket,1,3)='ip:'", p.RateLimits.PerIP},
	} {
		if kind.limit == nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM endpoint_policy_buckets WHERE resource=? AND `+kind.predicate, resource); err != nil {
				return err
			}
			continue
		}
		limit := kind.limit
		// Round expiry upwards so debt is never evicted before it has fully refilled.
		if _, err := tx.ExecContext(ctx, `UPDATE endpoint_policy_buckets SET tokens=min(tokens,?),rate=?,burst=?,expires=updated+CAST((?-min(tokens,?))*60000.0/? AS INTEGER)+1 WHERE resource=? AND `+kind.predicate, limit.Burst, limit.RequestsPerMinute, limit.Burst, limit.Burst, limit.Burst, limit.RequestsPerMinute, resource); err != nil {
			return err
		}
	}
	return nil
}
