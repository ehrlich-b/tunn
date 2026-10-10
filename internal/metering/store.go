// Package metering owns the durable, metadata-only ingress ledger. Its authority
// is the login node; all relay nodes share its atomic admission and byte checks.
package metering

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	MaxEvents       = 10000
	MaxUsageRows    = 100000
	MaxGrants       = 10000
	RetentionMonths = 13
)

var ErrCapacity = errors.New("metering storage capacity reached")

// Backend is also implemented by the authenticated internal gRPC client.
type Backend interface {
	Resolve(context.Context, *pb.ResolveRequest) (*pb.Grant, error)
	CreateGrant(context.Context, *pb.Grant) (*pb.Grant, error)
	RevokeGrant(context.Context, *pb.Grant) (*emptypb.Empty, error)
	Admit(context.Context, *pb.Event) (*pb.Decision, error)
	Charge(context.Context, *pb.ChargeRequest) (*pb.Decision, error)
	Finish(context.Context, *pb.Event) (*emptypb.Empty, error)
	Export(context.Context, *pb.ExportRequest) (*pb.ExportResponse, error)
}

type Store struct {
	pb.UnimplementedMeteringServer
	db  *sql.DB
	mu  sync.Mutex
	now func() time.Time
	// Fixed hard caps, reduced in retention tests.
	maxEvents, maxUsage, maxGrants int
}

func New(db *sql.DB) (*Store, error) {
	// SQLite transactions must share one connection, including in-memory fixtures.
	db.SetMaxOpenConns(1)
	_, err := db.Exec(`
 CREATE TABLE IF NOT EXISTS meter_grants (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, endpoint TEXT NOT NULL,
 digest BLOB UNIQUE NOT NULL, expires INTEGER NOT NULL, data BLOB NOT NULL,
 rate_minute INTEGER NOT NULL DEFAULT 0, rate_count INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS meter_events (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, endpoint TEXT NOT NULL,
 month TEXT NOT NULL, finished INTEGER NOT NULL, data BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS meter_events_export ON meter_events(owner,endpoint,month);
 CREATE TABLE IF NOT EXISTS meter_usage (
 owner TEXT NOT NULL, endpoint TEXT NOT NULL, caller TEXT NOT NULL, month TEXT NOT NULL,
 requests INTEGER NOT NULL DEFAULT 0, admitted INTEGER NOT NULL DEFAULT 0,
 request_bytes INTEGER NOT NULL DEFAULT 0, response_bytes INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(owner,endpoint,caller,month));`)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: time.Now, maxEvents: MaxEvents, maxUsage: MaxUsageRows, maxGrants: MaxGrants}
	// A crash cannot erase charges already committed. Mark incomplete audit records
	// explicitly; do not invent a completed delivery or replay the application call.
	rows, err := db.Query(`SELECT data FROM meter_events WHERE finished=0`)
	if err != nil {
		return nil, err
	}
	var interrupted []*pb.Event
	for rows.Next() {
		e := new(pb.Event)
		var data []byte
		if err = rows.Scan(&data); err != nil {
			break
		}
		if err = json.Unmarshal(data, e); err != nil {
			break
		}
		interrupted = append(interrupted, e)
	}
	scanErr := rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	if scanErr != nil {
		return nil, scanErr
	}
	for _, e := range interrupted {
		e.Finished = true
		e.Reason = "relay_restart"
		e.Status = 502
		e.DurationMs = max(0, s.now().UnixMilli()-e.StartedAt)
		data, _ := json.Marshal(e)
		if _, err = db.Exec(`UPDATE meter_events SET finished=1,data=? WHERE id=?`, data, e.RequestId); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) transaction(ctx context.Context, f func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = f(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Resolve(ctx context.Context, r *pb.ResolveRequest) (*pb.Grant, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT data FROM meter_grants WHERE owner=? AND endpoint=? AND digest=?`, r.Owner, r.Endpoint, r.TokenSha256).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return &pb.Grant{}, nil
	}
	if err != nil {
		return nil, err
	}
	g := new(pb.Grant)
	if err = json.Unmarshal(data, g); err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Store) CreateGrant(ctx context.Context, g *pb.Grant) (*pb.Grant, error) {
	g = proto.Clone(g).(*pb.Grant)
	now := s.now()
	if g.Owner == "" || len(g.Owner) > 254 || g.Endpoint == "" || len(g.Endpoint) > 63 || len(g.Consumer) > 254 || len(g.TokenSha256) != sha256.Size || g.ExpiresAt <= now.UnixMilli() || g.ExpiresAt > now.Add(365*24*time.Hour).UnixMilli() || g.RequestsPerMinute < 0 || g.MonthlyRequests < 0 || g.MonthlyBytes < 0 {
		return nil, fmt.Errorf("invalid grant: require endpoint, owner, SHA-256 digest, expiry within one year and nonnegative limits")
	}
	g.Id = uuid.NewString()
	g.Revoked = false
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		cutoff := now.UTC().AddDate(0, -RetentionMonths, 0)
		if _, err := tx.Exec(`DELETE FROM meter_grants WHERE expires<?`, cutoff.UnixMilli()); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM meter_grants`).Scan(&count); err != nil {
			return err
		}
		if count >= s.maxGrants {
			return ErrCapacity
		}
		data, err := json.Marshal(g)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO meter_grants(id,owner,endpoint,digest,expires,data) VALUES(?,?,?,?,?,?)`, g.Id, g.Owner, g.Endpoint, g.TokenSha256, g.ExpiresAt, data)
		return err
	})
	if err != nil {
		return nil, err
	}
	g.TokenSha256 = nil
	return g, nil
}

func grant(tx *sql.Tx, id string) (*pb.Grant, error) {
	var data []byte
	err := tx.QueryRow(`SELECT data FROM meter_grants WHERE id=?`, id).Scan(&data)
	if err != nil {
		return nil, err
	}
	g := new(pb.Grant)
	err = json.Unmarshal(data, g)
	return g, err
}
func (s *Store) RevokeGrant(ctx context.Context, r *pb.Grant) (*emptypb.Empty, error) {
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		g, err := grant(tx, r.Id)
		if err != nil {
			return err
		}
		if g.Owner != r.Owner || g.Endpoint != r.Endpoint {
			return fmt.Errorf("grant not found")
		}
		g.Revoked = true
		data, _ := json.Marshal(g)
		_, err = tx.Exec(`UPDATE meter_grants SET data=? WHERE id=?`, data, g.Id)
		return err
	})
	return &emptypb.Empty{}, err
}
func readEvent(tx *sql.Tx, id string) (*pb.Event, error) {
	var data []byte
	err := tx.QueryRow(`SELECT data FROM meter_events WHERE id=?`, id).Scan(&data)
	if err != nil {
		return nil, err
	}
	e := new(pb.Event)
	err = json.Unmarshal(data, e)
	return e, err
}
func saveEvent(tx *sql.Tx, e *pb.Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO meter_events(id,owner,endpoint,month,finished,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET finished=excluded.finished,data=excluded.data`, e.RequestId, e.Owner, e.Endpoint, e.Month, e.Finished, data)
	return err
}
func usage(tx *sql.Tx, e *pb.Event) (*pb.Usage, error) {
	u := &pb.Usage{Owner: e.Owner, Endpoint: e.Endpoint, Caller: e.Caller, Month: e.Month}
	err := tx.QueryRow(`SELECT requests,admitted,request_bytes,response_bytes FROM meter_usage WHERE owner=? AND endpoint=? AND caller=? AND month=?`, e.Owner, e.Endpoint, e.Caller, e.Month).Scan(&u.Requests, &u.AdmittedRequests, &u.RequestBytes, &u.ResponseBytes)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return u, err
}
func addUsage(tx *sql.Tx, e *pb.Event, requests, admitted, reqBytes, respBytes int64) error {
	_, err := tx.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month,requests,admitted,request_bytes,response_bytes) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(owner,endpoint,caller,month) DO UPDATE SET requests=requests+excluded.requests,admitted=admitted+excluded.admitted,request_bytes=request_bytes+excluded.request_bytes,response_bytes=response_bytes+excluded.response_bytes`, e.Owner, e.Endpoint, e.Caller, e.Month, requests, admitted, reqBytes, respBytes)
	return err
}
func decision(e *pb.Event) *pb.Decision {
	return &pb.Decision{Allowed: e.Allowed, Reason: e.Reason, Status: e.Status, RequestsRemaining: -1, BytesRemaining: -1, RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes}
}
func deny(d *pb.Decision, reason string, status int32) {
	d.Allowed = false
	d.Reason = reason
	d.Status = status
}
func checkGrant(g *pb.Grant, e *pb.Event, d *pb.Decision, now time.Time) {
	if g.Owner != e.Owner || g.Endpoint != e.Endpoint {
		deny(d, "invalid_grant", 403)
	} else if g.Revoked {
		deny(d, "grant_revoked", 403)
	} else if now.UnixMilli() >= g.ExpiresAt {
		deny(d, "grant_expired", 403)
	}
}
func remaining(g *pb.Grant, u *pb.Usage, d *pb.Decision) {
	if g.MonthlyRequests > 0 {
		d.RequestsRemaining = max(0, g.MonthlyRequests-u.AdmittedRequests)
	}
	if g.MonthlyBytes > 0 {
		d.BytesRemaining = max(0, g.MonthlyBytes-u.RequestBytes-u.ResponseBytes)
	}
}

func (s *Store) Admit(ctx context.Context, input *pb.Event) (*pb.Decision, error) {
	e := proto.Clone(input).(*pb.Event)
	if len(e.RequestId) != 32 || len(e.Owner) > 254 || len(e.Endpoint) == 0 || len(e.Endpoint) > 63 || len(e.Caller) == 0 || len(e.Caller) > 256 || len(e.AuthMethod) > 32 || len(e.Reason) > 64 {
		return nil, fmt.Errorf("invalid audit metadata")
	}
	var d *pb.Decision
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		prior, err := readEvent(tx, e.RequestId)
		if err == nil {
			d = decision(prior)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := s.now().UTC()
		e.StartedAt = now.UnixMilli()
		e.Month = now.Format("2006-01")
		e.RequestBytes = 0
		e.ResponseBytes = 0
		e.Finished = !e.Allowed
		e.Forwarded = false
		e.DurationMs = 0
		// Bounded rows, not merely a time-based retention promise. Never evict active
		// events or current counters to make a depleted budget appear unused.
		if _, err = tx.Exec(`DELETE FROM meter_usage WHERE month<?`, now.AddDate(0, -RetentionMonths+1, 0).Format("2006-01")); err != nil {
			return err
		}
		var count int
		if err = tx.QueryRow(`SELECT count(*) FROM meter_events`).Scan(&count); err != nil {
			return err
		}
		if count >= s.maxEvents {
			_, err = tx.Exec(`DELETE FROM meter_events WHERE id IN (SELECT id FROM meter_events WHERE finished=1 ORDER BY rowid LIMIT ?)`, count-s.maxEvents+1)
			if err != nil {
				return err
			}
		}
		if err = tx.QueryRow(`SELECT count(*) FROM meter_events`).Scan(&count); err != nil {
			return err
		}
		if count >= s.maxEvents {
			return ErrCapacity
		}
		u, err := usage(tx, e)
		if err != nil {
			return err
		}
		if u.Requests == 0 {
			if err = tx.QueryRow(`SELECT count(*) FROM meter_usage`).Scan(&count); err != nil {
				return err
			}
			if count >= s.maxUsage {
				return ErrCapacity
			}
		}
		d = decision(e)
		if e.Allowed && e.GrantId != "" {
			g, err := grant(tx, e.GrantId)
			if errors.Is(err, sql.ErrNoRows) {
				deny(d, "invalid_grant", 403)
			} else if err != nil {
				return err
			} else {
				checkGrant(g, e, d, now)
				remaining(g, u, d)
				if d.Allowed && d.RequestsRemaining == 0 {
					deny(d, "request_budget", 429)
					d.RetryAfter = secondsToMonth(now)
				}
				if d.Allowed && d.BytesRemaining >= 0 && (d.BytesRemaining == 0 || e.ContentLength > d.BytesRemaining) {
					deny(d, "byte_budget", 429)
					d.RetryAfter = secondsToMonth(now)
				}
				var minute, count int64
				if err = tx.QueryRow(`SELECT rate_minute,rate_count FROM meter_grants WHERE id=?`, g.Id).Scan(&minute, &count); err != nil {
					return err
				}
				thisMinute := now.Unix() / 60
				if minute != thisMinute {
					count = 0
				}
				if d.Allowed && g.RequestsPerMinute > 0 && count >= g.RequestsPerMinute {
					deny(d, "request_rate", 429)
					d.RetryAfter = 60 - now.Unix()%60
				}
				if d.Allowed {
					if _, err = tx.Exec(`UPDATE meter_grants SET rate_minute=?,rate_count=? WHERE id=?`, thisMinute, count+1, g.Id); err != nil {
						return err
					}
					if d.RequestsRemaining > 0 {
						d.RequestsRemaining--
					}
				}
			}
		}
		e.Allowed = d.Allowed
		e.Reason = d.Reason
		e.Status = d.Status
		e.Finished = !d.Allowed
		admitted := int64(0)
		if d.Allowed {
			admitted = 1
		}
		if err = addUsage(tx, e, 1, admitted, 0, 0); err != nil {
			return err
		}
		return saveEvent(tx, e)
	})
	return d, err
}
func secondsToMonth(now time.Time) int64 {
	return max(1, int64(time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC).Sub(now).Seconds()))
}

func (s *Store) Charge(ctx context.Context, r *pb.ChargeRequest) (*pb.Decision, error) {
	var d *pb.Decision
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		e, err := readEvent(tx, r.RequestId)
		if err != nil {
			return err
		}
		d = decision(e)
		if r.RequestBytes < e.RequestBytes || r.ResponseBytes < e.ResponseBytes || r.RequestBytes < 0 || r.ResponseBytes < 0 {
			return fmt.Errorf("byte counts must be monotonic")
		}
		if e.Finished {
			if r.RequestBytes != e.RequestBytes || r.ResponseBytes != e.ResponseBytes {
				return fmt.Errorf("audit event already finished")
			}
			return nil
		}
		reqDelta, respDelta := r.RequestBytes-e.RequestBytes, r.ResponseBytes-e.ResponseBytes
		if reqDelta > 1<<40 || respDelta > 1<<40 {
			return fmt.Errorf("byte charge too large")
		}
		if e.GrantId != "" {
			g, err := grant(tx, e.GrantId)
			if err != nil {
				return err
			}
			checkGrant(g, e, d, s.now())
			u, err := usage(tx, e)
			if err != nil {
				return err
			}
			remaining(g, u, d)
			if !d.Allowed {
				reqDelta = 0
				respDelta = 0
			} else if d.BytesRemaining >= 0 {
				available := d.BytesRemaining
				reqDelta = min(reqDelta, available)
				available -= reqDelta
				respDelta = min(respDelta, available)
				if reqDelta+e.RequestBytes < r.RequestBytes || respDelta+e.ResponseBytes < r.ResponseBytes {
					deny(d, "byte_budget", 429)
					d.RetryAfter = secondsToMonth(s.now().UTC())
				}
				d.BytesRemaining -= reqDelta + respDelta
			}
		}
		e.RequestBytes += reqDelta
		e.ResponseBytes += respDelta
		d.RequestBytes = e.RequestBytes
		d.ResponseBytes = e.ResponseBytes
		if !d.Allowed {
			e.Reason = d.Reason
		} // admission remains allowed, outcome records termination
		if err = addUsage(tx, e, 0, 0, reqDelta, respDelta); err != nil {
			return err
		}
		return saveEvent(tx, e)
	})
	return d, err
}

func (s *Store) Finish(ctx context.Context, r *pb.Event) (*emptypb.Empty, error) {
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		e, err := readEvent(tx, r.RequestId)
		if err != nil {
			return err
		}
		if e.Finished {
			return nil
		}
		e.Finished = true
		e.Status = r.Status
		e.DurationMs = max(0, s.now().UnixMilli()-e.StartedAt)
		e.Forwarded = r.Forwarded
		// Reserve before writing to prevent concurrent overspend, then reconcile a
		// short/failed writer to its actual byte count. A crash keeps the reservation
		// conservatively and is labeled relay_restart on the next startup.
		if r.ResponseBytes < 0 || r.ResponseBytes > e.ResponseBytes {
			return fmt.Errorf("invalid final response byte count")
		}
		if err = addUsage(tx, e, 0, 0, 0, r.ResponseBytes-e.ResponseBytes); err != nil {
			return err
		}
		e.ResponseBytes = r.ResponseBytes
		if r.Reason != "" {
			if len(r.Reason) > 64 {
				return fmt.Errorf("invalid reason")
			}
			e.Reason = r.Reason
		}
		return saveEvent(tx, e)
	})
	return &emptypb.Empty{}, err
}
func (s *Store) Export(ctx context.Context, r *pb.ExportRequest) (*pb.ExportResponse, error) {
	if r.Owner == "" || r.Endpoint == "" {
		return nil, fmt.Errorf("owner and endpoint required")
	}
	if month, err := time.Parse("2006-01", r.Month); err != nil || month.Format("2006-01") != r.Month {
		return nil, fmt.Errorf("month must be YYYY-MM")
	}
	out := &pb.ExportResponse{}
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT caller,requests,admitted,request_bytes,response_bytes FROM meter_usage WHERE owner=? AND endpoint=? AND month=? ORDER BY caller`, r.Owner, r.Endpoint, r.Month)
		if err != nil {
			return err
		}
		for rows.Next() {
			u := &pb.Usage{Owner: r.Owner, Endpoint: r.Endpoint, Month: r.Month}
			if err = rows.Scan(&u.Caller, &u.Requests, &u.AdmittedRequests, &u.RequestBytes, &u.ResponseBytes); err != nil {
				_ = rows.Close()
				return err
			}
			out.Usage = append(out.Usage, u)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		rows, err = tx.Query(`SELECT data FROM meter_events WHERE owner=? AND endpoint=? AND month=? ORDER BY rowid`, r.Owner, r.Endpoint, r.Month)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var data []byte
			if err = rows.Scan(&data); err != nil {
				return err
			}
			e := new(pb.Event)
			if err = json.Unmarshal(data, e); err != nil {
				return err
			}
			out.Events = append(out.Events, e)
		}
		return rows.Err()
	})
	return out, err
}

// TokenID is a stable, non-secret identity for existing endpoint credentials.
func TokenID(digest []byte) string {
	return "token:" + fmt.Sprintf("%x", digest[:min(16, len(digest))])
}
func CallerEmail(email string) string { return "email:" + strings.ToLower(email) }
