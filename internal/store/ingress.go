package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

// IngressEvent is metadata only. Never add paths, headers, bodies, IPs, or tokens.
// Bytes count payload successfully sent to the publisher / written to the caller.
// These diagnostic units are not billable usage.
type IngressEvent struct {
	Sequence      int64     `json:"sequence"`
	RequestID     string    `json:"request_id"`
	AccountID     string    `json:"-"`
	EndpointID    string    `json:"endpoint_id"`
	CallerID      string    `json:"caller_id"`
	AuthMethod    string    `json:"auth_method"`
	Reason        string    `json:"reason"`
	Outcome       string    `json:"outcome"`
	Status        int       `json:"status"`
	StartedAt     time.Time `json:"started_at"`
	DurationMS    int64     `json:"duration_ms"`
	Forwarded     bool      `json:"forwarded"`
	RequestBytes  int64     `json:"request_bytes"`
	ResponseBytes int64     `json:"response_bytes"`
}

type IngressCounter struct {
	Sequence      int64  `json:"sequence"`
	EndpointID    string `json:"endpoint_id"`
	CallerID      string `json:"caller_id"`
	AuthMethod    string `json:"auth_method"`
	Requests      int64  `json:"requests"`
	Forwarded     int64  `json:"forwarded_requests"`
	Denied        int64  `json:"denied_requests"`
	Errors        int64  `json:"failed_requests"`
	RequestBytes  int64  `json:"request_bytes"`
	ResponseBytes int64  `json:"response_bytes"`
}

type IngressQuery struct {
	AccountID  string
	Month      string
	EndpointID string
	After      int64
	Limit      int
	Counters   bool
}

type IngressExport struct {
	Month      string           `json:"month"`
	Events     []IngressEvent   `json:"events,omitempty"`
	Counters   []IngressCounter `json:"counters,omitempty"`
	NextCursor int64            `json:"next_cursor"`
	Billable   bool             `json:"billable"`
}

var ErrInvalidIngress = errors.New("invalid ingress metadata or query")

const IngressPageLimit = 500

func (q IngressQuery) Validate() error {
	month, err := time.Parse("2006-01", q.Month)
	if err != nil || month.Format("2006-01") != q.Month || q.AccountID == "" || q.After < 0 || q.Limit < 1 || q.Limit > IngressPageLimit || len(q.EndpointID) > 253 {
		return ErrInvalidIngress
	}
	return nil
}

func (e IngressEvent) Validate() error {
	if e.RequestID == "" || len(e.RequestID) > 64 || e.AccountID == "" || len(e.AccountID) > 128 || e.EndpointID == "" || len(e.EndpointID) > 253 || e.CallerID == "" || len(e.CallerID) > 320 || e.StartedAt.IsZero() || e.DurationMS < 0 || e.RequestBytes < 0 || e.ResponseBytes < 0 || e.RequestBytes > math.MaxInt64-e.ResponseBytes || e.Status < 100 || e.Status > 599 {
		return ErrInvalidIngress
	}
	switch e.AuthMethod {
	case "none", "cookie", "bearer", "endpoint_token", "grant":
	default:
		return ErrInvalidIngress
	}
	switch e.Reason {
	case "open", "allow_list", "endpoint_token", "authentication_required", "access_denied", "owner_quota_exceeded", "grant", "grant_invalid", "grant_expired", "grant_revoked", "grant_exhausted", "grant_scope_denied", "grant_unavailable":
	default:
		return ErrInvalidIngress
	}
	switch e.Outcome {
	case "completed", "denied", "proxy_error", "canceled":
	default:
		return ErrInvalidIngress
	}
	return nil
}

type IngressStore struct{ db *sql.DB }

func NewIngressStore(db *sql.DB) *IngressStore { return &IngressStore{db: db} }

// Record commits the event and counters together. Replaying the same request ID
// after an ambiguous RPC result cannot increment counters twice.
func (s *IngressStore) Record(ctx context.Context, e IngressEvent) error {
	if err := e.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Merges flatten aliases; resolving in this transaction prevents stale-ID
	// writes after ownership transfer.
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT account_id FROM account_aliases WHERE alias_id=?),?)`, e.AccountID, e.AccountID).Scan(&e.AccountID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO ingress_events
 (request_id,account_id,month,endpoint_id,caller_id,auth_method,reason,outcome,status,started_at,duration_ms,forwarded,request_bytes,response_bytes)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(request_id) DO NOTHING`,
		e.RequestID, e.AccountID, e.StartedAt.UTC().Format("2006-01"), e.EndpointID, e.CallerID, e.AuthMethod, e.Reason, e.Outcome, e.Status, e.StartedAt.UnixMilli(), e.DurationMS, e.Forwarded, e.RequestBytes, e.ResponseBytes)
	if err != nil {
		return err
	}
	added, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if added == 0 {
		return tx.Commit()
	}
	denied, failed := 0, 0
	if e.Outcome == "denied" {
		denied = 1
	}
	if e.Outcome == "proxy_error" || e.Outcome == "canceled" {
		failed = 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ingress_counters
 (account_id,month,endpoint_id,caller_id,auth_method,requests,forwarded,denied,errors,request_bytes,response_bytes)
 VALUES(?,?,?,?,?,1,?,?,?,?,?)
 ON CONFLICT(account_id,month,endpoint_id,caller_id,auth_method) DO UPDATE SET
 requests=requests+1,forwarded=forwarded+excluded.forwarded,denied=denied+excluded.denied,errors=errors+excluded.errors,
 request_bytes=request_bytes+excluded.request_bytes,response_bytes=response_bytes+excluded.response_bytes`,
		e.AccountID, e.StartedAt.UTC().Format("2006-01"), e.EndpointID, e.CallerID, e.AuthMethod, e.Forwarded, denied, failed, e.RequestBytes, e.ResponseBytes)
	if err != nil {
		return err
	}
	// Keep the existing owner quota in the same idempotent transaction. This
	// covers ambiguous internal RPC acknowledgements without another charge.
	if units := e.RequestBytes + e.ResponseBytes; units > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO account_usage(account_id,month,bytes_used) VALUES(?,?,?)
   ON CONFLICT(account_id,month) DO UPDATE SET bytes_used=bytes_used+excluded.bytes_used`, e.AccountID, e.StartedAt.UTC().Format("2006-01"), units); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Export is scoped to a trusted account ID supplied by the authenticated handler.
// Cursor values are opaque sequence numbers, never authorization credentials.
func (s *IngressStore) Export(ctx context.Context, q IngressQuery) (*IngressExport, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	out := &IngressExport{Month: q.Month}
	filter := ` WHERE account_id=? AND month=? AND sequence>?`
	args := []any{q.AccountID, q.Month, q.After}
	if q.EndpointID != "" {
		filter += ` AND endpoint_id=?`
		args = append(args, q.EndpointID)
	}
	args = append(args, q.Limit+1)
	columns := `sequence,request_id,endpoint_id,caller_id,auth_method,reason,outcome,status,started_at,duration_ms,forwarded,request_bytes,response_bytes`
	table := "ingress_events"
	if q.Counters {
		table = "ingress_counters"
		columns = `sequence,endpoint_id,caller_id,auth_method,requests,forwarded,denied,errors,request_bytes,response_bytes`
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM `+table+filter+` ORDER BY sequence LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if q.Counters {
			var c IngressCounter
			if err := rows.Scan(&c.Sequence, &c.EndpointID, &c.CallerID, &c.AuthMethod, &c.Requests, &c.Forwarded, &c.Denied, &c.Errors, &c.RequestBytes, &c.ResponseBytes); err != nil {
				return nil, err
			}
			if len(out.Counters) == q.Limit {
				out.NextCursor = out.Counters[len(out.Counters)-1].Sequence
				break
			}
			out.Counters = append(out.Counters, c)
		} else {
			var e IngressEvent
			var started int64
			if err := rows.Scan(&e.Sequence, &e.RequestID, &e.EndpointID, &e.CallerID, &e.AuthMethod, &e.Reason, &e.Outcome, &e.Status, &started, &e.DurationMS, &e.Forwarded, &e.RequestBytes, &e.ResponseBytes); err != nil {
				return nil, err
			}
			e.StartedAt = time.UnixMilli(started).UTC()
			if len(out.Events) == q.Limit {
				out.NextCursor = out.Events[len(out.Events)-1].Sequence
				break
			}
			out.Events = append(out.Events, e)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("export ingress: %w", err)
	}
	return out, nil
}
