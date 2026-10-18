package metering

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuditBackend interface {
	Audit(context.Context, *pb.AuditRequest) (*pb.AuditResponse, error)
}

// Invalid legacy metadata must not make additive index creation or later
// writes fail. Such rows have no usable audit timestamp and remain untouched.
const auditTimeExpression = `CASE WHEN json_valid(CAST(data AS TEXT)) THEN json_extract(CAST(data AS TEXT),'$.started_at') END`

// All schema changes are additive; timestamp indexes read the existing JSON.
func (s *Store) initAudit() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS meter_audit_retention (
 owner TEXT PRIMARY KEY, days INTEGER NOT NULL CHECK(days IN (7,30,90)));
 CREATE INDEX IF NOT EXISTS meter_events_audit ON meter_events(owner,` + auditTimeExpression + ` DESC,id DESC);
 CREATE INDEX IF NOT EXISTS meter_events_audit_retention ON meter_events(owner,finished,` + auditTimeExpression + `);`)
	return err
}

func (s *Store) Audit(ctx context.Context, in *pb.AuditRequest) (*pb.AuditResponse, error) {
	if in.Owner == "" || len(in.Owner) > 254 || len(in.Endpoint) > 63 || len(in.RequestId) > 32 || in.StatusClass < 0 || in.StatusClass > 5 || in.Since < 0 || in.Until < 0 || in.Until > 0 && in.Until <= in.Since || in.Limit < 0 || in.Limit > MaxEvents || in.BeforeStarted < 0 || len(in.BeforeId) > 32 || (in.BeforeStarted == 0) != (in.BeforeId == "") {
		return nil, status.Error(codes.InvalidArgument, "Invalid audit filters")
	}
	if in.Operation != "list" && in.Operation != "retention" {
		return nil, status.Error(codes.InvalidArgument, "Invalid audit operation")
	}
	if in.Operation == "retention" && in.RetentionDays != 0 && in.RetentionDays != 7 && in.RetentionDays != 30 && in.RetentionDays != 90 {
		return nil, status.Error(codes.InvalidArgument, "Choose 7, 30 or 90 days")
	}
	out := &pb.AuditResponse{}
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		owner, err := canonicalOwner(tx, in.Owner)
		if err != nil {
			return err
		}
		if in.Operation == "retention" {
			if in.RetentionDays == 0 {
				_, err = tx.ExecContext(ctx, `DELETE FROM meter_audit_retention WHERE owner=?`, owner)
			} else {
				_, err = tx.ExecContext(ctx, `INSERT INTO meter_audit_retention(owner,days) VALUES(?,?) ON CONFLICT(owner) DO UPDATE SET days=excluded.days`, owner, in.RetentionDays)
			}
			if err != nil {
				return err
			}
		}
		err = tx.QueryRowContext(ctx, `SELECT coalesce((SELECT days FROM meter_audit_retention WHERE owner=?),0)`, owner).Scan(&out.RetentionDays)
		if err != nil {
			return err
		}
		if in.Operation == "retention" {
			return nil
		}
		since := in.Since
		if out.RetentionDays > 0 {
			since = max(since, s.now().Add(-time.Duration(out.RetentionDays)*24*time.Hour).UnixMilli())
		}
		query := `SELECT data FROM meter_events WHERE owner=? AND ` + auditTimeExpression + `>=?`
		args := []any{owner, since}
		if in.Until > 0 {
			query += ` AND ` + auditTimeExpression + `<?`
			args = append(args, in.Until)
		}
		if in.Endpoint != "" {
			query += ` AND endpoint=?`
			args = append(args, in.Endpoint)
		}
		if in.RequestId != "" {
			query += ` AND id=?`
			args = append(args, in.RequestId)
		}
		if in.StatusClass > 0 {
			query += ` AND CASE WHEN json_valid(CAST(data AS TEXT)) THEN json_extract(CAST(data AS TEXT),'$.status') END>=? AND CASE WHEN json_valid(CAST(data AS TEXT)) THEN json_extract(CAST(data AS TEXT),'$.status') END<?`
			args = append(args, in.StatusClass*100, (in.StatusClass+1)*100)
		}
		if in.BeforeStarted > 0 {
			query += ` AND (` + auditTimeExpression + `,id)<(?,?)`
			args = append(args, in.BeforeStarted, in.BeforeId)
		}
		limit := int(in.Limit)
		if limit == 0 {
			limit = 50
		}
		query += ` ORDER BY ` + auditTimeExpression + ` DESC,id DESC LIMIT ?`
		args = append(args, limit+1)
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
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
		if len(out.Events) > limit {
			out.HasMore = true
			out.Events = out.Events[:limit]
		}
		return rows.Err()
	})
	return out, err
}

func (r *Remote) Audit(ctx context.Context, in *pb.AuditRequest) (*pb.AuditResponse, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	// Match the existing bounded usage-export envelope for a full retained ledger.
	return c.Audit(ctx, in, grpc.MaxCallRecvMsgSize(128<<20))
}

const auditRetentionOwners = 32
const auditRetentionBatch = 100

// SweepAuditRetention bounds each tick to 32 accounts and 100 completed records
// per account. Active requests and aggregate billing counters are never deleted.
// The primary-key cursor advances even for accounts without expired records.
func (s *Store) SweepAuditRetention(ctx context.Context, after string) (next string, deleted int64, err error) {
	type setting struct {
		owner string
		days  int
	}
	var settings []setting
	rows, err := s.db.QueryContext(ctx, `SELECT owner,days FROM meter_audit_retention WHERE owner>? ORDER BY owner LIMIT ?`, after, auditRetentionOwners)
	if err != nil {
		return "", 0, err
	}
	for rows.Next() {
		var v setting
		if err = rows.Scan(&v.owner, &v.days); err != nil {
			break
		}
		settings = append(settings, v)
	}
	scanErr := rows.Err()
	rows.Close()
	if err != nil {
		return "", 0, err
	}
	if scanErr != nil {
		return "", 0, scanErr
	}
	for _, v := range settings {
		err = s.transaction(ctx, func(tx *sql.Tx) error {
			// Re-read inside the delete transaction so a concurrent setting increase
			// cannot delete records using an obsolete, shorter retention period.
			result, e := tx.ExecContext(ctx, `DELETE FROM meter_events WHERE id IN (
 SELECT e.id FROM meter_events e INDEXED BY meter_events_audit_retention
 WHERE e.owner=? AND e.finished=1 AND `+auditTimeExpression+` <
 (SELECT ?-days*86400000 FROM meter_audit_retention WHERE owner=?)
 ORDER BY `+auditTimeExpression+` LIMIT ?)`, v.owner, s.now().UnixMilli(), v.owner, auditRetentionBatch)
			if e != nil {
				return e
			}
			n, e := result.RowsAffected()
			deleted += n
			return e
		})
		if err != nil {
			return next, deleted, err
		}
		next = v.owner
	}
	if len(settings) < auditRetentionOwners {
		next = ""
	}
	return next, deleted, nil
}

func (s *Store) RunAuditRetention(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	cursor := ""
	for {
		batchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		next, _, err := s.SweepAuditRetention(batchCtx, cursor)
		cancel()
		if err != nil && ctx.Err() == nil {
			common.LogError("audit retention failed", "error", fmt.Sprint(err))
		} else {
			cursor = next
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
