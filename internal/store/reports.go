package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrReportRateLimited = errors.New("report rate limit reached")
var ErrReportCapacity = errors.New("report capacity reached")

// IncidentReport is bounded intake metadata. There is deliberately no body,
// attachment, URL, email, free-form description, or automatic mail action.
type IncidentReport struct {
	ID        string `json:"id"`
	AccountID string `json:"account_id"`
	Category  string `json:"category"`
	Endpoint  string `json:"endpoint"`
	State     string `json:"state"`
	Version   int64  `json:"version"`
	CreatedAt string `json:"created_at"`
	ChangedAt string `json:"changed_at"`
	Actor     string `json:"actor"`
}

func (s *OperationsStore) IntakeReport(ctx context.Context, account, category, endpoint string) (*IncidentReport, error) {
	if category != "abuse" && category != "billing" && category != "availability" {
		return nil, fmt.Errorf("invalid report category")
	}
	if !boundedText(endpoint, 63) || endpoint[0] == '-' || endpoint[len(endpoint)-1] == '-' {
		return nil, fmt.Errorf("invalid endpoint")
	}
	for _, c := range endpoint {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return nil, fmt.Errorf("invalid endpoint")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	id, err := canonicalAccount(ctx, tx, account)
	if err != nil {
		return nil, err
	}
	var total, recent int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM ops_reports").Scan(&total); err != nil {
		return nil, err
	}
	if total >= 10000 {
		return nil, ErrReportCapacity
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM ops_reports WHERE account_id=? AND created_at>?", id, s.now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05.000000000Z")).Scan(&recent); err != nil {
		return nil, err
	}
	if recent >= 5 {
		return nil, ErrReportRateLimited
	}
	now := s.now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	out := &IncidentReport{uuid.NewString(), id, category, endpoint, "received", 1, now, now, "account:" + id}
	_, err = tx.ExecContext(ctx, "INSERT INTO ops_reports VALUES(?,?,?,?,?,?,?,?,?)", out.ID, id, category, endpoint, out.State, out.Version, now, now, out.Actor)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *OperationsStore) RespondReport(ctx context.Context, p AdminPrincipal, id, state string, expected int64) (*IncidentReport, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	out := new(IncidentReport)
	if err = tx.QueryRowContext(ctx, "SELECT id,account_id,category,endpoint,state,version,created_at,changed_at,actor FROM ops_reports WHERE id=?", id).Scan(&out.ID, &out.AccountID, &out.Category, &out.Endpoint, &out.State, &out.Version, &out.CreatedAt, &out.ChangedAt, &out.Actor); err != nil {
		return nil, err
	}
	if err = p.authorize(out.AccountID); err != nil {
		return nil, err
	}
	if out.Version != expected {
		return nil, ErrVersionConflict
	}
	valid := out.State == "received" && state == "triaged" || out.State == "triaged" && (state == "action_taken" || state == "closed") || out.State == "action_taken" && state == "closed"
	if !valid {
		return nil, fmt.Errorf("invalid report response transition")
	}
	out.State, out.Version, out.ChangedAt, out.Actor = state, out.Version+1, s.now().UTC().Format(time.RFC3339Nano), p.actor
	_, err = tx.ExecContext(ctx, "UPDATE ops_reports SET state=?,version=?,changed_at=?,actor=? WHERE id=?", state, out.Version, out.ChangedAt, out.Actor, id)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
