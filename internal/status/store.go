// Package status records external relay probes without access to account data.
package status

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const Retention = 90 * 24 * time.Hour
const Freshness = 150 * time.Second

type Store struct{ db *sql.DB }
type Sample struct {
	CheckedAt time.Time `json:"checked_at"`
	Health    bool      `json:"health"`
	Ready     bool      `json:"ready"`
}
type Incident struct {
	ID         int64      `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Title      string     `json:"title"`
	Note       string     `json:"note"`
}
type Day struct {
	Date     string `json:"date"`
	State    string `json:"state"`
	Observed int    `json:"observed"`
	Healthy  int    `json:"healthy"`
	Expected int    `json:"expected"`
}
type Snapshot struct {
	GeneratedAt time.Time  `json:"generated_at"`
	CheckedAt   *time.Time `json:"checked_at,omitempty"`
	State       string     `json:"state"`
	HealthState string     `json:"health_state"`
	ReadyState  string     `json:"ready_state"`
	Days        []Day      `json:"days"`
	Incidents   []Incident `json:"incidents"`
	Observed    int        `json:"observed_minutes"`
	Expected    int        `json:"expected_minutes"`
	Healthy     int        `json:"healthy_minutes"`
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("status database path is required")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
 CREATE TABLE IF NOT EXISTS status_meta (id INTEGER PRIMARY KEY CHECK(id=1), origin TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS status_samples (minute INTEGER PRIMARY KEY, checked INTEGER NOT NULL, health INTEGER NOT NULL CHECK(health IN (0,1)), ready INTEGER NOT NULL CHECK(ready IN (0,1)));
 CREATE TABLE IF NOT EXISTS status_incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, started INTEGER NOT NULL, resolved INTEGER, title TEXT NOT NULL, note TEXT NOT NULL);`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }

// BindOrigin prevents silently mixing measurements of different relays.
func (s *Store) BindOrigin(ctx context.Context, origin string) error {
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO status_meta(id,origin) VALUES(1,?)`, origin); err != nil {
		return err
	}
	var saved string
	if err := s.db.QueryRowContext(ctx, `SELECT origin FROM status_meta WHERE id=1`).Scan(&saved); err != nil {
		return err
	}
	if saved != origin {
		return errors.New("status database belongs to a different probe origin; use a separate database")
	}
	return nil
}
func (s *Store) Record(ctx context.Context, sample Sample) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO status_samples(minute,checked,health,ready) VALUES(?,?,?,?) ON CONFLICT(minute) DO UPDATE SET checked=max(checked,excluded.checked), health=min(health,excluded.health), ready=min(ready,excluded.ready)`, sample.CheckedAt.Unix()/60, sample.CheckedAt.Unix(), sample.Health, sample.Ready)
	if err != nil {
		return err
	}
	cutoff := sample.CheckedAt.Add(-Retention).Unix()
	if _, err = tx.ExecContext(ctx, `DELETE FROM status_samples WHERE checked < ?`, cutoff); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM status_incidents WHERE resolved IS NOT NULL AND resolved < ?`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) AddIncident(ctx context.Context, now time.Time, title, note string) (int64, error) {
	if len(title) == 0 || len(title) > 120 || len(note) == 0 || len(note) > 2000 {
		return 0, errors.New("incident requires a title (1–120 bytes) and note (1–2000 bytes)")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO status_incidents(started,title,note) VALUES(?,?,?)`, now.Unix(), title, note)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}
func (s *Store) ResolveIncident(ctx context.Context, now time.Time, id int64, note string) error {
	if len(note) == 0 || len(note) > 2000 {
		return errors.New("resolution note must be 1–2000 bytes")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE status_incidents SET resolved=?,note=? WHERE id=? AND resolved IS NULL AND started<=?`, now.Unix(), note, id, now.Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("open incident not found")
	}
	return nil
}
func state(health, ready bool) string {
	if !health {
		return "down"
	}
	if !ready {
		return "degraded"
	}
	return "healthy"
}
func Unknown(now time.Time) Snapshot {
	now = now.UTC()
	v := Snapshot{GeneratedAt: now, State: "unknown", HealthState: "unknown", ReadyState: "unknown", Days: []Day{}, Incidents: []Incident{}}
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	for day := midnight.AddDate(0, 0, -89); !day.After(midnight); day = day.AddDate(0, 0, 1) {
		d := Day{Date: day.Format("2006-01-02"), State: "unknown", Expected: 1440}
		if day.Equal(midnight) {
			d.Expected = int(now.Sub(midnight)/time.Minute) + 1
		}
		v.Days = append(v.Days, d)
		v.Expected += d.Expected
	}
	return v
}
func (s *Store) Snapshot(ctx context.Context, now time.Time) (Snapshot, error) {
	now = now.UTC()
	v := Unknown(now)
	start, err := time.Parse("2006-01-02", v.Days[0].Date)
	if err != nil {
		return v, err
	}
	var latest Sample
	var checked int64
	err = s.db.QueryRowContext(ctx, `SELECT checked,health,ready FROM status_samples WHERE minute>=? AND checked<=? ORDER BY minute DESC LIMIT 1`, start.Unix()/60, now.Unix()).Scan(&checked, &latest.Health, &latest.Ready)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	if err == nil {
		latest.CheckedAt = time.Unix(checked, 0).UTC()
		v.CheckedAt = &latest.CheckedAt
		if now.Sub(latest.CheckedAt) <= Freshness {
			v.State = state(latest.Health, latest.Ready)
			v.HealthState = "down"
			v.ReadyState = "down"
			if latest.Health {
				v.HealthState = "healthy"
			}
			if latest.Ready {
				v.ReadyState = "healthy"
			}
		}
	}
	// Aggregate in SQLite so a public request allocates only 90 daily rows.
	rows, err := s.db.QueryContext(ctx, `SELECT strftime('%Y-%m-%d',checked,'unixepoch'),count(*),sum(health=1 AND ready=1),min(health),min(ready) FROM status_samples WHERE minute>=? AND checked<=? GROUP BY 1`, start.Unix()/60, now.Unix())
	if err != nil {
		return v, err
	}
	byDay := make(map[string]Day)
	for rows.Next() {
		var d Day
		var health, ready bool
		if err := rows.Scan(&d.Date, &d.Observed, &d.Healthy, &health, &ready); err != nil {
			_ = rows.Close()
			return v, err
		}
		d.State = state(health, ready)
		byDay[d.Date] = d
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return v, err
	}
	for i := range v.Days {
		d := &v.Days[i]
		if observed, ok := byDay[d.Date]; ok {
			d.Observed = observed.Observed
			d.Healthy = observed.Healthy
			d.State = observed.State
			if d.State == "healthy" && d.Observed < d.Expected {
				d.State = "partial"
			}
		}
		v.Observed += d.Observed
		v.Healthy += d.Healthy
	}
	// Limit notes so maximum-size HTML-escaped text fits the relay response cap.
	rows, err = s.db.QueryContext(ctx, `SELECT id,started,resolved,title,note FROM status_incidents WHERE started<=? AND (resolved IS NULL OR resolved>=?) ORDER BY (resolved IS NULL) DESC,started DESC LIMIT 75`, now.Unix(), now.Add(-Retention).Unix())
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var i Incident
		var started int64
		var resolved sql.NullInt64
		if err := rows.Scan(&i.ID, &started, &resolved, &i.Title, &i.Note); err != nil {
			return v, err
		}
		i.StartedAt = time.Unix(started, 0).UTC()
		if resolved.Valid {
			t := time.Unix(resolved.Int64, 0).UTC()
			i.ResolvedAt = &t
		}
		v.Incidents = append(v.Incidents, i)
	}
	if err := rows.Err(); err != nil {
		return v, fmt.Errorf("read incident history: %w", err)
	}
	return v, nil
}

// Uptime is the share of checked minutes that were healthy, for the status page.
func (s Snapshot) Uptime() string { return percent(s.Healthy, s.Observed) }

// Since is the first UTC day with any check, or "" when nothing was checked.
func (s Snapshot) Since() string {
	for _, d := range s.Days {
		if d.Observed > 0 {
			if t, err := time.Parse("2006-01-02", d.Date); err == nil {
				return t.Format("2 Jan 2006")
			}
			return d.Date
		}
	}
	return ""
}

// Up is the share of the day's checked minutes that were healthy.
func (d Day) Up() string { return percent(d.Healthy, d.Observed) }

// Checked is the share of the day's minutes that had a check.
func (d Day) Checked() string { return percent(d.Observed, d.Expected) }

func percent(part, whole int) string {
	if whole <= 0 {
		return "--"
	}
	p := float64(part) * 100 / float64(whole)
	if part < whole && p > 99.99 {
		p = 99.99
	}
	s := strconv.FormatFloat(p, 'f', 2, 64)
	s = strings.TrimSuffix(strings.TrimSuffix(s, "0"), ".0")
	return strings.TrimSuffix(s, ".") + "%"
}

// OpenOffline reads an existing origin-bound store without migration or writes.
func OpenOffline(path, origin string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: absolute, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var saved string
	if err = db.QueryRow(`SELECT origin FROM status_meta WHERE id=1`).Scan(&saved); err != nil || saved != origin {
		db.Close()
		return nil, errors.New("offline status database must exist and match the selected probe origin")
	}
	return &Store{db: db}, nil
}
