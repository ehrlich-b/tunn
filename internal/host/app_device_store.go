package host

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

const appDeviceLifetime = 30 * 24 * time.Hour
const appInvitationLifetime = 5 * time.Minute
const appDeviceLeaseLifetime = 5 * time.Second
const appDeviceCapacity = 10000

type appDevice struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Account   string `json:"account_id"`
	Email     string `json:"email"`
	Host      string `json:"hostname"`
	Namespace string `json:"namespace"`
	Publisher string `json:"publisher"`
	Endpoint  string `json:"endpoint"`
	Resource  string `json:"resource_id"`
	Created   int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used_at"`
	Expires   int64  `json:"expires_at"`
	Revoked   int64  `json:"revoked_at"`
}

type appInvitation struct {
	ID string `json:"id"`
	appDevice
	Claim     string `json:"claim_id,omitempty"`
	Challenge string `json:"-"`
	Phrase    string `json:"phrase,omitempty"`
	Approved  bool   `json:"approved"`
	Consumed  bool   `json:"consumed"`
	Failures  int    `json:"-"`
	Polled    int64  `json:"-"`
}

type appDeviceStore struct {
	db  *sql.DB
	now func() time.Time
}

func newAppDeviceStore(db *sql.DB) (*appDeviceStore, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS app_devices (
 id TEXT PRIMARY KEY, digest BLOB UNIQUE NOT NULL, account TEXT NOT NULL, host TEXT NOT NULL,
 expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, data BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS app_devices_scope ON app_devices(account,host);
 CREATE TABLE IF NOT EXISTS app_device_invitations (
 id TEXT PRIMARY KEY, digest BLOB UNIQUE NOT NULL, account TEXT NOT NULL, expires INTEGER NOT NULL,
 claim TEXT UNIQUE, challenge TEXT NOT NULL DEFAULT '', phrase TEXT NOT NULL DEFAULT '',
 approved INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0,
 failures INTEGER NOT NULL DEFAULT 0, polled INTEGER NOT NULL DEFAULT 0, data BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS app_device_invitations_account ON app_device_invitations(account,expires);
 CREATE TABLE IF NOT EXISTS app_device_rates (key TEXT PRIMARY KEY, minute INTEGER NOT NULL, count INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS app_device_leases (id TEXT PRIMARY KEY, device TEXT NOT NULL, expires INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS app_device_leases_device ON app_device_leases(device,expires);`)
	return &appDeviceStore{db: db, now: time.Now}, err
}

type appDeviceError struct {
	status  int
	message string
}

func (e *appDeviceError) Error() string           { return e.message }
func appProblem(status int, message string) error { return &appDeviceError{status, message} }

// Rate keys and invitations contain hashes, never enrollment handles or verifiers.
func appDigest(raw string) []byte { d := sha256.Sum256([]byte(raw)); return d[:] }
func appRateKey(kind, value string) string {
	return kind + ":" + base64.RawURLEncoding.EncodeToString(appDigest(value))
}

func (s *appDeviceStore) cleanup(ctx context.Context, tx *sql.Tx, now int64) error {
	for _, q := range []string{
		`DELETE FROM app_device_invitations WHERE id IN (SELECT id FROM app_device_invitations WHERE expires<=? LIMIT 256)`,
		`DELETE FROM app_device_leases WHERE id IN (SELECT id FROM app_device_leases WHERE expires<=? LIMIT 256)`,
		`DELETE FROM app_devices WHERE id IN (SELECT id FROM app_devices WHERE expires<=? LIMIT 256)`,
	} {
		if _, err := tx.ExecContext(ctx, q, now); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM app_device_rates WHERE key IN (SELECT key FROM app_device_rates WHERE minute<? LIMIT 256)`, now/60000-1)
	return err
}

func appRate(ctx context.Context, tx *sql.Tx, key string, now int64, limit int, increment bool) (bool, error) {
	var minute int64
	var count int
	err := tx.QueryRowContext(ctx, `SELECT minute,count FROM app_device_rates WHERE key=?`, key).Scan(&minute, &count)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	err = nil
	if minute != now/60000 {
		count = 0
	}
	if count >= limit {
		return false, nil
	}
	if increment {
		var total int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM app_device_rates`).Scan(&total); err != nil {
			return false, err
		}
		if total >= appDeviceCapacity && !exists {
			return false, nil
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO app_device_rates(key,minute,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET minute=excluded.minute,count=CASE WHEN minute=excluded.minute THEN count+1 ELSE 1 END`, key, now/60000)
	}
	return err == nil, err
}

func (s *appDeviceStore) invite(ctx context.Context, scope appDevice) (*appInvitation, string, error) {
	id, err := randomOAuthValue("ai_")
	if err != nil {
		return nil, "", err
	}
	secret, err := randomOAuthValue("tunn_inv_")
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	scope.Created = now.UnixMilli()
	scope.Expires = now.Add(appInvitationLifetime).UnixMilli()
	data, err := json.Marshal(scope)
	if err != nil {
		return nil, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = s.cleanup(ctx, tx, now.UnixMilli()); err != nil {
		return nil, "", err
	}
	allowed, err := appRate(ctx, tx, appRateKey("invite", scope.Account), now.UnixMilli(), 5, true)
	if err != nil {
		return nil, "", err
	}
	if !allowed {
		return nil, "", appProblem(429, "Invitation limit reached; try again in a minute")
	}
	var account, total int
	err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM app_device_invitations WHERE account=? AND consumed=0 AND expires>?), (SELECT count(*) FROM app_device_invitations)`, scope.Account, now.UnixMilli()).Scan(&account, &total)
	if err != nil {
		return nil, "", err
	}
	if account >= 5 || total >= appDeviceCapacity {
		return nil, "", appProblem(429, "Too many outstanding invitations")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO app_device_invitations(id,digest,account,expires,data) VALUES(?,?,?,?,?)`, id, appDigest(secret), scope.Account, scope.Expires, data)
	if err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return &appInvitation{ID: id, appDevice: scope}, secret, nil
}

type appScanner interface{ Scan(...any) error }

func scanAppInvitation(row appScanner) (*appInvitation, error) {
	i := new(appInvitation)
	var data []byte
	var expiry int64
	var claim sql.NullString
	err := row.Scan(&i.ID, &claim, &i.Challenge, &i.Phrase, &i.Approved, &i.Consumed, &i.Failures, &i.Polled, &data, &expiry)
	if err != nil {
		return nil, err
	}
	i.Claim = claim.String
	if err = json.Unmarshal(data, &i.appDevice); err != nil {
		return nil, err
	}
	i.Expires = expiry
	return i, nil
}

const appInvitationColumns = `id,claim,challenge,phrase,approved,consumed,failures,polled,data,expires`

func (s *appDeviceStore) admitClaimSource(ctx context.Context, source string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	if err = s.cleanup(ctx, tx, now); err != nil {
		return err
	}
	allowed, err := appRate(ctx, tx, appRateKey("claim-ip", source), now, 30, true)
	if err != nil {
		return err
	}
	if !allowed {
		return appProblem(429, "Enrollment source limit reached; try again in a minute")
	}
	return tx.Commit()
}

func (s *appDeviceStore) invitation(ctx context.Context, column, value string) (*appInvitation, error) {
	if column != "id" && column != "claim" {
		return nil, fmt.Errorf("invalid invitation lookup")
	}
	i, err := scanAppInvitation(s.db.QueryRowContext(ctx, `SELECT `+appInvitationColumns+` FROM app_device_invitations WHERE `+column+`=?`, value))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, appProblem(400, "Invalid, expired or consumed invitation")
	}
	if err != nil {
		return nil, err
	}
	if i.Expires <= s.now().UnixMilli() || i.Consumed {
		return nil, appProblem(400, "Expired or consumed invitation; pair again")
	}
	if i.Failures >= 10 {
		return nil, appProblem(429, "Invitation attempt limit reached; create a new invitation")
	}
	return i, nil
}

func validAppChallenge(challenge string) bool {
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(b) == 32 && len(challenge) == 43
}
func validAppVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	return strings.IndexFunc(verifier, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c))
	}) < 0
}
func appClaimPhrase(claim, challenge, host string) string {
	words := []string{"amber", "birch", "cedar", "dawn", "elm", "fern", "grove", "harbor", "iris", "jade", "kite", "lake", "maple", "north", "oak", "pine", "quartz", "river", "stone", "tide", "umber", "vale", "willow", "xenon", "yarrow", "zinc", "bloom", "cloud", "dune", "frost", "glade", "hill"}
	d := sha256.Sum256([]byte(claim + "\x00" + challenge + "\x00" + host))
	return fmt.Sprintf("%s %s %s %s · %02x%02x", words[d[0]%32], words[d[1]%32], words[d[2]%32], words[d[3]%32], d[4], d[5])
}

func (s *appDeviceStore) claim(ctx context.Context, secret, challenge, name, host string) (*appInvitation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	i, err := scanAppInvitation(tx.QueryRowContext(ctx, `SELECT `+appInvitationColumns+` FROM app_device_invitations WHERE digest=?`, appDigest(secret)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, appProblem(400, "Invalid invitation")
	}
	if err != nil {
		return nil, err
	}
	if i.Expires <= s.now().UnixMilli() || i.Consumed {
		return nil, appProblem(400, "Expired or consumed invitation")
	}
	if i.Failures >= 10 {
		return nil, appProblem(429, "Invitation attempt limit reached")
	}
	if i.Claim != "" || !validAppChallenge(challenge) || name == "" || len(name) > 80 || strings.ContainsAny(name, "\r\n\x00") || host != i.Host {
		_, err = tx.ExecContext(ctx, `UPDATE app_device_invitations SET failures=failures+1 WHERE id=?`, i.ID)
		if err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return nil, appProblem(400, "Claim is frozen, or claim input does not match invitation")
	}
	i.Claim, err = randomOAuthValue("ac_")
	if err != nil {
		return nil, err
	}
	i.Challenge = challenge
	i.Name = name
	i.Phrase = appClaimPhrase(i.Claim, challenge, i.Host)
	data, err := json.Marshal(i.appDevice)
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE app_device_invitations SET claim=?,challenge=?,phrase=?,data=? WHERE id=? AND claim IS NULL AND consumed=0`, i.Claim, challenge, i.Phrase, data, i.ID)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, appProblem(400, "Invitation already claimed")
	}
	return i, tx.Commit()
}

func (s *appDeviceStore) approve(ctx context.Context, i *appInvitation) error {
	res, err := s.db.ExecContext(ctx, `UPDATE app_device_invitations SET approved=1 WHERE id=? AND claim=? AND challenge=? AND consumed=0 AND failures<10 AND expires>?`, i.ID, i.Claim, i.Challenge, s.now().UnixMilli())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return appProblem(400, "Invitation changed or expired")
	}
	return nil
}

// Consume and insert are one transaction. A lost response never permits reissuance.
func (s *appDeviceStore) redeem(ctx context.Context, claim, verifier, host, phrase string, confirmed bool) (*appDevice, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	i, err := scanAppInvitation(tx.QueryRowContext(ctx, `SELECT `+appInvitationColumns+` FROM app_device_invitations WHERE claim=?`, claim))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", appProblem(400, "Invalid claim")
	}
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	if i.Consumed || i.Expires <= now.UnixMilli() {
		return nil, "", appProblem(400, "Expired or consumed invitation; pair again")
	}
	if i.Failures >= 10 {
		return nil, "", appProblem(429, "Invitation attempt limit reached")
	}
	if i.Polled != 0 && now.UnixMilli()-i.Polled < 5000 {
		return nil, "", appProblem(429, "Poll no faster than every 5 seconds")
	}
	_, err = tx.ExecContext(ctx, `UPDATE app_device_invitations SET polled=? WHERE id=?`, now.UnixMilli(), i.ID)
	if err != nil {
		return nil, "", err
	}
	digest := base64.RawURLEncoding.EncodeToString(appDigest(verifier))
	if !validAppVerifier(verifier) || subtle.ConstantTimeCompare([]byte(digest), []byte(i.Challenge)) != 1 || !confirmed || host != i.Host || phrase != i.Phrase {
		_, err = tx.ExecContext(ctx, `UPDATE app_device_invitations SET failures=failures+1 WHERE id=?`, i.ID)
		if err != nil {
			return nil, "", err
		}
		if err = tx.Commit(); err != nil {
			return nil, "", err
		}
		return nil, "", appProblem(400, "Verifier or device confirmation does not match")
	}
	if !i.Approved {
		if err = tx.Commit(); err != nil {
			return nil, "", err
		}
		return nil, "", appProblem(202, "Waiting for browser approval")
	}
	if err = s.cleanup(ctx, tx, now.UnixMilli()); err != nil {
		return nil, "", err
	}
	var count, total int
	err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM app_devices WHERE account=? AND host=? AND revoked=0 AND expires>?), (SELECT count(*) FROM app_devices)`, i.Account, i.Host, now.UnixMilli()).Scan(&count, &total)
	if err != nil {
		return nil, "", err
	}
	if count >= 20 || total >= appDeviceCapacity {
		return nil, "", appProblem(429, "Device capacity reached; revoke a device first")
	}
	d := i.appDevice
	d.ID, err = randomOAuthValue("ad_")
	if err != nil {
		return nil, "", err
	}
	secret, err := randomOAuthValue("tunn_app_")
	if err != nil {
		return nil, "", err
	}
	d.Created = now.UnixMilli()
	d.LastUsed = 0
	d.Expires = now.Add(appDeviceLifetime).UnixMilli()
	data, err := json.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO app_devices(id,digest,account,host,expires,data) VALUES(?,?,?,?,?,?)`, d.ID, appDigest(secret), d.Account, d.Host, d.Expires, data)
	if err != nil {
		return nil, "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE app_device_invitations SET consumed=1 WHERE id=?`, i.ID)
	if err != nil {
		return nil, "", err
	}
	return &d, secret, tx.Commit()
}

func (s *appDeviceStore) list(ctx context.Context, host, account string, owner bool) ([]appDevice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data,revoked FROM app_devices WHERE host=? AND (? OR account=?) ORDER BY rowid DESC LIMIT 10000`, host, owner, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []appDevice{}
	for rows.Next() {
		var d appDevice
		var data []byte
		if err = rows.Scan(&data, &d.Revoked); err != nil {
			return nil, err
		}
		revoked := d.Revoked
		if err = json.Unmarshal(data, &d); err != nil {
			return nil, err
		}
		d.Revoked = revoked
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *appDeviceStore) revoke(ctx context.Context, host, account, id string, owner bool) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	res, err := tx.ExecContext(ctx, `UPDATE app_devices SET revoked=? WHERE host=? AND (? OR account=?) AND (?='' OR id=?) AND revoked=0`, now, host, owner, account, id, id)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if id != "" && n == 0 {
		return 0, appProblem(404, "Device not found or already revoked")
	}
	// Revoking all also invalidates this caller's pending enrollments on the scope.
	if id == "" {
		_, err = tx.ExecContext(ctx, `UPDATE app_device_invitations SET consumed=1 WHERE (? OR account=?) AND json_extract(data,'$.hostname')=?`, owner, account, host)
		if err != nil {
			return 0, err
		}
	}
	return now, tx.Commit()
}

func (s *appDeviceStore) check(ctx context.Context, in *internalpb.AppDeviceCheckRequest) (*internalpb.AppDeviceCheckResponse, error) {
	if len(in.TokenSha256) != 32 || len(in.Source) > 128 || len(in.Hostname) > 253 || len(in.LeaseId) > 80 || len(in.DeviceId) > 80 {
		return nil, appProblem(400, "Invalid app device check")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.now().UnixMilli()
	if err = s.cleanup(ctx, tx, now); err != nil {
		return nil, err
	}
	out := &internalpb.AppDeviceCheckResponse{Status: 200}
	var d appDevice
	var data []byte
	var expiry, revoked int64
	err = tx.QueryRowContext(ctx, `SELECT data,expires,revoked FROM app_devices WHERE digest=?`, in.TokenSha256).Scan(&data, &expiry, &revoked)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	found := err == nil
	if found {
		if err = json.Unmarshal(data, &d); err != nil {
			return nil, err
		}
		d.Expires = expiry
		d.Revoked = revoked
	}
	keys := []string{appRateKey("validate-ip", in.Source)}
	if found {
		keys = append(keys, appRateKey("validate-account", d.Account+"\x00"+in.Hostname))
	}
	if in.Operation == "resolve" || in.Operation == "acquire" || in.Operation == "failure" {
		for _, key := range keys {
			allowed, err := appRate(ctx, tx, key, now, 30, false)
			if err != nil {
				return nil, err
			}
			if !allowed {
				out.Status = 429
				return out, tx.Commit()
			}
		}
	}
	if in.Operation == "release" {
		_, err = tx.ExecContext(ctx, `DELETE FROM app_device_leases WHERE id=? AND device=?`, in.LeaseId, in.DeviceId)
		if err != nil {
			return nil, err
		}
		return out, tx.Commit()
	}
	if !found || revoked != 0 || expiry <= now {
		out.Status = 401
	} else if d.Host != in.Hostname {
		out.Status = 403
	}
	if in.Operation == "failure" && out.Status == 200 {
		out.Status = 403
	}
	if out.Status != 200 {
		if in.Operation != "renew" && in.Operation != "watch" {
			for _, key := range keys {
				allowed, err := appRate(ctx, tx, key, now, 30, true)
				if err != nil {
					return nil, err
				}
				if !allowed {
					out.Status = 429
				}
			}
		}
		return out, tx.Commit()
	}
	switch in.Operation {
	case "resolve", "watch":
	case "acquire":
		if in.LeaseId == "" {
			return nil, appProblem(400, "Missing lease")
		}
		var active int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM app_device_leases WHERE device=? AND expires>?`, d.ID, now).Scan(&active); err != nil {
			return nil, err
		}
		if active >= 10 {
			out.Status = 429
			return out, tx.Commit()
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO app_device_leases(id,device,expires) VALUES(?,?,?)`, in.LeaseId, d.ID, now+appDeviceLeaseLifetime.Milliseconds())
		if err != nil {
			return nil, err
		}
		d.LastUsed = now
		data, err = json.Marshal(d)
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE app_devices SET data=? WHERE id=?`, data, d.ID)
		if err != nil {
			return nil, err
		}
	case "renew":
		res, err := tx.ExecContext(ctx, `UPDATE app_device_leases SET expires=? WHERE id=? AND device=? AND expires>?`, now+appDeviceLeaseLifetime.Milliseconds(), in.LeaseId, d.ID, now)
		if err != nil {
			return nil, err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			out.Status = 403
			return out, tx.Commit()
		}
	default:
		return nil, appProblem(400, "Unknown device check operation")
	}
	out.DeviceJson, err = json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func appStatus(err error) int {
	var problem *appDeviceError
	if errors.As(err, &problem) {
		return problem.status
	}
	return http.StatusServiceUnavailable
}
