package host

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/golang-jwt/jwt/v4"
)

const deviceAccessLifetime = 5 * time.Minute
const deviceReauthCapability = "device-reauth-v1"

var errDeviceCredential = errors.New("device credential revoked, reused or invalid")

type deviceCredentialStore struct{ db *sql.DB }
type durableDevice struct {
	Purpose   string `json:"purpose"`
	AccountID string `json:"-"`
	ID        string `json:"id"`
	Email     string `json:"-"`
	Name      string `json:"name"`
	Created   int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used_at"`
	Revoked   int64  `json:"revoked_at"`
}

func newDeviceCredentialStore(db *sql.DB) (*deviceCredentialStore, error) {
	if err := store.MigrateDevicePurpose(db); err != nil {
		return nil, err
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS durable_devices (
 id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL,
 digest BLOB NOT NULL UNIQUE, created INTEGER NOT NULL, last_used INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0, purpose TEXT NOT NULL DEFAULT 'publisher', account_id TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS durable_device_used (
 digest BLOB PRIMARY KEY, device TEXT NOT NULL, request TEXT NOT NULL,
 used INTEGER NOT NULL, replacement BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS durable_devices_email ON durable_devices(email);
 CREATE UNIQUE INDEX IF NOT EXISTS durable_device_requests ON durable_device_used(device,request);`)
	if err == nil {
		err = migrateDurablePurpose(db)
	}
	if err == nil {
		err = store.MigrateCredentialOwnership(db)
	}
	return &deviceCredentialStore{db: db}, err
}

func (s *deviceCredentialStore) issue(code, name string, now time.Time) (*durableDevice, string, error) {
	return s.issueForPurpose(code, name, "publisher", now)
}

func (s *deviceCredentialStore) issueForPurpose(code, name, purpose string, now time.Time) (*durableDevice, string, error) {
	id, err := randomOAuthValue("dev_")
	if err != nil {
		return nil, "", err
	}
	secret, err := randomOAuthValue("tunn_rt_")
	if err != nil {
		return nil, "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var email, bound string
	err = tx.QueryRow(`DELETE FROM device_codes WHERE code=? AND purpose=? AND authorized=1 AND expires_at>? RETURNING email,account_id`, code, purpose, now.Unix()).Scan(&email, &bound)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", errDeviceCredential
	}
	if err != nil {
		return nil, "", err
	}
	// Also covers authorized codes persisted before canonicalization was added.
	email = common.NormalizeEmail(email)
	var accountID string
	if bound != "" {
		var primary string
		err = tx.QueryRow(`SELECT id,primary_email FROM accounts WHERE id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)`, bound, bound).Scan(&accountID, &primary)
		if err == nil {
			var member int
			err = tx.QueryRow(`SELECT count(*) FROM account_emails WHERE email=? AND account_id=?`, email, accountID).Scan(&member)
			if member == 0 {
				email = primary
			}
		}
	} else {
		err = tx.QueryRow(`SELECT account_id FROM account_emails WHERE email=?`, email).Scan(&accountID)
	}
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256([]byte(secret))
	d := &durableDevice{ID: id, Email: email, Name: name, Purpose: purpose, AccountID: accountID, Created: now.Unix(), LastUsed: now.Unix()}
	_, err = tx.Exec(`INSERT INTO durable_devices(id,email,name,digest,created,last_used,purpose,account_id) VALUES(?,?,?,?,?,?,?,?)`, id, email, name, digest[:], d.Created, d.LastUsed, purpose, accountID)
	if err != nil {
		return nil, "", err
	}
	return d, secret, tx.Commit()
}

func (s *deviceCredentialStore) rotate(secret, request string, key []byte, now time.Time) (*durableDevice, string, error) {
	if len(secret) > 256 || !strings.HasPrefix(secret, "tunn_rt_") || len(request) < 32 || len(request) > 128 {
		return nil, "", errDeviceCredential
	}
	digest := sha256.Sum256([]byte(secret))
	tx, err := s.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var d durableDevice
	err = tx.QueryRow(`SELECT id,email,name,created,last_used,revoked,account_id FROM durable_devices WHERE digest=? AND purpose='publisher'`, digest[:]).Scan(&d.ID, &d.Email, &d.Name, &d.Created, &d.LastUsed, &d.Revoked, &d.AccountID)
	if errors.Is(err, sql.ErrNoRows) {
		var oldRequest string
		var replacement, current []byte
		err = tx.QueryRow(`SELECT u.device,u.request,u.replacement,d.digest,d.email,d.revoked,d.account_id FROM durable_device_used u JOIN durable_devices d ON d.id=u.device WHERE u.digest=? AND d.purpose='publisher'`, digest[:]).Scan(&d.ID, &oldRequest, &replacement, &current, &d.Email, &d.Revoked, &d.AccountID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", errDeviceCredential
		}
		if err != nil {
			return nil, "", err
		}
		d.Email = common.NormalizeEmail(d.Email)
		if d.Revoked != 0 {
			return nil, "", errDeviceCredential
		}
		// A lost response is recoverable with the same request ID for as long
		// as its replacement has never been redeemed, however long the client
		// slept or retried. Once the replacement rotates, any reuse revokes.
		if oldRequest == request && hmac.Equal(replacement, current) {
			if _, err = tx.Exec(`UPDATE durable_devices SET last_used=? WHERE id=?`, now.Unix(), d.ID); err != nil {
				return nil, "", err
			}
			d.LastUsed = now.Unix()
			return &d, deriveDeviceRefresh(key, d.ID, request), tx.Commit()
		}
		if _, err = tx.Exec(`UPDATE durable_devices SET revoked=? WHERE id=?`, now.Unix(), d.ID); err != nil {
			return nil, "", err
		}
		if err = tx.Commit(); err != nil {
			return nil, "", err
		}
		common.LogInfo("device credential audit", "action", "reuse_revoked", "device", d.ID)
		return nil, "", errDeviceCredential
	}
	if err != nil {
		return nil, "", err
	}
	d.Email = common.NormalizeEmail(d.Email)
	if d.Revoked != 0 {
		return nil, "", errDeviceCredential
	}
	next := deriveDeviceRefresh(key, d.ID, request)
	replacement := sha256.Sum256([]byte(next))
	_, err = tx.Exec(`INSERT INTO durable_device_used(digest,device,request,used,replacement) VALUES(?,?,?,?,?)`, digest[:], d.ID, request, now.Unix(), replacement[:])
	if err != nil {
		return nil, "", err
	}
	_, err = tx.Exec(`UPDATE durable_devices SET digest=?,last_used=? WHERE id=?`, replacement[:], now.Unix(), d.ID)
	if err != nil {
		return nil, "", err
	}
	d.LastUsed = now.Unix()
	return &d, next, tx.Commit()
}

func deriveDeviceRefresh(key []byte, id, request string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "tunn-device-refresh-v1\x00%s\x00%s", id, request)
	return "tunn_rt_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (p *ProxyServer) forwardDeviceService(w http.ResponseWriter, r *http.Request) bool {
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Invalid authentication host", 403)
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	if p.devices != nil {
		return false
	}
	p.loginNodeMu.RLock()
	addr := p.loginNodeHTTPAddr
	p.loginNodeMu.RUnlock()
	if addr != "" && r.Header.Get("Tunn-Device-Forwarded") == "" {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		clone.Header.Set("Tunn-Device-Forwarded", "1")
		p.proxyToNode(w, clone, addr, "")
	} else {
		oauthProblem(w, 503, "temporarily_unavailable", "Device authentication service unavailable; retry shortly")
	}
	return true
}

func (p *ProxyServer) writeDurableToken(w http.ResponseWriter, r *http.Request, d *durableDevice, secret string) {
	d.Email = common.NormalizeEmail(d.Email)
	// Suspension/account lookup errors fail closed before any token is returned.
	a, err := p.storage.GetAccount(r.Context(), d.AccountID)
	if err != nil || a == nil || a.OperationalState != "active" {
		oauthProblem(w, 403, "access_denied", "Account unavailable or suspended; contact the account owner")
		return
	}
	linked := false
	for _, alias := range a.Emails {
		if common.NormalizeEmail(alias.Email) == d.Email {
			linked = true
			break
		}
	}
	if !linked {
		d.Email = a.PrimaryEmail
	}
	// Anchor access expiry to the committed rotation or recovery, each of which
	// checked revocation. An in-flight response cannot extend its own lease.
	now := time.Unix(d.LastUsed, 0)
	remaining := int(now.Add(deviceAccessLifetime).Sub(p.currentTime()).Seconds())
	if remaining <= 0 {
		oauthProblem(w, 401, "invalid_grant", "Refresh response expired; run tunn login")
		return
	}
	claims := jwt.MapClaims{"email": d.Email, "sub": d.Email, "type": "device_access", "iss": "tunn", "aud": "tunn-tunnels", "scope": "publish connect", "device": d.ID, "account_id": a.ID, "iat": now.Unix(), "exp": now.Add(deviceAccessLifetime).Unix()}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		oauthProblem(w, 500, "server_error", "Could not issue access token")
		return
	}
	writeOAuthJSON(w, 200, map[string]any{"access_token": token, "refresh_token": secret, "token_type": "Bearer", "expires_in": remaining, "device_id": d.ID})
}

func (p *ProxyServer) handleDurableExchange(w http.ResponseWriter, r *http.Request) {
	if p.forwardDeviceService(w, r) {
		return
	}
	name := r.URL.Query().Get("name")
	if len(name) > 128 {
		oauthProblem(w, 400, "invalid_request", "Device name is too long")
		return
	}
	code, err := p.storage.GetDeviceCode(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Retry login shortly")
		return
	}
	if code != nil && !code.Authorized {
		writeOAuthJSON(w, 200, map[string]string{"error": "authorization_pending"})
		return
	}
	if code != nil && code.Purpose != "publisher" {
		oauthProblem(w, 400, "invalid_grant", "This code is for account management")
		return
	}
	d, secret, err := p.devices.issue(r.URL.Query().Get("code"), name, p.currentTime())
	if err != nil {
		if errors.Is(err, errDeviceCredential) {
			oauthProblem(w, 400, "expired_token", "Request a new login code")
		} else {
			oauthProblem(w, 503, "temporarily_unavailable", "Retry login shortly")
		}
		return
	}
	common.LogInfo("device credential audit", "action", "created", "device", d.ID)
	p.writeDurableToken(w, r, d, secret)
}

func (p *ProxyServer) handleDeviceRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if p.forwardDeviceService(w, r) {
		return
	}
	if !p.requireAuthOrigin(w, r, true) {
		return
	}
	var input struct {
		Refresh string `json:"refresh_token"`
		Request string `json:"request_id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil {
		oauthProblem(w, 400, "invalid_request", "Expected refresh_token and request_id")
		return
	}
	d, secret, err := p.devices.rotate(input.Refresh, input.Request, p.getJWTSigningKey(), p.currentTime())
	if err != nil {
		if errors.Is(err, errDeviceCredential) {
			oauthProblem(w, 401, "invalid_grant", "Device revoked or credential reused; run tunn login on this device")
		} else {
			oauthProblem(w, 503, "temporarily_unavailable", "Retry refresh shortly")
		}
		return
	}
	common.LogInfo("device credential audit", "action", "rotated", "device", d.ID)
	p.writeDurableToken(w, r, d, secret)
}

func (p *ProxyServer) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if p.forwardDeviceService(w, r) {
		return
	}
	email, ok := p.getAuthFromCookie(r)
	if !ok {
		http.Redirect(w, r, "/login?return_to=/account/devices", 302)
		return
	}
	var account *storage.Account
	var err error
	if claims, valid := p.accountSession(r); valid {
		account, err = p.sessionAccount(r, claims)
	} else {
		account, err = p.storage.GetAccountByEmail(r.Context(), email)
	}
	if err != nil || account == nil {
		http.Error(w, "Account unavailable", 503)
		return
	}
	if r.Method == http.MethodPost {
		if !p.requireCSRFToken(w, r, "/account/devices") {
			return
		}
		var owner string
		id := r.FormValue("device_id")
		err = p.devices.db.QueryRowContext(r.Context(), `SELECT account_id FROM durable_devices WHERE id=?`, id).Scan(&owner)
		if err != nil {
			http.Error(w, "Device not found", 404)
			return
		}
		deviceAccount, lookupErr := p.storage.GetAccount(r.Context(), owner)
		if lookupErr != nil || deviceAccount == nil || deviceAccount.ID != account.ID {
			http.Error(w, "Device not found", 404)
			return
		}
		_, err = p.devices.db.ExecContext(r.Context(), `UPDATE durable_devices SET revoked=? WHERE id=? AND revoked=0`, p.currentTime().Unix(), id)
		if err != nil {
			http.Error(w, "Device service unavailable", 503)
			return
		}
		common.LogInfo("device credential audit", "action", "owner_revoked", "device", id)
		http.Redirect(w, r, "/account/devices", 303)
		return
	}
	rows, err := p.devices.db.QueryContext(r.Context(), `SELECT id,email,name,created,last_used,revoked,account_id FROM durable_devices
 WHERE COALESCE((SELECT account_id FROM account_merges WHERE old_id=durable_devices.account_id),account_id)=?
 ORDER BY created DESC`, account.ID)
	if err != nil {
		http.Error(w, "Device service unavailable", 503)
		return
	}
	var list []durableDevice
	for rows.Next() {
		var d durableDevice
		if err = rows.Scan(&d.ID, &d.Email, &d.Name, &d.Created, &d.LastUsed, &d.Revoked, &d.AccountID); err != nil {
			break
		}
		list = append(list, d)
	}
	scanErr := rows.Err()
	_ = rows.Close()
	if err != nil || scanErr != nil {
		http.Error(w, "Device service unavailable", 503)
		return
	}
	csrf, err := p.createCSRFToken(r, "/account/devices")
	if err != nil {
		http.Error(w, "Confirmation unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	writePageStart(w, "tunn - Devices")
	_, _ = fmt.Fprint(w, `<section class="management"><h1>Devices</h1><p>Publisher devices can publish and connect to tunnels; management devices administer the account. Revocation stops management access and renewal immediately; publisher leases expire within five minutes.</p>`)
	for _, d := range list {
		_, _ = fmt.Fprintf(w, `<section class="card"><h2>%s</h2><code>%s</code><p>Created: %s; last refresh: %s; revoked: %t</p>`, html.EscapeString(d.Name), html.EscapeString(d.ID), time.Unix(d.Created, 0).UTC().Format(time.RFC3339), time.Unix(d.LastUsed, 0).UTC().Format(time.RFC3339), d.Revoked != 0)
		if d.Revoked == 0 {
			_, _ = fmt.Fprintf(w, `<form method="post" action="/account/devices"><input type="hidden" name="csrf_token" value="%s"><input type="hidden" name="device_id" value="%s"><button class="btn danger">Revoke device</button></form>`, html.EscapeString(csrf), html.EscapeString(d.ID))
		}
		_, _ = fmt.Fprint(w, `</section>`)
	}
	_, _ = fmt.Fprint(w, `</section>`)
	writePageEnd(w)
}
