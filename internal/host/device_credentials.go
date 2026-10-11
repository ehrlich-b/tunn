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
	"github.com/golang-jwt/jwt/v4"
)

const deviceAccessLifetime = 5 * time.Minute
const deviceReauthCapability = "device-reauth-v1"

var errDeviceCredential = errors.New("device credential revoked, reused or invalid")

type deviceCredentialStore struct{ db *sql.DB }
type durableDevice struct {
	ID       string `json:"id"`
	Email    string `json:"-"`
	Name     string `json:"name"`
	Created  int64  `json:"created_at"`
	LastUsed int64  `json:"last_used_at"`
	Revoked  int64  `json:"revoked_at"`
}

func newDeviceCredentialStore(db *sql.DB) (*deviceCredentialStore, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS durable_devices (
 id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL,
 digest BLOB NOT NULL UNIQUE, created INTEGER NOT NULL, last_used INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS durable_device_used (
 digest BLOB PRIMARY KEY, device TEXT NOT NULL, request TEXT NOT NULL,
 used INTEGER NOT NULL, replacement BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS durable_devices_email ON durable_devices(email);
 CREATE UNIQUE INDEX IF NOT EXISTS durable_device_requests ON durable_device_used(device,request);`)
	return &deviceCredentialStore{db: db}, err
}

func (s *deviceCredentialStore) issue(code, name string, now time.Time) (*durableDevice, string, error) {
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
	var email string
	err = tx.QueryRow(`DELETE FROM device_codes WHERE code=? AND authorized=1 AND expires_at>? RETURNING email`, code, now.Unix()).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", errDeviceCredential
	}
	if err != nil {
		return nil, "", err
	}
	// Also covers authorized codes persisted before canonicalization was added.
	email = common.NormalizeEmail(email)
	digest := sha256.Sum256([]byte(secret))
	d := &durableDevice{ID: id, Email: email, Name: name, Created: now.Unix(), LastUsed: now.Unix()}
	_, err = tx.Exec(`INSERT INTO durable_devices(id,email,name,digest,created,last_used) VALUES(?,?,?,?,?,?)`, id, email, name, digest[:], d.Created, d.LastUsed)
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
	err = tx.QueryRow(`SELECT id,email,name,created,last_used,revoked FROM durable_devices WHERE digest=?`, digest[:]).Scan(&d.ID, &d.Email, &d.Name, &d.Created, &d.LastUsed, &d.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		var oldRequest string
		var used int64
		var replacement, current []byte
		err = tx.QueryRow(`SELECT u.device,u.request,u.used,u.replacement,d.digest,d.email,d.revoked FROM durable_device_used u JOIN durable_devices d ON d.id=u.device WHERE u.digest=?`, digest[:]).Scan(&d.ID, &oldRequest, &used, &replacement, &current, &d.Email, &d.Revoked)
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
		if oldRequest == request && now.Unix() >= used && now.Unix()-used < 60 && hmac.Equal(replacement, current) {
			d.LastUsed = used
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
	a, err := p.storage.GetAccountByEmail(r.Context(), d.Email)
	if err != nil || a == nil || a.OperationalState != "active" {
		oauthProblem(w, 403, "access_denied", "Account unavailable or suspended; contact the account owner")
		return
	}
	// Anchor access expiry to the committed rotation, including retries. An
	// in-flight response after revocation cannot extend its original lease.
	now := time.Unix(d.LastUsed, 0)
	remaining := int(now.Add(deviceAccessLifetime).Sub(p.currentTime()).Seconds())
	if remaining <= 0 {
		oauthProblem(w, 401, "invalid_grant", "Refresh response expired; run tunn login")
		return
	}
	claims := jwt.MapClaims{"email": d.Email, "sub": d.Email, "type": "device_access", "iss": "tunn", "aud": "tunn-tunnels", "scope": "publish connect", "device": d.ID, "iat": now.Unix(), "exp": now.Add(deviceAccessLifetime).Unix()}
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
	account, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil || account == nil {
		http.Error(w, "Account unavailable", 503)
		return
	}
	emails, err := p.storage.GetEmailBucket(r.Context(), email)
	if err != nil {
		http.Error(w, "Account unavailable", 503)
		return
	}
	owned := func(owner string) bool {
		// Compatibility for devices already issued with mixed-case owners. Use
		// the account policy (including Unicode folding), without rewriting rows.
		owner = common.NormalizeEmail(owner)
		for _, e := range emails {
			if common.NormalizeEmail(e) == owner {
				return true
			}
		}
		return owner == common.NormalizeEmail(account.PrimaryEmail)
	}
	if r.Method == http.MethodPost {
		if !p.requireCSRFToken(w, r, "/account/devices") {
			return
		}
		var owner string
		id := r.FormValue("device_id")
		err = p.devices.db.QueryRowContext(r.Context(), `SELECT email FROM durable_devices WHERE id=?`, id).Scan(&owner)
		if err != nil || !owned(owner) {
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
	rows, err := p.devices.db.QueryContext(r.Context(), `SELECT id,email,name,created,last_used,revoked FROM durable_devices ORDER BY created DESC`)
	if err != nil {
		http.Error(w, "Device service unavailable", 503)
		return
	}
	var list []durableDevice
	for rows.Next() {
		var d durableDevice
		if err = rows.Scan(&d.ID, &d.Email, &d.Name, &d.Created, &d.LastUsed, &d.Revoked); err != nil {
			break
		}
		if owned(d.Email) {
			list = append(list, d)
		}
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
	_, _ = fmt.Fprint(w, `<h1>Devices</h1><p>Devices can publish and connect to tunnels. Revocation stops renewal immediately; existing publisher leases expire within five minutes.</p>`)
	for _, d := range list {
		_, _ = fmt.Fprintf(w, `<p><strong>%s</strong> <code>%s</code> Created: %s; last refresh: %s; revoked: %t</p>`, html.EscapeString(d.Name), html.EscapeString(d.ID), time.Unix(d.Created, 0).UTC().Format(time.RFC3339), time.Unix(d.LastUsed, 0).UTC().Format(time.RFC3339), d.Revoked != 0)
		if d.Revoked == 0 {
			_, _ = fmt.Fprintf(w, `<form method="post" action="/account/devices"><input type="hidden" name="csrf_token" value="%s"><input type="hidden" name="device_id" value="%s"><button>Revoke device</button></form>`, html.EscapeString(csrf), html.EscapeString(d.ID))
		}
	}
	writePageEnd(w)
}
