package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"
)

const (
	deviceCodeExpiry   = 3 * time.Minute
	deviceCodeInterval = 3 // seconds
)

// DeviceCode represents a pending device authorization
type DeviceCode struct {
	Code       string
	UserCode   string
	ExpiresAt  time.Time
	Interval   int
	Authorized bool
	Email      string
}

// DeviceCodeStore manages device codes in SQLite
type DeviceCodeStore struct {
	db *sql.DB
}

// NewDeviceCodeStore creates a new SQLite-backed device code store
func NewDeviceCodeStore(db *sql.DB) *DeviceCodeStore {
	store := &DeviceCodeStore{db: db}
	// Start cleanup goroutine
	go store.cleanup()
	return store
}

// Create generates a new device code
func (s *DeviceCodeStore) Create() (*DeviceCode, error) {
	deviceCode, err := generateSecureCode(32)
	if err != nil {
		return nil, err
	}

	userCode, err := generateUserCode()
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(deviceCodeExpiry)

	_, err = s.db.Exec(
		"INSERT INTO device_codes (code, user_code, expires_at, authorized) VALUES (?, ?, ?, 0)",
		deviceCode, userCode, expiresAt.Unix(),
	)
	if err != nil {
		return nil, err
	}

	return &DeviceCode{
		Code:      deviceCode,
		UserCode:  userCode,
		ExpiresAt: expiresAt,
		Interval:  deviceCodeInterval,
	}, nil
}

// Get retrieves a device code by its code
func (s *DeviceCodeStore) Get(deviceCode string) *DeviceCode {
	var code DeviceCode
	var expiresAtUnix int64
	var authorized int
	var email sql.NullString

	err := s.db.QueryRow(
		"SELECT code, user_code, expires_at, authorized, email FROM device_codes WHERE code = ?",
		deviceCode,
	).Scan(&code.Code, &code.UserCode, &expiresAtUnix, &authorized, &email)
	if err != nil {
		return nil
	}

	code.ExpiresAt = time.Unix(expiresAtUnix, 0)
	code.Authorized = authorized == 1
	code.Interval = deviceCodeInterval
	if email.Valid {
		code.Email = email.String
	}

	// Check expiration
	if time.Now().After(code.ExpiresAt) {
		return nil
	}

	return &code
}

// GetByUserCode retrieves a device code by its user code
func (s *DeviceCodeStore) GetByUserCode(userCode string) *DeviceCode {
	var code DeviceCode
	var expiresAtUnix int64
	var authorized int
	var email sql.NullString

	err := s.db.QueryRow(
		"SELECT code, user_code, expires_at, authorized, email FROM device_codes WHERE user_code = ?",
		userCode,
	).Scan(&code.Code, &code.UserCode, &expiresAtUnix, &authorized, &email)
	if err != nil {
		return nil
	}

	code.ExpiresAt = time.Unix(expiresAtUnix, 0)
	code.Authorized = authorized == 1
	code.Interval = deviceCodeInterval
	if email.Valid {
		code.Email = email.String
	}

	// Check expiration
	if time.Now().After(code.ExpiresAt) {
		return nil
	}

	return &code
}

// Authorize marks a device code as authorized with the user's email
func (s *DeviceCodeStore) Authorize(deviceCode, email string) bool {
	result, err := s.db.Exec(
		"UPDATE device_codes SET authorized = 1, email = ? WHERE code = ? AND expires_at > ?",
		email, deviceCode, time.Now().Unix(),
	)
	if err != nil {
		return false
	}

	rows, err := result.RowsAffected()
	return err == nil && rows > 0
}

// Delete removes a device code
func (s *DeviceCodeStore) Delete(deviceCode string) {
	s.db.Exec("DELETE FROM device_codes WHERE code = ?", deviceCode)
}

// cleanup periodically removes expired codes
func (s *DeviceCodeStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.db.Exec("DELETE FROM device_codes WHERE expires_at < ?", time.Now().Unix())
	}
}

// generateSecureCode generates a cryptographically secure random string
func generateSecureCode(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

// generateUserCode generates a short user-friendly code (e.g., "ABC-123")
func generateUserCode() (string, error) {
	// Use uppercase letters and digits, avoiding confusing chars (0, O, I, L)
	const charset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	code := make([]byte, 7) // 3 chars + hyphen + 3 chars
	for i := 0; i < 3; i++ {
		code[i] = charset[int(b[i])%len(charset)]
	}
	code[3] = '-'
	for i := 0; i < 3; i++ {
		code[i+4] = charset[int(b[i+3])%len(charset)]
	}

	return string(code), nil
}
