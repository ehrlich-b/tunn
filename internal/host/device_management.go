package host

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/golang-jwt/jwt/v4"
)

func migrateDurablePurpose(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(durable_devices)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, nn, pk int
		var name, kind string
		var def any
		if err = rows.Scan(&cid, &name, &kind, &nn, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, column := range []string{"purpose", "account_id"} {
		if !columns[column] {
			value := ""
			if column == "purpose" {
				value = "publisher"
			}
			if _, err = db.Exec(fmt.Sprintf("ALTER TABLE durable_devices ADD COLUMN %s TEXT NOT NULL DEFAULT '%s'", column, value)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *ProxyServer) managementToken(d *durableDevice) (string, error) {
	now := p.currentTime()
	claims := jwt.MapClaims{"email": d.Email, "sub": d.Email, "type": "management_access", "iss": "tunn", "aud": "tunn-account", "scope": "account:manage", "device": d.ID, "account": d.AccountID, "iat": now.Unix(), "exp": now.Add(24 * time.Hour).Unix()}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
}

func (p *ProxyServer) managementIdentity(r *http.Request, claims jwt.MapClaims) (string, error) {
	email, _ := claims["email"].(string)
	id, _ := claims["device"].(string)
	account, _ := claims["account"].(string)
	email = common.NormalizeEmail(email)
	if claims["type"] != "management_access" || claims["iss"] != "tunn" || claims["aud"] != "tunn-account" || claims["scope"] != "account:manage" || email == "" || id == "" || account == "" || claims.Valid() != nil {
		return "", fmt.Errorf("invalid management credential")
	}
	scoped, ok := p.storage.(storage.ScopedDeviceStorage)
	if !ok {
		return "", fmt.Errorf("device authority unavailable")
	}
	ctx, stop := context.WithTimeout(r.Context(), 2*time.Second)
	defer stop()
	valid, err := scoped.CheckManagementDevice(ctx, id, email, account)
	if err != nil || !valid {
		return "", fmt.Errorf("management credential unavailable")
	}
	return email, nil
}
