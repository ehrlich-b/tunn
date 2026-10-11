package domains

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/crypto/acme"
)

// ConfigureACME persists the account signing key encrypted with the same key as
// domain keys. Losing either the volume or encryption secret loses this identity.
func (r *Registry) ConfigureACME(directory, email string, hc *http.Client) error {
	u, err := url.Parse(directory)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || email == "" {
		return fmt.Errorf("ACME requires an HTTPS directory and contact email")
	}
	var sealed []byte
	err = r.db.QueryRow(`SELECT value FROM domain_settings WHERE name='acme_account'`).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		sealed, err = r.encrypt("acme_account", der)
		if err != nil {
			return err
		}
		if _, err := r.db.Exec(`INSERT INTO domain_settings(name,value) VALUES('acme_account',?)`, sealed); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	der, err := r.decrypt("acme_account", sealed)
	if err != nil {
		return fmt.Errorf("decrypt ACME account: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return err
	}
	signer, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid ACME account key")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30e9}
	}
	r.issuer = &ACMEIssuer{Client: &acme.Client{Key: signer, DirectoryURL: directory, HTTPClient: hc, UserAgent: "tunn-custom-domains"}, Email: email}
	return nil
}

type ACMEIssuer struct {
	Client *acme.Client
	Email  string
}

func (i *ACMEIssuer) Issue(ctx context.Context, name string, present PresentChallenge) ([]byte, []byte, error) {
	if _, err := i.Client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + i.Email}}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, nil, err
	}
	order, err := i.Client.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return nil, nil, err
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := i.Client.GetAuthorization(ctx, authURL)
		if err != nil {
			return nil, nil, err
		}
		if auth.Identifier.Value != name || auth.Wildcard {
			return nil, nil, fmt.Errorf("unexpected ACME identifier")
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "http-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			return nil, nil, fmt.Errorf("ACME directory does not offer HTTP-01")
		}
		response, err := i.Client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return nil, nil, err
		}
		cleanup, err := present(ctx, challenge.Token, response)
		if err != nil {
			return nil, nil, err
		}
		// Keep the shared challenge present until authorization reaches valid.
		err = func() error {
			defer cleanup()
			if _, err := i.Client.Accept(ctx, challenge); err != nil {
				return err
			}
			_, err := i.Client.WaitAuthorization(ctx, authURL)
			return err
		}()
		if err != nil {
			return nil, nil, err
		}
	}
	orderURI := order.URI
	order, err = i.Client.WaitOrder(ctx, orderURI)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if err != nil {
		return nil, nil, err
	}
	chain, _, err := i.Client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	// Some CAs (including Pebble) omit Location on the processing response.
	// x/crypto then tries to poll an empty URI after successful finalization.
	// Resume with the original order using only the library's ACME operations.
	var pollError *url.Error
	if errors.As(err, &pollError) && pollError.URL == "" {
		pending, lookupErr := i.Client.GetOrder(ctx, orderURI)
		if lookupErr == nil && (pending.Status == acme.StatusProcessing || pending.Status == acme.StatusValid) {
			pending, err = i.Client.WaitOrder(ctx, orderURI)
			if err == nil {
				chain, err = i.Client.FetchCert(ctx, pending.CertURL, true)
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
