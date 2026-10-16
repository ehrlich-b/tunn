package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/mcpauth"
)

func validMCPGrants(grants []string) bool {
	if len(grants) == 0 {
		return true
	}
	if len(grants) > 2 || !slices.Contains(grants, "authorization_code") {
		return false
	}
	return len(grants) == 1 || (grants[0] != grants[1] && slices.Contains(grants, "refresh_token"))
}

func (p *ProxyServer) mcpCurrentResource(ctx context.Context, tunnel *TunnelConnection, owner string) (*meterpb.WebResource, error) {
	backend := p.sharingBackend()
	if backend == nil {
		return nil, errMCPRefreshInvalid
	}
	out, err := backend.Sharing(ctx, &meterpb.SharingRequest{Operation: "get", Owner: owner, Endpoint: tunnel.TunnelID})
	if err != nil || out == nil || len(out.Resources) != 1 {
		return nil, errMCPRefreshInvalid
	}
	resource := out.Resources[0]
	generation := tunnel.PolicyResourceID
	if generation == "" {
		generation = tunnel.ResourceID
	}
	if resource.Owner != owner || generation != "" && resource.Id != generation {
		return nil, errMCPRefreshInvalid
	}
	return resource, nil
}

func parseMCPRefresh(raw string) (int64, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	value, ok := strings.CutPrefix(raw, "tunn_mcp_refresh_")
	if !ok {
		return 0, zero, errMCPRefreshInvalid
	}
	idText, secret, ok := strings.Cut(value, ".")
	id, err := strconv.ParseInt(idText, 10, 64)
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(secret)
	if !ok || err != nil || id <= 0 || strconv.FormatInt(id, 10) != idText || decodeErr != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != secret {
		return 0, zero, errMCPRefreshInvalid
	}
	return id, sha256.Sum256([]byte(secret)), nil
}

func (p *ProxyServer) handleMCPRefresh(w http.ResponseWriter, r *http.Request) {
	form := r.PostForm
	client, err := p.mcpOAuth.client(r.Context(), form.Get("client_id"))
	if err != nil {
		oauthProblem(w, 400, "invalid_client", "Unknown client")
		return
	}
	if !slices.Contains(client.GrantTypes, "refresh_token") || form.Has("scope") && form.Get("scope") != "mcp" {
		oauthProblem(w, 400, "invalid_grant", "Invalid refresh scope or client grant")
		return
	}
	id, digest, err := parseMCPRefresh(form.Get("refresh_token"))
	if err != nil {
		oauthProblem(w, 400, "invalid_grant", "Invalid refresh credential")
		return
	}
	p.mcpOAuth.mu.Lock()
	defer p.mcpOAuth.mu.Unlock()
	var auth mcpAuthorization
	err = p.mcpOAuth.db.QueryRowContext(r.Context(), `SELECT a.id,a.owner,a.person,a.email,a.endpoint,a.client,a.resource,a.generation FROM mcp_oauth_authorizations a JOIN mcp_oauth_sessions s ON s.authorization=a.id WHERE s.family=?`, id).Scan(&auth.ConsentID, &auth.Owner, &auth.Person, &auth.Email, &auth.Endpoint, &auth.ClientID, &auth.Resource, &auth.Generation)
	if err != nil || auth.ClientID != client.ID || auth.Resource != form.Get("resource") {
		oauthProblem(w, 400, "invalid_grant", "Invalid refresh binding")
		return
	}
	auth.Scope = "mcp"
	p.issueMCPCredentials(w, r, &auth, id, digest)
}

// A grant is prepared first, then made usable only when the consent, rotation,
// family and access binding commit under the authority's SQLite writer lock.
// Revocation uses the same lock, including mutations from other processes.
func (p *ProxyServer) issueMCPCredentials(w http.ResponseWriter, r *http.Request, auth *mcpAuthorization, family int64, previous [sha256.Size]byte) {
	ctx := r.Context()
	tunnel, owner, err := p.mcpTunnel(ctx, auth.Endpoint)
	if err != nil || owner.ID != auth.Owner || !p.mcpUserAllowed(ctx, auth.Email, tunnel, owner) {
		oauthProblem(w, 400, "invalid_grant", "Authorization no longer valid")
		return
	}
	resource, err := p.mcpCurrentResource(ctx, tunnel, owner.ID)
	person, personErr := p.storage.GetAccountByEmail(ctx, auth.Email)
	binding := mcpRefreshBinding{OwnerID: auth.Owner, PersonID: auth.Person, ClientID: auth.ClientID, Resource: auth.Resource, Generation: auth.Generation}
	if err != nil || personErr != nil || person == nil || person.ID != auth.Person || resource.Id != auth.Generation || !binding.valid() {
		oauthProblem(w, 400, "invalid_grant", "Authorization binding changed")
		return
	}
	access, err := randomOAuthValue("tunn_mcp_")
	if err != nil {
		oauthProblem(w, 500, "server_error", "Could not issue credentials")
		return
	}
	secret, err := randomOAuthValue("")
	if err != nil {
		oauthProblem(w, 500, "server_error", "Could not issue credentials")
		return
	}
	client, err := p.mcpOAuth.client(ctx, auth.ClientID)
	if err != nil {
		oauthProblem(w, 400, "invalid_client", "Unknown client")
		return
	}
	refreshEnabled := slices.Contains(client.GrantTypes, "refresh_token")
	// Reject unknown credentials before allocating a ledger grant and reclaim
	// expired OAuth access rows so hourly refresh lasts the full consent lifetime.
	preparation, err := p.mcpOAuth.refreshTx(ctx)
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Authorization authority unavailable")
		return
	}
	err = mcpauth.Valid(ctx, preparation, auth.ConsentID, p.currentTime())
	if err == nil && family != 0 {
		err = p.mcpOAuth.boundMCPRefreshFamily(ctx, preparation, family, binding)
		if err == nil {
			var used int
			err = preparation.QueryRowContext(ctx, `SELECT used FROM mcp_oauth_refresh_tokens WHERE family=? AND digest=?`, family, previous[:]).Scan(&used)
			if err == nil && used != 0 {
				err = p.mcpOAuth.rotateRefreshTx(ctx, preparation, family, binding, previous, sha256.Sum256([]byte(secret)))
			}
		}
	}
	if errors.Is(err, errMCPRefreshReplay) {
		commitErr := preparation.Commit()
		if commitErr != nil {
			oauthProblem(w, 503, "temporarily_unavailable", "Authorization authority unavailable")
		} else {
			oauthProblem(w, 400, "invalid_grant", "Refresh credential reused; consent required")
		}
		return
	}
	if err == nil {
		err = mcpauth.PruneAccess(ctx, preparation, auth.Owner, p.currentTime())
	}
	if err == nil {
		err = preparation.Commit()
	}
	_ = preparation.Rollback()
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errMCPRefreshInvalid) {
		oauthProblem(w, 400, "invalid_grant", "Consent or refresh credential invalid")
		return
	}
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Authorization authority unavailable")
		return
	}
	accessDigest := sha256.Sum256([]byte(access))
	grant, err := p.meter.CreateGrant(ctx, &meterpb.Grant{Owner: auth.Owner, Endpoint: auth.Endpoint, Consumer: "oauth:" + auth.ClientID, TokenSha256: accessDigest[:], ExpiresAt: p.currentTime().Add(mcpAccessTokenLifetime).UnixMilli()})
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Grant ledger unavailable")
		return
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = p.meter.RevokeGrant(cleanup, grant)
		}
	}()
	tx, err := p.mcpOAuth.refreshTx(ctx)
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Authorization authority unavailable")
		return
	}
	defer tx.Rollback()
	if err = mcpauth.Valid(ctx, tx, auth.ConsentID, p.currentTime()); err != nil {
		oauthProblem(w, 400, "invalid_grant", "Consent revoked or expired")
		return
	}
	var expiry int64
	if err = tx.QueryRowContext(ctx, `SELECT expires FROM mcp_oauth_authorizations WHERE id=?`, auth.ConsentID).Scan(&expiry); err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Authorization authority unavailable")
		return
	}
	next := sha256.Sum256([]byte(secret))
	if family != 0 {
		err = p.mcpOAuth.rotateRefreshTx(ctx, tx, family, binding, previous, next)
	} else if refreshEnabled {
		family, err = p.mcpOAuth.createRefreshFamilyTx(ctx, tx, binding, next, time.Unix(expiry, 0))
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_sessions(family,authorization) VALUES(?,?)`, family, auth.ConsentID)
		}
	}
	if errors.Is(err, errMCPRefreshReplay) {
		if commitErr := tx.Commit(); commitErr != nil {
			oauthProblem(w, 503, "temporarily_unavailable", "Authorization authority unavailable")
			return
		}
		oauthProblem(w, 400, "invalid_grant", "Refresh credential reused; consent required")
		return
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_access(grant_id,authorization,family) VALUES(?,?,?)`, grant.Id, auth.ConsentID, family)
	}
	if err == nil {
		err = tx.Commit()
	}
	if errors.Is(err, errMCPRefreshInvalid) {
		oauthProblem(w, 400, "invalid_grant", "Invalid refresh credential")
		return
	}
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Authorization authority unavailable or full")
		return
	}
	committed = true
	response := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(mcpAccessTokenLifetime.Seconds()), "scope": "mcp"}
	if refreshEnabled {
		response["refresh_token"] = "tunn_mcp_refresh_" + strconv.FormatInt(family, 10) + "." + secret
	}
	writeOAuthJSON(w, 200, response)
}
