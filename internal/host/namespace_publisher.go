package host

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/domains"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
)

// Publisher credentials may resolve one already-verified app for publication.
// They cannot list, create, verify, delete, or otherwise manage domain claims.
func (p *ProxyServer) handleNamespacePublisher(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Publisher API requires the relay origin", 403)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if p.domains == nil || p.storage == nil || !p.storage.Available() {
		http.Error(w, "Namespace authority unavailable", 503)
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !p.visitorJWTConfigured() {
		http.Error(w, "Publisher authentication required", 401)
		return
	}
	email, device, _, deviceErr := parseDeviceToken(parts[1], p.getJWTSigningKey(), p.currentTime())
	if deviceErr == nil {
		// Only the login authority holds the live device registry. Existing device
		// forwarding uses the node transport and a bounded one-hop forwarding marker.
		if p.forwardDeviceService(w, r) {
			return
		}
		var deviceEmail string
		err := p.devices.db.QueryRowContext(r.Context(), `SELECT email FROM durable_devices WHERE id=? AND revoked=0`, device).Scan(&deviceEmail)
		if err != nil || common.NormalizeEmail(deviceEmail) != email {
			http.Error(w, "Publisher device revoked or unavailable", 401)
			return
		}
	} else {
		// Preserve the existing owner-JWT management validator unchanged.
		var capability, ok bool
		email, _, capability, ok = p.getAuthFromTunnelBearer(r, &TunnelConnection{})
		if !ok || capability {
			http.Error(w, "Publisher authentication required", 401)
			return
		}
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Account authority unavailable", 503)
		return
	}
	if account == nil || account.ID == "" || account.OperationalState != "active" {
		http.Error(w, "Active publisher account required", 403)
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		http.Error(w, "App hostname required", 400)
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		http.Error(w, "One app hostname required", 400)
		return
	}
	name, err := domains.NormalizeName(input.Name, p.Domain)
	if err != nil || strings.HasPrefix(name, "*.") {
		http.Error(w, "Concrete app hostname required", 400)
		return
	}
	route, err := p.domains.Route(r.Context(), &pb.Domain{Name: name})
	if err != nil {
		domainHTTPError(w, err)
		return
	}
	if !strings.HasPrefix(route.Name, "*.") || route.Owner != account.ID {
		http.Error(w, "Namespace app must belong to this account", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Tunnel string `json:"tunnel"`
	}{route.Tunnel})
}
