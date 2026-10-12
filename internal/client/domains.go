package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/domains"
)

// DomainCall uses owner credentials and inherits origin validation and redirect
// refusal from the usage/grants client. Consumer credentials never manage names.
func (c *ManagementClient) DomainCall(ctx context.Context, method, name, action string, input any) (json.RawMessage, error) {
	path := "/api/domains"
	if name != "" {
		normalized, err := domains.NormalizeName(name, "")
		if err != nil {
			return nil, err
		}
		path += "/" + normalized
	}
	switch {
	case name == "" && action == "" && (method == http.MethodGet || method == http.MethodPost):
	case name != "" && action == "verify" && method == http.MethodPost:
		path += "/verify"
	case name != "" && action == "" && method == http.MethodDelete:
	default:
		return nil, fmt.Errorf("invalid domain operation")
	}
	return c.callPath(ctx, method, path, "", input)
}

// NamespaceTunnel resolves owner-visible metadata, including historical publisher
// IDs. It never creates a claim or reserves a global name as a side effect.
func (c *ManagementClient) NamespaceTunnel(ctx context.Context, namespace, label string) (string, error) {
	name, err := domains.NormalizeName("*."+strings.TrimPrefix(namespace, "*."), "")
	if err != nil || !domains.ValidLabel(label) || common.IsReservedTunnelName(label) {
		return "", fmt.Errorf("valid namespace and app label required")
	}
	data, err := c.DomainCall(ctx, http.MethodGet, "", "", nil)
	if err != nil {
		return "", err
	}
	var list pb.DomainList
	if err = json.Unmarshal(data, &list); err != nil {
		return "", err
	}
	for _, d := range list.Domains {
		if d.Name != name {
			continue
		}
		if d.State != "ready" || d.VerifiedUntil <= time.Now().Unix() {
			return "", fmt.Errorf("namespace %s is not verified; run tunn domain verify", name)
		}
		for _, n := range d.AppNames {
			if n.Label == label && domains.ValidLabel(n.Tunnel) {
				return n.Tunnel, nil
			}
		}
		return "", fmt.Errorf("app name %s is not registered in %s; run tunn domain add '%s' --tunnel %s", label, name, name, label)
	}
	return "", fmt.Errorf("namespace %s does not belong to this account", name)
}
