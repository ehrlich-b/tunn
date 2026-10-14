package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/common"
	"net/http"
	"strings"

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

// NamespaceTunnel resolves one existing app through the narrow publisher API.
// Live durable-device credentials can look up their own verified app, but cannot
// manage or list claims. Redirect refusal and origin credential checks remain.
func (c *ManagementClient) NamespaceTunnel(ctx context.Context, namespace, label string) (string, error) {
	name, err := domains.NormalizeName("*."+strings.TrimPrefix(namespace, "*."), "")
	if err != nil || !domains.ValidLabel(label) || common.IsReservedTunnelName(label) {
		return "", fmt.Errorf("valid namespace and app label required")
	}
	data, err := c.callPath(ctx, http.MethodPost, "/api/domains/publisher", "", struct {
		Name string `json:"name"`
	}{label + "." + strings.TrimPrefix(name, "*.")})
	if err != nil {
		return "", err
	}
	var out struct {
		Tunnel string `json:"tunnel"`
	}
	if err = json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if !domains.ValidLabel(out.Tunnel) {
		return "", fmt.Errorf("invalid namespace publisher ID")
	}
	return out.Tunnel, nil
}
