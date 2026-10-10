package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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
