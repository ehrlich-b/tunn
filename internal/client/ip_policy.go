package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (c *ManagementClient) IPPolicy(ctx context.Context, action, endpoint string, allow, deny []string) (json.RawMessage, error) {
	if endpoint != "" && !validManagementEndpoint(endpoint) {
		return nil, fmt.Errorf("invalid endpoint name")
	}
	path := "/api/ip-policy"
	if endpoint != "" {
		path += "/" + endpoint
	}
	switch action {
	case "get":
		return c.callPath(ctx, http.MethodGet, path, "", nil)
	case "clear":
		return c.callPath(ctx, http.MethodDelete, path, "", nil)
	case "set":
		return c.callPath(ctx, http.MethodPut, path, "", struct {
			Allow []string `json:"allow_cidrs"`
			Deny  []string `json:"deny_cidrs"`
		}{allow, deny})
	default:
		return nil, fmt.Errorf("use get, set or clear")
	}
}
