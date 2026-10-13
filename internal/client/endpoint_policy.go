package client

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
)

func ExecutePolicy(ctx context.Context, action, endpoint string, p *trafficpolicy.Policy, c *ManagementClient, out io.Writer) error {
	method := http.MethodGet
	var input any
	switch action {
	case "get":
	case "set":
		if p == nil {
			return fmt.Errorf("policy is required")
		}
		if err := p.Validate(); err != nil {
			return err
		}
		method = http.MethodPut
		input = p
	case "clear":
		method = http.MethodDelete
	default:
		return fmt.Errorf("unsupported policy action")
	}
	data, err := c.Call(ctx, method, endpoint, "policy", input)
	if err != nil {
		return err
	}
	_, err = trafficpolicy.Decode(data)
	if err != nil {
		return fmt.Errorf("owner API returned invalid policy: %w", err)
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
