package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/cliopts"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"io"
	"net/url"
)

func ExecuteMetering(ctx context.Context, o *cliopts.Metering, c *ManagementClient, out io.Writer) error {
	switch o.Action {
	case "usage":
		query := "month=" + url.QueryEscape(o.Month)
		if o.Since != "" {
			query = "since=" + url.QueryEscape(o.Since)
		}
		data, err := c.Call(ctx, "GET", o.Endpoint, "usage?"+query, nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "list":
		data, err := c.Call(ctx, "GET", o.Endpoint, "grants", nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "revoke":
		_, err := c.Call(ctx, "DELETE", o.Endpoint, "grants/"+o.GrantID, nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "Grant revoked")
		return err
	case "create":
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		token := "tunn_gr_" + base64.RawURLEncoding.EncodeToString(random)
		digest := sha256.Sum256([]byte(token))
		data, err := c.Call(ctx, "POST", o.Endpoint, "grants", &pb.Grant{Consumer: o.Consumer, TokenSha256: digest[:], ExpiresAt: o.Expires.UnixMilli(), RequestsPerMinute: o.Rate, MonthlyRequests: o.Requests, MonthlyBytes: o.Bytes})
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Grant json.RawMessage `json:"grant"`
			Token string          `json:"token"`
		}{data, token})
	}
	return fmt.Errorf("unsupported metering action")
}
