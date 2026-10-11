package hostmode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
)

type API struct {
	Server, Token string
	Insecure      bool
	Client        *http.Client // Optional fixture transport; production always uses TLS.
}

type APIError struct{ Status int }

func (e *APIError) Error() string {
	return fmt.Sprintf("host registry returned HTTP %d (requires an authenticated relay with TUNN_HOST_MODE=true)", e.Status)
}
func (e *APIError) Permanent() bool { return e.Status >= 400 && e.Status < 500 && e.Status != 429 }

func (a API) request(ctx context.Context, method string, manifest *common.HostManifest) ([]common.Machine, error) {
	if err := ValidateAddress(a.Server); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Token) == "" {
		return nil, fmt.Errorf("run tunn login or configure token_file")
	}
	var body io.Reader
	if manifest != nil {
		b, err := json.Marshal(manifest)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, "https://"+a.Server+"/api/hosts", body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(a.Token))
	r.Header.Set("Content-Type", "application/json")
	h := a.Client
	if h == nil {
		tr := relaytransport.Transport(a.Insecure)
		defer tr.CloseIdleConnections()
		h = &http.Client{Timeout: 10 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := h.Do(r)
	if err != nil {
		return nil, fmt.Errorf("host registry connection failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode}
	}
	if manifest != nil {
		return nil, nil
	}
	var machines []common.Machine
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&machines); err != nil {
		return nil, fmt.Errorf("invalid hosts response: %w", err)
	}
	if machines == nil {
		machines = []common.Machine{}
	}
	return machines, nil
}

func (a API) Register(ctx context.Context, c *Config) error {
	m := common.HostManifest{Machine: c.Machine, Tunnels: []common.HostEndpointSpec{}}
	for _, t := range c.Tunnels {
		m.Tunnels = append(m.Tunnels, common.HostEndpointSpec{Name: t.Name, Kind: t.Kind})
	}
	_, err := a.request(ctx, http.MethodPost, &m)
	return err
}

func (a API) Hosts(ctx context.Context) ([]common.Machine, error) {
	return a.request(ctx, http.MethodGet, nil)
}
