package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
)

type rawAccess struct {
	emails  []string
	creator string
	digest  []byte
	path    string
}

// Account-only publishers register the existing email policy without a bearer
// capability. The relay still verifies the publisher JWT and visitor identity.
func prepareRawAccess(opts *tcpCommandOptions, token, name string) (*rawAccess, error) {
	a := &rawAccess{emails: append([]string(nil), opts.allowedEmails...)}
	if opts.public {
		if opts.accountOnly {
			return nil, fmt.Errorf("account-only endpoints must be private")
		}
		return a, nil
	}
	var err error
	a.creator, err = common.ExtractEmailFromJWT(token)
	if err != nil && (opts.accountOnly || len(a.emails) == 0) {
		return nil, fmt.Errorf("private raw endpoints require a tunn login token or an explicit --allow")
	}
	if a.creator != "" {
		a.emails = appendUniqueEmail(a.emails, a.creator)
	}
	if opts.accountOnly {
		return a, nil
	}
	endpointToken, digest, err := client.GenerateEndpointToken()
	if err != nil {
		return nil, err
	}
	a.path, err = client.SaveEndpointToken(name, endpointToken)
	if err != nil {
		return nil, err
	}
	a.digest = digest
	return a, nil
}

func loadConnectToken(opts *connectCommandOptions, endpointName string) (string, error) {
	if opts.account {
		if endpointName == "" {
			return "", fmt.Errorf("--account requires a named endpoint on the configured relay")
		}
		token, err := client.LoadToken()
		if err != nil {
			return "", fmt.Errorf("account login required; run tunn login: %w", err)
		}
		if _, err := common.ExtractEmailFromJWT(token); err != nil {
			return "", fmt.Errorf("invalid account login; run tunn login")
		}
		return strings.TrimSpace(token), nil
	}
	token := opts.token
	if token == "" && opts.tokenFile != "" {
		data, err := os.ReadFile(opts.tokenFile)
		if err != nil {
			return "", fmt.Errorf("read endpoint token: %w", err)
		}
		token = strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("endpoint token file is empty")
		}
	}
	if token == "" {
		token = os.Getenv("TUNN_ENDPOINT_TOKEN")
	}
	if token == "" && endpointName != "" {
		token, _ = client.LoadEndpointToken(endpointName)
	}
	if token == "" && !opts.public {
		return "", fmt.Errorf("credential required; use --account, --token-file or TUNN_ENDPOINT_TOKEN")
	}
	return token, nil
}
