package host

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ehrlich-b/tunn/internal/config"
	"golang.org/x/oauth2/google"
)

const graphMeURL = "https://graph.microsoft.com/v1.0/me?$select=id"
const graphGroupsURL = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group?$select=id&$top=100"
const directoryGroupsURL = "https://admin.googleapis.com/admin/directory/v1/groups"
const directoryGroupsScope = "https://www.googleapis.com/auth/admin.directory.group.readonly"

func (p *ProxyServer) resolveOrgGroups(ctx context.Context, org config.OIDCOrg, token *oidc.IDToken, claims orgClaims, accessToken string) ([]string, error) {
	groups := claims.Groups
	source, overage := claims.ClaimNames["groups"]
	if org.Provider == "entra" && (claims.HasGroups != nil || overage) {
		if overage && source == "" {
			return nil, fmt.Errorf("missing Entra overage source")
		}
		if claims.HasGroups != nil && !*claims.HasGroups {
			return nil, fmt.Errorf("ambiguous Entra overage")
		}
		var err error
		groups, err = p.entraGroups(ctx, org, claims.ObjectID, accessToken)
		if err != nil {
			return nil, err
		}
	} else if org.Provider == "google" && len(org.Groups) > 0 {
		var err error
		groups, err = p.workspaceGroups(ctx, org, token.Subject)
		if err != nil {
			return nil, err
		}
	}
	groupSet, roleSet := map[string]bool{}, map[string]bool{}
	for _, value := range groups {
		groupSet[value] = true
	}
	if org.Provider == "entra" {
		for _, value := range claims.Roles {
			roleSet[value] = true
		}
	}
	matched := []string{}
	for _, mapping := range org.Groups {
		if mapping.Claim == "groups" && groupSet[mapping.Value] || mapping.Claim == "roles" && roleSet[mapping.Value] {
			matched = append(matched, "group:"+org.ID+":"+mapping.ID)
		}
	}
	return matched, nil
}

func (p *ProxyServer) orgGroupGET(ctx context.Context, org config.OIDCOrg, address, bearer string, out any) error {
	if bearer == "" || strings.ContainsAny(bearer, "\r\n") {
		return fmt.Errorf("group authority credentials missing")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	response, err := p.orgHTTPClient(org).Do(req)
	if err != nil {
		return fmt.Errorf("group authority unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("group authority refused request")
	}
	decoder := json.NewDecoder(response.Body)
	if decoder.Decode(out) != nil {
		return fmt.Errorf("invalid group response")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return fmt.Errorf("invalid group response suffix")
	}
	return nil
}

func (p *ProxyServer) entraGroups(ctx context.Context, org config.OIDCOrg, objectID, bearer string) ([]string, error) {
	var me struct {
		ID string `json:"id"`
	}
	if err := p.orgGroupGET(ctx, org, graphMeURL, bearer, &me); err != nil || me.ID == "" || me.ID != objectID {
		return nil, fmt.Errorf("Graph token belongs to another identity or is unavailable")
	}
	groups := []string{}
	address := graphGroupsURL
	seen := map[string]bool{}
	for page := 0; page < 32; page++ {
		if seen[address] {
			return nil, fmt.Errorf("repeated Graph membership page")
		}
		seen[address] = true
		var result struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err := p.orgGroupGET(ctx, org, address, bearer, &result); err != nil {
			return nil, err
		}
		if result.Value == nil {
			return nil, fmt.Errorf("missing Graph memberships")
		}
		for _, group := range result.Value {
			if group.ID == "" || len(group.ID) > 256 || strings.ContainsAny(group.ID, "\x00\r\n") {
				return nil, fmt.Errorf("invalid Graph group")
			}
			groups = append(groups, group.ID)
		}
		if len(groups) > 4096 {
			return nil, fmt.Errorf("too many Graph memberships")
		}
		if result.Next == "" {
			return groups, nil
		}
		u, err := url.Parse(result.Next)
		if err != nil || u.Scheme != "https" || u.Host != "graph.microsoft.com" || u.User != nil || u.Fragment != "" || u.RawPath != "" || u.Path != "/v1.0/me/transitiveMemberOf/microsoft.graph.group" || len(result.Next) > 8192 {
			return nil, fmt.Errorf("untrusted Graph pagination URL")
		}
		address = result.Next
	}
	return nil, fmt.Errorf("too many Graph membership pages")
}

func (p *ProxyServer) workspaceGroups(ctx context.Context, org config.OIDCOrg, subject string) ([]string, error) {
	data, err := config.ReadPrivateOIDCFile(org.GoogleCredentialsFile)
	if err != nil {
		return nil, err
	}
	credentials, err := google.JWTConfigFromJSON(data, directoryGroupsScope)
	if err != nil || credentials.Email == "" || credentials.PrivateKeyID == "" || credentials.TokenURL != googleTokenURL || org.GoogleDirectoryAdmin == "" {
		return nil, fmt.Errorf("invalid Workspace delegation credentials")
	}
	credentials.Subject = org.GoogleDirectoryAdmin
	access, err := credentials.TokenSource(ctx).Token()
	if err != nil {
		return nil, fmt.Errorf("Workspace delegation refused")
	}
	groups := []string{}
	pageToken := ""
	seen := map[string]bool{}
	for page := 0; page < 32; page++ {
		// The stable, signed Google user ID binds membership to this login;
		// Directory userKey accepts the unique user ID as well as email.
		q := url.Values{"userKey": {subject}, "maxResults": {"200"}}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		var result struct {
			Groups []struct {
				ID string `json:"id"`
			} `json:"groups"`
			Next string `json:"nextPageToken"`
		}
		if err = p.orgGroupGET(ctx, org, directoryGroupsURL+"?"+q.Encode(), access.AccessToken, &result); err != nil {
			return nil, err
		}
		for _, group := range result.Groups {
			if group.ID == "" || len(group.ID) > 256 || strings.ContainsAny(group.ID, "\x00\r\n") {
				return nil, fmt.Errorf("invalid Workspace group")
			}
			groups = append(groups, group.ID)
		}
		if len(groups) > 4096 {
			return nil, fmt.Errorf("too many Workspace memberships")
		}
		if result.Next == "" {
			return groups, nil
		}
		if len(result.Next) > 4096 || seen[result.Next] {
			return nil, fmt.Errorf("invalid Workspace pagination")
		}
		seen[result.Next] = true
		pageToken = result.Next
	}
	return nil, fmt.Errorf("too many Workspace membership pages")
}
