package azuredevops

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	// The data provider the ADO web UI uses for both PAT and SSH key creation.
	sshKeyContributionID = "ms.vss-token-web.personal-access-token-issue-session-token-provider"
)

func (c *Client) ListPersonalAccessTokens(ctx context.Context) ([]PersonalAccessToken, error) {
	vssps := c.VSSPSClient()
	path := fmt.Sprintf("/_apis/tokens/pats?api-version=%s", APIVersionPreview)

	var result PersonalAccessTokenList
	if err := vssps.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing PATs: %w", err)
	}
	return result.Value, nil
}

func (c *Client) CreatePersonalAccessToken(ctx context.Context, req CreatePATRequest) (*PersonalAccessToken, error) {
	vssps := c.VSSPSClient()
	path := fmt.Sprintf("/_apis/tokens/pats?api-version=%s", APIVersionPreview)

	var result PersonalAccessToken
	if err := vssps.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("creating PAT: %w", err)
	}
	return &result, nil
}

func (c *Client) RevokePersonalAccessToken(ctx context.Context, authorizationID string) error {
	vssps := c.VSSPSClient()
	path := fmt.Sprintf("/_apis/tokens/pats?authorizationId=%s&api-version=%s", authorizationID, APIVersionPreview)

	if err := vssps.deleteRequest(ctx, path); err != nil {
		return fmt.Errorf("revoking PAT: %w", err)
	}
	return nil
}

func (c *Client) ListSSHKeys(ctx context.Context) ([]SSHKey, error) {
	vssps := c.VSSPSClient()
	path := "/_apis/Token/SessionTokens?isPublic=true&includePublicData=true&api-version=7.0-preview.1"

	var result SSHKeyList
	if err := vssps.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing SSH keys: %w", err)
	}
	return result.Value, nil
}

// The web UI's internal API; ADO has no standalone REST endpoint for SSH key creation.
func (c *Client) CreateSSHKey(ctx context.Context, req CreateSSHKeyRequest) (*SSHKey, error) {
	connData, err := c.GetConnectionData(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting connection data for org ID: %w", err)
	}
	if connData.InstanceID == "" {
		return nil, fmt.Errorf("could not determine organization account ID from connection data")
	}

	hq := hierarchyQueryRequest{
		ContributionIDs: []string{sshKeyContributionID},
		DataProviderContext: hierarchyDataProviderContext{
			Properties: map[string]interface{}{
				"displayName":    req.DisplayName,
				"publicData":     req.PublicData,
				"validTo":        req.ValidTo,
				"scope":          "app_token",
				"isPublic":       true,
				"targetAccounts": []string{connData.InstanceID},
			},
		},
	}

	path := "/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"
	var hqResp hierarchyQueryResponse
	if err := c.postJSON(ctx, path, hq, &hqResp); err != nil {
		return nil, fmt.Errorf("creating SSH key via HierarchyQuery: %w", err)
	}

	providerData, ok := hqResp.DataProviders[sshKeyContributionID]
	if !ok {
		return nil, fmt.Errorf("SSH key creation response missing data provider %q", sshKeyContributionID)
	}

	var sshKey SSHKey
	if err := json.Unmarshal(providerData, &sshKey); err != nil {
		return nil, fmt.Errorf("parsing SSH key response: %w", err)
	}

	return &sshKey, nil
}

func (c *Client) DeleteSSHKey(ctx context.Context, authorizationID string) error {
	vssps := c.VSSPSClient()
	path := fmt.Sprintf("/_apis/Token/SessionTokens/%s?isPublic=true&api-version=5.0-preview.1", authorizationID)

	if err := vssps.deleteRequest(ctx, path); err != nil {
		return fmt.Errorf("deleting SSH key: %w", err)
	}
	return nil
}
