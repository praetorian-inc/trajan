package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

func (c *Client) ListSecurityNamespaces(ctx context.Context) ([]SecurityNamespace, error) {
	path := fmt.Sprintf("/_apis/securitynamespaces?api-version=%s", APIVersion)

	var result SecurityNamespaceList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing security namespaces: %w", err)
	}
	return result.Value, nil
}

func (c *Client) GetSecurityNamespace(ctx context.Context, namespaceID string) (*SecurityNamespace, error) {
	encodedID := url.PathEscape(namespaceID)
	path := fmt.Sprintf("/_apis/securitynamespaces/%s?api-version=%s", encodedID, APIVersion)

	var result SecurityNamespaceList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting security namespace: %w", err)
	}
	if len(result.Value) == 0 {
		return nil, fmt.Errorf("security namespace %s not found", namespaceID)
	}
	return &result.Value[0], nil
}

func (c *Client) QueryAccessControlLists(ctx context.Context, namespaceID, token string) ([]AccessControlList, error) {
	encodedNS := url.PathEscape(namespaceID)
	encodedToken := url.QueryEscape(token)
	path := fmt.Sprintf("/_apis/accesscontrollists/%s?token=%s&includeExtendedInfo=true&api-version=%s",
		encodedNS, encodedToken, APIVersion)

	var result AccessControlListResponse
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("querying ACLs: %w", err)
	}
	return result.Value, nil
}

func (c *Client) ResolveIdentity(ctx context.Context, descriptor string) (*Identity, error) {
	vssps := c.VSSPSClient()
	encodedDesc := url.QueryEscape(descriptor)
	path := fmt.Sprintf("/_apis/identities?descriptors=%s&queryMembership=direct&api-version=%s", encodedDesc, APIVersionPreview)

	var result IdentityList
	if err := vssps.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("resolving identity: %w", err)
	}
	if len(result.Value) == 0 {
		return nil, fmt.Errorf("identity %s not found", descriptor)
	}
	return &result.Value[0], nil
}

func (c *Client) HasPermission(ctx context.Context, namespaceID, token, descriptor string, permissionBit int) (bool, error) {
	acls, err := c.QueryAccessControlLists(ctx, namespaceID, token)
	if err != nil {
		return false, err
	}

	for _, acl := range acls {
		if ace, ok := acl.AcesDictionary[descriptor]; ok {
			effectiveAllow := ace.ExtendedInfo.EffectiveAllow
			effectiveDeny := ace.ExtendedInfo.EffectiveDeny
			if effectiveDeny&permissionBit != 0 {
				return false, nil
			}
			if effectiveAllow&permissionBit != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// The permissions API identifies the caller from the credential, so no descriptor is needed.
func (c *Client) CheckPermission(ctx context.Context, namespaceID string, permissionBit int, securityToken string) (bool, error) {
	path := fmt.Sprintf("/_apis/permissions/%s/%d?alwaysAllowAdministrators=false&api-version=7.1",
		namespaceID, permissionBit)
	if securityToken != "" {
		path += "&tokens=" + url.QueryEscape(securityToken)
	}

	var result struct {
		Count int    `json:"count"`
		Value []bool `json:"value"`
	}
	if err := c.getJSON(ctx, path, &result); err != nil {
		return false, fmt.Errorf("checking permission: %w", err)
	}
	if len(result.Value) > 0 {
		return result.Value[0], nil
	}
	return false, nil
}
