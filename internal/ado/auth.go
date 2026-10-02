package ado

import (
	"errors"
	"fmt"

	"github.com/praetorian-inc/trajan/internal/engine"
)

var ErrServerUnsupported = errors.New("unsupported instance: Azure DevOps Server; leave the instance root empty to scan dev.azure.com")

var ErrNoToken = errors.New("no Azure DevOps credential: pass --token/--azure-bearer-token or set TRAJAN_ADO_TOKEN/ADO_PAT/AZURE_DEVOPS_PAT/AZDO_PAT/AZURE_DEVOPS_EXT_PAT/AZURE_BEARER_TOKEN/SYSTEM_ACCESSTOKEN")

func ResolveCredential(explicitPAT, explicitBearer string) (engine.Credential, error) {
	c, ok := engine.ResolveADO(explicitPAT, explicitBearer)
	if !ok {
		return engine.Credential{}, ErrNoToken
	}
	return c, nil
}

func clientFor(cfg *engine.Config, org string) (*Client, error) {
	switch {
	case cfg.BearerToken != "":
		return NewClientBearer(org, cfg.BearerToken), nil
	case cfg.Token != "":
		return NewClient(org, cfg.Token), nil
	}
	return nil, fmt.Errorf("%w for Azure DevOps", engine.ErrNoCredential)
}
