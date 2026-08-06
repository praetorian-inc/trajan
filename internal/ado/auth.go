package ado

import (
	"errors"

	"github.com/praetorian-inc/trajan/internal/engine"
)

var ErrNoToken = errors.New("no Azure DevOps credential: pass --token/--azure-bearer-token or set TRAJAN_ADO_TOKEN/ADO_PAT/AZURE_DEVOPS_PAT/AZDO_PAT/AZURE_DEVOPS_EXT_PAT/AZURE_BEARER_TOKEN/SYSTEM_ACCESSTOKEN")

func ResolveCredential(explicitPAT, explicitBearer string) (engine.Credential, error) {
	c, ok := engine.ResolveADO(explicitPAT, explicitBearer)
	if !ok {
		return engine.Credential{}, ErrNoToken
	}
	return c, nil
}
