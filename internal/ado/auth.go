package ado

import (
	"errors"
	"os"
	"strings"
)

var ErrNoToken = errors.New("no Azure DevOps PAT: pass --token or set ADO_PAT, AZURE_DEVOPS_PAT, or AZDO_PAT")

// AZURE_DEVOPS_PAT and AZDO_PAT rank behind ADO_PAT because the legacy CLI
// documents them.
func ResolveToken(explicit string) (string, error) {
	if v := strings.TrimSpace(explicit); v != "" {
		return v, nil
	}
	for _, k := range []string{"ADO_PAT", "AZURE_DEVOPS_PAT", "AZDO_PAT"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, nil
		}
	}
	return "", ErrNoToken
}
