package ado

import (
	"errors"
	"os"
	"strings"
)

// ErrNoToken is returned when no Azure DevOps PAT is found.
var ErrNoToken = errors.New("no Azure DevOps PAT: pass --token or set ADO_PAT, AZURE_DEVOPS_PAT, or AZDO_PAT")

// ResolveToken returns the PAT: an explicit value (the global --token flag) wins,
// otherwise the environment. ADO_PAT is checked first to match the firing-range
// convention; AZURE_DEVOPS_PAT / AZDO_PAT are the names the legacy CLI documents.
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
