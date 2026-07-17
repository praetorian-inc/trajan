package ado

import (
	"errors"
	"os"
	"strings"
)

// ErrNoToken is returned when no Azure DevOps PAT is found in the environment.
var ErrNoToken = errors.New("no Azure DevOps PAT: set ADO_PAT, AZURE_DEVOPS_PAT, or AZDO_PAT")

// ResolveToken reads the PAT from the environment. ADO_PAT is checked first to
// match the firing-range convention; the AZURE_DEVOPS_PAT / AZDO_PAT names are
// the ones the legacy CLI already documents.
func ResolveToken() (string, error) {
	for _, k := range []string{"ADO_PAT", "AZURE_DEVOPS_PAT", "AZDO_PAT"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, nil
		}
	}
	return "", ErrNoToken
}
