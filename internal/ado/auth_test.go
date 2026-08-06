package ado

import (
	"errors"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func clearADOEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"TRAJAN_ADO_TOKEN", "ADO_PAT", "AZURE_DEVOPS_PAT", "AZDO_PAT", "AZURE_DEVOPS_EXT_PAT",
		"AZURE_BEARER_TOKEN", "SYSTEM_ACCESSTOKEN",
	} {
		t.Setenv(k, "")
	}
}

func TestResolveCredentialEnvBeatsExplicit(t *testing.T) {
	clearADOEnv(t)
	t.Setenv("ADO_PAT", "env-pat")

	c, err := ResolveCredential("  explicit-pat  ", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Value != "env-pat" || c.Kind != engine.CredPAT {
		t.Fatalf("expected env PAT to beat flag, got %+v", c)
	}
}

func TestResolveCredentialEnvPrecedence(t *testing.T) {
	clearADOEnv(t)
	t.Setenv("ADO_PAT", "ado-pat")
	t.Setenv("AZURE_DEVOPS_PAT", "azure-devops-pat")
	t.Setenv("AZDO_PAT", "azdo-pat")

	c, err := ResolveCredential("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Value != "ado-pat" {
		t.Fatalf("expected ADO_PAT to win, got %q", c.Value)
	}
}

func TestResolveCredentialSkipsBlankEnvAndFallsThrough(t *testing.T) {
	clearADOEnv(t)
	t.Setenv("ADO_PAT", "   ")
	t.Setenv("AZURE_DEVOPS_PAT", "")
	t.Setenv("AZDO_PAT", "azdo-pat")

	c, err := ResolveCredential("   ", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Value != "azdo-pat" {
		t.Fatalf("expected fall-through to AZDO_PAT, got %q", c.Value)
	}
}

func TestResolveCredentialNoneSetReturnsErrNoToken(t *testing.T) {
	clearADOEnv(t)
	if _, err := ResolveCredential("", ""); !errors.Is(err, ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestResolveCredentialBearerKind(t *testing.T) {
	clearADOEnv(t)
	t.Setenv("AZURE_BEARER_TOKEN", "jwt")
	c, err := ResolveCredential("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Kind != engine.CredBearer || c.Value != "jwt" {
		t.Fatalf("expected bearer, got %+v", c)
	}
}
