package ado

import (
	"errors"
	"testing"
)

func TestResolveTokenExplicitBeatsEnv(t *testing.T) {
	t.Setenv("ADO_PAT", "env-pat")

	tok, err := ResolveToken("  explicit-pat  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "explicit-pat" {
		t.Fatalf("expected the explicit token to win (trimmed), got %q", tok)
	}
}

func TestResolveTokenEnvPrecedence(t *testing.T) {
	t.Setenv("ADO_PAT", "ado-pat")
	t.Setenv("AZURE_DEVOPS_PAT", "azure-devops-pat")
	t.Setenv("AZDO_PAT", "azdo-pat")

	tok, err := ResolveToken("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "ado-pat" {
		t.Fatalf("expected ADO_PAT to win, got %q", tok)
	}
}

// A variable set to whitespace is as good as unset — otherwise `export ADO_PAT=`
// in a sourced env file would mask a real token further down the list.
func TestResolveTokenSkipsBlankEnvAndFallsThrough(t *testing.T) {
	t.Setenv("ADO_PAT", "   ")
	t.Setenv("AZURE_DEVOPS_PAT", "")
	t.Setenv("AZDO_PAT", "azdo-pat")

	tok, err := ResolveToken("   ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "azdo-pat" {
		t.Fatalf("expected fall-through to AZDO_PAT, got %q", tok)
	}
}

func TestResolveTokenNoneSetReturnsErrNoToken(t *testing.T) {
	t.Setenv("ADO_PAT", "")
	t.Setenv("AZURE_DEVOPS_PAT", "")
	t.Setenv("AZDO_PAT", "")

	if _, err := ResolveToken(""); !errors.Is(err, ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}
