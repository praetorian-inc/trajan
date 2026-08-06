package engine

import (
	"testing"
)

func clearCredEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"TRAJAN_GH_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
		"TRAJAN_GL_TOKEN", "GITLAB_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN",
		"TRAJAN_ADO_TOKEN", "ADO_PAT", "AZURE_DEVOPS_PAT", "AZDO_PAT", "AZURE_DEVOPS_EXT_PAT",
		"AZURE_BEARER_TOKEN", "SYSTEM_ACCESSTOKEN",
	} {
		t.Setenv(k, "")
	}
}

func TestResolveGitHubPrecedence(t *testing.T) {
	clearCredEnv(t)
	t.Setenv("TRAJAN_GH_TOKEN", "trajan")
	t.Setenv("GH_TOKEN", "gh")
	t.Setenv("GITHUB_TOKEN", "github")

	c, ok := ResolveGitHub("flag")
	if !ok || c.Value != "trajan" || c.Source != "TRAJAN_GH_TOKEN" {
		t.Fatalf("got %+v ok=%v, want TRAJAN_GH_TOKEN", c, ok)
	}

	t.Setenv("TRAJAN_GH_TOKEN", "")
	c, ok = ResolveGitHub("flag")
	if !ok || c.Value != "gh" || c.Source != "GH_TOKEN" {
		t.Fatalf("got %+v ok=%v, want GH_TOKEN", c, ok)
	}

	t.Setenv("GH_TOKEN", "  ")
	c, ok = ResolveGitHub("flag")
	if !ok || c.Value != "github" || c.Source != "GITHUB_TOKEN" {
		t.Fatalf("blank GH_TOKEN must fall through, got %+v", c)
	}

	t.Setenv("GITHUB_TOKEN", "")
	c, ok = ResolveGitHub("  flag-tok  ")
	if !ok || c.Value != "flag-tok" || c.Source != "--token" {
		t.Fatalf("got %+v ok=%v, want --token", c, ok)
	}
}

func TestResolveGitHubEnvBeatsFlag(t *testing.T) {
	clearCredEnv(t)
	t.Setenv("GH_TOKEN", "from-env")
	c, ok := ResolveGitHub("from-flag")
	if !ok || c.Value != "from-env" {
		t.Fatalf("env must beat flag, got %+v", c)
	}
}

func TestResolveGitLabPrecedence(t *testing.T) {
	clearCredEnv(t)
	t.Setenv("TRAJAN_GL_TOKEN", "trajan")
	t.Setenv("GITLAB_TOKEN", "gitlab")
	t.Setenv("GL_TOKEN", "gl")
	t.Setenv("CI_JOB_TOKEN", "ci")

	c, ok := ResolveGitLab("flag")
	if !ok || c.Value != "trajan" {
		t.Fatalf("got %+v, want TRAJAN_GL_TOKEN", c)
	}
	t.Setenv("TRAJAN_GL_TOKEN", "")
	c, _ = ResolveGitLab("flag")
	if c.Value != "gitlab" {
		t.Fatalf("got %q, want GITLAB_TOKEN", c.Value)
	}
	t.Setenv("GITLAB_TOKEN", "")
	c, _ = ResolveGitLab("flag")
	if c.Value != "gl" {
		t.Fatalf("got %q, want GL_TOKEN", c.Value)
	}
	t.Setenv("GL_TOKEN", "")
	c, _ = ResolveGitLab("flag")
	if c.Value != "ci" || c.Source != "CI_JOB_TOKEN" {
		t.Fatalf("got %+v, want CI_JOB_TOKEN", c)
	}
	t.Setenv("CI_JOB_TOKEN", "")
	c, ok = ResolveGitLab("  flag  ")
	if !ok || c.Value != "flag" {
		t.Fatalf("got %+v, want --token", c)
	}
}

func TestResolveADOPatVsBearerAndPrecedence(t *testing.T) {
	clearCredEnv(t)
	t.Setenv("ADO_PAT", "ado")
	t.Setenv("AZURE_BEARER_TOKEN", "bearer")

	c, ok := ResolveADO("flag-pat", "flag-bearer")
	if !ok || c.Value != "ado" || c.Kind != CredPAT {
		t.Fatalf("ADO_PAT must beat bearer sources, got %+v", c)
	}

	t.Setenv("ADO_PAT", "")
	t.Setenv("AZURE_DEVOPS_PAT", "")
	t.Setenv("AZDO_PAT", "")
	t.Setenv("AZURE_DEVOPS_EXT_PAT", "")
	c, ok = ResolveADO("flag-pat", "flag-bearer")
	if !ok || c.Value != "bearer" || c.Kind != CredBearer || c.Source != "AZURE_BEARER_TOKEN" {
		t.Fatalf("got %+v, want AZURE_BEARER_TOKEN bearer", c)
	}

	t.Setenv("AZURE_BEARER_TOKEN", "")
	t.Setenv("SYSTEM_ACCESSTOKEN", "system")
	c, ok = ResolveADO("", "flag-bearer")
	if !ok || c.Value != "system" || c.Kind != CredBearer {
		t.Fatalf("got %+v, want SYSTEM_ACCESSTOKEN", c)
	}

	t.Setenv("SYSTEM_ACCESSTOKEN", "")
	c, ok = ResolveADO("  flag-pat  ", "flag-bearer")
	if !ok || c.Value != "flag-pat" || c.Kind != CredPAT || c.Source != "--token" {
		t.Fatalf("got %+v, want --token PAT", c)
	}

	c, ok = ResolveADO("", "  flag-bearer  ")
	if !ok || c.Value != "flag-bearer" || c.Kind != CredBearer || c.Source != "--azure-bearer-token" {
		t.Fatalf("got %+v, want --azure-bearer-token", c)
	}
}

func TestResolveADOBlankFallsThrough(t *testing.T) {
	clearCredEnv(t)
	t.Setenv("TRAJAN_ADO_TOKEN", "   ")
	t.Setenv("ADO_PAT", "")
	t.Setenv("AZURE_DEVOPS_PAT", "  ")
	t.Setenv("AZDO_PAT", "azdo")

	c, ok := ResolveADO("   ", "")
	if !ok || c.Value != "azdo" || c.Source != "AZDO_PAT" {
		t.Fatalf("blank entries must fall through, got %+v", c)
	}
}

func TestResolveNone(t *testing.T) {
	clearCredEnv(t)
	if _, ok := ResolveGitHub(""); ok {
		t.Fatal("ResolveGitHub: expected no credential")
	}
	if _, ok := ResolveGitLab(""); ok {
		t.Fatal("ResolveGitLab: expected no credential")
	}
	if _, ok := ResolveADO("", ""); ok {
		t.Fatal("ResolveADO: expected no credential")
	}
}
