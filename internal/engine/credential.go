package engine

import (
	"log/slog"
	"os"
	"strings"
)

type CredKind string

const (
	CredPAT    CredKind = "pat"
	CredBearer CredKind = "bearer"
)

type Credential struct {
	Value  string
	Kind   CredKind
	Source string
}

func envTrim(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func logCred(c Credential) Credential {
	slog.Info("using credential", "source", c.Source)
	return c
}

// ResolveGitHub: TRAJAN_GH_TOKEN → GH_TOKEN → GITHUB_TOKEN → --token.
// The gh auth token shell-out stays in the GitHub package, below the flag.
func ResolveGitHub(explicit string) (Credential, bool) {
	for _, k := range []string{"TRAJAN_GH_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"} {
		if v := envTrim(k); v != "" {
			return logCred(Credential{Value: v, Kind: CredPAT, Source: k}), true
		}
	}
	if v := strings.TrimSpace(explicit); v != "" {
		return logCred(Credential{Value: v, Kind: CredPAT, Source: "--token"}), true
	}
	return Credential{}, false
}

// ResolveGitLab: TRAJAN_GL_TOKEN → GITLAB_TOKEN → GL_TOKEN → CI_JOB_TOKEN → --token.
func ResolveGitLab(explicit string) (Credential, bool) {
	for _, k := range []string{"TRAJAN_GL_TOKEN", "GITLAB_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN"} {
		if v := envTrim(k); v != "" {
			return logCred(Credential{Value: v, Kind: CredPAT, Source: k}), true
		}
	}
	if v := strings.TrimSpace(explicit); v != "" {
		return logCred(Credential{Value: v, Kind: CredPAT, Source: "--token"}), true
	}
	return Credential{}, false
}

// ResolveADO walks PAT and bearer sources in one list so precedence is unambiguous.
func ResolveADO(explicitPAT, explicitBearer string) (Credential, bool) {
	type entry struct {
		source string
		value  string
		kind   CredKind
	}
	for _, e := range []entry{
		{"TRAJAN_ADO_TOKEN", envTrim("TRAJAN_ADO_TOKEN"), CredPAT},
		{"ADO_PAT", envTrim("ADO_PAT"), CredPAT},
		{"AZURE_DEVOPS_PAT", envTrim("AZURE_DEVOPS_PAT"), CredPAT},
		{"AZDO_PAT", envTrim("AZDO_PAT"), CredPAT},
		{"AZURE_DEVOPS_EXT_PAT", envTrim("AZURE_DEVOPS_EXT_PAT"), CredPAT},
		{"AZURE_BEARER_TOKEN", envTrim("AZURE_BEARER_TOKEN"), CredBearer},
		{"SYSTEM_ACCESSTOKEN", envTrim("SYSTEM_ACCESSTOKEN"), CredBearer},
		{"--token", strings.TrimSpace(explicitPAT), CredPAT},
		{"--azure-bearer-token", strings.TrimSpace(explicitBearer), CredBearer},
	} {
		if e.value != "" {
			return logCred(Credential{Value: e.value, Kind: e.kind, Source: e.source}), true
		}
	}
	return Credential{}, false
}
