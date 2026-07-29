package gitlab

import (
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func yamlUnmarshal(b []byte, v any) error { return yaml.Unmarshal(b, v) }

func nowUTC() time.Time { return time.Now().UTC() }

// parseDatePrefix parses the YYYY-MM-DD prefix of an ISO date/timestamp.
func parseDatePrefix(s string) time.Time {
	if len(s) < 10 {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", s[:10])
	if err != nil {
		return time.Time{}
	}
	return t
}

// duoNode returns the aiSettings / duoSettings object for the scope. Group is
// {group:{aiSettings:{...}}}; instance is {duoSettings:{...}}.
func duoNode(duo map[string]any, scope string) map[string]any {
	if scope == "group" {
		return entMap(entGetIn(duo, "group", "aiSettings"))
	}
	return entMap(duo["duoSettings"])
}

func duoBool(duo map[string]any, scope, key string) any {
	if duo == nil || entUnobserved(duo) {
		return false
	}
	return entBool(duoNode(duo, scope)[key])
}

// duoGuardrail returns promptInjectionProtectionLevel UPPERCASE verbatim
// (LOG_ONLY/NO_CHECKS/INTERRUPT) — hard contract C-guardrail, never lowercased.
func duoGuardrail(duo map[string]any, scope string) any {
	if duo == nil || entUnobserved(duo) {
		return nil
	}
	v := entStr(duoNode(duo, scope)["promptInjectionProtectionLevel"])
	if v == "" {
		return nil
	}
	return v
}

// ---- .gitlab-ci.yml text folds (project/credential derived booleans) ----
//
// These are cheap textual scans over the raw entrypoint sufficient for the
// project/credential effective booleans. Full include-tree resolution and
// per-job facts are the job normalizer's responsibility.

var (
	reIDTokens    = regexp.MustCompile(`(?m)^\s*id_tokens\s*:`)
	reEnvironment = regexp.MustCompile(`(?m)^\s*environment\s*:`)
	reTagJob      = regexp.MustCompile(`CI_COMMIT_TAG|only\s*:\s*\n\s*-?\s*tags|rules:.*\$CI_COMMIT_TAG`)
	reDebugTrace  = regexp.MustCompile(`(?m)CI_DEBUG_TRACE\s*:\s*["']?(1|true|yes|on)`)
)

func ciYAMLHasDeployIdentity(b []byte) bool {
	if b == nil {
		return false
	}
	s := string(b)
	return reIDTokens.MatchString(s) || reEnvironment.MatchString(s)
}

func ciYAMLHasTagJob(b []byte) bool {
	if b == nil {
		return false
	}
	return reTagJob.MatchString(string(b))
}

func ciYAMLDebugTrace(b []byte) bool {
	if b == nil {
		return false
	}
	return reDebugTrace.MatchString(string(b)) || strings.Contains(strings.ToUpper(string(b)), "CI_DEBUG_TRACE")
}
