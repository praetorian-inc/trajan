package github

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func TestNormalizeRulesetsDistinguishesUnreadableFromEmpty(t *testing.T) {
	runDir := t.TempDir()
	write := func(repo string, data map[string]any) {
		t.Helper()
		p := filepath.Join(runDir, engine.CollectRulesetsRepo(repo))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(map[string]any{"data": data})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("denied", map[string]any{"scope": "repo", "repo": "denied", "_unavailable": true, "_unavailable_status": 403})
	write("partial", map[string]any{"scope": "repo", "repo": "partial", "rulesets": []any{},
		"_detail_unavailable": map[string]any{"7": 403}})
	write("bare", map[string]any{"scope": "repo", "repo": "bare", "rulesets": []any{}})

	if _, err := normalizeRulesets(engine.PriorPhase{RunDir: runDir}, engine.CurrentPhase{RunDir: runDir}, "acme"); err != nil {
		t.Fatalf("normalizeRulesets: %v", err)
	}

	read := func(rel string) map[string]any {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(runDir, rel))
		if err != nil {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, repo := range []string{"denied", "partial"} {
		if rec := read(normRulesetSentinelPath(repo, "unavailable")); rec == nil || rec["_unavailable"] != true {
			t.Errorf("%s: no unavailable sentinel; a denied ruleset surface reads as unprotected", repo)
		}
	}
	if rec := read(normRulesetSentinelPath("denied", "none")); rec != nil {
		t.Error("denied: an unreadable surface also emitted the empty sentinel")
	}
	if rec := read(normRulesetSentinelPath("bare", "none")); rec == nil || rec["_empty"] != true {
		t.Error("bare: a genuinely empty surface must still emit the empty sentinel")
	}
	if rec := read(normRulesetSentinelPath("bare", "unavailable")); rec != nil {
		t.Error("bare: an empty surface must not be marked unavailable")
	}
}
