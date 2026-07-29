package gitlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The firing-range corpus (trajan-fr-group/trjfx, scenario projects cat-NN-vMM)
// is the independent oracle for these tests: we assert the field contract holds
// across a full Normalize of a real collected run, never what the code happens to
// produce for a hand-built input. The corpus is a P2 collect run dir; point the
// test at one with TRAJAN_GL_CORPUS. Absent, the test skips (the corpus is large
// and lives outside the tree). A run dir is copied so Normalize's in-place writes
// never mutate the shared corpus.
func corpusRun(t *testing.T) string {
	t.Helper()
	src := os.Getenv("TRAJAN_GL_CORPUS")
	if src == "" {
		t.Skip("set TRAJAN_GL_CORPUS to a P2 collect run dir to run corpus-oracle tests")
	}
	if _, err := os.Stat(filepath.Join(src, "00-collect", "project")); err != nil {
		t.Fatalf("TRAJAN_GL_CORPUS=%q is not a collect run dir: %v", src, err)
	}
	dst := t.TempDir()
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copy corpus: %v", err)
	}
	if err := Normalize(t.Context(), dst); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return dst
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

// readNormRecords loads every JSON record in a 10-normalize subdir, as raw text
// (to inspect on-disk serialization) and decoded.
func readNormRecords(t *testing.T, run, dir string) []map[string]any {
	t.Helper()
	d := filepath.Join(run, "10-normalize", dir)
	entries, err := os.ReadDir(d)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(d, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var rec map[string]any
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatalf("decode %s: %v", e.Name(), err)
		}
		rec["__raw"] = string(b)
		rec["__file"] = e.Name()
		out = append(out, rec)
	}
	return out
}

// TestCorpusEmptyListsSerializeAsBracket is hard-contract C1: every list-typed
// field named in the contract must serialize as [] when empty, never null and
// never omitted — valuesEqual(nil,[]) is false, so an absent list breaks the
// rules that gate on == [] / != []. We assert directly against the on-disk JSON.
func TestCorpusEmptyListsSerializeAsBracket(t *testing.T) {
	run := corpusRun(t)
	// (dir, field) pairs the contract calls out as load-bearing for == []/!= [].
	checks := map[string][]string{
		"projects":       {"protected_branches", "protected_tags", "cicd_variables", "members", "registry_protection_rules"},
		"jobs":           {"triggers", "includes", "cross_project_needs", "cache", "artifact_paths", "attacker_input_fields", "runner_tags", "id_token_aud"},
		"merge-requests": {"external_status_checks"},
		"agents":         {"ci_access_targets", "environments_filter"},
		"integrations":   {"custom_headers"},
		"groups":         {"cicd_variables", "descendants"},
	}
	for dir, fields := range checks {
		recs := readNormRecords(t, run, dir)
		if len(recs) == 0 {
			continue
		}
		for _, rec := range recs {
			raw := rec["__raw"].(string)
			for _, f := range fields {
				v, present := rec[f]
				if !present {
					t.Errorf("%s/%s: field %q omitted (contract requires [] when empty)", dir, rec["__file"], f)
					continue
				}
				if v == nil {
					t.Errorf("%s/%s: field %q serialized null (contract requires [])", dir, rec["__file"], f)
					continue
				}
				if _, ok := v.([]any); !ok {
					t.Errorf("%s/%s: field %q is %T, want list", dir, rec["__file"], f, v)
				}
				// Guard against the "field": null textual form slipping through.
				if strings.Contains(raw, "\""+f+"\": null") || strings.Contains(raw, "\""+f+"\":null") {
					t.Errorf("%s/%s: field %q appears as null in raw JSON", dir, rec["__file"], f)
				}
			}
		}
	}
}

// TestCorpusBooleansPresent is the C-boolean contract: every derived project
// boolean the rules read must be present (defaulting false), never omitted — a
// rule writing `x == true`/`x != true` against a missing key silently misfires.
func TestCorpusBooleansPresent(t *testing.T) {
	run := corpusRun(t)
	recs := readNormRecords(t, run, "projects")
	if len(recs) == 0 {
		t.Skip("no project records in corpus")
	}
	must := []string{
		"has_guest_member", "has_developer_pushable_unprotected_ref", "has_developer_reachable_secret",
		"has_masked_unprotected_secret_var", "has_plain_unprotected_secret_var", "has_scoped_unprotected_secret_var",
		"developer_writable_protected_branch", "has_reachable_runner", "has_self_managed_runner",
		"holds_protected_resources", "ci_debug_trace_enabled", "public_pipelines",
	}
	for _, rec := range recs {
		for _, f := range must {
			v, present := rec[f]
			if !present {
				t.Errorf("projects/%s: boolean %q omitted", rec["__file"], f)
				continue
			}
			if _, ok := v.(bool); !ok {
				t.Errorf("projects/%s: %q is %T, want bool", rec["__file"], f, v)
			}
		}
	}
}

// TestCorpusAccessLevelsNumeric is hard-contract C3: protected-branch/tag access
// levels and member access levels are numeric (rules read >=30, ∋{30}, ==30). A
// string role enum leaking through would make those predicates dead.
func TestCorpusAccessLevelsNumeric(t *testing.T) {
	run := corpusRun(t)
	saw := false
	for _, rec := range readNormRecords(t, run, "projects") {
		for _, raw := range asList(rec["members"]) {
			m, _ := raw.(map[string]any)
			assertNumericLevel(t, rec, "members.access_level", m["access_level"])
			saw = true
		}
		for _, raw := range asList(rec["protected_branches"]) {
			b, _ := raw.(map[string]any)
			for _, lvl := range asList(b["push_access_levels"]) {
				assertNumericLevel(t, rec, "protected_branches.push_access_levels", lvl)
				saw = true
			}
		}
		for _, raw := range asList(rec["protected_tags"]) {
			tg, _ := raw.(map[string]any)
			for _, lvl := range asList(tg["create_access_levels"]) {
				assertNumericLevel(t, rec, "protected_tags.create_access_levels", lvl)
				saw = true
			}
		}
	}
	if !saw {
		t.Skip("corpus carried no access-level lists to check")
	}
}

func assertNumericLevel(t *testing.T, rec map[string]any, path string, v any) {
	t.Helper()
	if _, ok := v.(float64); !ok { // JSON numbers decode to float64
		t.Errorf("%s: %s = %v (%T), want numeric access level", rec["__file"], path, v, v)
	}
}

// TestCorpusDuoGuardrailUppercase is hard-contract C-guardrail: any emitted
// prompt-injection level (job duo_guardrail_level/duo_instance_guardrail_level,
// instance prompt_injection_protection_level) that carries the GraphQL enum must
// keep it UPPERCASE verbatim. We only assert on values that look like the enum.
func TestCorpusDuoGuardrailUppercase(t *testing.T) {
	run := corpusRun(t)
	enum := map[string]bool{"NO_CHECKS": true, "LOG_ONLY": true, "INTERRUPT": true}
	check := func(file string, field string, v any) {
		s, ok := v.(string)
		if !ok || s == "" {
			return
		}
		if enum[strings.ToUpper(s)] && s != strings.ToUpper(s) {
			t.Errorf("%s: %s = %q, want uppercase verbatim", file, field, s)
		}
	}
	for _, rec := range readNormRecords(t, run, "jobs") {
		check(rec["__file"].(string), "duo_guardrail_level", rec["duo_guardrail_level"])
		check(rec["__file"].(string), "duo_instance_guardrail_level", rec["duo_instance_guardrail_level"])
	}
	for _, rec := range readNormRecords(t, run, "instance") {
		check(rec["__file"].(string), "prompt_injection_protection_level", rec["prompt_injection_protection_level"])
	}
}

// TestCorpusChainKeys is the hard for_each contract: correlate must write each of
// the nine joins under exactly its contract key (an unset/mismatched key makes
// iterChainItems default to "links" → iterate nothing). This is checked against
// the contract table, not the code.
func TestCorpusChainKeys(t *testing.T) {
	run := corpusRun(t)
	want := map[string]string{
		"job-token-allowlist":        "edges",
		"protected-var-reachability": "reachable_vars",
		"dotenv-flow":                "edges",
		"cache-keyspace":             "prefix_overlaps",
		"cross-project-artifact":     "edges",
		"deploy-key-reuse":           "reused_keys",
		"agent-ci-access":            "grants",
		"runner-reachability":        "reachable_runners",
		"group-runner-reachability":  "reachable_runners",
	}
	for join, key := range want {
		b, err := os.ReadFile(filepath.Join(run, "10-normalize", "chains", join+".json"))
		if err != nil {
			t.Errorf("chain %s not emitted: %v", join, err)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("chain %s decode: %v", join, err)
		}
		if m["chain"] != join {
			t.Errorf("chain %s: chain=%v", join, m["chain"])
		}
		v, present := m[key]
		if !present {
			t.Errorf("chain %s: missing for_each key %q (keys=%v)", join, key, keysOf(m))
			continue
		}
		if _, ok := v.([]any); !ok {
			t.Errorf("chain %s: %q is %T, want list of tuples", join, key, v)
		}
	}
}

// TestCorpusProtectedVarSelfResolving asserts the self-resolving invariant on the
// real join output: every emitted reachable_vars tuple carries a protected var,
// and the tuple's project equals the var's project (correlation (b): member ⊂ ref
// project). If the join leaked non-protected vars or cross-project members the
// literal-only rules would fire wrongly.
func TestCorpusProtectedVarSelfResolving(t *testing.T) {
	run := corpusRun(t)
	b, err := os.ReadFile(filepath.Join(run, "10-normalize", "chains", "protected-var-reachability.json"))
	if err != nil {
		t.Fatalf("read join: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	tuples := asList(m["reachable_vars"])
	if len(tuples) == 0 {
		t.Skip("corpus produced no protected-var tuples")
	}
	for _, raw := range tuples {
		tp, _ := raw.(map[string]any)
		v, _ := tp["var"].(map[string]any)
		if v["protected"] != true {
			t.Errorf("reachable_vars: emitted non-protected var %v", v["key"])
		}
		if tp["project"] != v["project"] {
			t.Errorf("reachable_vars: tuple.project=%v != var.project=%v (self-resolve (b) violated)", tp["project"], v["project"])
		}
	}
}

// TestCorpusProvenanceOnEveryRecord: _provenance rides on every normalized record
// (evidence templating depends on it). Checked across all subject dirs present.
func TestCorpusProvenanceOnEveryRecord(t *testing.T) {
	run := corpusRun(t)
	for _, dir := range []string{"projects", "jobs", "groups", "instance", "merge-requests", "environments", "runners", "agents", "credentials", "integrations"} {
		for _, rec := range readNormRecords(t, run, dir) {
			if _, ok := rec["_provenance"]; !ok {
				t.Errorf("%s/%s: missing _provenance", dir, rec["__file"])
			}
			if _, ok := rec["_id"]; !ok {
				t.Errorf("%s/%s: missing _id", dir, rec["__file"])
			}
		}
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
