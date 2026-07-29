package ado

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// One step can call several shadowable binaries; each is a separate hijack
// target and must survive as its own edge.
func TestLoggingInjectionKeepsEveryConsumerAtOneStep(t *testing.T) {
	dir := t.TempDir()
	cp := engine.CurrentPhase{RunDir: dir}
	timer := &engine.PhaseTimer{}

	job := map[string]any{
		"project": "Mobile-Release", "pipeline_id": int64(2), "job": "build_and_publish",
		"vso_echo_sources": []any{
			map[string]any{"untrusted_source": "file_content", "step_index": int64(1)},
		},
		"bare_binary_calls": []any{
			map[string]any{"bin": "npm", "step_index": int64(2)},
			map[string]any{"bin": "git", "step_index": int64(2)},
		},
	}
	if err := deriveLoggingInjection(cp, timer, job, pipeInfo{identityScope: "project"}, grantIndex{}); err != nil {
		t.Fatalf("deriveLoggingInjection: %v", err)
	}

	written, err := filepath.Glob(filepath.Join(dir, "10-normalize", "edges", "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 2 {
		t.Fatalf("npm and git at the same step must emit 2 edges, got %d", len(written))
	}
	bins := map[string]bool{}
	for _, p := range written {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var rec map[string]any
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		bins[entStr(rec["target_resource"])] = true
	}
	for _, want := range []string{"npm", "git"} {
		if !bins[want] {
			t.Errorf("no edge names %q as the shadowed binary (got %v)", want, bins)
		}
	}
}

// A $[ variables ] compile-keyword redirect is a real attack path only when the variable
// is confirmed queue-settable. Declared-settable is settable regardless of the limit;
// otherwise it needs the limit observed off; unobserved settings must fail closed so we
// never assert a redirect a compensating control might silently block.
func TestRuntimeVarRedirectReachable(t *testing.T) {
	rv := func(declaredSettable bool) map[string]any {
		return map[string]any{"is_declared_settable": declaredSettable}
	}
	cases := []struct {
		name string
		ps   map[string]any
		meta pipeInfo
		want bool
	}{
		{"declared settable is reachable even under the limit", rv(true), pipeInfo{enforceSettable: true, settingsObserved: true}, true},
		{"declared settable is reachable even when unobserved", rv(true), pipeInfo{settingsObserved: false}, true},
		{"not declared, limit observed off -> reachable", rv(false), pipeInfo{enforceSettable: false, settingsObserved: true}, true},
		{"not declared, limit observed on -> blocked", rv(false), pipeInfo{enforceSettable: true, settingsObserved: true}, false},
		{"not declared, settings unobserved -> fail closed", rv(false), pipeInfo{enforceSettable: false, settingsObserved: false}, false},
	}
	for _, c := range cases {
		if got := runtimeVarRedirectReachable(c.ps, c.meta); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// One job can reference the same macro from several steps; each is its own
// injection point and must survive as a distinct edge carrying its step.
func TestQueueTimeInjectionKeepsEveryStep(t *testing.T) {
	dir := t.TempDir()
	cp := engine.CurrentPhase{RunDir: dir}
	timer := &engine.PhaseTimer{}

	job := map[string]any{
		"project": "Payments-API", "pipeline_id": int64(2), "job": "build",
		"macro_sinks": []any{
			map[string]any{"macro_name": "buildConfiguration", "macro_kind": "user", "location": "script", "step_index": int64(2)},
			map[string]any{"macro_name": "buildConfiguration", "macro_kind": "user", "location": "script", "step_index": int64(3)},
		},
	}
	if err := deriveQueueTimeInjection(cp, timer, job, pipeInfo{identityScope: "project"}, grantIndex{}); err != nil {
		t.Fatalf("deriveQueueTimeInjection: %v", err)
	}

	written, err := filepath.Glob(filepath.Join(dir, "10-normalize", "edges", "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 2 {
		t.Fatalf("the same macro at two steps must emit 2 edges, got %d", len(written))
	}
	steps := map[int64]bool{}
	for _, p := range written {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var rec map[string]any
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		steps[entInt64(rec["step_index"])] = true
	}
	for _, want := range []int64{2, 3} {
		if !steps[want] {
			t.Errorf("no edge records step %d (got %v)", want, steps)
		}
	}
}

// buildValidated drives the highest-confidence poisoning trigger; it is populated
// from the BUILD_VALIDATES edges derivePolicyAttribution wrote earlier in the pass.
func TestIndexPipelinesCarriesBuildValidated(t *testing.T) {
	pipelines := []map[string]any{
		{"project": "P", "id": float64(7), "name": "gated"},
		{"project": "P", "id": float64(8), "name": "ungated"},
	}
	meta := indexPipelines(pipelines, map[string]bool{pipeKey("P", 7): true})
	if !meta[pipeKey("P", 7)].buildValidated {
		t.Error("pipeline 7 is build-validated but the flag is false")
	}
	if meta[pipeKey("P", 8)].buildValidated {
		t.Error("pipeline 8 has no build-validation policy but the flag is true")
	}
}
