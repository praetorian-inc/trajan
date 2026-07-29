package github

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine/detect"
)

// --- extractNeedsOutputRefs: the cross-job needs.<job>.outputs.<var> extractor ---

func TestExtractNeedsOutputRefs(t *testing.T) {
	t.Run("plain-ref", func(t *testing.T) {
		got := extractNeedsOutputRefs("echo ${{ needs.build.outputs.tag }}")
		want := []NeedsOutputRef{{JobID: "build", OutputName: "tag"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("fromJSON-wrapped-nested", func(t *testing.T) {
		// The ref is buried inside fromJSON(...) inside a larger expression; the
		// extractor matches on the raw blob, not on whole interpolations.
		got := extractNeedsOutputRefs("${{ fromJSON(needs.meta.outputs.matrix).include }}")
		want := []NeedsOutputRef{{JobID: "meta", OutputName: "matrix"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("non-match", func(t *testing.T) {
		// steps.<id>.outputs and needs.<job>.result are not needs-output refs.
		for _, text := range []string{
			"${{ steps.build.outputs.tag }}",
			"${{ needs.build.result }}",
			"echo no expressions here",
			"",
		} {
			if got := extractNeedsOutputRefs(text); len(got) != 0 {
				t.Errorf("extractNeedsOutputRefs(%q) = %v, want empty", text, got)
			}
		}
	})

	t.Run("dedup-distinct-vars-kept", func(t *testing.T) {
		text := "${{ needs.a.outputs.x }} ${{ needs.a.outputs.x }} ${{ needs.a.outputs.y }} ${{ needs.b.outputs.x }}"
		got := extractNeedsOutputRefs(text)
		want := []NeedsOutputRef{
			{JobID: "a", OutputName: "x"},
			{JobID: "a", OutputName: "y"},
			{JobID: "b", OutputName: "x"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

// --- deriveJobOutputFlow: producer->consumer single-hop edges ---
//
// These build normalized-record maps in the same map[string]any shape correlate
// reads off disk (the .get()-keyed shapes), mirroring the fr-01-12 firing-range
// scenario: one producer job declaring an output, one consumer job referencing
// needs.<producer>.outputs.<var>.

type jobMap = map[string]any

// producerJob builds a normalized producer-job record with one output. The
// output is attacker-influenced via contextFields (output expression interpolates
// an attacker context field) and/or execRefs (the producing step wrote attacker
// data to $GITHUB_OUTPUT).
func producerJob(repo, wf, jobID, outputName string, triggers []string, contextFields, execRefs []string) jobMap {
	return jobMap{
		"_id":               repo + "__" + wf + "__" + jobID,
		"repo":              repo,
		"workflow_filename": wf,
		"job_id":            jobID,
		"triggers":          toAnyList(triggers),
		"outputs": []any{
			jobMap{
				"name":                               outputName,
				"attacker_context_fields_referenced": toAnyList(contextFields),
				"producing_step_attacker_exec_refs":  toAnyList(execRefs),
			},
		},
	}
}

// consumerJob builds a consumer-job record with a single step referencing
// needs.<producerJobID>.outputs.<outputName> in the given context ("exec" or
// "binding").
func consumerJob(repo, wf, jobID, producerJobID, outputName, context string, triggers []string) jobMap {
	refKey := "needs_output_refs_binding"
	if context == "exec" {
		refKey = "needs_output_refs_exec"
	}
	ref := jobMap{"job_id": producerJobID, "output_name": outputName}
	return jobMap{
		"_id":               repo + "__" + wf + "__" + jobID,
		"repo":              repo,
		"workflow_filename": wf,
		"job_id":            jobID,
		"triggers":          toAnyList(triggers),
		"needs_output_refs": []any{ref},
		"steps": []any{
			jobMap{refKey: []any{ref}},
		},
	}
}

// strategyConsumerJob builds a consumer-job record whose only
// needs.<producer>.outputs.<var> reference lives in the job-level strategy/matrix
// block: it surfaces as a job-level needs_output_refs_exec ref (step_index -1)
// with no step carrying it, mirroring what normalizeJob produces for
// `strategy: { matrix: ${{ fromJSON(needs.<producer>.outputs.matrix) }} }`.
func strategyConsumerJob(repo, wf, jobID, producerJobID, outputName string, triggers []string) jobMap {
	ref := jobMap{"job_id": producerJobID, "output_name": outputName}
	return jobMap{
		"_id":                    repo + "__" + wf + "__" + jobID,
		"repo":                   repo,
		"workflow_filename":      wf,
		"job_id":                 jobID,
		"triggers":               toAnyList(triggers),
		"needs_output_refs":      []any{ref},
		"needs_output_refs_exec": []any{ref},
		"steps":                  []any{},
	}
}

func toAnyList(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

func edgesOf(t *testing.T, result map[string]any) []map[string]any {
	t.Helper()
	raw, ok := result["edges"].([]map[string]any)
	if !ok {
		t.Fatalf("edges not []map[string]any: %T", result["edges"])
	}
	return raw
}

func TestDeriveJobOutputFlowBenignProducer(t *testing.T) {
	// (a) producer output carries no attacker influence -> edge exists but
	// attacker_influenced == false.
	prod := producerJob("o/r", "ci.yml", "build", "tag", []string{"push"}, nil, nil)
	cons := consumerJob("o/r", "ci.yml", "deploy", "build", "tag", "exec", []string{"push"})

	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(edges))
	}
	if edges[0]["attacker_influenced"] != false {
		t.Errorf("benign producer must yield attacker_influenced=false, got %v", edges[0]["attacker_influenced"])
	}
}

func TestDeriveJobOutputFlowAttackerInfluencedViaContextField(t *testing.T) {
	// (b1) producer output expression interpolates github.event.pull_request.title,
	// consumed in another job's run: (exec) -> attacker_influenced == true.
	prod := producerJob("o/r", "ci.yml", "meta", "title", []string{"pull_request_target"},
		[]string{"github.event.pull_request.title"}, nil)
	cons := consumerJob("o/r", "ci.yml", "use", "meta", "title", "exec", []string{"pull_request_target"})

	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(edges))
	}
	if edges[0]["attacker_influenced"] != true {
		t.Errorf("context-field-referenced output must be attacker_influenced, got %v", edges[0]["attacker_influenced"])
	}
	if edges[0]["consumer"].(map[string]any)["context"] != "exec" {
		t.Errorf("consumer context should be exec, got %v", edges[0]["consumer"])
	}
}

func TestDeriveJobOutputFlowAttackerInfluencedViaProducingStepExec(t *testing.T) {
	// (b2) a producing step wrote attacker data to $GITHUB_OUTPUT (captured as
	// producing_step_attacker_exec_refs) -> attacker_influenced == true even
	// though the output's own value_expression referenced nothing.
	prod := producerJob("o/r", "ci.yml", "meta", "data", []string{"issue_comment"},
		nil, []string{"github.event.comment.body"})
	cons := consumerJob("o/r", "ci.yml", "use", "meta", "data", "exec", []string{"issue_comment"})

	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(edges))
	}
	if edges[0]["attacker_influenced"] != true {
		t.Errorf("producing-step exec ref must mark the edge attacker_influenced, got %v", edges[0]["attacker_influenced"])
	}
}

func TestDeriveJobOutputFlowCrossWorkflowNoEdge(t *testing.T) {
	// (c) producer lives in a different workflow file; needs is intra-workflow,
	// so the (repo, workflow_filename, job_id) join key misses -> NO edge.
	prod := producerJob("o/r", "producer.yml", "build", "tag", []string{"pull_request"},
		[]string{"github.event.pull_request.title"}, nil)
	cons := consumerJob("o/r", "consumer.yml", "deploy", "build", "tag", "exec", []string{"pull_request"})

	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 0 {
		t.Fatalf("cross-workflow producer must not join (one-hop, same-workflow only), got %d edges", len(edges))
	}
}

func TestDeriveJobOutputFlowSameRepoDifferentRepoNoEdge(t *testing.T) {
	// Same workflow filename and job id but different repos must not join.
	prod := producerJob("o/r1", "ci.yml", "build", "tag", []string{"pull_request"},
		[]string{"github.event.pull_request.title"}, nil)
	cons := consumerJob("o/r2", "ci.yml", "deploy", "build", "tag", "exec", []string{"pull_request"})

	if edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons})); len(edges) != 0 {
		t.Fatalf("different-repo producer must not join, got %d edges", len(edges))
	}
}

func TestDeriveJobOutputFlowStrategyMatrixJobLevel(t *testing.T) {
	// The classic dynamic-matrix-from-PR sink: a producer under a low-trust
	// trigger emits an attacker-influenced output consumed via
	// fromJSON(needs.<producer>.outputs.matrix) in a job-level strategy block.
	// The consumer ref is job-level (no step), so the edge must carry
	// step_index -1 and context exec, and be attacker_influenced.
	prod := producerJob("o/r", "ci.yml", "setup", "matrix", []string{"pull_request_target"},
		[]string{"github.event.pull_request.title"}, nil)
	cons := strategyConsumerJob("o/r", "ci.yml", "build", "setup", "matrix", []string{"pull_request_target"})

	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 1 {
		t.Fatalf("want 1 job-level strategy edge, got %d", len(edges))
	}
	e := edges[0]
	if e["attacker_influenced"] != true {
		t.Errorf("strategy matrix from attacker-influenced output must be attacker_influenced, got %v", e["attacker_influenced"])
	}
	c := e["consumer"].(map[string]any)
	if c["context"] != "exec" {
		t.Errorf("consumer context must be exec, got %v", c["context"])
	}
	if c["step_index"] != -1 {
		t.Errorf("job-level strategy ref must mark step_index -1, got %v", c["step_index"])
	}
}

func TestDeriveJobOutputFlowStrategyMatrixBenignNoFire(t *testing.T) {
	// Negative: a benign producer output (no attacker influence) consumed via a
	// job-level strategy matrix still emits an edge, but attacker_influenced is
	// false so the rule will not fire.
	prod := producerJob("o/r", "ci.yml", "setup", "matrix", []string{"push"}, nil, nil)
	cons := strategyConsumerJob("o/r", "ci.yml", "build", "setup", "matrix", []string{"push"})

	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(edges))
	}
	if edges[0]["attacker_influenced"] != false {
		t.Errorf("benign matrix producer must yield attacker_influenced=false, got %v", edges[0]["attacker_influenced"])
	}
}

func TestDeriveJobOutputFlowStrategyMatrixNoDoubleEdge(t *testing.T) {
	// A ref present in BOTH a step and the job-level exec list (the union case)
	// must emit a single step-level edge, not an extra spurious step -1 edge.
	prod := producerJob("o/r", "ci.yml", "setup", "tag", []string{"pull_request_target"},
		[]string{"github.event.pull_request.title"}, nil)
	cons := consumerJob("o/r", "ci.yml", "build", "setup", "tag", "exec", []string{"pull_request_target"})

	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 1 {
		t.Fatalf("ref carried by a step must yield exactly 1 edge, got %d", len(edges))
	}
	if edges[0]["consumer"].(map[string]any)["step_index"] != 0 {
		t.Errorf("step-carried ref must keep its step index, got %v", edges[0]["consumer"])
	}
}

// normalizeJob must lift a needs.<job>.outputs.<var> ref appearing only in the
// job-level strategy/matrix block into the job-level exec/union ref lists.
func TestNormalizeJobStrategyMatrixNeedsRef(t *testing.T) {
	wf := `
name: ci
on: pull_request_target
jobs:
  setup:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.gen.outputs.matrix }}
    steps:
      - id: gen
        run: echo "matrix=$(cat pr.json)" >> "$GITHUB_OUTPUT"
  build:
    needs: setup
    strategy:
      matrix: ${{ fromJSON(needs.setup.outputs.matrix) }}
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	recs, err := normalizeWorkflowText(wf, normalizeCtx{org: "o", repo: "o/r", branch: "main", isDefault: true, relpath: "00-collect/workflows/o-r/ci.yml"})
	if err != nil {
		t.Fatalf("normalizeWorkflowText: %v", err)
	}
	var build *Job
	for i := range recs {
		if recs[i].JobID == "build" {
			build = &recs[i]
		}
	}
	if build == nil {
		t.Fatal("build job not normalized")
	}
	want := NeedsOutputRef{JobID: "setup", OutputName: "matrix"}
	if !reflect.DeepEqual(build.NeedsOutputRefsExec, []NeedsOutputRef{want}) {
		t.Errorf("strategy matrix ref not lifted into needs_output_refs_exec: %v", build.NeedsOutputRefsExec)
	}
	if !reflect.DeepEqual(build.NeedsOutputRefs, []NeedsOutputRef{want}) {
		t.Errorf("strategy matrix ref not in union: %v", build.NeedsOutputRefs)
	}
	// The ref lives in no step, so no step carries it.
	for _, s := range build.Steps {
		if len(s.NeedsOutputRefsExec) != 0 || len(s.NeedsOutputRefsBinding) != 0 {
			t.Errorf("step unexpectedly carries a needs ref: %+v", s)
		}
	}
}

// --- chain rule via EvaluateChainRule on a job-output-flow chain ---

// loadCrossJobRule loads the embedded cross-job-output chain rule by its id.
func loadCrossJobRule(t *testing.T) *detect.Rule {
	t.Helper()
	rules, err := detect.LoadRules("github")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	for i := range rules {
		if rules[i].ID == "cat-01/chain-prt-cross-job-output" {
			return &rules[i]
		}
	}
	t.Fatal("cat-01/chain-prt-cross-job-output rule not found")
	return nil
}

// jobOutputChain wraps a single edge into the chain document shape correlate
// writes (chain=job-output-flow, edges=[...]), as JSON-decoded maps.
func jobOutputChain(edge map[string]any) map[string]any {
	return map[string]any{
		"chain": "job-output-flow",
		"edges": []any{edge},
	}
}

func crossJobEdge(attackerInfluenced bool, consumerContext string, consumerTriggers, producerTriggers []string) map[string]any {
	return map[string]any{
		"_id":                 "jof__p__c",
		"attacker_influenced": attackerInfluenced,
		"producer": map[string]any{
			"job_id":   "producer",
			"triggers": toAnyList(producerTriggers),
		},
		"consumer": map[string]any{
			"job_id":      "consumer",
			"context":     consumerContext,
			"output_name": "payload",
			"step_index":  float64(0),
			"triggers":    toAnyList(consumerTriggers),
		},
		"attacker_path": []any{"producer job producer output payload"},
	}
}

func TestCrossJobOutputRuleFiresOnExecAttackerLowTrust(t *testing.T) {
	rule := loadCrossJobRule(t)
	failOnErr := func(err error) { t.Fatalf("eval error: %v", err) }

	t.Run("low-trust-on-consumer", func(t *testing.T) {
		edge := crossJobEdge(true, "exec", []string{"pull_request_target"}, []string{"push"})
		matched := detect.EvaluateChainRule(rule, jobOutputChain(edge), failOnErr)
		if len(matched) != 1 {
			t.Fatalf("rule must fire on exec+attacker_influenced+low-trust consumer, got %d matches", len(matched))
		}
	})

	t.Run("low-trust-on-producer", func(t *testing.T) {
		// any_of: producer.triggers low-trust also satisfies the trigger clause.
		edge := crossJobEdge(true, "exec", []string{"push"}, []string{"issue_comment"})
		matched := detect.EvaluateChainRule(rule, jobOutputChain(edge), failOnErr)
		if len(matched) != 1 {
			t.Fatalf("rule must fire when producer carries the low-trust trigger, got %d matches", len(matched))
		}
	})
}

func TestCrossJobOutputRuleFiresOnStrategyMatrixEdge(t *testing.T) {
	// End-to-end: a job-level strategy-matrix edge (step_index -1) derived by
	// deriveJobOutputFlow must satisfy the chain rule, since the where clause
	// keys on attacker_influenced/context/triggers, not on step_index.
	rule := loadCrossJobRule(t)
	failOnErr := func(err error) { t.Fatalf("eval error: %v", err) }

	prod := producerJob("o/r", "ci.yml", "setup", "matrix", []string{"pull_request_target"},
		[]string{"github.event.pull_request.title"}, nil)
	cons := strategyConsumerJob("o/r", "ci.yml", "build", "setup", "matrix", []string{"pull_request_target"})
	edges := edgesOf(t, deriveJobOutputFlow([]jobMap{prod, cons}))
	if len(edges) != 1 {
		t.Fatalf("want 1 derived edge, got %d", len(edges))
	}

	chain := map[string]any{"chain": "job-output-flow", "edges": []any{edges[0]}}
	matched := detect.EvaluateChainRule(rule, chain, failOnErr)
	if len(matched) != 1 {
		t.Fatalf("rule must fire on derived strategy-matrix exec edge, got %d matches", len(matched))
	}
}

func TestCrossJobOutputRuleDoesNotFire(t *testing.T) {
	rule := loadCrossJobRule(t)
	failOnErr := func(err error) { t.Fatalf("eval error: %v", err) }

	cases := []struct {
		name string
		edge map[string]any
	}{
		{
			// benign: not attacker-influenced.
			name: "not-attacker-influenced",
			edge: crossJobEdge(false, "exec", []string{"pull_request_target"}, []string{"pull_request_target"}),
		},
		{
			// binding-only consumption is not an exec sink.
			name: "binding-context",
			edge: crossJobEdge(true, "binding", []string{"pull_request_target"}, []string{"pull_request_target"}),
		},
		{
			// attacker-influenced + exec but neither side has a low-trust trigger.
			name: "no-low-trust-trigger",
			edge: crossJobEdge(true, "exec", []string{"push"}, []string{"schedule"}),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matched := detect.EvaluateChainRule(rule, jobOutputChain(c.edge), failOnErr)
			if len(matched) != 0 {
				t.Fatalf("rule must NOT fire (%s), got %d matches", c.name, len(matched))
			}
		})
	}
}
