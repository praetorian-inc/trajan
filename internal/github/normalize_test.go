package github

import (
	"encoding/json"
	"testing"
)

// Oracle fr-05-06-workflow-run-chain: GitHub matches a workflow_run `workflows:`
// entry against the upstream's declared `name:`, so workflow_name must be that key
// verbatim — path-ifying it deletes the chain — and empty where none is declared.
func TestWorkflowNameIsTheDeclaredNameAndPairsWorkflowRun(t *testing.T) {
	files := map[string]string{
		"midstream.yml": `
name: B
on:
  workflow_run:
    workflows: ["A"]
    types: [completed]
jobs:
  relay:
    runs-on: ubuntu-latest
    steps:
      - run: ./relay.sh
`,
		"downstream.yml": `
name: C
on:
  workflow_run:
    workflows: ["B"]
    types: [completed]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: ./release.sh
`,
		"unnamed.yml": `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh
`,
	}

	var jobs []map[string]any
	byFile := map[string]Job{}
	for name, text := range files {
		recs, err := normalizeWorkflowText(text, normalizeCtx{
			org: "ghektestorg", repo: "ghektestorg/fr-05-06-workflow-run-chain",
			branch: "main", isDefault: true,
			relpath: "00-collect/workflows/fr-05-06-workflow-run-chain/" + name,
		})
		if err != nil {
			t.Fatalf("normalize %s: %v", name, err)
		}
		if len(recs) != 1 {
			t.Fatalf("normalize %s: want 1 job, got %d", name, len(recs))
		}
		byFile[name] = recs[0]

		b, err := json.Marshal(recs[0])
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		jobs = append(jobs, m)
	}

	for name, want := range map[string]string{"midstream.yml": "B", "downstream.yml": "C", "unnamed.yml": ""} {
		if got := byFile[name].WorkflowName; got != want {
			t.Errorf("%s: workflow_name = %q, want the declared name %q", name, got, want)
		}
	}

	pairs := deriveTriggerChannels(jobs)["workflow_run_pairs"].([]map[string]any)
	if len(pairs) != 1 {
		t.Fatalf("want exactly the B→C pair (A is not in the corpus), got %d: %v", len(pairs), pairs)
	}
	up := pairs[0]["upstream"].(map[string]any)
	down := pairs[0]["downstream"].(map[string]any)
	if up["workflow_filename"] != "midstream.yml" || down["workflow_filename"] != "downstream.yml" {
		t.Errorf("pair should be midstream→downstream, got %v→%v", up["workflow_filename"], down["workflow_filename"])
	}
}
