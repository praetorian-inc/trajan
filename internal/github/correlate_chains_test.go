package github

import (
	"strings"
	"testing"
)

func cacheOps(keys ...string) []any {
	out := []any{}
	for _, k := range keys {
		e := cacheEntry(k)
		out = append(out, map[string]any{"key_template": e.KeyTemplate, "scope": e.Scope, "restore_keys": nil})
	}
	return out
}

func cacheJob(repo, workflow, job, trigger string, writes, reads []any) map[string]any {
	return map[string]any{
		"_id":  repo + "__" + strings.TrimSuffix(workflow, ".yml") + "__" + job,
		"repo": repo, "workflow_filename": workflow, "job_id": job,
		"triggers": []any{trigger}, "cache_writes": writes, "cache_reads": reads,
	}
}

// restore-keys match on a literal prefix, so the grouping unit is the literal head
// of the key; and GitHub scopes caches per repository, so fr-09-01 and fr-09-03
// caching the same "npm-..." key share nothing.
func TestCacheOverlapsGroupPerRepoOnTheLiteralKeyHead(t *testing.T) {
	const npmKey = "npm-${{ runner.os }}-${{ hashFiles('package-lock.json') }}"
	const npmRestore = "npm-${{ runner.os }}-"
	jobs := []map[string]any{
		cacheJob("fr-09-01-restore-keys-prefix-match-bypass", "writer.yml", "build", "push",
			cacheOps(npmKey), cacheOps(npmKey, npmRestore)),
		cacheJob("fr-09-01-restore-keys-prefix-match-bypass", "release.yml", "release", "push",
			nil, cacheOps(npmKey, npmRestore)),
		cacheJob("fr-09-03-runtime-token-exfiltration", "release.yml", "release", "push",
			cacheOps(npmKey), cacheOps(npmKey, npmRestore)),
		cacheJob("fr-09-03-runtime-token-exfiltration", "reader.yml", "read", "push",
			nil, cacheOps(npmKey, npmRestore)),
		cacheJob("fr-09-02-cache-stuffing-lru-eviction", "release.yml", "release", "push",
			cacheOps("build-tools-v3-pinned-2026-05"), cacheOps("build-tools-v3-pinned-2026-05")),
		cacheJob("fr-09-02-cache-stuffing-lru-eviction", "stuff.yml", "stuff", "pull_request",
			cacheOps("build-tools-v3-pinned-2026-05"), nil),
	}

	out := deriveCacheKeyspace(jobs)
	for _, field := range []string{"reads_by_prefix", "writes_by_prefix"} {
		for prefix, rows := range out[field].(map[string]any) {
			for _, row := range rows.([]map[string]any) {
				if key, _ := row["key"].(string); !strings.HasPrefix(key, prefix) {
					t.Errorf("%s: prefix %q is not a literal prefix of key %q", field, prefix, key)
				}
			}
		}
	}

	got := map[[2]string]bool{}
	for _, o := range out["prefix_overlaps"].([]map[string]any) {
		repo, prefix := mStr(o, "repo"), mStr(o, "key_prefix")
		got[[2]string{repo, prefix}] = true
		for _, side := range []string{"writers", "readers"} {
			for _, r := range o[side].([]map[string]any) {
				if from := mStr(r["job"].(map[string]any), "repo"); from != repo {
					t.Errorf("overlap %q in %q counts a %s from %q", prefix, repo, side, from)
				}
			}
		}
	}
	for _, want := range [][2]string{
		{"fr-09-01-restore-keys-prefix-match-bypass", "npm"},
		{"fr-09-03-runtime-token-exfiltration", "npm"},
		{"fr-09-02-cache-stuffing-lru-eviction", "build-tools-v3-pinned-2026-05"},
	} {
		if !got[want] {
			t.Errorf("no overlap for %v; got %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d overlaps, want one per (repo, prefix): %v", len(got), got)
	}
}

// fr-05-09: the callee downloads "${{ inputs.artifact-name }}", so the handoff is
// only visible once that name is resolved against the caller's input value.
func TestArtifactHandoffResolvesTheCalleeInputName(t *testing.T) {
	const repo = "fr-05-09-reusable-workflow-laundering"
	jobs := []map[string]any{
		{"_id": repo + "__upstream__build", "repo": repo, "workflow_filename": "upstream.yml",
			"job_id": "build", "triggers": []any{"pull_request"},
			"artifact_writes": []any{map[string]any{"name": "build-out"}}},
		{"_id": repo + "__downstream__release", "repo": repo, "workflow_filename": "downstream.yml",
			"job_id": "release", "triggers": []any{"workflow_run"},
			"calls_reusable_workflows": []any{map[string]any{
				"path": ".github/workflows/_reusable.yml", "kind": "local", "secrets_inherit": true,
				"inputs": map[string]any{"artifact-name": "build-out", "run-id": "${{ github.event.workflow_run.id }}"},
			}}},
		{"_id": repo + "___reusable__release", "repo": repo, "workflow_filename": "_reusable.yml",
			"job_id": "release", "triggers": []any{"workflow_call"},
			"artifact_reads": []any{map[string]any{"name": "${{ inputs.artifact-name }}"}}},
	}

	handoffs := deriveTriggerChannels(jobs)["artifact_handoffs"].([]map[string]any)
	if len(handoffs) != 1 {
		t.Fatalf("got %d handoffs, want the upstream -> callee one: %v", len(handoffs), handoffs)
	}
	h := handoffs[0]
	if h["artifact_name"] != "build-out" {
		t.Errorf("artifact_name = %v, want the caller's input value", h["artifact_name"])
	}
	if from := mStr(h["writer"].(map[string]any), "workflow_filename"); from != "upstream.yml" {
		t.Errorf("writer = %q, want upstream.yml", from)
	}
	if to := mStr(h["reader"].(map[string]any), "workflow_filename"); to != "_reusable.yml" {
		t.Errorf("reader = %q, want _reusable.yml", to)
	}
}
