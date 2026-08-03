package graph

import (
	"slices"
	"testing"
)

func orgFixture(secrets ...any) map[string]any {
	return map[string]any{
		"_id": "portus-labs", "org": "portus-labs",
		"org_actions_secrets": secrets,
	}
}

// Both visibility fan-outs run repository -> resource, so the thing whose blast
// radius is under test is the "to" end and the repositories are what collect.
func canAccessSources(s *edgeSet, to NodeLabel) map[string][]string {
	out := map[string][]string{}
	for _, e := range edgesOfType(s, CanAccess) {
		if e.ToLabel == to {
			out[e.To] = append(out[e.To], e.From)
		}
	}
	for _, v := range out {
		slices.Sort(v)
	}
	return out
}

// An org secret with visibility "selected" and an empty repository list is
// reachable by nothing. The count alone cannot say so: a fan-out driven by
// Secret.visibility would give it the widest blast radius in the org, which is
// the exact inverse of the setting.
func TestOrgSecretSelectedWithEmptyListReachesNothing(t *testing.T) {
	s := build(t, map[string]any{
		"org/portus-labs.json": orgFixture(
			map[string]any{"name": "PLATFORM_BOT_PAT", "visibility": "all", "selected_repositories": []any{}},
			map[string]any{"name": "NPM_TOKEN", "visibility": "selected", "selected_repositories": []any{}},
			map[string]any{"name": "DEPLOY_KEY", "visibility": "selected", "selected_repositories": []any{"payments-api"}},
			map[string]any{"name": "INTERNAL_ONLY", "visibility": "private", "selected_repositories": []any{}},
		),
		"repos/payments-api.json":     map[string]any{"_id": "payments-api", "repo": "payments-api", "visibility": "private"},
		"repos/portus-cli.json":       map[string]any{"_id": "portus-cli", "repo": "portus-cli", "visibility": "public"},
		"repos/shared-workflows.json": map[string]any{"_id": "shared-workflows", "repo": "shared-workflows", "visibility": "private"},
	})

	reach := canAccessSources(s, Secret)

	if got := reach["Secret|org|portus-labs|NPM_TOKEN"]; len(got) != 0 {
		t.Errorf("NPM_TOKEN reaches %v, want nothing: an empty selected set names no repository", got)
	}
	if got := len(reach["Secret|org|portus-labs|PLATFORM_BOT_PAT"]); got != 3 {
		t.Errorf("PLATFORM_BOT_PAT reaches %d repos, want all 3", got)
	}
	want := []string{"Repository|portus-labs/payments-api"}
	if got := reach["Secret|org|portus-labs|DEPLOY_KEY"]; !slices.Equal(got, want) {
		t.Errorf("DEPLOY_KEY reaches %v, want %v", got, want)
	}
	// "private" is every non-public repo, so the public one must be absent.
	if got := reach["Secret|org|portus-labs|INTERNAL_ONLY"]; slices.Contains(got, "Repository|portus-labs/portus-cli") {
		t.Errorf("INTERNAL_ONLY reaches %v, want the public repo excluded", got)
	}
}

// The visibility a group was configured with is what bounds it, not the number
// of runners in it: an empty "selected" list reaches nothing even though the
// group holds a live fleet.
func TestRunnerGroupSelectedWithEmptyListReachesNoRepository(t *testing.T) {
	s := build(t, map[string]any{
		"org/portus-labs.json":    orgFixture(),
		"repos/payments-api.json": map[string]any{"_id": "payments-api", "repo": "payments-api", "visibility": "private"},
		"repos/portus-cli.json":   map[string]any{"_id": "portus-cli", "repo": "portus-cli", "visibility": "private"},
		"runner-groups/1.json": map[string]any{"_id": "1", "group_id": 1, "org": "portus-labs",
			"name": "Default", "visibility": "all", "member_runner_ids": []any{2}, "selected_repositories": []any{}},
		"runner-groups/3.json": map[string]any{"_id": "3", "group_id": 3, "org": "portus-labs",
			"name": "Locked", "visibility": "selected", "member_runner_ids": []any{7}, "selected_repositories": []any{}},
		"runners/portus-labs__2.json": map[string]any{"_id": "portus-labs__2", "runner_id": 2,
			"scope": "org", "scope_key": "portus-labs", "name": "vm-a", "labels": []any{"self-hosted", "Linux"}},
		"runners/portus-labs__7.json": map[string]any{"_id": "portus-labs__7", "runner_id": 7,
			"scope": "org", "scope_key": "portus-labs", "name": "vm-b", "labels": []any{"self-hosted", "Linux"}},
	})

	reach := canAccessSources(s, RunnerGroup)
	if got := len(reach["RunnerGroup|portus-labs|1"]); got != 2 {
		t.Errorf("visibility \"all\" group reaches %d repos, want 2", got)
	}
	if got := reach["RunnerGroup|portus-labs|3"]; len(got) != 0 {
		t.Errorf("empty selected group reaches %v, want nothing", got)
	}

	// Membership comes from the group, not from the runner: the org listing
	// leaves runner_group_id null on every runner it returns.
	members := []string{}
	for _, e := range edgesOfType(s, Contains) {
		if e.FromLabel == RunnerGroup {
			members = append(members, e.From+" -> "+e.To)
		}
	}
	slices.Sort(members)
	want := []string{
		"RunnerGroup|portus-labs|1 -> Runner|org|portus-labs|2",
		"RunnerGroup|portus-labs|3 -> Runner|org|portus-labs|7",
	}
	if !slices.Equal(members, want) {
		t.Errorf("group membership = %v, want %v", members, want)
	}
}

func runsOnCorpus(t *testing.T, jobFields map[string]any) *edgeSet {
	t.Helper()
	job := map[string]any{
		"_id": "portus-cli__ci__build", "repo": "portus-cli",
		"workflow_filename": "ci.yml", "job_id": "build",
	}
	for k, v := range jobFields {
		job[k] = v
	}
	return build(t, map[string]any{
		"org/portus-labs.json":  orgFixture(),
		"repos/portus-cli.json": map[string]any{"_id": "portus-cli", "repo": "portus-cli", "visibility": "private"},
		"runner-groups/1.json": map[string]any{"_id": "1", "group_id": 1, "org": "portus-labs",
			"name": "Default", "visibility": "all", "member_runner_ids": []any{2}, "selected_repositories": []any{}},
		"runners/portus-labs__2.json": map[string]any{"_id": "portus-labs__2", "runner_id": 2,
			"scope": "org", "scope_key": "portus-labs", "name": "vm-trajan-devops",
			"labels": []any{"self-hosted", "Linux", "X64"}},
		"jobs/portus-cli__ci__build.json": job,
	})
}

// A runner runs a job only when it carries every label the job asked for.
// Matching on any label instead would put a Linux job on an arm64 machine, and
// the count of jobs that could not be placed has to stay honest either way.
func TestRunsOnRequiresTheRunnerToCarryEveryRequestedLabel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		labels    []any
		wantEdges int
		wantMiss  int
	}{
		{"exact subset", []any{"self-hosted", "Linux"}, 1, 0},
		{"case insensitive", []any{"SELF-HOSTED", "linux"}, 1, 0},
		{"label the runner lacks", []any{"self-hosted", "arm64"}, 0, 1},
		{"unevaluated label", []any{"${{ inputs.runner-label }}"}, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := runsOnCorpus(t, map[string]any{
				"self_hosted": true, "runs_on": tc.labels, "runner_labels": tc.labels,
			})
			got := edgesOfType(s, RunsOn)
			if len(got) != tc.wantEdges {
				t.Errorf("RUNS_ON edges = %d, want %d (%v)", len(got), tc.wantEdges, got)
			}
			if miss := s.unbuilt[edgeKey(RunsOn, Job, Runner)]; miss != tc.wantMiss {
				t.Errorf("unbuilt RUNS_ON{Job,Runner} = %d, want %d", miss, tc.wantMiss)
			}
		})
	}
}

// A GitHub-hosted job names "ubuntu-latest" and must not be placed on a
// self-hosted machine, nor counted as a job that could not be placed.
func TestRunsOnIgnoresGitHubHostedJobs(t *testing.T) {
	s := runsOnCorpus(t, map[string]any{
		"self_hosted": false, "runs_on": []any{"ubuntu-latest"}, "runner_labels": []any{"ubuntu-latest"},
	})
	if got := edgesOfType(s, RunsOn); len(got) != 0 {
		t.Errorf("RUNS_ON edges = %v, want none for a GitHub-hosted job", got)
	}
	if miss := s.unbuilt[edgeKey(RunsOn, Job, Runner)]; miss != 0 {
		t.Errorf("unbuilt RUNS_ON{Job,Runner} = %d, want 0: no runner was ever asked for", miss)
	}
}

// The runner listing returns runner_group_id: null, so group membership is only
// knowable from the groups' member_runner_ids. Reading the null field instead
// leaves every org runner ungated: a job pinned to one group lands on another
// group's machine, and a group scoped away from the repo still serves it.
func TestRunsOnHonorsGroupMembership(t *testing.T) {
	corpus := func(t *testing.T, group map[string]any, job map[string]any) *edgeSet {
		t.Helper()
		base := map[string]any{"_id": "portus-cli__ci__build", "repo": "portus-cli",
			"workflow_filename": "ci.yml", "job_id": "build",
			"self_hosted": true, "runner_labels": []any{"self-hosted"}}
		for k, v := range job {
			base[k] = v
		}
		return build(t, map[string]any{
			"org/portus-labs.json":  orgFixture(),
			"repos/portus-cli.json": map[string]any{"_id": "portus-cli", "repo": "portus-cli", "visibility": "private"},
			"repos/payments-api.json": map[string]any{"_id": "payments-api", "repo": "payments-api",
				"visibility": "private"},
			"runner-groups/1.json": group,
			"runners/portus-labs__9.json": map[string]any{"_id": "portus-labs__9", "runner_id": 9,
				"scope": "org", "scope_key": "portus-labs", "name": "vm-other",
				"labels": []any{"self-hosted"}},
			"jobs/portus-cli__ci__build.json": base,
		})
	}

	t.Run("a group scoped away from the repo does not serve it", func(t *testing.T) {
		s := corpus(t, map[string]any{"_id": "1", "group_id": 1, "org": "portus-labs",
			"name": "Locked", "visibility": "selected", "member_runner_ids": []any{9},
			"selected_repositories": []any{"payments-api"}}, nil)
		if got := edgesOfType(s, RunsOn); len(got) != 0 {
			t.Errorf("RUNS_ON = %v, want none: runner 9's group serves payments-api only", got)
		}
	})

	t.Run("a job pinned to one group does not reach another group's runner", func(t *testing.T) {
		s := corpus(t, map[string]any{"_id": "1", "group_id": 1, "org": "portus-labs",
			"name": "Dev", "visibility": "all", "member_runner_ids": []any{9},
			"selected_repositories": []any{}}, map[string]any{"runner_group": "Prod"})
		for _, e := range edgesOfType(s, RunsOn) {
			if e.ToLabel == Runner {
				t.Errorf("RUNS_ON -> %s, want no Runner edge: the job pinned group Prod, runner 9 is in Dev", e.To)
			}
		}
	})
}
