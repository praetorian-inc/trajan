package github

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

type RunnerFact struct {
	ID       string `json:"_id"`
	RunnerID int64  `json:"runner_id"`
	Name     any    `json:"name"`

	Scope    string `json:"scope"`
	ScopeKey string `json:"scope_key"`
	Owner    any    `json:"owner"`
	Repo     any    `json:"repo"`

	OS     any `json:"os"`
	Status any `json:"status"`
	Busy   any `json:"busy"`

	// The API omits "ephemeral" on persistently registered runners, so absent is false.
	Ephemeral bool `json:"ephemeral"`

	Labels        []string `json:"labels"`
	RunnerGroupID *int64   `json:"runner_group_id"`

	Provenance []SourceProvenance `json:"_provenance"`
}

type RunnerGroupFact struct {
	ID      string `json:"_id"`
	GroupID int64  `json:"group_id"`
	Org     string `json:"org"`
	Name    any    `json:"name"`

	Default    bool `json:"default"`
	Inherited  bool `json:"inherited"`
	Visibility any  `json:"visibility"`

	AllowsPublicRepositories bool  `json:"allows_public_repositories"`
	RestrictedToWorkflows    bool  `json:"restricted_to_workflows"`
	SelectedWorkflows        []any `json:"selected_workflows"`

	SelectedRepositories []string `json:"selected_repositories"`
	SelectedRepoCount    int      `json:"selected_repo_count"`
	MemberRunnerIDs      []int64  `json:"member_runner_ids"`
	MemberRunnerCount    int      `json:"member_runner_count"`

	Provenance []SourceProvenance `json:"_provenance"`
}

func normalizeRunners(prior engine.PriorPhase, cp engine.CurrentPhase, org string, onError func(error)) error {
	files, err := prior.IterJSON(path.Join("00-collect", "runners"))
	if err != nil {
		return err
	}

	type collectedGroup struct {
		data   map[string]any
		source string
	}
	groups := map[int64]collectedGroup{}

	for _, f := range files {
		scopeKey := strings.TrimSuffix(path.Base(f.Rel), ".json")
		data := entDataOf(f.Data)
		if data == nil {
			return fmt.Errorf("runners: %s has no data object", f.Rel)
		}
		scope := entStr(data["scope"])
		if scope == "" {
			return fmt.Errorf("runners: %s has no scope", f.Rel)
		}
		source := engine.CollectRunners(scopeKey)

		buckets := entObj(data, "_unavailable_buckets")
		for _, bucket := range slices.Sorted(maps.Keys(buckets)) {
			onError(fmt.Errorf("runners: %s %s unavailable (HTTP %d), inventory incomplete",
				scopeKey, bucket, entInt(buckets[bucket])))
		}
		if entTruthy(data["_unavailable"]) {
			onError(fmt.Errorf("runners: %s runners unavailable (HTTP %d), inventory incomplete",
				scopeKey, entInt(data["_unavailable_status"])))
		}

		for _, r := range entListOf(data, "runners") {
			rm := entMap(r)
			id := entInt64(rm["id"])
			if id == 0 {
				onError(fmt.Errorf("runners: runner without an id in %s", source))
				continue
			}
			var groupID *int64
			if gid := entInt64(rm["runner_group_id"]); gid != 0 {
				groupID = &gid
			}
			rec := RunnerFact{
				ID:       fmt.Sprintf("%s__%d", scopeKey, id),
				RunnerID: id,
				Name:     rm["name"],

				Scope:    scope,
				ScopeKey: scopeKey,
				Owner:    data["owner"],
				Repo:     data["repo"],

				OS:     rm["os"],
				Status: rm["status"],
				Busy:   rm["busy"],

				Ephemeral:     entTruthy(rm["ephemeral"]),
				Labels:        runnerLabelNames(entList(rm["labels"])),
				RunnerGroupID: groupID,

				Provenance: []SourceProvenance{{File: source}},
			}
			if err := cp.Write(engine.NormalizeRunner(scopeKey, id), rec); err != nil {
				return err
			}
		}

		if scope == "org" {
			for _, g := range entListOf(data, "runner_groups") {
				gm := entMap(g)
				if id := entInt64(gm["id"]); id != 0 {
					groups[id] = collectedGroup{gm, source}
				}
			}
		}
	}

	// The per-group files carry the same enriched objects as the org bundle; they win
	// so provenance points at the narrower file when it was collected.
	groupFiles, err := prior.IterJSON(path.Join("00-collect", "runner-groups"))
	if err != nil {
		return err
	}
	for _, f := range groupFiles {
		gm := entDataOf(f.Data)
		if gm == nil {
			return fmt.Errorf("runner-groups: %s has no data object", f.Rel)
		}
		id := entInt64(gm["id"])
		if id == 0 {
			onError(fmt.Errorf("runner-groups: %s has no id", f.Rel))
			continue
		}
		groups[id] = collectedGroup{gm, engine.CollectRunnerGroup(id)}
	}

	for _, id := range slices.Sorted(maps.Keys(groups)) {
		g := groups[id]
		if st := g.data["_repositories_unavailable"]; st != nil {
			onError(fmt.Errorf("runner-groups: %d selected repositories unavailable (HTTP %d), reachability incomplete",
				id, entInt(st)))
		}
		if st := g.data["_member_runners_unavailable"]; st != nil {
			onError(fmt.Errorf("runner-groups: %d member runners unavailable (HTTP %d), membership incomplete",
				id, entInt(st)))
		}

		repos := repoNames(entList(g.data["selected_repositories"]))
		members := runnerGroupMemberIDs(entList(g.data["member_runners"]))

		rec := RunnerGroupFact{
			ID:      strconv.FormatInt(id, 10),
			GroupID: id,
			Org:     org,
			Name:    g.data["name"],

			Default:    entTruthy(g.data["default"]),
			Inherited:  entTruthy(g.data["inherited"]),
			Visibility: g.data["visibility"],

			AllowsPublicRepositories: entTruthy(g.data["allows_public_repositories"]),
			RestrictedToWorkflows:    entTruthy(g.data["restricted_to_workflows"]),
			SelectedWorkflows:        entListOrEmpty(g.data["selected_workflows"]),

			SelectedRepositories: repos,
			SelectedRepoCount:    len(repos),
			MemberRunnerIDs:      members,
			MemberRunnerCount:    len(members),

			Provenance: []SourceProvenance{{File: g.source}},
		}
		if err := cp.Write(engine.NormalizeRunnerGroup(id), rec); err != nil {
			return err
		}
	}
	return nil
}

func runnerLabelNames(labels []any) []string {
	out := []string{}
	for _, l := range labels {
		if name := entStr(entMap(l)["name"]); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func runnerGroupMemberIDs(runners []any) []int64 {
	out := []int64{}
	for _, r := range runners {
		if id := entInt64(entMap(r)["id"]); id != 0 {
			out = append(out, id)
		}
	}
	return out
}
