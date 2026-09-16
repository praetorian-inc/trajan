package ado

import (
	"fmt"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// ADO's friendly policy-type names, which is what the normalized records carry.
const (
	minReviewersType    = "Minimum number of reviewers"
	buildValidationType = "Build"
)

// Action names from the Git Repositories security namespace.
const (
	actContribute       = "GenericContribute"
	actEditPolicies     = "EditPolicies"
	actBypassPush       = "PolicyExempt"            // Bypass policies when pushing
	actBypassPRComplete = "PullRequestBypassPolicy" // Bypass policies when completing PRs
)

// CAN_PUSH_TO is unreviewed write, CAN_MERGE_VIA_PR its gated complement, and
// CAN_BYPASS an explicit Git-namespace bypass grant. These are added alongside the
// HAS_POLICY/BranchPolicy premises they are derived from, never in place of them.
func deriveBranchAccessEdges(prior engine.PriorPhase, cp engine.CurrentPhase, timer *engine.PhaseTimer) error {
	branches, err := loadRecords(prior, "10-normalize/branches")
	if err != nil {
		return fmt.Errorf("correlate: load branches: %w", err)
	}
	policies, err := loadRecords(prior, "10-normalize/policies")
	if err != nil {
		return fmt.Errorf("correlate: load policies: %w", err)
	}
	polByConfig := map[int64]map[string]any{}
	for _, p := range policies {
		polByConfig[mInt64(p, "config_id")] = p
	}
	hasPolicy, err := loadRecords(prior, "10-normalize/edges/has-policy")
	if err != nil {
		return fmt.Errorf("correlate: load has-policy: %w", err)
	}
	policiesByBranch := map[string][]map[string]any{}
	for _, e := range hasPolicy {
		policiesByBranch[mStr(e, "branch_id")] = append(policiesByBranch[mStr(e, "branch_id")], e)
	}
	repoGrants, err := loadRepoGrants(prior)
	if err != nil {
		return fmt.Errorf("correlate: load has-role: %w", err)
	}
	repos, err := loadRecords(prior, "10-normalize/repos")
	if err != nil {
		return fmt.Errorf("correlate: load repos: %w", err)
	}
	repoIDByName := map[string]string{} // "project/repo" -> repo node _id
	for _, r := range repos {
		repoIDByName[mStr(r, "project")+"/"+mStr(r, "name")] = mStr(r, "_id")
	}

	for _, b := range branches {
		branchID := mStr(b, "_id")
		// branch.repo_id is the repo GUID; HAS_ROLE resource_id is the repo node _id
		// ("org/project/repo"), so resolve via the name index to join the two.
		repoID := repoIDByName[mStr(b, "project")+"/"+mStr(b, "repo")]
		gov := governingPolicies(policiesByBranch[branchID], polByConfig)
		branchVia := branchWeaknesses(gov)
		contributors := repoGrants.with(repoID, actContribute)

		for _, g := range contributors {
			via := append([]string{}, branchVia...)
			if repoGrants.grantHas(g, repoID, actBypassPush) {
				via = append(via, "bypass_policies")
			}
			if repoGrants.grantHas(g, repoID, actEditPolicies) {
				via = append(via, "edit_policies")
			}
			if len(via) > 0 {
				if err := emitBranchEdge(cp, timer, "can-push-to", "CAN_PUSH_TO", b, g, via, gov); err != nil {
					return err
				}
			}
			// A blocking review policy exists, so the same contributor can still land code
			// through a PR — trivially where self-approval counts.
			if gov.blockingMinReviewers != nil {
				mergeVia := []string{"reviewed_pr"}
				if entBool(mMap(gov.blockingMinReviewers, "settings")["creator_vote_counts"]) {
					mergeVia = []string{"self_approve"}
				}
				if err := emitBranchEdge(cp, timer, "can-merge-via-pr", "CAN_MERGE_VIA_PR", b, g, mergeVia, gov); err != nil {
					return err
				}
			}
		}
	}

	return deriveCanBypass(cp, timer, hasPolicy, polByConfig, repoIDByName, repoGrants)
}

type govPolicies struct {
	blockingMinReviewers map[string]any
	buildValidations     []map[string]any
	anyBlocking          bool
}

func governingPolicies(edges []map[string]any, polByConfig map[int64]map[string]any) govPolicies {
	var g govPolicies
	for _, e := range edges {
		if !mBool(e, "is_enabled") {
			continue
		}
		pol := polByConfig[mInt64(e, "config_id")]
		switch mStr(e, "policy_type") {
		case minReviewersType:
			if mBool(e, "is_blocking") {
				g.anyBlocking = true
				if g.blockingMinReviewers == nil {
					g.blockingMinReviewers = pol
				}
			}
		case buildValidationType:
			g.buildValidations = append(g.buildValidations, e)
			if mBool(e, "is_blocking") {
				g.anyBlocking = true
			}
		default:
			if mBool(e, "is_blocking") {
				g.anyBlocking = true
			}
		}
	}
	return g
}

// The via variants that hold for the branch itself, independent of any principal:
// the ways an unreviewed push lands despite the policies.
func branchWeaknesses(g govPolicies) []string {
	var via []string
	if !g.anyBlocking {
		return []string{"no_policy"}
	}
	if mr := g.blockingMinReviewers; mr != nil {
		s := mMap(mr, "settings")
		if mInt64(s, "minimum_approver_count") == 0 {
			via = append(via, "weak_review")
		}
		if entBool(s["creator_vote_counts"]) {
			via = append(via, "self_approve")
		}
		if !entBool(s["reset_on_source_push"]) {
			via = append(via, "stale_approval")
		}
	}
	for _, bv := range g.buildValidations {
		if !mBool(bv, "is_blocking") || !mBool(bv, "is_enabled") {
			via = append(via, "optional_build_validation")
			break
		}
	}
	return via
}

func emitBranchEdge(cp engine.CurrentPhase, timer *engine.PhaseTimer, kind, edgeKind string, b, grant map[string]any, via []string, gov govPolicies) error {
	desc := mStr(grant, "descriptor")
	rec := map[string]any{
		"kind": edgeKind, "project": mStr(b, "project"), "repo": mStr(b, "repo"),
		"branch": mStr(b, "name"), "branch_id": mStr(b, "_id"),
		"principal": desc, "members": listOrEmpty(grant, "members"),
		"via": via[0], "all_via": toAnyStrings(via),
		"has_blocking_policy": gov.anyBlocking, "target": mStr(b, "_id"),
	}
	return emitEdge(cp, timer, kind, hashKey(edgeKind, desc, mStr(b, "_id")), rec)
}

// One edge per (bypass-holding principal, governed BranchPolicy): the per-policy
// fan-out is intentional, not a missing dedup.
func deriveCanBypass(cp engine.CurrentPhase, timer *engine.PhaseTimer, hasPolicy []map[string]any, polByConfig map[int64]map[string]any, repoIDByName map[string]string, repoGrants repoGrantIndex) error {
	seen := map[string]bool{}
	for _, e := range hasPolicy {
		repoID := repoIDByName[mStr(e, "project")+"/"+mStr(e, "repo")]
		if repoID == "" {
			continue
		}
		pol := polByConfig[mInt64(e, "config_id")]
		polID := mStr(pol, "_id")
		if polID == "" {
			continue
		}
		for _, mode := range []struct{ action, name string }{
			{actBypassPush, "push"}, {actBypassPRComplete, "pull_request"},
		} {
			for _, g := range repoGrants.with(repoID, mode.action) {
				desc := mStr(g, "descriptor")
				key := hashKey(desc, polID, mode.name)
				if seen[key] {
					continue
				}
				seen[key] = true
				rec := map[string]any{
					"kind": "CAN_BYPASS", "project": mStr(e, "project"), "repo": mStr(e, "repo"),
					"principal": desc, "members": listOrEmpty(g, "members"),
					"branch_policy_id": polID, "config_id": mInt64(e, "config_id"),
					"policy_type": mStr(e, "policy_type"), "bypass_mode": mode.name, "target": polID,
				}
				if err := emitEdge(cp, timer, "can-bypass", key, rec); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type repoGrantIndex struct {
	byRepoAction map[string]map[string][]map[string]any
}

func loadRepoGrants(prior engine.PriorPhase) (repoGrantIndex, error) {
	idx := repoGrantIndex{byRepoAction: map[string]map[string][]map[string]any{}}
	roles, err := loadRecords(prior, "10-normalize/edges/has-role")
	if err != nil {
		return idx, err
	}
	for _, role := range roles {
		if mStr(role, "namespace") != gitNS || mStr(role, "resource_kind") != "Repository" {
			continue
		}
		repoID := mStr(role, "resource_id")
		grant := map[string]any{"descriptor": mStr(role, "graph_descriptor"), "members": listOrEmpty(role, "expanded_members")}
		if grant["descriptor"] == "" {
			continue
		}
		if idx.byRepoAction[repoID] == nil {
			idx.byRepoAction[repoID] = map[string][]map[string]any{}
		}
		for _, a := range mList(role, "allowed_actions") {
			if action, _ := a.(string); action != "" {
				idx.byRepoAction[repoID][action] = append(idx.byRepoAction[repoID][action], grant)
			}
		}
	}
	return idx, nil
}

func (r repoGrantIndex) with(repoID, action string) []map[string]any {
	return r.byRepoAction[repoID][action]
}

func (r repoGrantIndex) grantHas(grant map[string]any, repoID, action string) bool {
	desc := mStr(grant, "descriptor")
	for _, g := range r.byRepoAction[repoID][action] {
		if mStr(g, "descriptor") == desc {
			return true
		}
	}
	return false
}

func toAnyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
