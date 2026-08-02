package graph

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/finding"
)

const (
	scanDir  = "20-scan"
	graphDir = "30-graph"
)

// Build reads 10-normalize and 20-scan and writes 30-graph/{nodes,edges,_summary}.json.
// targets maps a rule id to its graph target; the caller supplies it because
// internal/github imports internal/graph and the dependency cannot be reversed.
func Build(ctx context.Context, cfg *engine.Config, runDir string, targets map[string]Target) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	timer := engine.StartPhaseTimer(engine.PhaseGraph, "graph")
	buildErr := runBuild(ctx, cfg, runDir, targets, timer)

	state.RecordPhase(timer.Stop(buildErr))
	if err := state.Save(runDir); err != nil {
		return err
	}
	return buildErr
}

type nodesFile struct {
	Nodes []node `json:"nodes"`
}

type edgesFile struct {
	Edges []edge `json:"edges"`
}

func runBuild(ctx context.Context, cfg *engine.Config, runDir string, targets map[string]Target, timer *engine.PhaseTimer) error {
	if err := os.RemoveAll(filepath.Join(runDir, graphDir)); err != nil {
		return fmt.Errorf("clear %s: %w", graphDir, err)
	}
	onError := func(e error) { timer.Errors = append(timer.Errors, e.Error()) }

	c, err := loadCorpus(ctx, cfg, runDir, onError)
	if err != nil {
		return err
	}
	timer.InputFiles = c.files

	nodes, err := buildNodes(ctx, c)
	if err != nil {
		return err
	}
	edges, err := buildEdges(ctx, c, nodes)
	if err != nil {
		return err
	}
	observed := backfillObserved(nodes, edges)

	findings, err := loadFindings(ctx, cfg, runDir, onError)
	if err != nil {
		return err
	}
	att := newAttacher(c, nodes, edges, targets)
	if err := att.run(ctx, findings); err != nil {
		return err
	}

	dropped := dropDangling(nodes, edges)
	all := nodes.all()
	for i := range all {
		all[i].Findings = finalizeFindings(all[i].Findings, all[i].Properties)
	}
	edgeList := edges.all()
	for i := range edgeList {
		edgeList[i].Findings = finalizeFindings(edgeList[i].Findings, edgeList[i].Properties)
	}

	sum := summarize(runDir, all, edgeList, edges, nodes, observed, dropped, &att.res)
	cp := engine.CurrentPhase{RunDir: runDir}
	for _, w := range []struct {
		rel string
		v   any
	}{
		{engine.GraphNodes(), nodesFile{all}},
		{engine.GraphEdges(), edgesFile{edgeList}},
		{engine.GraphSummary(), sum},
	} {
		if err := cp.Write(w.rel, w.v); err != nil {
			return fmt.Errorf("write %s: %w", w.rel, err)
		}
	}
	timer.OutputFiles = 3
	slog.Info("graph built", "nodes", len(all), "edges", len(edgeList),
		"findings_attached", att.res.attached, "findings_unattached", len(att.res.unattached))
	return nil
}

func loadFindings(ctx context.Context, cfg *engine.Config, runDir string, onError func(error)) ([]finding.Finding, error) {
	files, err := engine.PriorPhase{RunDir: runDir}.IterJSON(scanDir)
	if err != nil {
		return nil, err
	}
	out := engine.RunPartial(ctx, cfg.Concurrency, files,
		func(_ context.Context, f engine.PhaseFile) (finding.Finding, error) {
			var v finding.Finding
			if err := json.Unmarshal(f.Data, &v); err != nil {
				return v, fmt.Errorf("%s/%s: %w", scanDir, f.Rel, err)
			}
			return v, nil
		},
		func(_ engine.PhaseFile, err error) { onError(err) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b finding.Finding) int {
		return cmp.Or(cmp.Compare(ruleID(&a), ruleID(&b)), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	return out, nil
}

// An edge endpoint whose full identity tuple is known but which has no backing
// record is a real entity outside the collection, not a placeholder: the two
// reusable-workflow callees in uncollected repos and the environments named only
// by a deployment. Emitting it keeps the relation truthful; inventing an
// identity value would not, which is why upsert still refuses those.
func backfillObserved(n *nodeSet, s *edgeSet) int {
	minted := 0
	for _, id := range slices.Sorted(maps.Keys(s.byID)) {
		e := s.byID[id]
		for _, ep := range [2]struct {
			id    string
			label NodeLabel
		}{{e.From, e.FromLabel}, {e.To, e.ToLabel}} {
			if n.has(ep.id) {
				continue
			}
			label, key, ok := parseNodeID(ep.id)
			if !ok || label != ep.label {
				continue
			}
			props := map[string]any{"observed_only": true}
			if src, isArray := e.Properties["_source"].([]any); isArray {
				props["_source"] = src
			}
			if n.upsert(label, key, props, "") != nil {
				minted++
			}
		}
	}
	return minted
}

// parseNodeID inverts nodeID. esc is injective and leaves no unescaped '|', so
// splitting on unescaped '|' recovers the identity tuple exactly.
func parseNodeID(id string) (NodeLabel, map[string]string, bool) {
	parts := []string{}
	var b strings.Builder
	escaped := false
	for _, r := range id {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '|':
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	parts = append(parts, b.String())

	label := NodeLabel(parts[0])
	want := IdentityKey(label)
	if len(want) == 0 || len(parts)-1 != len(want) {
		return "", nil, false
	}
	key := make(map[string]string, len(want))
	for i, k := range want {
		key[k] = parts[i+1]
	}
	return label, key, true
}

// Zero on a correct build: backfillObserved has already emitted every endpoint
// whose identity is complete, so a survivor here is a builder bug.
func dropDangling(n *nodeSet, s *edgeSet) map[EdgeType]int {
	out := map[EdgeType]int{}
	for id, e := range s.byID {
		if !n.has(e.From) || !n.has(e.To) {
			out[e.Type]++
			delete(s.byID, id)
		}
	}
	return out
}

func finalizeFindings(fs []findingRef, props map[string]any) []findingRef {
	slices.SortFunc(fs, func(a, b findingRef) int {
		return cmp.Or(
			cmp.Compare(finding.SeverityRank(b.Severity), finding.SeverityRank(a.Severity)),
			cmp.Compare(finding.ConfidenceRank(b.Confidence), finding.ConfidenceRank(a.Confidence)),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	props["findings_count"] = len(fs)
	buckets := map[string][]string{}
	for _, f := range fs {
		if b := SeverityBucket(f.Severity); b != "" {
			buckets[b] = append(buckets[b], f.RuleID)
		}
	}
	for _, b := range FindingBuckets() {
		ids := buckets[b]
		if len(ids) == 0 {
			continue
		}
		slices.Sort(ids)
		props[b] = slices.Compact(ids)
	}
	return fs
}

type countByType struct {
	Total  int              `json:"total"`
	ByType map[EdgeType]int `json:"by_type"`
}

func counted(m map[EdgeType]int) countByType {
	total := 0
	for _, n := range m {
		total += n
	}
	return countByType{total, m}
}

type nodesSummary struct {
	Total                int                `json:"total"`
	ByLabel              map[NodeLabel]int  `json:"by_label"`
	Synthetic            int                `json:"synthetic"`
	ObservedOnly         int                `json:"observed_only"`
	IncompleteIdentities map[NodeLabel]int  `json:"incomplete_identities"`
	IdentityMerges       []identityMerge    `json:"identity_merges"`
	PropertyConflicts    []propertyConflict `json:"property_conflicts"`
}

type edgesSummary struct {
	Total           int              `json:"total"`
	ByType          map[EdgeType]int `json:"by_type"`
	Unbuilt         countByType      `json:"unbuilt"`
	DroppedDangling countByType      `json:"dropped_dangling"`
}

type findingsSummary struct {
	Total              int                 `json:"total"`
	Attached           int                 `json:"attached"`
	Unattached         int                 `json:"unattached"`
	AttachedTo         map[string]int      `json:"attached_to"`
	UnattachedByReason map[string]int      `json:"unattached_by_reason"`
	UnattachedByRule   map[string]int      `json:"unattached_by_rule"`
	UnattachedDetail   []unattachedFinding `json:"unattached_detail"`
}

type gapsSummary struct {
	EmptyLabels    []NodeLabel `json:"empty_labels"`
	EmptyEdgeTypes []EdgeType  `json:"empty_edge_types"`
	Register       []gapEntry  `json:"register"`
}

type summary struct {
	RunID       string          `json:"run_id"`
	GeneratedAt string          `json:"generated_at"`
	Nodes       nodesSummary    `json:"nodes"`
	Edges       edgesSummary    `json:"edges"`
	Findings    findingsSummary `json:"findings"`
	Gaps        gapsSummary     `json:"gaps"`
}

const conflictsReported = 20

func summarize(runDir string, all []node, edgeList []edge, edges *edgeSet, nodes *nodeSet,
	observed int, dropped map[EdgeType]int, res *attachResult) summary {

	byLabel := nodes.byLabel()
	byType := edges.byType()
	synthetic := 0
	for _, n := range all {
		if truthy(n.Properties["synthetic"]) {
			synthetic++
		}
	}
	conflicts := nodes.propertyConflicts()

	empties := []NodeLabel{}
	for _, l := range NodeLabels() {
		if byLabel[l] == 0 {
			empties = append(empties, l)
		}
	}
	emptyEdges := []EdgeType{}
	for _, t := range EdgeTypes() {
		if byType[t] == 0 {
			emptyEdges = append(emptyEdges, t)
		}
	}

	return summary{
		RunID:       filepath.Base(runDir),
		GeneratedAt: engine.IsoformatUTC(time.Now()),
		Nodes: nodesSummary{
			Total:                len(all),
			ByLabel:              byLabel,
			Synthetic:            synthetic,
			ObservedOnly:         observed,
			IncompleteIdentities: nodes.incompleteIdentities(),
			IdentityMerges:       nodes.merges(),
			PropertyConflicts:    conflicts[:min(conflictsReported, len(conflicts))],
		},
		Edges: edgesSummary{
			Total:           len(edgeList),
			ByType:          byType,
			Unbuilt:         counted(edges.unbuilt),
			DroppedDangling: counted(dropped),
		},
		Findings: findingsSummary{
			Total:              res.total,
			Attached:           res.attached,
			Unattached:         len(res.unattached),
			AttachedTo:         map[string]int{"nodes": res.toNodes, "edges": res.toEdges},
			UnattachedByReason: res.byReason,
			UnattachedByRule:   res.byRule,
			UnattachedDetail:   res.unattached,
		},
		Gaps: gapsSummary{
			EmptyLabels:    empties,
			EmptyEdgeTypes: emptyEdges,
			Register:       registerWithCounts(res.byTarget),
		},
	}
}

// gapEntry is a curated finding of the collect/normalize audit. targets names the
// rule targets whose unattached findings the gap explains, so findings_blocked is
// computed from the run and cannot drift from it.
type gapEntry struct {
	Subject         string   `json:"subject"`
	Kind            string   `json:"kind"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
	UpstreamFix     string   `json:"upstream_fix"`
	FindingsBlocked int      `json:"findings_blocked"`
	targets         []string `json:"-"`
}

func registerWithCounts(byTarget map[string]int) []gapEntry {
	out := slices.Clone(gapRegister)
	for i := range out {
		for _, t := range out[i].targets {
			out[i].FindingsBlocked += byTarget[t]
		}
	}
	return out
}

var gapRegister = []gapEntry{{
	Subject:     "Tag",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "no tag instances exist anywhere in 10-normalize; collect fetches no /tags or /git/matching-refs/tags surface. Ruleset target:\"tag\" yields refs/tags/v* patterns, and a glob is not an identity.",
	UpstreamFix: "collect repository tags, then normalize them as tag records so PROTECTED_BY{Tag,Ruleset} and DEPLOYABLE_FROM{Environment,Tag} can be built.",
}, {
	Subject:     "Runner",
	Kind:        "node",
	Status:      "empty",
	Reason:      "zero runners are registered in the org: every 00-collect/runners/*.json returned HTTP 200 with an empty runners array, and runner-groups/1.json has member_runner_ids []. A job carries runs_on labels, and a label is not an identity.",
	UpstreamFix: "firing range: register self-hosted runners. No code change needed — /orgs/{org}/actions/runners and /repos/{o}/{r}/actions/runners are already collected.",
	targets:     []string{"edge(RUNS_ON, Job, Runner)"},
}, {
	Subject:     "CloudRole",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "the job record has no cloud-role field; oidc_sub_template is GitHub's subject template, not a role. The literal ARNs live only in jobs[].steps[].with[\"role-to-assume\"], which the Neo4j-legal property filter excludes, and reaching into it would reimplement classify_sink.go's cloud-login vocabulary in the graph layer. Roughly 40% of the blocked findings name no role at all.",
	UpstreamFix: "internal/github/normalize_entities.go: emit cloud_roles: [{provider, identifier}] as a first-class field on the job record.",
	targets:     []string{"edge(CAN_ASSUME, Job, CloudRole)"},
}, {
	Subject:     "ExternalActor",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "identityKeys[ExternalActor] = {kind} names a vocabulary no API returns and nothing in collect or normalize supplies. The builder mints the singleton {kind:\"external\"} and puts the victim job's trigger classes on the attack edge instead, because 14 victim jobs have an empty low_trust list and a per-trigger-class actor would leave them sourceless.",
	UpstreamFix: "normalize could emit a first-class external-actor record per low-trust trigger class; until then the singleton is the least-wrong option and the kind vocabulary stays a builder invention.",
	targets:     []string{"attack(PWN_REQUEST)", "attack(EXPRESSION_INJECTION)", "attack(AGENT_INJECTION)"},
}, {
	Subject:     "RepositoryRole / OrganizationAdmin",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "both are real ruleset bypass actor types present in the data and neither has a NodeLabel, so their CAN_BYPASS grants cannot be represented at all.",
	UpstreamFix: "add the labels to schema.go, or give CAN_BYPASS a generic actor endpoint.",
}, {
	Subject:     "CAN_BYPASS{DeployKey,Ruleset}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "a deploy key appears as a ruleset bypass actor in the corpus, but edgeEndpoints[CAN_BYPASS] allows only User/Team/App, so the relation is rejected as an illegal pair and counted unbuilt.",
	UpstreamFix: "add {DeployKey, Ruleset} to edgeEndpoints[CAN_BYPASS] in schema.go.",
}, {
	Subject:     "CAN_BYPASS{App,Ruleset}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "cat-11/ruleset-app-in-bypass-actors matches bypass.any_bypass_present == true — any actor type — while declaring an App endpoint. Only the Integration actors resolve (actor_id -> apps[].app_id -> app_slug); Team, RepositoryRole, OrganizationAdmin and DeployKey actors do not.",
	UpstreamFix: "the rule, not the data: add an actor-type predicate, or retarget it to node(Ruleset).",
	targets:     []string{"edge(CAN_BYPASS, App, Ruleset)"},
}, {
	Subject:     "MINTS_TOKEN_AS{Job,App}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "every item in chains/app-mintable.json mints has app: null and app_id_resolved: false because app_id_literal is always an unevaluated ${{ secrets.*_APP_ID }}. The app_id -> app_slug lookup that rescues CAN_BYPASS is unavailable because the literal is a secret reference.",
	UpstreamFix: "unrecoverable from configuration alone; resolving it needs the secret value or an installation-level mapping from collect.",
	targets:     []string{"edge(MINTS_TOKEN_AS, Job, App)"},
}, {
	Subject:     "CAN_APPROVE{Job,Repository}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "cat-03/write-collab-self-pr-approve declares the edge but its where clause tests only the job-side pull-requests: write — its own description says the repo can_approve_pull_request_reviews condition was left out of the port. The edge is built only where that repo setting is on, so the rule fires on jobs in repos that cannot approve.",
	UpstreamFix: "the rule, not the data: add can_approve_pull_request_reviews to the rule now that the repo record carries it.",
	targets:     []string{"edge(CAN_APPROVE, Job, Repository)"},
}, {
	Subject:     "READS{Job,Secret} for unscoped references",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "a secret reference whose scope and scope_key are null cannot name a Secret node. Most are GITHUB_TOKEN, which is the ephemeral job token and has no node by design, but the rest are real secret names the normalizer could not attribute to a repo or environment.",
	UpstreamFix: "internal/github/normalize_entities.go: resolve a bare ${{ secrets.NAME }} against the repo and environment secret inventories already collected, and model GITHUB_TOKEN explicitly rather than as an unscoped secret.",
	targets:     []string{"edge(READS, Job, Secret)"},
}, {
	Subject:     "REQUIRES_REVIEW_BY{Environment,User}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "no environment record carries reviewer identities: reviewers_required is [] across all environments and protection_rules_raw holds only branch_policy entries. The fr-12-02 \"bot as required reviewer\" scenario has protection_rules: [] in the raw API response, so the gap starts in the firing range.",
	UpstreamFix: "firing range: configure required reviewers on fr-12-02. Then normalize must keep the reviewer identities rather than only reviewers_count.",
	targets:     []string{"edge(REQUIRES_REVIEW_BY, Environment, User)"},
}, {
	Subject:     "RUNS_ON{Job,Runner|RunnerGroup}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "self-hosted jobs and one job naming runner_group \"prod-builders\" assert the relation, but no Runner node exists and the named group has no runner-groups/ record. A placeholder would make every self-hosted job appear to share one machine, which is the exact claim the cat-07 rules exist to test.",
	UpstreamFix: "see the Runner row; additionally collect the runner groups referenced by workflows, not only those the org API lists.",
	targets:     []string{"edge(RUNS_ON, Job, Runner)"},
}, {
	Subject:     "TARGETS{Job,Environment}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "a deployment whose env_name is an unevaluated expression (${{ inputs.target }}, ${{ github.event.client_payload.environment }}) names no environment: the target is chosen at run time, so no identity exists to point at. Deployments naming an environment with no record are emitted against an observed_only node instead.",
	UpstreamFix: "unrecoverable from configuration alone; it needs deployment history to see which environments the expression actually resolved to.",
	targets:     []string{"edge(TARGETS, Job, Environment)"},
}, {
	Subject:     "DEPLOYABLE_FROM{Environment,Branch|Tag}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "deployment_branch_policy.patterns are globs, and a glob is not a ref identity. A pattern only yields an edge when it names a Branch node that already exists; the \"v*\" tag glob has no Tag nodes to expand against.",
	UpstreamFix: "collect tags (see the Tag row); expanding branch globs is already possible and only the tag side is blocked.",
}, {
	Subject:     "PUSHES_TO{Job,Branch|Repository}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "no producer: normalize records no job-writes-to-ref relation, and no rule targets the edge.",
	UpstreamFix: "classify push sinks during normalize (a git push step, or contents: write plus a checked-out ref) if the edge is wanted.",
}, {
	Subject:     "TRIGGERED_BY{Workflow,ExternalActor|User}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "no producer: the workflow trigger surface is normalized onto the job record as trigger_class_summary, never as a relation to an actor node, and no rule targets the edge.",
	UpstreamFix: "derive it from the same trigger classification the attack edges use, if a workflow-level actor edge is wanted.",
}, {
	Subject:     "CAN_ACCESS{App,Repository}",
	Kind:        "edge",
	Status:      "not_collected",
	Reason:      "the installation repository list is never fetched, so an app's repository scope is unknown and its blast radius cannot be drawn.",
	UpstreamFix: "collect /orgs/{org}/installations/{id}/repositories (or the installation's repository_selection plus selected repositories) and normalize it onto the app record.",
}, {
	Subject:     "HAS_ACCESS{Team,Repository}",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "collect stores permission from an endpoint that returns permissions + role_name, so every team grant normalizes to permission: null and can_push: false. The edges exist but assert nothing, and the same defect zeroes CAN_LAND_CODE{Team,Branch}.",
	UpstreamFix: "internal/github/collect_surfaces.go: read role_name (or the permissions map) for team repository grants instead of the absent permission field.",
}, {
	Subject:     "identityKeys[Secret]",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "{scope, name} keys a secret on the scope KIND, not the scope, so every repository's NPM_TOKEN collapses to one node and READS edges converge on it — a fabricated shared-credential path. Fixed here by adding scope_key.",
	UpstreamFix: "fixed in schema.go; internal/github/normalize_secrets.go should still stop skipping org-scope secrets so they carry visibility and selected_repositories.",
}, {
	Subject:     "identityKeys[Job]",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "branch is deliberately excluded, so branch-scoped job records merge onto one job definition. Adding branch would leave Workflow{repo,path} un-branched and make CONTAINS{Workflow,Job} incoherent, so the merged branch set is preserved on properties.branches instead and every finding keeps its branch-qualified subject_id.",
	UpstreamFix: "none wanted at the graph layer; branch-scoping the graph would require branching Workflow identity too.",
}, {
	Subject:     "Cache.key_prefix",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "the two sources disagree: jobs[].cache_reads[]/cache_writes[].scope embeds a differently-derived string (\"scope-prefix:build-tools-v3-pinned-2026-05\") while chains/cache-keyspace.json keys the same cache as \"build/tools\". Cache nodes and their READS/WRITES edges therefore come from cache-keyspace only.",
	UpstreamFix: "emit the bare prefix as its own field on cache_reads/cache_writes rather than embedding a differently-derived string in scope-prefix:.",
}, {
	Subject:     "Organization secrets",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "internal/github/normalize_secrets.go skips org-scope secrets entirely, so 10-normalize/secrets/ holds none. They are recovered here from org.org_actions_secrets[], which closes CONTAINS{Organization,Secret}, the org-scope READS references and the org -> node(Secret) findings, but carries only the name.",
	UpstreamFix: "normalize org-scope secrets as records so they carry visibility and selected_repositories like repo and environment secrets do.",
}}
