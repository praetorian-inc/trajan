package graph

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/finding"
	"github.com/praetorian-inc/trajan/internal/ui"
)

const (
	scanDir  = "20-scan"
	graphDir = "30-graph"
)

// targets maps a rule id to its graph target; the caller supplies it because
// internal/github imports internal/graph and the dependency cannot be reversed.
func Build(ctx context.Context, cfg *engine.Config, runDir string, targets map[string]Target) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhaseGraph); err != nil {
		return err
	}
	ui.PhaseHeader("Graph")
	timer := engine.StartPhaseTimer(engine.PhaseGraph, "graph")
	stats, buildErr := runBuild(ctx, cfg, runDir, targets, timer)

	rec := timer.Stop(buildErr)
	state.RecordPhase(rec)
	saveErr := state.Save(runDir)
	if buildErr == nil {
		ui.Outcome("Graph complete", []ui.Count{
			{Label: "nodes", N: stats.nodes},
			{Label: "edges", N: stats.edges},
		}, engine.Elapsed(rec.DurationS))
		if stats.attached > 0 || stats.unattached > 0 {
			ui.Note(fmt.Sprintf("%d findings attached, %d unattached", stats.attached, stats.unattached))
		}
	}
	return errors.Join(buildErr, saveErr)
}

type buildStats struct{ nodes, edges, attached, unattached int }

type nodesFile struct {
	Nodes []node `json:"nodes"`
}

type edgesFile struct {
	Edges []edge `json:"edges"`
}

func runBuild(ctx context.Context, cfg *engine.Config, runDir string, targets map[string]Target, timer *engine.PhaseTimer) (buildStats, error) {
	// RunPartial calls onError from its workers.
	var errMu sync.Mutex
	onError := func(e error) {
		errMu.Lock()
		timer.Errors = append(timer.Errors, e.Error())
		errMu.Unlock()
	}

	c, err := loadCorpus(ctx, cfg, runDir, onError)
	if err != nil {
		return buildStats{}, err
	}
	findings, findingsSeen, err := loadFindings(ctx, cfg, runDir, onError)
	if err != nil {
		return buildStats{}, err
	}
	in := inputsSummary{
		NormalizeSeen:    c.seen,
		NormalizeDropped: c.seen - c.files,
		FindingsSeen:     findingsSeen,
		FindingsDropped:  findingsSeen - len(findings),
	}
	timer.InputFiles = in.NormalizeSeen + in.FindingsSeen
	if in.NormalizeDropped+in.FindingsDropped > 0 {
		slog.Warn("graph built on incomplete input", "normalize_dropped", in.NormalizeDropped,
			"findings_dropped", in.FindingsDropped)
	}

	if err := os.RemoveAll(filepath.Join(runDir, graphDir)); err != nil {
		return buildStats{}, fmt.Errorf("clear %s: %w", graphDir, err)
	}

	nodes, err := buildNodes(ctx, c)
	if err != nil {
		return buildStats{}, err
	}
	edges, err := buildEdges(ctx, c, nodes)
	if err != nil {
		return buildStats{}, err
	}
	observed := backfillObserved(nodes, edges)
	dropped := dropDangling(nodes, edges)

	att := newAttacher(c, nodes, edges, targets)
	if err := att.run(ctx, findings); err != nil {
		return buildStats{}, err
	}

	all := nodes.all()
	for i := range all {
		all[i].Findings = finalizeFindings(all[i].Findings, all[i].Properties)
	}
	edgeList := edges.all()
	for i := range edgeList {
		edgeList[i].Findings = finalizeFindings(edgeList[i].Findings, edgeList[i].Properties)
	}

	sum := summarize(runDir, in, all, edgeList, edges, nodes, observed, dropped, &att.res)
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
			return buildStats{}, fmt.Errorf("write %s: %w", w.rel, err)
		}
	}
	timer.OutputFiles = 3
	return buildStats{
		nodes:      len(all),
		edges:      len(edgeList),
		attached:   att.res.attached,
		unattached: len(att.res.unattached),
	}, nil
}

// An absent 20-scan is a missing input, not an empty one: IterJSON would report
// it as zero findings, which reads as a scan that raised none. A scan that ran
// and found nothing leaves the directory behind and is still accepted.
func loadFindings(ctx context.Context, cfg *engine.Config, runDir string, onError func(error)) ([]finding.Finding, int, error) {
	pp := engine.PriorPhase{RunDir: runDir}
	if _, err := os.Stat(pp.Abs(scanDir)); err != nil {
		return nil, 0, fmt.Errorf("%s unreadable; run `trajan github scan` first: %w", scanDir, err)
	}
	files, err := pp.IterJSON(scanDir)
	if err != nil {
		return nil, 0, err
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
		return nil, 0, err
	}
	slices.SortFunc(out, func(a, b finding.Finding) int {
		return cmp.Or(cmp.Compare(ruleID(&a), ruleID(&b)), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	return out, len(files), nil
}

// An endpoint with a complete identity tuple and no backing record is a real entity
// outside the collection — a callee in an uncollected repo, an environment named only
// by a deployment — so emitting it is truthful where inventing an identity is not.
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
		// findings_<severity> is deduplicated to rule ids, so its length is a
		// rule count and not the number of findings at that severity.
		props["findings_count_"+strings.TrimPrefix(b, "findings_")] = len(ids)
		slices.Sort(ids)
		props[b] = slices.Compact(ids)
	}
	return fs
}

type countByType[K ~string] struct {
	Total  int       `json:"total"`
	ByType map[K]int `json:"by_type"`
}

func counted[K ~string](m map[K]int) countByType[K] {
	total := 0
	for _, n := range m {
		total += n
	}
	return countByType[K]{total, m}
}

type nodesSummary struct {
	Total                int                `json:"total"`
	ByLabel              map[NodeLabel]int  `json:"by_label"`
	Synthetic            int                `json:"synthetic"`
	ObservedOnly         int                `json:"observed_only"`
	IncompleteIdentities map[NodeLabel]int  `json:"incomplete_identities"`
	IdentityMerges       []identityMerge    `json:"identity_merges"`
	PropertyConflicts    []propertyConflict `json:"property_conflicts"`
	DroppedProperties    int                `json:"dropped_properties"`
}

type edgesSummary struct {
	Total             int                   `json:"total"`
	ByType            map[EdgeType]int      `json:"by_type"`
	Unbuilt           countByType[string]   `json:"unbuilt"`
	DroppedDangling   countByType[EdgeType] `json:"dropped_dangling"`
	PropertyConflicts []edgeConflict        `json:"property_conflicts"`
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
	EmptyLabels      []NodeLabel `json:"empty_labels"`
	EmptyEdgeTypes   []EdgeType  `json:"empty_edge_types"`
	EmptyEdgeTriples []string    `json:"empty_edge_triples"`
	Register         []gapEntry  `json:"register"`
}

// A dropped input is a per-item failure the phase continues past, so every count
// downstream of it is a floor rather than a total; seen and dropped are reported
// so a consumer can tell a complete graph from one built on part of its inputs.
type inputsSummary struct {
	NormalizeSeen    int `json:"normalize_seen"`
	NormalizeDropped int `json:"normalize_dropped"`
	FindingsSeen     int `json:"findings_seen"`
	FindingsDropped  int `json:"findings_dropped"`
}

type summary struct {
	RunID       string          `json:"run_id"`
	GeneratedAt string          `json:"generated_at"`
	Inputs      inputsSummary   `json:"inputs"`
	Nodes       nodesSummary    `json:"nodes"`
	Edges       edgesSummary    `json:"edges"`
	Findings    findingsSummary `json:"findings"`
	Gaps        gapsSummary     `json:"gaps"`
}

const conflictsReported = 20

func summarize(runDir string, in inputsSummary, all []node, edgeList []edge, edges *edgeSet, nodes *nodeSet,
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
	edgeConflicts := edges.propertyConflicts()

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
		Inputs:      in,
		Nodes: nodesSummary{
			Total:                len(all),
			ByLabel:              byLabel,
			Synthetic:            synthetic,
			ObservedOnly:         observed,
			IncompleteIdentities: nodes.incompleteIdentities(),
			IdentityMerges:       nodes.merges(),
			PropertyConflicts:    conflicts[:min(conflictsReported, len(conflicts))],
			DroppedProperties:    nodes.dropped,
		},
		Edges: edgesSummary{
			Total:             len(edgeList),
			ByType:            byType,
			Unbuilt:           counted(edges.unbuilt),
			DroppedDangling:   counted(dropped),
			PropertyConflicts: edgeConflicts[:min(conflictsReported, len(edgeConflicts))],
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
			EmptyLabels:      empties,
			EmptyEdgeTypes:   emptyEdges,
			EmptyEdgeTriples: emptyEdgeTriples(edgeList),
			Register:         registerWithCounts(res.byTarget),
		},
	}
}

// Targets names the rule targets whose unattached findings the gap explains, so
// findings_blocked is computed from the run rather than written down. A target belongs
// to exactly one row, or the column stops summing to findings.unattached.
type gapEntry struct {
	Subject         string   `json:"subject"`
	Kind            string   `json:"kind"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
	UpstreamFix     string   `json:"upstream_fix"`
	FindingsBlocked int      `json:"findings_blocked"`
	Targets         []string `json:"targets"`
}

func registerWithCounts(byTarget map[string]int) []gapEntry {
	out := slices.Clone(gapRegister)
	for i := range out {
		for _, t := range out[i].Targets {
			out[i].FindingsBlocked += byTarget[t]
		}
	}
	return out
}

var gapRegister = []gapEntry{{
	Subject:     "Tag",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "no tag instances exist anywhere in 10-normalize; collect fetches no /tags or /git/matching-refs/tags surface. Ruleset target:\"tag\" yields refs/tags/v* patterns, and a glob is not an identity. Three declared relationships wait on it: CONTAINS{Repository,Tag}, PROTECTED_BY{Tag,Ruleset} and DEPLOYABLE_FROM{Environment,Tag}.",
	UpstreamFix: "collect repository tags; then a normalizeTags, which does not exist, to write tag records; then an emitTags node writer, which buildNodes does not have. All three are missing, so collecting alone yields no Tag node.",
}, {
	Subject:     "Runner",
	Kind:        "node",
	Status:      "partial",
	Reason:      "emitRunners now writes a node per 10-normalize/runners record, keyed {scope, scope_key, id} with scope_key qualified to the org or to owner/repo. It is empty only where the org has registered none: every ghektestorg 00-collect/runners/*.json returned HTTP 200 with an empty runners array. A job still carries runs_on labels, and a label is not an identity — see the RUNS_ON row.",
	UpstreamFix: "firing range: register self-hosted runners in ghektestorg so the cat-07 scenarios have a machine to point at.",
}, {
	Subject:     "CAN_ASSUME{Job,CloudRole}",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "extractCloudRoles now keeps the role as written, the way ArtifactRef.Name is kept, and emitCanAssume resolves ${{ inputs.* }} across the reusable-workflow call edge with the same calleeInputs helper artifacts use — so a callee naming ${{ inputs.role-arn }} reaches the literal its caller passed, and a disputed input stays unresolved rather than guessed. What is left unbuilt is ${{ vars.* }}: 7 fr-11-02 jobs name ${{ vars.AWS_PROD_ROLE_ARN }}, which no collected fact resolves, and they now show as 7 unbuilt CAN_ASSUME plus 7 incomplete CloudRole identities instead of as an absent field. The remaining blocked findings sit on jobs that mint an id token and name no role at all, so there is nothing to point at.",
	UpstreamFix: "resolve ${{ vars.* }} against 00-collect/variables/ (values are returned in plaintext) once the firing range defines AWS_PROD_ROLE_ARN. The roleless jobs are a rule-target question, not a data gap.",
	Targets:     []string{"edge(CAN_ASSUME, Job, CloudRole)"},
}, {
	Subject:     "ExternalActor",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "identityKeys[ExternalActor] = {kind} names a vocabulary no API returns and nothing in collect or normalize supplies. The builder mints the singleton {kind:\"external\"} and puts the victim job's low-trust and medium trigger-class lists on the attack edge instead, because 7 victim jobs have an empty low_trust list and a per-trigger-class actor would leave them sourceless.",
	UpstreamFix: "normalize could emit a first-class external-actor record per low-trust trigger class; until then the singleton is the least-wrong option and the kind vocabulary stays a builder invention.",
	Targets:     []string{"attack(PWN_REQUEST)", "attack(EXPRESSION_INJECTION)", "attack(AGENT_INJECTION)"},
}, {
	Subject:     "RepositoryRole / OrganizationAdmin",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "both are real ruleset bypass actor types present in the data and neither has a NodeLabel, so their CAN_BYPASS grants cannot be represented at all.",
	UpstreamFix: "add the labels to schema.go, or give CAN_BYPASS a generic actor endpoint.",
}, {
	Subject:     "CAN_BYPASS{DeployKey,Ruleset}",
	Kind:        "edge",
	Status:      "represented_elsewhere",
	Reason:      "the deploy-key bypass actor carries actor_id: null, so no key identity exists to point at and emitCanBypass's actor switch never builds an endpoint for it — it takes the default arm, which counts one unbuilt (an endpoint pair the schema forbids would abort the phase instead, so this was never an illegal pair). The fact is not lost: deriveCapabilityEdges fans the actor over the repo's push-capable keys, and fr-11-16's two CAN_LAND_CODE{DeployKey,Branch} edges carry circumvents [\"bypass_always\"] while its read-only third key correctly does not. The same default arm also absorbs actor types with no NodeLabel and, latently, a User/Team/Integration whose principal record was never collected: unbuilt CAN_BYPASS is 1 DeployKey + 1 OrganizationAdmin + 3 RepositoryRole.",
	UpstreamFix: "none wanted. Adding {DeployKey, Ruleset} to edgeEndpoints builds nothing without an actor_id, and would restate at ruleset level what the capability model already asserts on CAN_LAND_CODE.",
}, {
	Subject:     "CAN_BYPASS{App,Ruleset}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "cat-11/ruleset-app-in-bypass-actors matches bypass.any_bypass_present == true — any actor type — while declaring an App endpoint. Only the Integration actors resolve (actor_id -> apps[].app_id -> app_slug); Team, RepositoryRole, OrganizationAdmin and DeployKey actors do not.",
	UpstreamFix: "the rule, not the data: add an actor-type predicate, or retarget it to node(Ruleset).",
	Targets:     []string{"edge(CAN_BYPASS, App, Ruleset)"},
}, {
	Subject:     "MINTS_TOKEN_AS{Job,App}",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "emitMintsTokenAs writes the edge wherever chains/app-mintable resolved an App. Two resolution paths exist: an app-id input looked up against apps[].app_id, and a fixed app slug for an action that authenticates as its own published App (anthropics/claude-code-action), looked up against apps[].app_slug. The slug path is gated on that App actually being installed in the org — without the installation the action uses whatever token the workflow handed it, which is not a mint. What stays unbuilt is the app-id path where the id is an expression: ${{ secrets.*_APP_ID }} is permanently unresolvable from configuration alone, ${{ vars.* }} is resolvable but ghektestorg defines no APP_ID variable.",
	UpstreamFix: "firing range: define the APP_ID variables, then resolve ${{ vars.* }} in deriveAppMintable against 00-collect/variables/, which already holds the plaintext values.",
	Targets:     []string{"edge(MINTS_TOKEN_AS, Job, App)"},
}, {
	Subject:     "CAN_APPROVE{Job,Repository}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "the edge carries both halves of the capability — the repo's can_approve_pull_request_reviews and the job token's pull-requests: write — so it exists only where a job actually holds it, not for every job in a can-approve repo. cat-03/write-collab-self-pr-approve tests only the job half, as its own description records, so it also fires in the 12 repos where the setting is off and those findings have no edge to land on.",
	UpstreamFix: "the rule, not the data: add can_approve_pull_request_reviews to the rule now that the repo record carries it. Any rule targeting this edge must keep the pull-requests: write predicate — the edge is gated on it and a wider predicate silently loses its matches.",
	Targets:     []string{"edge(CAN_APPROVE, Job, Repository)"},
}, {
	Subject:     "CAN_LAND_CODE circumvents[approval_count_self_satisfiable] scope",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "set where the PR route is this principal's only way in, the gate still binds them, exactly one approval is demanded, and the repo lets an Actions run cast it. Exactly one because a repository has a single Actions identity and GitHub refuses a self-review, so two required approvals still cost a human. Two things it does not check. It presumes a ref exists outside the ruleset's ref_name scope to push the approving workflow to: deriveBranchCoverage reads conditions.ref_name and discards it, so nothing records that protect-main covers only ~DEFAULT_BRANCH. And the code-owner escape the rule pairs with it is probe-based — codeowners.covers_ci_execution tests five representative locations, and scripts/setup-env.sh, the file the portus-labs path actually turns on, is not one of them. The verdict happens to be right about that file — CODEOWNERS there owns only /.github/workflows/ and /README.md — but the probes are what the finding rests on, and they never touched it. The approval count also folds legacy protection the way single_approval_required does, so \"legacy requires a PR\" can pair with \"a ruleset says one approval\" from different sources.",
	UpstreamFix: "for the ref scope: keep conditions.ref_name on the branch-coverage row, then require an ungated ref; isCatchAll already exists in collect.go. Write an fr-* scenario with a ~ALL ruleset carrying `creation` first, so the term has an oracle. For the code-owner half: collect the repository tree and model CODEOWNERS as OWNS_PATH{User|Team,Repository} carrying the pattern, which is the only shape that answers \"is THIS path owned\".",
}, {
	Subject:     "READS{Job,Secret} for unscoped references",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "a secret reference whose scope and scope_key are null cannot name a Secret node. Most are GITHUB_TOKEN, which is the ephemeral job token and has no node by design, but the rest are real secret names the normalizer could not attribute to a repo or environment.",
	UpstreamFix: "internal/github/normalize_entities.go: resolve a bare ${{ secrets.NAME }} against the repo and environment secret inventories already collected, and model GITHUB_TOKEN explicitly rather than as an unscoped secret.",
	Targets:     []string{"edge(READS, Job, Secret)"},
}, {
	Subject:     "REQUIRES_REVIEW_BY{Environment,User|Team}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "no environment record carries reviewer identities: reviewers_required is [] across all environments and protection_rules_raw holds only branch_policy entries. The fr-12-02 \"bot as required reviewer\" scenario has protection_rules: [] in the raw API response, so the gap starts in the firing range. The builder has neither an add nor a miss for the type — it is absent from buildEdges entirely, so the count is 0 rather than unbuilt.",
	UpstreamFix: "firing range: configure required reviewers on fr-12-02; then normalize must keep the reviewer identities rather than only reviewers_count; then a graph writer.",
	Targets:     []string{"edge(REQUIRES_REVIEW_BY, Environment, User)"},
}, {
	Subject:     "RUNS_ON{Job,Runner|RunnerGroup}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "emitRunsOn now answers the join: a job reaches a runner whose label set covers every label the job asks for and whose scope serves the job's repository, and a runner group by NAME when that name is unique in the org. It stays empty in both corpora for want of data, not code — ghektestorg registers no runners at all, and portus-labs' one org runner is not asked for by any job (the only job that could is the reusable deploy callee, whose runs_on is ${{ inputs.runner-label }} and whose caller passes no such input). A job that resolves to nothing is counted, never given a placeholder: one stand-in Runner would make every self-hosted job appear to share a machine, which is the exact claim the cat-07 rules exist to test.",
	UpstreamFix: "firing range: register runners whose labels a job actually names; additionally collect the runner groups referenced by workflows, not only those the org API lists.",
	Targets:     []string{"edge(RUNS_ON, Job, Runner)"},
}, {
	Subject:     "TARGETS{Job,Environment}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "a deployment whose env_name is an unevaluated expression (${{ inputs.target }}, ${{ github.event.client_payload.environment }}) names no environment: the target is chosen at run time, so no identity exists to point at. Deployments naming an environment with no record are emitted against an observed_only node instead.",
	UpstreamFix: "unrecoverable from configuration alone; it needs deployment history to see which environments the expression actually resolved to.",
	Targets:     []string{"edge(TARGETS, Job, Environment)"},
}, {
	Subject:     "DEPLOYABLE_FROM{Environment,Branch|Tag}",
	Kind:        "edge",
	Status:      "blocked",
	Reason:      "deployment_branch_policy.patterns are globs, and a glob is not a ref identity. Unlike on.<event>.branches these patterns match tags as well as branches — the only glob in the corpus is fr-02-08's \"v*\", a tag policy — so they are deliberately NOT expanded against Branch nodes: doing so would assert a branch deployment route from a rule about tags. A pattern only yields an edge when it names a Branch node literally.",
	UpstreamFix: "collect tags (see the Tag row), then expand a pattern against branches and tags together so the ref kind is decided by what matched rather than by which writer ran.",
}, {
	Subject:     "TARGETS{Workflow,Branch}",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "on.<event>.branches patterns are expanded against the branches that exist: \"*\" stops at a path separator and \"**\" does not, matching GitHub's filter syntax. What stays unbuilt is a pattern this expansion refuses (?, +, character ranges, or a leading ! negation, none of which resolve without the whole filter list) and a literal naming a branch the repository does not have — fr-03-02's attacker-dev and fr-11-03's attacker-feat are the branches those scenarios say an attacker would create.",
	UpstreamFix: "none for the two absent literals: minting them would assert refs the repository does not have. A negated filter needs the sibling filters evaluated as a set, which the per-value loop does not model.",
}, {
	Subject:     "CAN_ACCESS{App,Repository}",
	Kind:        "edge",
	Status:      "not_collected",
	Reason:      "the installation repository list is never fetched, so an app's repository scope is unknown and its blast radius cannot be drawn. CAN_LAND_CODE{App,Branch} no longer waits on it: deriveCapabilityEdges fans a \"selected\" installation over the repositories where a job actually mints its token (write_via \"app_token_mint\") rather than over every repo, which is sound without the call and covers every repository the grant is reachable from a workflow in. What that scoping cannot see is a repository the installation holds but no workflow mints in — real blast radius the graph still omits.",
	UpstreamFix: "collect /orgs/{org}/installations/{id}/repositories and normalize it onto the app record; then this pair is built and CAN_LAND_CODE stops being bounded by mint sites.",
}, {
	Subject:     "repos[].codeowners",
	Kind:        "node",
	Status:      "partial",
	Reason:      "the CODEOWNERS file is collected into the repository bundle and parsed onto the repo record, and its coverage rides the effective-ruleset chain so cat-11/codeowners-ci-paths-uncovered can join it against require_code_owner_review_active. Two limits. covers_ci_execution is decided by a fixed probe list, not by the repository tree: it reports that CODEOWNERS leaves representative executable locations unowned, never that a specific executed file is unowned. And the file is read from the default branch only, so the rule is scoped to is_default_branch — a protected non-default branch may carry a different CODEOWNERS the run has not looked at. Runs collected before this exists carry codeowners: null and are correctly not reported.",
	UpstreamFix: "resolve the paths the repository's own workflows execute (run: script invocations and local composite action uses:) and test those instead of the probes; collect CODEOWNERS per protected branch rather than per repository.",
}, {
	Subject:     "User.org_role",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "org_role is null on every User node: loginIDType (internal/github/collect_surfaces.go:913) reduces each org member to {login, id, type}, and /orgs/{org}/members returns no role to begin with, so an org owner is indistinguishable from a member. Repository access itself is intact — collaborator and team grants both carry permission, can_push and is_admin — so this is the only principal-side gap left.",
	UpstreamFix: "internal/github/collect_surfaces.go: paginate /orgs/{org}/members?role=admin alongside the plain listing (or GET /orgs/{org}/memberships/{user}) and keep the role on the member entry.",
}, {
	Subject:     "identityKeys[Secret]",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "{scope, name} keys a secret on the scope KIND, not the scope, so every repository's NPM_TOKEN collapses to one node and READS edges converge on it — a fabricated shared-credential path. Fixed here by adding scope_key.",
	UpstreamFix: "fixed in schema.go; internal/github/normalize_secrets.go should still stop skipping org-scope secrets so they get records of their own.",
}, {
	Subject:     "identityKeys[Job]",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "branch is deliberately excluded, so branch-scoped job records merge onto one job definition. Adding branch would leave Workflow{repo,path} un-branched and make CONTAINS{Workflow,Job} incoherent, so the merged branch set is preserved on properties.branches instead and every finding keeps its branch-qualified subject_id.",
	UpstreamFix: "none wanted at the graph layer; branch-scoping the graph would require branching Workflow identity too.",
}, {
	Subject:     "identityKeys[Workflow]",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "{repo, path} omits the branch, so one node stands for every branch's copy of the file and their differences merge. CONTAINS now runs Branch -> Workflow, which makes the collapse visible rather than fixing it: ghektestorg's conf-ci/reusable-build.yml is 3 distinct blobs across 4 branches and still one node with 4 inbound edges, so a permissions block or a pinned ref that only one branch carries reads as if every branch carried it.",
	UpstreamFix: "add branch to the key, which rekeys CONTAINS{Branch,Workflow}, CONTAINS{Workflow,Job}, CALLS{Job,Workflow}, TRIGGERS{Workflow,Workflow} and TARGETS{Workflow,Branch}, and the 6 rules whose graph: line names Workflow.",
}, {
	Subject:     "Organization secrets",
	Kind:        "node",
	Status:      "partial",
	Reason:      "internal/github/normalize_secrets.go skips org-scope secrets entirely, so 10-normalize/secrets/ holds none. They are recovered here from org.org_actions_secrets[], which closes CONTAINS{Organization,Secret}, the org-scope READS references and the org -> node(Secret) findings. They now carry visibility, selected_repo_count AND selected_repositories, which is what CAN_ACCESS{Repository,Secret} is built from. What is still lost is everything else a SecretFact carries — created_at, updated_at, bucket — and the org secret has no record of its own to be a finding subject.",
	UpstreamFix: "normalize org-scope secrets as records like repo and environment secrets.",
}, {
	Subject:     "CAN_APPROVE{User|Team,Environment}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "the same absence as REQUIRES_REVIEW_BY: with no reviewer identity on any environment record there is no principal to point at. The two types are the two directions of one fact, so one firing-range change closes all four declared pairs.",
	UpstreamFix: "see the REQUIRES_REVIEW_BY row; a single writer should emit both directions from the same reviewer list.",
}, {
	Subject:     "CAN_ACCESS{Repository,Secret}",
	Kind:        "edge",
	Status:      "built",
	Reason:      "built from org secret visibility now that orgSecretSummaries keeps the repository names: \"all\" reaches every live repo, \"private\" every non-public one, \"selected\" exactly the named list; an archived repo is excluded from all three because it runs no workflow. The edge carries visibility so a consumer can tell the cases apart. The \"selected\" case is the one no query could reproduce from the node: an empty selected list means the secret is reachable by nothing, which a fan-out from Secret.visibility would get exactly backwards. The cost is real — 7 org secrets over 145 repos is 864 edges in ghektestorg (archived repos excluded) — and it is paid so the two cases live in one relation.",
	UpstreamFix: "none. normalize_secrets.go could still write org-scope secrets as records rather than leaving them to be recovered from org.org_actions_secrets[]; see the Organization secrets row.",
}, {
	Subject:     "CAN_ACCESS{Repository,RunnerGroup}",
	Kind:        "edge",
	Status:      "built",
	Reason:      "built from the group's visibility on the same rule as the secret pair, and pointed the same way: the repository is the consumer and the group the resource, so it runs with RUNS_ON{Job,RunnerGroup} rather than against it. It is what bounds RUNS_ON for an org runner that names a group: a group scoped to selected repositories cannot run a job in a repository outside the list.",
	UpstreamFix: "none.",
}, {
	Subject:     "MEMBER_OF{Team,Team}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "parent_slug is a first-class field on all three team records and is null on all three, so the org has no nested teams. This is the only empty pair whose normalize field is present and whose writer simply does not read it — emitMemberOf handles the user side only.",
	UpstreamFix: "firing range: create a child team, then read parent_slug in emitMemberOf. Writing the reader first leaves it with no oracle, since it would be a no-op against this corpus.",
}, {
	Subject:     "TRIGGERS{Job,Workflow}",
	Kind:        "edge",
	Status:      "empty",
	Reason:      "workflow_run_pairs cannot produce it: GitHub's workflow_run event fires on RUN completion, not job completion, so a Job -> Workflow edge from those rows would assert causality that does not exist and shadow the 13 Workflow -> Workflow edges already built from them. The one honest producer is repository_dispatch_links, which has 0 items — two repos declare the trigger and no job emits a /dispatches call, so containsRepoDispatchEmit finds no emitter.",
	UpstreamFix: "firing range: a job that actually POSTs /dispatches; then read repository_dispatch_links in edges.go, which never references it today.",
}, {
	Subject:     "Branch.org_rulesets_unevaluable",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "an org ruleset whose conditions test a repository custom property cannot be evaluated, because the property values are never collected. 145 branches carry the ruleset id in org_rulesets_unevaluable and their coverage is reported as unknown rather than absent — d71ac57 removed the phantom coverage that applying such a ruleset blindly produced, and this row is the residue: the uncertainty is real and disclosed, not a defect to fix in correlate.",
	UpstreamFix: "collect /repos/{owner}/{repo}/properties/values as data.properties. readRepoIdentity already expects that shape and the include/exclude evaluation in collect.go is already correct, so the ruleset resolves as soon as the values exist.",
}}
