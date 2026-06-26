package github

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func Normalize(ctx context.Context, runDir string) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhaseNormalize); err != nil {
		return err
	}
	for _, d := range state.StaleDirs(engine.PhaseNormalize) {
		if err := os.RemoveAll(filepath.Join(runDir, d)); err != nil {
			return err
		}
	}

	org := state.Org
	if org == "" {
		return fmt.Errorf("org not set in %s; run collect first", engine.RunMeta())
	}

	timer := engine.StartPhaseTimer(engine.PhaseNormalize, "normalize")
	prior := engine.PriorPhase{RunDir: runDir}
	cp := engine.CurrentPhase{RunDir: runDir}

	jobs, normErr := normalizeJobs(prior, cp, org, timer)
	if normErr == nil {
		normErr = normalizeEntities(runDir)
	}
	if normErr == nil {
		normErr = correlate(prior, cp, jobs)
	}

	rec := timer.Stop(normErr)
	state.RecordPhase(rec)
	if err := state.Save(runDir); err != nil {
		return err
	}
	return normErr
}

func normalizeJobs(prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) ([]Job, error) {
	workflowsRoot := filepath.Join(prior.RunDir, "00-collect", "workflows")
	repoDirs, err := os.ReadDir(workflowsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			timer.Errors = append(timer.Errors, "00-collect/workflows missing")
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(repoDirs, func(i, j int) bool { return repoDirs[i].Name() < repoDirs[j].Name() })

	orgDefault := loadOrgDefaultPerms(prior, org)
	refResolutions := loadRefResolutions(prior)

	var allJobs []Job
	for _, rd := range repoDirs {
		if !rd.IsDir() {
			continue
		}
		dirName := rd.Name()
		repo, branch, isDefault := splitRepoBranchDir(dirName)
		if isDefault {
			branch = loadDefaultBranch(prior, repo)
		}
		repoDefault := loadRepoDefaultPerms(prior, repo)

		dirPath := filepath.Join(workflowsRoot, dirName)
		for _, yamlName := range workflowYAMLNames(dirPath) {
			timer.InputFiles++
			relpath := filepath.ToSlash(filepath.Join("00-collect", "workflows", dirName, yamlName))
			text, err := os.ReadFile(filepath.Join(dirPath, yamlName))
			if err != nil {
				timer.Errors = append(timer.Errors, fmt.Sprintf("%s: %v", relpath, err))
				continue
			}
			records, err := normalizeWorkflowText(string(text), normalizeCtx{
				org:            org,
				repo:           repo,
				branch:         branch,
				isDefault:      isDefault,
				relpath:        relpath,
				repoDefault:    repoDefault,
				orgDefault:     orgDefault,
				refResolutions: refResolutions,
			})
			if err != nil {
				timer.Errors = append(timer.Errors, fmt.Sprintf("%s: %v", relpath, err))
				continue
			}
			for _, rec := range records {
				out := engine.NormalizeJobBranch(repo, branch, isDefault, rec.WorkflowFilename, rec.JobID)
				if err := cp.Write(out, rec); err != nil {
					return allJobs, err
				}
				timer.OutputFiles++
			}
			allJobs = append(allJobs, records...)
		}
	}
	return allJobs, nil
}

// workflowYAMLNames orders .yml before .yaml so jobs with the same stem in both
// files keep a stable on-disk precedence.
func workflowYAMLNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var yml, yaml []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".meta.json") {
			continue
		}
		switch {
		case strings.HasSuffix(name, ".yml"):
			yml = append(yml, name)
		case strings.HasSuffix(name, ".yaml"):
			yaml = append(yaml, name)
		}
	}
	sort.Strings(yml)
	sort.Strings(yaml)
	return append(yml, yaml...)
}

// splitRepoBranchDir inverts engine.repoBranchDir: "<repo>" is the default
// branch, "<repo>@<branchSlug>" is a non-default branch.
func splitRepoBranchDir(dirName string) (repo, branch string, isDefault bool) {
	if i := strings.LastIndex(dirName, "@"); i >= 0 {
		return dirName[:i], dirName[i+1:], false
	}
	return dirName, "", true
}

type normalizeCtx struct {
	org            string
	repo           string
	branch         string
	isDefault      bool
	relpath        string
	repoDefault    string
	orgDefault     string
	refResolutions map[string]string
}

func normalizeWorkflowText(text string, nc normalizeCtx) ([]Job, error) {
	root, err := DecodeWorkflow(text)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}

	filename := filepath.Base(nc.relpath)

	workflowName := ".github/workflows/" + filename
	if name, ok := root.FieldValue("name", nil).(string); ok && strings.TrimSpace(name) != "" {
		workflowName = name
	}

	onNode := root.Field("on")
	if onNode == nil {
		// YAML 1.1 parsers coerce the unquoted `on:` key to boolean true.
		onNode = root.Field("true")
	}
	triggers, triggerFilters := extractTriggers(onNode)

	workflowPermsNode := root.Field("permissions")

	jobsNode := root.Field("jobs")
	if jobsNode == nil {
		return nil, nil
	}
	jobsMap, ok := jobsNode.Value.(map[string]*LineNode)
	if !ok {
		return nil, nil
	}

	jobIDs := make([]string, 0, len(jobsMap))
	for id := range jobsMap {
		jobIDs = append(jobIDs, id)
	}
	sort.Strings(jobIDs)

	var out []Job
	for _, jobID := range jobIDs {
		rec, ok := normalizeJob(jobInputs{
			repo:              nc.repo,
			branch:            nc.branch,
			isDefaultBranch:   nc.isDefault,
			workflowName:      workflowName,
			workflowFilename:  filename,
			jobID:             jobID,
			jobNode:           jobsMap[jobID],
			triggers:          triggers,
			triggerFilters:    triggerFilters,
			workflowPermsNode: workflowPermsNode,
			repoDefault:       nc.repoDefault,
			orgDefault:        nc.orgDefault,
			relpath:           nc.relpath,
			refResolutions:    nc.refResolutions,
		})
		if ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

func loadDefaultBranch(prior engine.PriorPhase, repo string) string {
	var env struct {
		Data struct {
			Repo struct {
				DefaultBranch string `json:"default_branch"`
			} `json:"repo"`
		} `json:"data"`
	}
	if err := engine.ReadJSON(prior.Abs(engine.CollectRepo(repo)), &env); err == nil {
		if env.Data.Repo.DefaultBranch != "" {
			return env.Data.Repo.DefaultBranch
		}
	}
	return "main"
}

type jobInputs struct {
	repo              string
	branch            string
	isDefaultBranch   bool
	workflowName      string
	workflowFilename  string
	jobID             string
	jobNode           *LineNode
	triggers          []string
	triggerFilters    map[string]TriggerFilter
	workflowPermsNode *LineNode
	repoDefault       string
	orgDefault        string
	relpath           string
	refResolutions    map[string]string
}

func normalizeJob(in jobInputs) (Job, bool) {
	jobPlain, ok := in.jobNode.Plain().(map[string]any)
	if !ok {
		return Job{}, false
	}

	jobPermsNode := in.jobNode.Field("permissions")
	var jobProv, wfProv *SourceProvenance
	if jobPermsNode != nil {
		jobProv = newSourceProvenance(in.relpath, jobPermsNode.Range())
	}
	if in.workflowPermsNode != nil {
		wfProv = newSourceProvenance(in.relpath, in.workflowPermsNode.Range())
	}
	perms := resolvePermissions(permInputs{
		JobPerms:           plainOrNil(jobPermsNode),
		WorkflowPerms:      plainOrNil(in.workflowPermsNode),
		RepoDefault:        in.repoDefault,
		OrgDefault:         in.orgDefault,
		JobProvenance:      jobProv,
		WorkflowProvenance: wfProv,
	})

	runsOn, selfHosted, runnerLabels, runnerGroup := resolveRunsOn(jobPlain["runs-on"])

	env, envDynamic := resolveEnvironment(jobPlain["environment"])

	ifSummary := classifyGate(stringPtrFromAny(jobPlain["if"]))

	stepsOut := []Step{}
	sinksSeen := []string{}
	executesCheckedOut := false
	checkoutOfPR := false
	cacheWrites := []CacheRef{}
	cacheReads := []CacheRef{}
	artifactWrites := []ArtifactRef{}
	artifactReads := []ArtifactRef{}
	actionRefs := []ActionRef{}
	secretsRef := []SecretRef{}
	callsReusable := []ReusableCall{}
	localComposites := []LocalCompositeRef{}
	attackerAll := []string{}
	attackerExec := []string{}
	attackerBinding := []string{}
	needsExec := []NeedsOutputRef{}
	needsBinding := []NeedsOutputRef{}
	needsUnion := []NeedsOutputRef{}
	stepByID := map[string]map[string]any{}

	// Runs before the step loop so a job-level uses lands first in the ref lists.
	if jobUses, ok := jobPlain["uses"].(string); ok {
		actionRefs = append(actionRefs, classifyActionRef(jobUses, in.refResolutions, in.repo))
		if isReusableWorkflowRef(jobUses) {
			call := parseReusableCall(jobUses)
			call.SecretsInherit = secretsInherit(jobPlain["secrets"])
			inputs := map[string]any{}
			if w, ok := jobPlain["with"].(map[string]any); ok {
				inputs = w
			}
			call.Inputs = &inputs
			call.JobLevel = true
			callsReusable = append(callsReusable, call)
		} else if isLocalCompositeRef(jobUses) {
			localComposites = append(localComposites, LocalCompositeRef{Uses: jobUses})
		}
	}

	stepsNode := in.jobNode.Field("steps")
	var stepLineNodes []*LineNode
	if stepsNode != nil {
		stepLineNodes, _ = stepsNode.Value.([]*LineNode)
	}

	if stepsList, ok := jobPlain["steps"].([]any); ok {
		for idx, raw := range stepsList {
			step, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			stepRec := buildStep(step, idx)
			classifiers := stepRec.Classifiers

			if uses, ok := step["uses"].(string); ok {
				actionRefs = append(actionRefs, classifyActionRef(uses, in.refResolutions, in.repo))
				if isReusableWorkflowRef(uses) {
					call := parseReusableCall(uses)
					call.SecretsInherit = secretsInherit(step["secrets"])
					callsReusable = append(callsReusable, call)
				} else if isLocalCompositeRef(uses) {
					localComposites = append(localComposites, LocalCompositeRef{Uses: uses})
				}
			}

			if classifiers.IsCheckout &&
				hasCheckoutOfPRRef(classifiers.CheckoutRefField, classifiers.CheckoutRepositoryField) {
				checkoutOfPR = true
			}
			if classifiers.SinkClass != nil && classifiers.ExecutesCheckedOutCode {
				if !slices.Contains(sinksSeen, *classifiers.SinkClass) {
					sinksSeen = append(sinksSeen, *classifiers.SinkClass)
				}
				executesCheckedOut = true
			}

			cw, cr := extractCacheOps(step)
			cacheWrites = append(cacheWrites, cw...)
			cacheReads = append(cacheReads, cr...)
			aw, ar := extractArtifactOps(step)
			artifactWrites = append(artifactWrites, aw...)
			artifactReads = append(artifactReads, ar...)

			for _, sec := range findSecretsReferenced(stepText(step)) {
				secretsRef = append(secretsRef, SecretRef{Name: sec, Scope: "unknown", StepIndex: idx})
			}

			for _, ref := range findAttackerReferences(stepExecText(step), in.triggers) {
				attackerExec = appendUnique(attackerExec, ref)
				attackerAll = appendUnique(attackerAll, ref)
			}
			for _, ref := range findAttackerReferences(stepBindingText(step), in.triggers) {
				attackerBinding = appendUnique(attackerBinding, ref)
				attackerAll = appendUnique(attackerAll, ref)
			}

			for _, ref := range stepRec.NeedsOutputRefsExec {
				needsExec = appendUniqueNeedsRef(needsExec, ref)
				needsUnion = appendUniqueNeedsRef(needsUnion, ref)
			}
			for _, ref := range stepRec.NeedsOutputRefsBinding {
				needsBinding = appendUniqueNeedsRef(needsBinding, ref)
				needsUnion = appendUniqueNeedsRef(needsUnion, ref)
			}
			if stepRec.ID != nil {
				stepByID[*stepRec.ID] = step
			}

			if stepsNode != nil && stepLineNodes != nil && idx < len(stepLineNodes) {
				stepRec.Provenance = newSourceProvenance(in.relpath, stepLineNodes[idx].Range())
			}
			stepsOut = append(stepsOut, stepRec)
		}
	}

	// A needs.<job>.outputs.<var> ref appearing only in the job's strategy/matrix
	// block drives job execution but lives in no step; capture it as a job-level
	// exec ref (step_index -1, mirroring SecretRef) so it joins to its producer.
	for _, ref := range extractNeedsOutputRefs(jsonDump(jobPlain["strategy"])) {
		needsExec = appendUniqueNeedsRef(needsExec, ref)
		needsUnion = appendUniqueNeedsRef(needsUnion, ref)
	}

	jobEnvText := jsonDump(jobPlain["env"])
	seenSecrets := map[string]bool{}
	for _, s := range secretsRef {
		seenSecrets[s.Name] = true
	}
	for _, sec := range findSecretsReferenced(jobEnvText) {
		if !seenSecrets[sec] {
			seenSecrets[sec] = true
			secretsRef = append(secretsRef, SecretRef{Name: sec, Scope: "unknown", StepIndex: -1})
		}
	}

	mintsIDToken := permScope(perms, "id-token") == "write"
	var oidcSub *string
	if mintsIDToken {
		s := "repo:<owner>/<repo>:ref:<ref>"
		oidcSub = &s
	}

	agent := classifyAgentSurface(jobPlain, perms)

	outputsOut := []JobOutput{}
	if outs, ok := jobPlain["outputs"].(map[string]any); ok {
		outputsNode := in.jobNode.Field("outputs")
		names := make([]string, 0, len(outs))
		for name := range outs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			expr := anyToStr(outs[name])
			attacker := nonNilSlice(findAttackerReferences(expr, in.triggers))

			var refStepID *string
			var producingRefs []string
			if m := stepOutputRefRE.FindStringSubmatch(expr); m != nil {
				id := m[1]
				refStepID = &id
				if raw, ok := stepByID[id]; ok {
					producingRefs = findAttackerReferences(stepExecText(raw), in.triggers)
				}
			}

			var prov *SourceProvenance
			if outputsNode != nil {
				prov = newSourceProvenance(in.relpath, outputFieldRange(outputsNode, name))
			}

			outputsOut = append(outputsOut, JobOutput{
				Name:                            name,
				ValueExpression:                 expr,
				AttackerContextFieldsReferenced: attacker,
				ReferencesStepID:                refStepID,
				ProducingStepAttackerExecRefs:   nonNilSlice(producingRefs),
				Provenance:                      prov,
			})
		}
	}

	return Job{
		ID:         in.repo + "__" + engineWFStem(in.workflowFilename) + "__" + in.jobID,
		Provenance: &JobProvenance{WorkflowFile: in.relpath, YAMLLineRange: lineRangeOrZero(in.jobNode.Range()), Repo: in.repo},
		Repo:       in.repo,

		Branch:          in.branch,
		IsDefaultBranch: in.isDefaultBranch,

		WorkflowName:     in.workflowName,
		WorkflowFilename: in.workflowFilename,
		JobID:            in.jobID,

		Triggers:            nonNilSlice(in.triggers),
		TriggerFilters:      nonNilFilters(in.triggerFilters),
		TriggerClassSummary: triggerClassSummary(in.triggers),

		AttackerContextFieldsReferenced:        attackerAll,
		AttackerContextFieldsReferencedExec:    attackerExec,
		AttackerContextFieldsReferencedBinding: attackerBinding,

		NeedsOutputRefsExec:    needsExec,
		NeedsOutputRefsBinding: needsBinding,
		NeedsOutputRefs:        needsUnion,

		RunsOn:       runsOn,
		SelfHosted:   selfHosted,
		RunnerLabels: runnerLabels,
		RunnerGroup:  runnerGroup,

		Steps:                  stepsOut,
		Outputs:                outputsOut,
		ExecutesCheckedOutCode: executesCheckedOut,
		HasCheckoutOfPRRef:     checkoutOfPR,
		Sinks:                  sinksSeen,

		Permissions: perms,

		ReadsAnySecret:    len(secretsRef) > 0,
		SecretsReferenced: secretsRef,

		IfConditionsSummary: ifSummary,

		Environment:                  env,
		EnvironmentChosenDynamically: envDynamic,

		InlinedFrom: nil,

		CallsReusableWorkflows:    callsReusable,
		LocalCompositeActionsUsed: localComposites,

		MintsIDToken:    mintsIDToken,
		OIDCAudience:    nil,
		OIDCSubTemplate: oidcSub,

		CacheWrites:    cacheWrites,
		CacheReads:     cacheReads,
		ArtifactWrites: artifactWrites,
		ArtifactReads:  artifactReads,

		AgentActionClass:        agent.actionClass,
		AgentToolsEnabled:       agent.tools,
		AgentPromptSources:      agent.promptSources,
		AgentOutputChannels:     agent.outputChannels,
		AgentMCPServers:         agent.mcpServers,
		AgentBypassPermissions:  agent.bypassPermissions,
		AgentAllowlistWildcards: agent.allowlistWildcards,
		AgentActorAllowlistRaw:  agent.actorAllowlistRaw,

		ActionRefs: actionRefs,
	}, true
}

func buildStep(step map[string]any, idx int) Step {
	s := Step{
		StepIndex:              idx,
		ID:                     stringPtrFromAny(step["id"]),
		Uses:                   stringPtrFromAny(step["uses"]),
		With:                   mapFromAny(step["with"]),
		Run:                    stringPtrFromAny(step["run"]),
		Name:                   stringPtrFromAny(step["name"]),
		If:                     stringPtrFromAny(step["if"]),
		NeedsOutputRefsExec:    extractNeedsOutputRefs(stepExecText(step)),
		NeedsOutputRefsBinding: extractNeedsOutputRefs(stepBindingText(step)),
	}
	s.Classifiers = classifyStep(s)
	return s
}

func extractTriggers(onNode *LineNode) ([]string, map[string]TriggerFilter) {
	if onNode == nil {
		return []string{}, map[string]TriggerFilter{}
	}
	switch plain := onNode.Plain().(type) {
	case string:
		return []string{plain}, map[string]TriggerFilter{}
	case []any:
		names := make([]string, 0, len(plain))
		for _, x := range plain {
			names = append(names, anyToStr(x))
		}
		return names, map[string]TriggerFilter{}
	case map[string]any:
		var names []string
		filters := map[string]TriggerFilter{}
		for _, k := range orderedKeys(onNode) {
			names = append(names, k)
			if m, ok := plain[k].(map[string]any); ok {
				filters[k] = TriggerFilter(m)
			} else {
				filters[k] = nil
			}
		}
		return names, filters
	default:
		return []string{}, map[string]TriggerFilter{}
	}
}

// orderedKeys sorts rather than preserving YAML order; rules key on trigger
// membership, not order, so sorting is sufficient and deterministic.
func orderedKeys(node *LineNode) []string {
	m, ok := node.Value.(map[string]*LineNode)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func resolveRunsOn(value any) (runsOn []string, selfHosted bool, runnerLabels []string, runnerGroup *string) {
	switch v := value.(type) {
	case string:
		labels := []string{v}
		return labels, anySelfHosted(labels), labels, nil
	case []any:
		labels := make([]string, 0, len(v))
		for _, x := range v {
			labels = append(labels, anyToStr(x))
		}
		return labels, anySelfHosted(labels), labels, nil
	case map[string]any:
		labels := []string{}
		switch lv := v["labels"].(type) {
		case string:
			labels = []string{lv}
		case []any:
			for _, x := range lv {
				labels = append(labels, anyToStr(x))
			}
		}
		var group *string
		if g, ok := v["group"].(string); ok {
			group = &g
		}
		return labels, anySelfHosted(labels), labels, group
	default:
		return []string{}, false, []string{}, nil
	}
}

func anySelfHosted(labels []string) bool {
	for _, l := range labels {
		if strings.Contains(l, "self-hosted") {
			return true
		}
	}
	return false
}

func resolveEnvironment(value any) (*EnvironmentRef, bool) {
	switch v := value.(type) {
	case string:
		return &EnvironmentRef{Name: v, URL: nil}, strings.Contains(v, "${{")
	case map[string]any:
		name, _ := v["name"].(string)
		ref := &EnvironmentRef{Name: name}
		if u, ok := v["url"].(string); ok {
			ref.URL = &u
		}
		dynamic := false
		if n, ok := v["name"].(string); ok {
			dynamic = strings.Contains(n, "${{")
		}
		return ref, dynamic
	default:
		return nil, false
	}
}

var secretRefRE = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)

var stepOutputRefRE = regexp.MustCompile(`steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.`)

func findSecretsReferenced(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, expr := range extractInterpolations(text) {
		for _, m := range secretRefRE.FindAllStringSubmatch(expr, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}

func stepText(step map[string]any) string {
	var parts []string
	for _, k := range []string{"run", "uses", "name", "if"} {
		if v, ok := step[k].(string); ok {
			parts = append(parts, v)
		}
	}
	parts = append(parts, mapStringValues(step["with"])...)
	parts = append(parts, mapStringValues(step["env"])...)
	return strings.Join(parts, "\n")
}

func stepExecText(step map[string]any) string {
	var parts []string
	if v, ok := step["run"].(string); ok {
		parts = append(parts, v)
	}
	parts = append(parts, mapStringValues(step["with"])...)
	return strings.Join(parts, "\n")
}

func stepBindingText(step map[string]any) string {
	var parts []string
	for _, k := range []string{"name", "if"} {
		if v, ok := step[k].(string); ok {
			parts = append(parts, v)
		}
	}
	parts = append(parts, mapStringValues(step["env"])...)
	return strings.Join(parts, "\n")
}

// mapStringValues sorts by key for determinism; downstream references are deduped
// on first sight, so value order is immaterial.
func mapStringValues(value any) []string {
	m, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			out = append(out, s)
		}
	}
	return out
}

var (
	dockerDigestRE = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
	semverTagRE    = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?$`)
)

func classifyActionRef(uses string, resolutions map[string]string, repo string) ActionRef {
	if strings.HasPrefix(uses, "./") {
		localKey := uses
		if repo != "" {
			localKey = repo + "::" + uses
		}
		return ActionRef{Uses: uses, RefKind: "local", RefMutable: true, ResolvedSHA: lookupSHA(resolutions, localKey)}
	}
	if strings.HasPrefix(uses, "docker://") {
		if i := strings.Index(uses, "@"); i >= 0 {
			digest := uses[i+1:]
			if dockerDigestRE.MatchString(digest) {
				d := digest
				return ActionRef{Uses: uses, RefKind: "digest", RefMutable: false, ResolvedSHA: &d}
			}
		}
		return ActionRef{Uses: uses, RefKind: "tag", RefMutable: true, ResolvedSHA: nil}
	}
	if !strings.Contains(uses, "@") {
		return ActionRef{Uses: uses, RefKind: "unknown", RefMutable: true, ResolvedSHA: nil}
	}
	_, ref, _ := strings.Cut(uses, "@")
	resolved := lookupSHA(resolutions, uses)
	kind, mutable := "tag", true
	switch {
	case !isMutableRef(ref):
		if resolved != nil && !strings.HasPrefix(strings.ToLower(*resolved), strings.ToLower(ref)) {
			kind, mutable = "tag", true
		} else {
			kind, mutable = "sha", false
		}
	case semverTagRE.MatchString(ref):
		kind, mutable = "tag", true
	case ref == "main" || ref == "master" || ref == "develop":
		kind, mutable = "branch", true
	}
	return ActionRef{Uses: uses, RefKind: kind, RefMutable: mutable, ResolvedSHA: resolved}
}

func lookupSHA(resolutions map[string]string, key string) *string {
	if resolutions == nil {
		return nil
	}
	if v, ok := resolutions[key]; ok && v != "" {
		return &v
	}
	return nil
}

func parseReusableCall(uses string) ReusableCall {
	if strings.HasPrefix(uses, "./") {
		return ReusableCall{
			Owner: nil, Repo: nil, Path: strings.TrimPrefix(uses, "./"),
			Ref: "local", Kind: "local", RefMutable: true,
		}
	}
	head, ref := uses, ""
	if i := strings.LastIndex(uses, "@"); i >= 0 {
		head, ref = uses[:i], uses[i+1:]
	}
	parts := strings.SplitN(head, "/", 3)
	var owner, repo *string
	if len(parts) > 0 {
		owner = &parts[0]
	}
	if len(parts) > 1 {
		repo = &parts[1]
	}
	path := ""
	if len(parts) == 3 {
		path = parts[2]
	}
	return ReusableCall{
		Owner: owner, Repo: repo, Path: path, Ref: ref,
		Kind: "remote", RefMutable: isMutableRef(ref),
	}
}

func secretsInherit(secrets any) bool {
	s, ok := secrets.(string)
	return ok && s == "inherit"
}

func extractCacheOps(step map[string]any) ([]CacheRef, []CacheRef) {
	uses, _ := step["uses"].(string)
	if uses == "" {
		return nil, nil
	}
	if !strings.HasPrefix(uses, "actions/cache") && !strings.Contains(uses, "/cache@") {
		return nil, nil
	}
	with, ok := step["with"].(map[string]any)
	if !ok {
		return nil, nil
	}
	doesWrite := !strings.Contains(uses, "/restore@")
	doesRead := !strings.Contains(uses, "/save@")

	var writes, reads []CacheRef
	if key, ok := with["key"].(string); ok && key != "" {
		if doesWrite {
			writes = append(writes, cacheEntry(key))
		}
		if doesRead {
			reads = append(reads, cacheEntry(key))
		}
	}
	if doesRead {
		for _, rk := range restoreKeyLines(with["restore-keys"]) {
			reads = append(reads, cacheEntry(rk))
		}
	}
	return writes, reads
}

func cacheEntry(k string) CacheRef {
	prefix := strings.Trim(strings.SplitN(k, "${{", 2)[0], "-_/")
	return CacheRef{KeyTemplate: k, Scope: "scope-prefix:" + prefix}
}

func restoreKeyLines(value any) []string {
	switch v := value.(type) {
	case string:
		var out []string
		for _, line := range strings.Split(v, "\n") {
			if s := strings.TrimSpace(line); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, x := range v {
			out = append(out, anyToStr(x))
		}
		return out
	default:
		return nil
	}
}

func extractArtifactOps(step map[string]any) ([]ArtifactRef, []ArtifactRef) {
	uses, _ := step["uses"].(string)
	if uses == "" {
		return nil, nil
	}
	var name *string
	if with, ok := step["with"].(map[string]any); ok {
		if n, ok := with["name"].(string); ok {
			name = &n
		}
	}
	switch {
	case strings.HasPrefix(uses, "actions/upload-artifact"):
		return []ArtifactRef{{Name: name}}, nil
	case strings.HasPrefix(uses, "actions/download-artifact"):
		return nil, []ArtifactRef{{Name: name}}
	default:
		return nil, nil
	}
}

type agentSurface struct {
	actionClass        *string
	tools              []string
	promptSources      []string
	outputChannels     []string
	mcpServers         []string
	bypassPermissions  bool
	allowlistWildcards []string
	actorAllowlistRaw  *string
}

var (
	allowedToolsArgRE = regexp.MustCompile(`--allowed[-_]tools[ =]+["']?([^\n"']+)`)
	splitToolsRE      = regexp.MustCompile(`[,\s]+`)
	mcpServersBlockRE = regexp.MustCompile(`(?s)"mcpServers"\s*:\s*\{([^}]+)`)
	mcpServerNameRE   = regexp.MustCompile(`"([A-Za-z0-9_-]+)"\s*:\s*\{`)
)

func classifyAgentSurface(jobPlain map[string]any, perms map[string]any) agentSurface {
	out := agentSurface{
		tools:              []string{},
		promptSources:      []string{},
		outputChannels:     []string{},
		mcpServers:         []string{},
		allowlistWildcards: []string{},
	}
	var argsInspected []string

	stepsList, _ := jobPlain["steps"].([]any)
	for _, raw := range stepsList {
		step, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		uses, ok := step["uses"].(string)
		if !ok {
			continue
		}
		lc := strings.ToLower(uses)
		isAgent := false
		switch {
		case strings.HasPrefix(uses, "anthropics/claude-code-action") || strings.Contains(uses, "claude-code"):
			out.actionClass = strPtr("claude")
			isAgent = true
		case strings.Contains(lc, "codex"):
			out.actionClass = strPtr("codex")
			isAgent = true
		case strings.Contains(lc, "gemini") || strings.Contains(lc, "google-gemini"):
			out.actionClass = strPtr("gemini")
			isAgent = true
		case strings.Contains(lc, "ai-action") || strings.HasPrefix(uses, "openai/"):
			out.actionClass = orStrPtr(out.actionClass, "openai")
			isAgent = true
		case strings.Contains(lc, "mcp-server-") || strings.Contains(lc, "modelcontextprotocol"):
			out.actionClass = orStrPtr(out.actionClass, "mcp")
			isAgent = true
		}
		if !isAgent {
			continue
		}

		wblock, _ := step["with"].(map[string]any)

		for _, tk := range []string{"allowed_tools", "allowedTools", "tools", "allowed-tools", "allowedtools"} {
			switch v := wblock[tk].(type) {
			case string:
				for _, tool := range splitToolsRE.Split(v, -1) {
					tool = strings.Trim(tool, " \"'")
					if tool != "" {
						out.tools = appendUnique(out.tools, tool)
					}
				}
			case []any:
				for _, t := range v {
					if s, ok := t.(string); ok {
						out.tools = appendUnique(out.tools, s)
					}
				}
			}
		}

		for _, ak := range []string{"claude_args", "codex_args", "gemini_args", "args"} {
			v, ok := wblock[ak].(string)
			if !ok {
				continue
			}
			argsInspected = append(argsInspected, v)
			if strings.Contains(v, "bypassPermissions") || strings.Contains(v, "--permission-mode bypassPermissions") {
				out.bypassPermissions = true
			}
			for _, m := range allowedToolsArgRE.FindAllStringSubmatch(v, -1) {
				for _, tool := range splitToolsRE.Split(m[1], -1) {
					tool = strings.Trim(tool, " \"'")
					if tool != "" {
						out.tools = appendUnique(out.tools, tool)
					}
				}
			}
		}

		mcpCfg, _ := wblock["mcp_config"].(string)
		if mcpCfg == "" {
			mcpCfg, _ = wblock["mcpConfig"].(string)
		}
		if mcpCfg != "" {
			for _, blk := range mcpServersBlockRE.FindAllStringSubmatch(mcpCfg, -1) {
				for _, sm := range mcpServerNameRE.FindAllStringSubmatch(blk[1], -1) {
					out.mcpServers = appendUnique(out.mcpServers, sm[1])
				}
			}
		}

		for _, ack := range []string{"allowed_users", "allowedUsers", "allowed-users", "trigger_phrases", "allowed_non_write_users"} {
			switch v := wblock[ack].(type) {
			case string:
				out.actorAllowlistRaw = strPtr(v)
				if strings.Contains(v, "*") || isAllOrAny(v) {
					out.allowlistWildcards = append(out.allowlistWildcards, ack)
				}
			case []any:
				out.actorAllowlistRaw = strPtr(pyListStr(v))
				for _, x := range v {
					if strings.Contains(anyToStr(x), "*") {
						out.allowlistWildcards = append(out.allowlistWildcards, ack)
						break
					}
				}
			}
		}

		for _, pk := range []string{"prompt", "system_prompt", "systemPrompt", "user_prompt"} {
			v, ok := wblock[pk].(string)
			if !ok {
				continue
			}
			if strings.Contains(v, "github.event.comment.body") || strings.Contains(v, "comment.body") {
				out.promptSources = append(out.promptSources, "comment.body")
			}
			if strings.Contains(v, "github.event.issue") {
				out.promptSources = append(out.promptSources, "issue")
			}
			if strings.Contains(v, "github.event.pull_request") {
				out.promptSources = append(out.promptSources, "pr")
			}
			vl := strings.ToLower(v)
			if strings.Contains(vl, ".md") || strings.Contains(vl, "agent.md") ||
				strings.Contains(vl, "claude.md") || strings.Contains(vl, "instructions.md") {
				out.promptSources = append(out.promptSources, "md_file")
			}
		}

		for _, arg := range argsInspected {
			if strings.Contains(arg, ".mcp.json") || strings.Contains(arg, "--mcp-config") {
				out.promptSources = appendUnique(out.promptSources, "mcp_config_file")
			}
			al := strings.ToLower(arg)
			if strings.Contains(al, ".md") || strings.Contains(al, "agent.md") || strings.Contains(al, "claude.md") {
				out.promptSources = appendUnique(out.promptSources, "md_file")
			}
		}

		if isWriteOrAdmin(permScope(perms, "issues")) {
			out.outputChannels = appendUnique(out.outputChannels, "pr_comment_or_issue")
		}
		if isWriteOrAdmin(permScope(perms, "pull-requests")) {
			out.outputChannels = appendUnique(out.outputChannels, "pr_review_or_comment")
		}
		if isWriteOrAdmin(permScope(perms, "contents")) {
			out.outputChannels = appendUnique(out.outputChannels, "repo_contents")
		}
		for _, t := range out.tools {
			switch t {
			case "Bash", "bash", "shell", "Shell", "Write", "Edit":
				out.outputChannels = appendUnique(out.outputChannels, "shell_exec")
			}
		}
	}
	return out
}

func loadOrgDefaultPerms(prior engine.PriorPhase, org string) string {
	var env struct {
		Data struct {
			ActionsWorkflowPermissions struct {
				DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
			} `json:"actions_workflow_permissions"`
			ActionsPermissions struct {
				DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
			} `json:"actions_permissions"`
		} `json:"data"`
	}
	if err := engine.ReadJSON(prior.Abs(engine.CollectOrg(org)), &env); err != nil {
		return ""
	}
	if v := env.Data.ActionsWorkflowPermissions.DefaultWorkflowPermissions; v != "" {
		return v
	}
	return env.Data.ActionsPermissions.DefaultWorkflowPermissions
}

func loadRepoDefaultPerms(prior engine.PriorPhase, repo string) string {
	var env struct {
		Data struct {
			WorkflowPermissions struct {
				DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
			} `json:"workflow_permissions"`
		} `json:"data"`
	}
	if err := engine.ReadJSON(prior.Abs(engine.CollectActionsSettings(repo)), &env); err != nil {
		return ""
	}
	return env.Data.WorkflowPermissions.DefaultWorkflowPermissions
}

// loadRefResolutions reads the two collect sources in order; action-resolutions
// overwrite action meta on key collision.
func loadRefResolutions(prior engine.PriorPhase) map[string]string {
	out := map[string]string{}
	collect := func(dir, suffix string) {
		root := prior.Abs(filepath.Join("00-collect", dir))
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(root, e.Name()))
			if err != nil {
				continue
			}
			var rec struct {
				Data struct {
					UsesKey     string `json:"uses_key"`
					ResolvedSHA string `json:"resolved_sha"`
				} `json:"data"`
			}
			if err := json.Unmarshal(b, &rec); err != nil {
				continue
			}
			if rec.Data.UsesKey != "" && rec.Data.ResolvedSHA != "" {
				out[rec.Data.UsesKey] = rec.Data.ResolvedSHA
			}
		}
	}
	collect("actions", ".meta.json")
	collect("action-resolutions", ".json")
	return out
}

func newSourceProvenance(file string, lr *LineRange) *SourceProvenance {
	return &SourceProvenance{File: file, LineRange: lr}
}

func lineRangeOrZero(lr *LineRange) LineRange {
	if lr == nil {
		return LineRange{0, 0}
	}
	return *lr
}

func plainOrNil(node *LineNode) any {
	if node == nil {
		return nil
	}
	return node.Plain()
}

func stringPtrFromAny(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func mapFromAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func permScope(perms map[string]any, key string) string {
	if v, ok := perms[key].(string); ok {
		return v
	}
	return ""
}

func isWriteOrAdmin(v string) bool { return v == "write" || v == "admin" }

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

func appendUniqueNeedsRef(s []NeedsOutputRef, v NeedsOutputRef) []NeedsOutputRef {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// outputFieldRange returns the range of a single output entry under the outputs
// node, falling back to the whole outputs block when the child is absent.
func outputFieldRange(outputsNode *LineNode, name string) *LineRange {
	if child := outputsNode.Field(name); child != nil {
		return child.Range()
	}
	return outputsNode.Range()
}

// nonNilSlice forces a nil slice to a non-nil empty so it marshals as [] not null.
func nonNilSlice[S ~[]E, E any](s S) S {
	if s == nil {
		return S{}
	}
	return s
}

func nonNilFilters(m map[string]TriggerFilter) map[string]TriggerFilter {
	if m == nil {
		return map[string]TriggerFilter{}
	}
	return m
}

func anyToStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func orStrPtr(cur *string, fallback string) *string {
	if cur != nil {
		return cur
	}
	return &fallback
}

func isAllOrAny(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "all" || s == "any"
}

// pyListStr reproduces Python's str(list) repr ('a', 'b') for the raw allowlist
// capture so the stored value matches the Python output byte-for-byte.
func pyListStr(v []any) string {
	parts := make([]string, len(v))
	for i, x := range v {
		if s, ok := x.(string); ok {
			parts[i] = "'" + s + "'"
		} else {
			parts[i] = fmt.Sprint(x)
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func jsonDump(v any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// engineWFStem mirrors engine.wfStem, which is unexported and so cannot be reused.
func engineWFStem(wf string) string {
	wf = strings.TrimSuffix(wf, ".yml")
	wf = strings.TrimSuffix(wf, ".yaml")
	return wf
}
