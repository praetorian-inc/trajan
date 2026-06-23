package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Backstops pathological non-catch-all globs in non-default branch selection.
const maxSelectedBranches = 64

var timeNow = time.Now

func Collect(ctx context.Context, cfg *engine.Config, locator string) (string, error) {
	scope, err := ParseScope(locator)
	if err != nil {
		return "", err
	}

	token, err := ResolveToken(ctx)
	if err != nil {
		return "", err
	}
	// Router decorator: dispatches each surface to its preferred capable
	// transport, synthesizing REST-shaped results so collectors stay unchanged.
	gh := newRouter(NewClient(token))
	defer closeRouter(gh)

	runDir, err := engine.MintRunDir(cfg, "gh", scope.Slug)
	if err != nil {
		return "", err
	}

	state, err := engine.LoadState(runDir)
	if err != nil {
		return "", err
	}
	if err := state.CheckPhase(engine.PhaseCollect); err != nil {
		return "", err
	}
	for _, d := range state.StaleDirs(engine.PhaseCollect) {
		if err := os.RemoveAll(filepath.Join(runDir, d)); err != nil {
			return "", err
		}
	}
	state.Platform = "gh"
	state.Scope = scopeString(scope)
	state.Org = scope.Org
	state.Invocation = os.Args[1:]
	if state.StartedAt == "" {
		state.StartedAt = engine.IsoformatUTC(timeNow())
	}

	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")
	cp := engine.CurrentPhase{RunDir: runDir}

	collectErr := runCollect(ctx, cfg, gh, cp, scope, timer)

	rec := timer.Stop(collectErr)
	state.RecordPhase(rec)
	if err := state.Save(runDir); err != nil {
		return runDir, err
	}
	if collectErr != nil {
		return runDir, collectErr
	}
	return runDir, nil
}

// Org rulesets MUST precede workflow collection because non-default-branch
// selection consumes them. The members collector runs last because it
// enumerates the collected repo files for per-repo collaborators.
func runCollect(ctx context.Context, cfg *engine.Config, gh GitHub, cp engine.CurrentPhase,
	scope Scope, timer *engine.PhaseTimer) error {
	org := scope.Org

	softSurface(timer, "org", func() error { return collectOrg(ctx, gh, cp, org) })
	softSurface(timer, "rulesets-org", func() error { return collectRulesets(ctx, gh, cp, org, "") })
	softSurface(timer, "secrets-org", func() error { return collectSecrets(ctx, gh, cp, org, "") })
	softSurface(timer, "variables-org", func() error { return collectVariables(ctx, gh, cp, org, "") })
	softSurface(timer, "runners-org", func() error { return collectRunners(ctx, gh, cp, org, "") })
	softSurface(timer, "apps", func() error { return collectApps(ctx, gh, cp, org) })

	repos, err := enumerateRepos(ctx, gh, scope)
	if err != nil {
		return err
	}
	timer.InputFiles = len(repos)

	tc := newTransitiveCache()

	results := engine.RunPartial(ctx, cfg.Concurrency, repos,
		func(ctx context.Context, r repoTarget) (int, error) {
			return collectOneRepo(ctx, gh, cp, r, tc, timer)
		},
		func(r repoTarget, e error) {
			appendErr(timer, fmt.Sprintf("%s: %v", r.Repo, e))
		},
	)
	written := 0
	for _, n := range results {
		written += n
	}
	timer.OutputFiles = written

	softSurface(timer, "members", func() error { return collectMembers(ctx, gh, cp, org) })
	return nil
}

type repoTarget struct {
	Owner string
	Repo  string
}

// Rulesets + environments must precede workflow collection because branch
// selection consumes them; workflows are therefore collected last per repo.
func collectOneRepo(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	r repoTarget, tc *transitiveCache, timer *engine.PhaseTimer) (int, error) {
	org, repo := r.Owner, r.Repo

	softSurface(timer, repo+"/repo", func() error { return collectRepo(ctx, gh, cp, org, repo) })
	softSurface(timer, repo+"/actions-settings", func() error { return collectActionsSettings(ctx, gh, cp, org, repo) })
	softSurface(timer, repo+"/rulesets", func() error { return collectRulesets(ctx, gh, cp, org, repo) })
	softSurface(timer, repo+"/environments", func() error { return collectEnvironments(ctx, gh, cp, org, repo) })
	softSurface(timer, repo+"/secrets", func() error { return collectSecrets(ctx, gh, cp, org, repo) })
	softSurface(timer, repo+"/variables", func() error { return collectVariables(ctx, gh, cp, org, repo) })
	softSurface(timer, repo+"/runners", func() error { return collectRunners(ctx, gh, cp, org, repo) })
	softSurface(timer, repo+"/deploy-keys", func() error { return collectDeployKeys(ctx, gh, cp, org, repo) })

	def := defaultBranch(cp, repo)

	written := 0
	stats, err := collectRepoWorkflows(ctx, gh, cp, tc, org, repo, def, true)
	if err != nil {
		return written, err
	}
	written += stats.total()

	selected, selErrs := selectBranchesToScan(ctx, gh, cp, org, repo, def)
	for _, e := range selErrs {
		appendErr(timer, e)
	}
	for _, b := range selected {
		stats, err := collectRepoWorkflows(ctx, gh, cp, tc, org, repo, b, false)
		if err != nil {
			return written, err
		}
		written += stats.total()
	}
	return written, nil
}

// With git active, scan ALL branches; otherwise fall back to the cost-driven
// REST selection. Both honor TRAJAN_DEFAULT_BRANCH_ONLY.
func selectBranchesToScan(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	org, repo, def string) ([]string, []string) {
	if defaultBranchOnly() {
		return nil, nil
	}
	if gitActive(gh) {
		branches, err := listBranches(ctx, gh, org, repo)
		if err != nil {
			var ghErr *GhError
			if asGhError(err, &ghErr) {
				return nil, []string{fmt.Sprintf("%s: branch enumeration unavailable (%v)", repo, err)}
			}
			return nil, []string{fmt.Sprintf("%s: branch enumeration failed (%v)", repo, err)}
		}
		var out []string
		for _, b := range branches {
			if b != def {
				out = append(out, b)
			}
		}
		slices.Sort(out)
		return out, nil
	}
	return selectNonDefaultBranches(ctx, gh, cp, org, repo, def)
}

func defaultBranchOnly() bool {
	v := strings.TrimSpace(os.Getenv("TRAJAN_DEFAULT_BRANCH_ONLY"))
	return v != "" && v != "0" && v != "false"
}

// gitActive gates the all-branches path: false under forced-REST or when git is
// unavailable, so those runs keep the cost-driven REST branch selection.
func gitActive(gh GitHub) bool {
	r, ok := gh.(*router)
	return ok && r.git != nil
}

func enumerateRepos(ctx context.Context, gh GitHub, scope Scope) ([]repoTarget, error) {
	if scope.Repo != "" {
		return []repoTarget{{Owner: scope.Org, Repo: scope.Repo}}, nil
	}
	items, err := gh.Paginate(ctx, "/orgs/"+scope.Org+"/repos", url.Values{"type": []string{"all"}}, 100)
	if err != nil {
		return nil, err
	}
	out := make([]repoTarget, 0, len(items))
	for _, raw := range items {
		var r struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || r.Name == "" {
			continue
		}
		out = append(out, repoTarget{Owner: scope.Org, Repo: r.Name})
	}
	return out, nil
}

// Reuses the already-collected repo bundle rather than re-querying.
func defaultBranch(cp engine.CurrentPhase, repo string) string {
	var env struct {
		Data struct {
			Repo struct {
				DefaultBranch string `json:"default_branch"`
			} `json:"repo"`
		} `json:"data"`
	}
	if err := engine.ReadJSON(filepath.Join(cp.RunDir, engine.CollectRepo(repo)), &env); err == nil {
		if env.Data.Repo.DefaultBranch != "" {
			return env.Data.Repo.DefaultBranch
		}
	}
	return "main"
}

// Optional surfaces must never abort the run, so every failure is recorded and
// swallowed here. Workflow collection propagates hard errors itself.
func softSurface(timer *engine.PhaseTimer, label string, fn func() error) {
	if err := fn(); err != nil {
		appendErr(timer, fmt.Sprintf("%s: %v", label, err))
	}
}

// Guards the shared timer.Errors slice against concurrent RunPartial workers.
var errMu sync.Mutex

func appendErr(timer *engine.PhaseTimer, msg string) {
	errMu.Lock()
	timer.Errors = append(timer.Errors, msg)
	errMu.Unlock()
	slog.Warn("collect surface degraded", "detail", msg)
}

func scopeString(s Scope) string {
	if s.Repo != "" {
		return s.Org + "/" + s.Repo
	}
	return s.Org
}

// The "sha" key is always present, serialized as null when sha is nil.
func collectedMeta(collector, sourceAPI, path, collectedAt string, sha *string) map[string]any {
	var shaVal any
	if sha != nil {
		shaVal = *sha
	}
	return map[string]any{
		"collected_at": collectedAt,
		"collector":    collector,
		"source":       map[string]any{"api": sourceAPI, "path": path},
		"sha":          shaVal,
	}
}

// Maps "" to nil so an empty sha serializes as null.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func decodeUTF8Replace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

func selectNonDefaultBranches(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	org, repo, def string) ([]string, []string) {
	var errs []string

	branches, err := listBranches(ctx, gh, org, repo)
	if err != nil {
		var ghErr *GhError
		if asGhError(err, &ghErr) {
			return nil, []string{fmt.Sprintf("%s: branch enumeration unavailable (%v)", repo, err)}
		}
		return nil, []string{fmt.Sprintf("%s: branch enumeration failed (%v)", repo, err)}
	}

	repoRS := readRulesets(cp, engine.CollectRulesetsRepo(repo))
	orgRS := readRulesets(cp, engine.CollectRulesetsOrg(org))
	envs := readEnvironments(cp, repo)

	repoID, repoProps := readRepoIdentity(cp, repo)

	selected, selErrs := selectBranches(branches, def, repo, repoRS, orgRS, envs, repoID, repoProps)
	errs = append(errs, selErrs...)
	return selected, errs
}

func listBranches(ctx context.Context, gh GitHub, org, repo string) ([]string, error) {
	items, err := gh.Paginate(ctx, "/repos/"+org+"/"+repo+"/branches", nil, 100)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, raw := range items {
		var b struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &b); err == nil && b.Name != "" {
			out = append(out, b.Name)
		}
	}
	return out, nil
}

type refNameCond struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type repoNameCond struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type repoIDCond struct {
	RepositoryIDs []int64 `json:"repository_ids"`
}

type repoPropEntry struct {
	Name           string   `json:"name"`
	PropertyValues []string `json:"property_values"`
}

type repoPropCond struct {
	Include []repoPropEntry `json:"include"`
	Exclude []repoPropEntry `json:"exclude"`
}

type rulesetConditions struct {
	RefName            *refNameCond  `json:"ref_name"`
	RepositoryName     *repoNameCond `json:"repository_name"`
	RepositoryID       *repoIDCond   `json:"repository_id"`
	RepositoryProperty *repoPropCond `json:"repository_property"`
}

type ruleset struct {
	Enforcement string            `json:"enforcement"`
	Conditions  rulesetConditions `json:"conditions"`
	scopeIsOrg  bool
}

type deploymentBranchPolicy struct {
	CustomBranchPolicies bool `json:"custom_branch_policies"`
}

type envBranchPolicy struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type environment struct {
	dbp      *deploymentBranchPolicy
	patterns []envBranchPolicy
}

func readRulesets(cp engine.CurrentPhase, rel string) []ruleset {
	var env struct {
		Data struct {
			Scope    string            `json:"scope"`
			Rulesets []json.RawMessage `json:"rulesets"`
		} `json:"data"`
	}
	if err := engine.ReadJSON(filepath.Join(cp.RunDir, rel), &env); err != nil {
		return nil
	}
	isOrg := env.Data.Scope == "org"
	out := make([]ruleset, 0, len(env.Data.Rulesets))
	for _, raw := range env.Data.Rulesets {
		var rs ruleset
		if err := json.Unmarshal(raw, &rs); err != nil {
			continue
		}
		rs.scopeIsOrg = isOrg
		out = append(out, rs)
	}
	return out
}

func readEnvironments(cp engine.CurrentPhase, repo string) []environment {
	dir := filepath.Dir(filepath.Join(cp.RunDir, engine.CollectEnvironment(repo, "_")))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []environment
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var env struct {
			Data struct {
				Base struct {
					DeploymentBranchPolicy *deploymentBranchPolicy `json:"deployment_branch_policy"`
				} `json:"base"`
				BranchPolicies struct {
					BranchPolicies []envBranchPolicy `json:"branch_policies"`
				} `json:"branch_policies"`
			} `json:"data"`
		}
		if err := engine.ReadJSON(filepath.Join(dir, e.Name()), &env); err != nil {
			continue
		}
		out = append(out, environment{
			dbp:      env.Data.Base.DeploymentBranchPolicy,
			patterns: env.Data.BranchPolicies.BranchPolicies,
		})
	}
	return out
}

// Absent properties return nil, on which the by-property org-ruleset gate fails closed.
func readRepoIdentity(cp engine.CurrentPhase, repo string) (int64, map[string]string) {
	var env struct {
		Data struct {
			Repo struct {
				ID int64 `json:"id"`
			} `json:"repo"`
			Properties []struct {
				PropertyName string `json:"property_name"`
				Value        string `json:"value"`
			} `json:"properties"`
		} `json:"data"`
	}
	if err := engine.ReadJSON(filepath.Join(cp.RunDir, engine.CollectRepo(repo)), &env); err != nil {
		return 0, nil
	}
	var props map[string]string
	if len(env.Data.Properties) > 0 {
		props = make(map[string]string, len(env.Data.Properties))
		for _, p := range env.Data.Properties {
			props[p.PropertyName] = p.Value
		}
	}
	return env.Data.Repo.ID, props
}

func selectBranches(branches []string, def, repoName string,
	repoRS, orgRS []ruleset, envs []environment,
	repoID int64, repoProps map[string]string) (selected []string, errs []string) {
	seen := map[string]bool{}
	for _, b := range branches {
		if b == def {
			continue
		}
		hit := false
		for _, rs := range repoRS {
			if rulesetSelectsBranch(rs, b, def, "", 0, nil) {
				hit = true
				break
			}
		}
		if !hit {
			for _, rs := range orgRS {
				if rulesetSelectsBranch(rs, b, def, repoName, repoID, repoProps) {
					hit = true
					break
				}
			}
		}
		if !hit {
			for _, e := range envs {
				if envSelectsBranch(e, b, def) {
					hit = true
					break
				}
			}
		}
		if hit && !seen[b] {
			seen[b] = true
			selected = append(selected, b)
		}
	}
	slices.Sort(selected)
	if len(selected) > maxSelectedBranches {
		errs = append(errs, fmt.Sprintf("branch selection truncated at %d for %s", maxSelectedBranches, repoName))
		selected = selected[:maxSelectedBranches]
	}
	return
}

func rulesetSelectsBranch(rs ruleset, branch, def, repoName string, repoID int64, repoProps map[string]string) bool {
	if rs.Enforcement != "active" {
		return false
	}
	if rs.Conditions.RefName == nil {
		return false
	}
	inc := rs.Conditions.RefName.Include
	exc := rs.Conditions.RefName.Exclude
	if !refMatchAnyNonCatchall(branch, def, inc) {
		return false
	}
	if len(exc) > 0 && refMatchAny(branch, def, exc) {
		return false
	}
	if rs.scopeIsOrg && !orgRepoGate(rs.Conditions, repoName, repoID, repoProps) {
		return false
	}
	return true
}

// The org-ruleset repo-scoping conditions are mutually exclusive; unresolvable
// id/property data fails closed.
func orgRepoGate(c rulesetConditions, repoName string, repoID int64, repoProps map[string]string) bool {
	switch {
	case c.RepositoryName != nil:
		rn := c.RepositoryName
		if len(rn.Include) > 0 && !(slices.Contains(rn.Include, "~ALL") || refMatchAny(repoName, "", rn.Include)) {
			return false
		}
		if len(rn.Exclude) > 0 && refMatchAny(repoName, "", rn.Exclude) {
			return false
		}
		return true
	case c.RepositoryID != nil:
		if repoID == 0 {
			return false
		}
		for _, id := range c.RepositoryID.RepositoryIDs {
			if id == repoID {
				return true
			}
		}
		return false
	case c.RepositoryProperty != nil:
		if repoProps == nil {
			return false
		}
		if len(c.RepositoryProperty.Include) > 0 && !propAny(c.RepositoryProperty.Include, repoProps) {
			return false
		}
		if len(c.RepositoryProperty.Exclude) > 0 && propAny(c.RepositoryProperty.Exclude, repoProps) {
			return false
		}
		return true
	default:
		return true
	}
}

func propAny(entries []repoPropEntry, repoProps map[string]string) bool {
	for _, e := range entries {
		v, ok := repoProps[e.Name]
		if !ok {
			continue
		}
		if slices.Contains(e.PropertyValues, v) {
			return true
		}
	}
	return false
}

func envSelectsBranch(e environment, branch, def string) bool {
	if e.dbp == nil || !e.dbp.CustomBranchPolicies {
		return false
	}
	for _, p := range e.patterns {
		if p.Type != "branch" {
			continue
		}
		if !isCatchAll(p.Name) && refMatch(branch, def, p.Name) {
			return true
		}
	}
	return false
}

func refMatch(branch, def, pat string) bool {
	switch pat {
	case "~ALL":
		return true
	case "~DEFAULT_BRANCH":
		return branch == def
	case branch:
		return true
	}
	if fnmatchSlash(branch, pat) {
		return true
	}
	if strings.HasPrefix(pat, "refs/heads/") && fnmatchSlash("refs/heads/"+branch, pat) {
		return true
	}
	return false
}

func refMatchAny(branch, def string, pats []string) bool {
	for _, p := range pats {
		if refMatch(branch, def, p) {
			return true
		}
	}
	return false
}

func isCatchAll(pat string) bool {
	switch pat {
	case "~ALL", "~DEFAULT_BRANCH", "*", "**", "refs/heads/*", "refs/heads/**":
		return true
	}
	return false
}

func refMatchAnyNonCatchall(branch, def string, pats []string) bool {
	for _, p := range pats {
		if !isCatchAll(p) && refMatch(branch, def, p) {
			return true
		}
	}
	return false
}

// Slash-aware glob (* does not cross /), unlike a plain fnmatch which over-matches.
func fnmatchSlash(s, pat string) bool {
	re, err := globToRegexp(pat)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

func globToRegexp(pat string) (*regexp.Regexp, error) {
	globMu.Lock()
	if re, ok := globCache[pat]; ok {
		globMu.Unlock()
		return re, nil
	}
	globMu.Unlock()
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch c {
		case '*':
			if i+1 < len(pat) && pat[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	globMu.Lock()
	globCache[pat] = re
	globMu.Unlock()
	return re, nil
}
