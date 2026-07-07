package github

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/praetorian-inc/trajan/internal/engine"
	yaml "go.yaml.in/yaml/v4"
)

type usesKind struct {
	Kind  string
	Owner string
	Repo  string
	Path  string
	Ref   string
	Raw   string
}

// Shared across all concurrently-collected repos/branches so a `uses:` ref is
// fetched at most once; all maps are guarded by mu.
type transitiveCache struct {
	mu              sync.Mutex
	written         map[string]bool
	mktResolved     map[string]*string // owner/repo@ref (lowercased) -> commit SHA; nil = unresolved
	mktResolvedSeen map[string]bool
	mktFilesWritten map[string]bool
}

func newTransitiveCache() *transitiveCache {
	return &transitiveCache{
		written:         map[string]bool{},
		mktResolved:     map[string]*string{},
		mktResolvedSeen: map[string]bool{},
		mktFilesWritten: map[string]bool{},
	}
}

// Returns true only to the first caller for outPath, atomically marking it written.
func (tc *transitiveCache) claimWrite(outPath string) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.written[outPath] {
		return false
	}
	tc.written[outPath] = true
	return true
}

// Undoes a claimWrite when the body turned out not to exist, so the claim does
// not permanently poison the cache for a path that was never written.
func (tc *transitiveCache) releaseWrite(outPath string) {
	tc.mu.Lock()
	delete(tc.written, outPath)
	tc.mu.Unlock()
}

func (tc *transitiveCache) claimMarketplaceFile(outPath string) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.mktFilesWritten[outPath] {
		return false
	}
	tc.mktFilesWritten[outPath] = true
	return true
}

type collectWorkflowStats struct {
	Workflows              int
	LocalActions           int
	Reusables              int
	MarketplaceResolutions int
}

func (s collectWorkflowStats) total() int {
	return s.Workflows + s.LocalActions + s.Reusables + s.MarketplaceResolutions
}

const workflowCollector = "00_collect_workflows.py@0.1"

// Transitively (one level) fetches actions and reusable workflows referenced by
// each workflow body. The default branch passes no ref to the Contents API; a
// selected non-default branch threads ref=<branch> through list and fetch.
func collectRepoWorkflows(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	tc *transitiveCache, org, repo, ref string, isDefault bool) (collectWorkflowStats, error) {
	var stats collectWorkflowStats

	listRef := ""
	if !isDefault {
		listRef = ref
	}

	files, err := listWorkflowFiles(ctx, gh, org, repo, listRef)
	if err != nil {
		return stats, err
	}

	for _, entry := range files {
		filename := entry.Name
		body, err := fetchRaw(ctx, gh, org, repo, ".github/workflows/"+filename, listRef)
		if err != nil {
			return stats, err
		}
		if body == nil {
			continue
		}

		if err := cp.WriteRaw(engine.CollectWorkflowYAMLBranch(repo, ref, isDefault, filename), body); err != nil {
			return stats, err
		}
		now := engine.IsoformatUTC(timeNow())
		meta := map[string]any{
			"_meta": collectedMeta(workflowCollector, sourceAPI(gh, surfaceWorkflowFiles),
				"/repos/"+org+"/"+repo+"/contents/.github/workflows/"+filename, now, strPtr(entry.SHA)),
			"data": map[string]any{
				"repo":     repo,
				"filename": filename,
				"sha":      entry.SHA,
				"size":     entry.Size,
			},
		}
		if err := cp.Write(engine.CollectWorkflowMetaBranch(repo, ref, isDefault, filename), meta); err != nil {
			return stats, err
		}
		stats.Workflows++

		text := decodeUTF8Replace(body)
		for _, refStr := range parseUsesReferences(text) {
			info := classifyUses(refStr)
			switch info.Kind {
			case "local_action":
				wrote, err := fetchLocalAction(ctx, gh, cp, tc, org, repo, info.Path, refStr)
				if err != nil {
					return stats, err
				}
				if wrote {
					stats.LocalActions++
				}
			case "local_reusable_workflow":
				wrote, err := fetchLocalReusable(ctx, gh, cp, tc, org, repo, info.Path, refStr)
				if err != nil {
					return stats, err
				}
				if wrote {
					stats.Reusables++
				}
			case "reusable_workflow":
				wrote, err := fetchRemoteReusable(ctx, gh, cp, tc, info, refStr)
				if err != nil {
					return stats, err
				}
				if wrote {
					stats.Reusables++
				}
			case "marketplace":
				wrote, err := resolveMarketplace(ctx, gh, cp, tc, info, refStr)
				if err != nil {
					return stats, err
				}
				if wrote {
					stats.MarketplaceResolutions++
				}
			}
		}
	}
	return stats, nil
}

type workflowEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

// The Contents API returns a bare object (not an array) when the directory holds
// a single file, so that case is unwrapped before filtering to YAML files.
func listWorkflowFiles(ctx context.Context, gh GitHub, org, repo, ref string) ([]workflowEntry, error) {
	var params url.Values
	if ref != "" {
		params = url.Values{"ref": []string{ref}}
	}
	raw, _, err := gh.Get(ctx, "/repos/"+org+"/"+repo+"/contents/.github/workflows", params, true)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	var entries []workflowEntry
	if strings.HasPrefix(trimmed, "{") {
		var single workflowEntry
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, nil
		}
		entries = []workflowEntry{single}
	} else {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, nil
		}
	}
	out := entries[:0]
	for _, e := range entries {
		if e.Type == "file" && (strings.HasSuffix(e.Name, ".yml") || strings.HasSuffix(e.Name, ".yaml")) {
			out = append(out, e)
		}
	}
	return out, nil
}

// A 404 returns (nil, nil); other errors propagate.
func fetchRaw(ctx context.Context, gh GitHub, org, repo, pathInRepo, ref string) ([]byte, error) {
	var params url.Values
	if ref != "" {
		params = url.Values{"ref": []string{ref}}
	}
	body, _, err := gh.GetRaw(ctx, "/repos/"+org+"/"+repo+"/contents/"+pathInRepo, params, "application/vnd.github.raw+json")
	if err != nil {
		var ghErr *GhError
		if asGhError(err, &ghErr) && ghErr.Status == 404 {
			return nil, nil
		}
		return nil, err
	}
	return body, nil
}

// Probes action.yml then action.yaml at HEAD. Returns whether a new file was
// written (false on a dedup hit or when neither file exists).
func fetchLocalAction(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	tc *transitiveCache, org, repo, actionPath, refStr string) (bool, error) {
	outPath := engine.CollectActionYAML(org, repo, actionPath, "HEAD")
	if !tc.claimWrite(outPath) {
		return false, nil
	}
	var fname, sha string
	var body []byte
	for _, candidate := range []string{"action.yml", "action.yaml"} {
		full := strings.TrimLeft(actionPath+"/"+candidate, "/")
		b, s, ok, err := gh.GetContentWithSHA(ctx, "/repos/"+org+"/"+repo+"/contents/"+full, "", true)
		if err != nil {
			return false, err
		}
		if ok {
			fname, sha, body = candidate, s, b
			break
		}
	}
	if body == nil {
		tc.releaseWrite(outPath)
		return false, nil
	}
	if err := cp.WriteRaw(outPath, body); err != nil {
		return false, err
	}
	now := engine.IsoformatUTC(timeNow())
	meta := map[string]any{
		"_meta": collectedMeta(workflowCollector, sourceAPI(gh, surfaceLocalActions),
			"/repos/"+org+"/"+repo+"/contents/"+actionPath+"/"+fname, now, strPtr(sha)),
		"data": map[string]any{
			"uses_key":         repo + "::" + refStr,
			"kind":             "local_action",
			"owner":            org,
			"repo":             repo,
			"path":             actionPath,
			"ref":              "HEAD",
			"resolved_sha":     sha,
			"resolved_at":      now,
			"fetched_filename": fname,
		},
	}
	if err := cp.Write(engine.CollectActionMeta(org, repo, actionPath, "HEAD"), meta); err != nil {
		return false, err
	}
	return true, nil
}

// Fetches the reusable workflow body directly at HEAD, not via the action.yml probe.
func fetchLocalReusable(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	tc *transitiveCache, org, repo, localPath, refStr string) (bool, error) {
	outPath := engine.CollectActionYAML(org, repo, localPath, "HEAD")
	if !tc.claimWrite(outPath) {
		return false, nil
	}
	body, sha, ok, err := gh.GetContentWithSHA(ctx, "/repos/"+org+"/"+repo+"/contents/"+localPath, "", true)
	if err != nil {
		return false, err
	}
	if !ok {
		tc.releaseWrite(outPath)
		return false, nil
	}
	if err := cp.WriteRaw(outPath, body); err != nil {
		return false, err
	}
	now := engine.IsoformatUTC(timeNow())
	meta := map[string]any{
		"_meta": collectedMeta(workflowCollector, sourceAPI(gh, surfaceLocalActions),
			"/repos/"+org+"/"+repo+"/contents/"+localPath, now, strPtr(sha)),
		"data": map[string]any{
			"uses_key":     repo + "::" + refStr,
			"kind":         "local_reusable_workflow",
			"owner":        org,
			"repo":         repo,
			"path":         localPath,
			"ref":          "HEAD",
			"resolved_sha": sha,
			"resolved_at":  now,
		},
	}
	if err := cp.Write(engine.CollectActionMeta(org, repo, localPath, "HEAD"), meta); err != nil {
		return false, err
	}
	return true, nil
}

func fetchRemoteReusable(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	tc *transitiveCache, info usesKind, refStr string) (bool, error) {
	outPath := engine.CollectActionYAML(info.Owner, info.Repo, info.Path, info.Ref)
	if !tc.claimWrite(outPath) {
		return false, nil
	}
	body, sha, ok, err := gh.GetContentWithSHA(ctx,
		"/repos/"+info.Owner+"/"+info.Repo+"/contents/"+info.Path, info.Ref, true)
	if err != nil {
		return false, err
	}
	if !ok {
		tc.releaseWrite(outPath)
		return false, nil
	}
	if err := cp.WriteRaw(outPath, body); err != nil {
		return false, err
	}
	now := engine.IsoformatUTC(timeNow())
	meta := map[string]any{
		"_meta": collectedMeta(workflowCollector, sourceAPI(gh, surfaceWorkflowFiles),
			"/repos/"+info.Owner+"/"+info.Repo+"/contents/"+info.Path, now, strPtr(sha)),
		"data": map[string]any{
			"uses_key":     refStr,
			"kind":         "reusable_workflow",
			"owner":        info.Owner,
			"repo":         info.Repo,
			"path":         info.Path,
			"ref":          info.Ref,
			"resolved_sha": sha,
			"resolved_at":  now,
		},
	}
	if err := cp.Write(engine.CollectActionMeta(info.Owner, info.Repo, info.Path, info.Ref), meta); err != nil {
		return false, err
	}
	return true, nil
}

// Resolves a marketplace action's ref to a commit SHA without fetching its body.
// The lowercased owner/repo@ref network lookup is memoized so case-variant refs
// share one resolution, but one file is still written per literal path.
func resolveMarketplace(ctx context.Context, gh GitHub, cp engine.CurrentPhase,
	tc *transitiveCache, info usesKind, refStr string) (bool, error) {
	mkey := strings.ToLower(info.Owner) + "/" + strings.ToLower(info.Repo) + "@" + info.Ref

	tc.mu.Lock()
	seen := tc.mktResolvedSeen[mkey]
	commitSHA := tc.mktResolved[mkey]
	tc.mu.Unlock()

	if !seen {
		sha, err := gh.ResolveRefCommitSHA(ctx, info.Owner, info.Repo, info.Ref)
		if err != nil {
			var ghErr *GhError
			if !asGhError(err, &ghErr) {
				return false, err
			}
			sha = "" // a GhError leaves the ref unresolved rather than aborting
		}
		var resolved *string
		if sha != "" {
			resolved = &sha
		}
		tc.mu.Lock()
		tc.mktResolvedSeen[mkey] = true
		tc.mktResolved[mkey] = resolved
		commitSHA = resolved
		tc.mu.Unlock()
	}

	outRes := engine.CollectRefResolution(info.Owner, info.Repo, info.Ref)
	if !tc.claimMarketplaceFile(outRes) {
		return false, nil
	}
	now := engine.IsoformatUTC(timeNow())
	var shaVal any
	if commitSHA != nil {
		shaVal = *commitSHA
	}
	record := map[string]any{
		"_meta": collectedMeta(workflowCollector, sourceAPI(gh, surfaceRefResolve),
			"/repos/"+info.Owner+"/"+info.Repo+"/commits/"+info.Ref, now, commitSHA),
		"data": map[string]any{
			"uses_key":     refStr,
			"kind":         "marketplace",
			"owner":        info.Owner,
			"repo":         info.Repo,
			"ref":          info.Ref,
			"resolved_sha": shaVal,
			"resolved_at":  now,
		},
	}
	if err := cp.Write(outRes, record); err != nil {
		return false, err
	}
	return true, nil
}

func parseUsesReferences(yamlText string) []string {
	var doc any
	if err := yaml.Unmarshal([]byte(yamlText), &doc); err != nil {
		return nil
	}
	var refs []string
	var walk func(node any)
	walk = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				if k == "uses" {
					if s, ok := v.(string); ok {
						refs = append(refs, s)
						continue
					}
				}
				walk(v)
			}
		case map[any]any:
			for k, v := range n {
				if ks, ok := k.(string); ok && ks == "uses" {
					if s, ok := v.(string); ok {
						refs = append(refs, s)
						continue
					}
				}
				walk(v)
			}
		case []any:
			for _, item := range n {
				walk(item)
			}
		}
	}
	walk(doc)
	return refs
}

func classifyUses(ref string) usesKind {
	if strings.HasPrefix(ref, "./") {
		if isReusableWorkflowRef(ref) {
			return usesKind{Kind: "local_reusable_workflow", Path: strings.TrimPrefix(ref, "./")}
		}
		if isLocalCompositeRef(ref) {
			return usesKind{Kind: "local_action", Path: strings.TrimPrefix(ref, "./")}
		}
		return usesKind{Kind: "unknown", Raw: ref}
	}
	if strings.HasPrefix(ref, "docker://") {
		return usesKind{Kind: "docker"}
	}
	if !strings.Contains(ref, "@") {
		return usesKind{Kind: "unknown", Raw: ref}
	}
	head, refPart, _ := strings.Cut(ref, "@")
	parts := strings.SplitN(head, "/", 3)
	if len(parts) < 2 {
		return usesKind{Kind: "unknown", Raw: ref}
	}
	owner := parts[0]
	repo := parts[1]
	pathInRepo := ""
	if len(parts) == 3 {
		pathInRepo = parts[2]
	}
	if (strings.HasSuffix(pathInRepo, ".yml") || strings.HasSuffix(pathInRepo, ".yaml")) &&
		strings.Contains(pathInRepo+"/", ".github/workflows/") {
		return usesKind{Kind: "reusable_workflow", Owner: owner, Repo: repo, Path: pathInRepo, Ref: refPart}
	}
	return usesKind{Kind: "marketplace", Owner: owner, Repo: repo, Path: pathInRepo, Ref: refPart}
}

var reusableLocalRE = regexp.MustCompile(`^\./\.github/workflows/[^/]+\.ya?ml$`)
var reusableRemoteTailRE = regexp.MustCompile(`(?:^|/)\.github/workflows/[^/]+\.ya?ml$`)

func isReusableWorkflowRef(uses string) bool {
	if strings.HasPrefix(uses, "./") {
		return reusableLocalRE.MatchString(uses)
	}
	if !strings.Contains(uses, "@") {
		return false
	}
	head, _, _ := strings.Cut(uses, "@")
	return strings.Count(head, "/") >= 2 && reusableRemoteTailRE.MatchString(head)
}

func isLocalCompositeRef(uses string) bool {
	if !strings.HasPrefix(uses, "./") {
		return false
	}
	if strings.HasSuffix(uses, ".yml") || strings.HasSuffix(uses, ".yaml") {
		return false
	}
	return true
}
