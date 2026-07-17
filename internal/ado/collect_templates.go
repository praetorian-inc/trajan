package ado

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	yaml "go.yaml.in/yaml/v4"

	"github.com/praetorian-inc/trajan/internal/engine"
)

const maxTemplateDepth = 5

// collectPipelineYAML fetches the entry YAML for a build definition and then
// recursively fetches its extends/template closure (cat-08). Template bodies are
// recoverable from neither the build definition nor preview, so collect must
// resolve and fetch them here.
func collectPipelineYAML(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, repos []repoRef, id int64, full json.RawMessage) error {
	repoObj := objField(full, "repository")
	repoID := strField(repoObj, "id")
	repoType := strField(repoObj, "type")
	yamlPath := strField(objField(full, "process"), "yamlFilename")
	if repoID == "" || yamlPath == "" || !strings.EqualFold(repoType, "TfsGit") {
		return nil // classic pipeline or non-Azure-Repos source: git items won't serve it
	}
	branch := stripRef(strField(repoObj, "defaultBranch"))
	if branch == "" {
		branch = "main"
	}

	byName := make(map[string]string, len(repos))
	for _, r := range repos {
		byName[strings.ToLower(r.Name)] = r.ID
	}

	visited := map[string]bool{}
	return fetchYAMLClosure(ctx, cl, cp, project, byName, id, repoID, yamlPath, branch, 0, visited)
}

func fetchYAMLClosure(ctx context.Context, cl ADO, cp engine.CurrentPhase, project string, reposByName map[string]string, pipelineID int64, repoID, path, version string, depth int, visited map[string]bool) error {
	key := repoID + "|" + path + "|" + version
	if visited[key] || depth > maxTemplateDepth {
		return nil
	}
	visited[key] = true

	raw, content, status, err := fetchItem(ctx, cl, project, repoID, path, version)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s@%s__%s", repoID, version, path)
	if status != 0 {
		return envelope(cp, engine.CollectADOPipelineYAML(project, pipelineID, name), "pipeline-yaml",
			itemPath(project, repoID, path, version),
			map[string]any{"_unresolved": true, "_status": status, "repo_id": repoID, "path": path, "version": version})
	}
	if err := envelope(cp, engine.CollectADOPipelineYAML(project, pipelineID, name), "pipeline-yaml",
		itemPath(project, repoID, path, version), raw); err != nil {
		return err
	}

	refs, aliases := parseTemplateRefs(content)
	for _, r := range refs {
		targetRepo, targetVer := repoID, version
		if r.alias != "" {
			res, ok := aliases[strings.ToLower(r.alias)]
			if !ok {
				continue // unknown alias
			}
			rid, ok := reposByName[strings.ToLower(lastSegment(res.name))]
			if !ok {
				// cross-project or external template repo: record the reference, don't fetch
				_ = envelope(cp, engine.CollectADOPipelineYAML(project, pipelineID,
					fmt.Sprintf("unresolved__%s__%s", r.alias, adoName(r.path))), "pipeline-yaml", "",
					map[string]any{"_unresolved_external": true, "alias": r.alias, "repository": res.name, "ref": res.ref, "path": r.path})
				continue
			}
			targetRepo = rid
			if v := stripRef(res.ref); v != "" {
				targetVer = v
			}
		}
		if err := fetchYAMLClosure(ctx, cl, cp, project, reposByName, pipelineID, targetRepo, normalizePath(r.path), targetVer, depth+1, visited); err != nil {
			return err
		}
	}
	return nil
}

func fetchItem(ctx context.Context, cl ADO, project, repoID, path, version string) (json.RawMessage, string, int, error) {
	p := fmt.Sprintf("/%s/_apis/git/repositories/%s/items", url.PathEscape(project), repoID)
	params := url.Values{
		"path":                          []string{normalizePath(path)},
		"includeContent":                []string{"true"},
		"versionDescriptor.version":     []string{version},
		"versionDescriptor.versionType": []string{"branch"},
	}
	raw, _, err := cl.Get(ctx, "core", APIVersion, p, params, true)
	if err != nil {
		if isSoft(err) {
			return nil, "", softStatus(err), nil
		}
		return nil, "", 0, err
	}
	if raw == nil {
		return nil, "", 404, nil
	}
	return raw, strField(raw, "content"), 0, nil
}

func itemPath(project, repoID, path, version string) string {
	return fmt.Sprintf("/%s/_apis/git/repositories/%s/items?path=%s&version=%s", project, repoID, normalizePath(path), version)
}

type templateRef struct {
	path  string
	alias string
}

type repoResource struct {
	name string
	ref  string
}

// parseTemplateRefs walks a pipeline/template YAML for every `template:` and
// `extends.template` string reference, and the `resources.repositories` alias map.
func parseTemplateRefs(content string) ([]templateRef, map[string]repoResource) {
	var root any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return nil, nil
	}
	var refs []templateRef
	aliases := map[string]repoResource{}
	collectRepoResources(root, aliases)
	walkTemplateNodes(root, &refs)
	return refs, aliases
}

func walkTemplateNodes(node any, refs *[]templateRef) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			if k == "template" {
				if s, ok := val.(string); ok && s != "" {
					*refs = append(*refs, splitTemplateRef(s))
				}
			}
			walkTemplateNodes(val, refs)
		}
	case []any:
		for _, e := range v {
			walkTemplateNodes(e, refs)
		}
	}
}

func collectRepoResources(node any, out map[string]repoResource) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if res, ok := m["resources"].(map[string]any); ok {
		if list, ok := res["repositories"].([]any); ok {
			for _, e := range list {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				alias, _ := em["repository"].(string)
				if alias == "" {
					continue
				}
				name, _ := em["name"].(string)
				ref, _ := em["ref"].(string)
				out[strings.ToLower(alias)] = repoResource{name: name, ref: ref}
			}
		}
	}
}

func splitTemplateRef(s string) templateRef {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return templateRef{path: s[:i], alias: s[i+1:]}
	}
	return templateRef{path: s}
}

func stripRef(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	return ref
}

func normalizePath(p string) string {
	if p == "" {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func adoName(s string) string {
	return strings.ReplaceAll(strings.TrimPrefix(s, "/"), "/", "__")
}
