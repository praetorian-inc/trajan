package gitlab

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
)

// Not safe for concurrent use.
type IncludeResolver struct {
	client     *Client
	projectID  int
	defaultRef string
	cache      map[string]*parser.NormalizedWorkflow
	processed  map[string]bool // cycle detection
	maxDepth   int
}

type IncludedWorkflow struct {
	Source   string // cache key
	Path     string // display path
	Type     string // local, project, template
	Content  []byte
	Workflow *parser.NormalizedWorkflow
	Includes []*IncludedWorkflow
}

func NewIncludeResolver(client *Client, projectID int, ref string) *IncludeResolver {
	return &IncludeResolver{
		client:     client,
		projectID:  projectID,
		defaultRef: ref,
		cache:      make(map[string]*parser.NormalizedWorkflow),
		processed:  make(map[string]bool),
		maxDepth:   10,
	}
}

// Parsing the cache key instead would break on paths containing colons.
func getDisplayPath(inc parser.GitLabInclude) string {
	switch inc.Type {
	case parser.IncludeTypeLocal:
		return inc.Path
	case parser.IncludeTypeProject:
		return inc.Path
	case parser.IncludeTypeTemplate:
		return inc.Template
	case parser.IncludeTypeRemote:
		return inc.Remote
	default:
		return ""
	}
}

func (r *IncludeResolver) makeKey(inc parser.GitLabInclude) string {
	switch inc.Type {
	case parser.IncludeTypeLocal:
		return fmt.Sprintf("local:%d:%s:%s", r.projectID, inc.Path, r.defaultRef)
	case parser.IncludeTypeProject:
		ref := inc.Ref
		if ref == "" {
			ref = "HEAD"
		}
		return fmt.Sprintf("project:%s:%s:%s", inc.Project, inc.Path, ref)
	case parser.IncludeTypeTemplate:
		return fmt.Sprintf("template:0:%s", inc.Template)
	default:
		return fmt.Sprintf("unknown:%s", inc.Path)
	}
}

func (r *IncludeResolver) fetchLocal(ctx context.Context, path string) ([]byte, error) {
	return r.client.GetWorkflowFile(ctx, r.projectID, path, r.defaultRef)
}

func (r *IncludeResolver) fetchProject(ctx context.Context, projectPath, filePath, ref string) ([]byte, error) {
	if projectPath == "" {
		return nil, fmt.Errorf("project path cannot be empty")
	}
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	project, err := r.client.GetProject(ctx, projectPath)
	if err != nil {
		return nil, fmt.Errorf("getting project %s: %w", projectPath, err)
	}

	if ref == "" {
		ref = "HEAD"
	}

	return r.client.GetWorkflowFile(ctx, project.ID, filePath, ref)
}

func (r *IncludeResolver) fetchTemplate(ctx context.Context, templateName string) ([]byte, error) {
	if templateName == "" {
		return nil, fmt.Errorf("template name cannot be empty")
	}
	return r.client.GetTemplate(ctx, templateName)
}

func (r *IncludeResolver) resolveInclude(ctx context.Context, inc parser.GitLabInclude, depth int) (*IncludedWorkflow, error) {
	if depth >= r.maxDepth {
		return nil, fmt.Errorf("max include depth %d exceeded", r.maxDepth)
	}

	key := r.makeKey(inc)

	if r.processed[key] {
		return nil, nil // already processed
	}
	r.processed[key] = true

	var content []byte
	var err error

	switch inc.Type {
	case parser.IncludeTypeLocal:
		content, err = r.fetchLocal(ctx, inc.Path)
	case parser.IncludeTypeProject:
		content, err = r.fetchProject(ctx, inc.Project, inc.Path, inc.Ref)
	case parser.IncludeTypeTemplate:
		content, err = r.fetchTemplate(ctx, inc.Template)
	case parser.IncludeTypeRemote:
		// Skip remote includes for security
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown include type: %s", inc.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("fetching include %s: %w", key, err)
	}

	gitlabParser := parser.NewGitLabParser()
	normalized, err := gitlabParser.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parsing include %s: %w", key, err)
	}

	r.cache[key] = normalized

	var nestedIncludes []*IncludedWorkflow
	if rawGitLabCI, ok := normalized.Raw.(*parser.GitLabCI); ok {
		if len(rawGitLabCI.Includes) > 0 {
			for _, nestedInc := range rawGitLabCI.Includes {
				nestedResult, err := r.resolveInclude(ctx, nestedInc, depth+1)
				if err != nil {
					// Graceful degradation: skip the failed nested include.
					continue
				}
				if nestedResult != nil {
					nestedIncludes = append(nestedIncludes, nestedResult)
				}
			}
		}
	}

	return &IncludedWorkflow{
		Source:   key,
		Path:     getDisplayPath(inc),
		Type:     string(inc.Type),
		Content:  content,
		Workflow: normalized,
		Includes: nestedIncludes,
	}, nil
}

func (r *IncludeResolver) ResolveIncludes(ctx context.Context, includes []parser.GitLabInclude) ([]*IncludedWorkflow, error) {
	var resolved []*IncludedWorkflow

	for _, inc := range includes {
		result, err := r.resolveInclude(ctx, inc, 0)
		if err != nil {
			// Graceful degradation: skip the failed include.
			continue
		}

		if result != nil {
			resolved = append(resolved, result)
		}
	}

	return resolved, nil
}
