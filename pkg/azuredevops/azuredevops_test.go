package azuredevops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPlatform(server *httptest.Server) *Platform {
	return &Platform{
		client: NewClient(server.URL, "test-pat"),
	}
}

// Mirrors the real ADO list endpoint, which omits the process/repository fields.
func buildDefListJSON(defs []BuildDefinition) string {
	list := BuildDefinitionList{Count: len(defs), Value: defs}
	b, _ := json.Marshal(list)
	return string(b)
}

// The detail endpoint, unlike the list endpoint, populates process.yamlFilename.
func buildDefDetailJSON(def BuildDefinition) string {
	b, _ := json.Marshal(def)
	return string(b)
}

func makeShallowDef(id int, name string) BuildDefinition {
	var d BuildDefinition
	d.ID = id
	d.Name = name
	return d
}

func makeFullDef(id int, name, yamlPath string) BuildDefinition {
	var d BuildDefinition
	d.ID = id
	d.Name = name
	d.Process.YamlFilename = yamlPath
	d.Process.Type = 2
	return d
}

func isListByRepo(r *http.Request) bool {
	return r.URL.Query().Get("repositoryId") != ""
}

func isGetDefinition(r *http.Request) (int, bool) {
	parts := strings.Split(r.URL.Path, "/")
	// parts: ["", "MyProject", "_apis", "build", "definitions", "42"]
	if len(parts) < 6 {
		return 0, false
	}
	if parts[len(parts)-2] != "definitions" {
		return 0, false
	}
	// A repositoryId means this is the list-by-repo call, not a get.
	if r.URL.Query().Get("repositoryId") != "" {
		return 0, false
	}
	var id int
	_, err := fmt.Sscanf(parts[len(parts)-1], "%d", &id)
	if err != nil {
		return 0, false
	}
	return id, true
}

func isGetWorkflowFile(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/git/repositories/")
}

func TestGetWorkflowsFromDefs_MultipleDefsForSameRepo(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	shallowDefs := []BuildDefinition{
		makeShallowDef(1, "CI"),
		makeShallowDef(2, "CD"),
	}
	fullDefs := map[int]BuildDefinition{
		1: makeFullDef(1, "CI", "ci.yml"),
		2: makeFullDef(2, "CD", "cd.yml"),
	}
	yamlContents := map[string]string{
		"ci.yml": "trigger:\n- main\n",
		"cd.yml": "trigger:\n- release\n",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(shallowDefs))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			for key, content := range yamlContents {
				if strings.Contains(rawPath, key) {
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprint(w, content)
					return
				}
			}
			http.Error(w, "not found: "+rawPath, http.StatusNotFound)

		default:
			if id, ok := isGetDefinition(r); ok {
				if def, found := fullDefs[id]; found {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, buildDefDetailJSON(def))
					return
				}
			}
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 2)

	paths := []string{workflows[0].Path, workflows[1].Path}
	assert.Contains(t, paths, "ci.yml")
	assert.Contains(t, paths, "cd.yml")

	for _, wf := range workflows {
		assert.Equal(t, projectName+"/"+repoName, wf.RepoSlug)
	}
}

func TestGetWorkflowsFromDefs_Deduplication(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	shallowDefs := []BuildDefinition{
		makeShallowDef(1, "First"),
		makeShallowDef(2, "Second"),
	}
	fullDefs := map[int]BuildDefinition{
		1: makeFullDef(1, "First", "azure-pipelines.yml"),
		2: makeFullDef(2, "Second", "azure-pipelines.yml"),
	}

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(shallowDefs))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			if strings.Contains(rawPath, "azure-pipelines.yml") {
				fetchCount++
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
				return
			}
			http.Error(w, "unexpected path: "+rawPath, http.StatusInternalServerError)

		default:
			if id, ok := isGetDefinition(r); ok {
				if def, found := fullDefs[id]; found {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, buildDefDetailJSON(def))
					return
				}
			}
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "duplicate YAML paths should produce only one workflow")
	assert.Equal(t, 1, fetchCount, "GetWorkflowFile should be called exactly once for deduplicated paths")
}

func TestGetWorkflowsFromDefs_FallbackOnListError(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			http.Error(w, "internal server error", http.StatusInternalServerError)

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			if strings.Contains(rawPath, "azure-pipelines.yml") {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
				return
			}
			http.Error(w, "not found: "+rawPath, http.StatusNotFound)

		default:
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "fallback should return azure-pipelines.yml when list API fails")
	assert.Equal(t, "azure-pipelines.yml", workflows[0].Path)
	assert.Equal(t, projectName+"/"+repoName, workflows[0].RepoSlug)
}

func TestGetWorkflowsFromDefs_FallbackWhenNoDefs(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(nil))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			if strings.Contains(rawPath, "azure-pipelines.yml") {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
				return
			}
			http.Error(w, "not found: "+rawPath, http.StatusNotFound)

		default:
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "fallback should return azure-pipelines.yml when no definitions exist")
	assert.Equal(t, "azure-pipelines.yml", workflows[0].Path)
	assert.Equal(t, projectName+"/"+repoName, workflows[0].RepoSlug)
}

func TestGetWorkflowsFromDefs_UnreadableYAMLSkipped(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	shallowDefs := []BuildDefinition{
		makeShallowDef(1, "Missing CI"),
		makeShallowDef(2, "Valid CI"),
	}
	fullDefs := map[int]BuildDefinition{
		1: makeFullDef(1, "Missing CI", "missing.yml"),
		2: makeFullDef(2, "Valid CI", "valid.yml"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(shallowDefs))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			switch {
			case strings.Contains(rawPath, "missing.yml"):
				http.Error(w, "not found", http.StatusNotFound)
			case strings.Contains(rawPath, "valid.yml"):
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
			default:
				http.Error(w, "unexpected path: "+rawPath, http.StatusInternalServerError)
			}

		default:
			if id, ok := isGetDefinition(r); ok {
				if def, found := fullDefs[id]; found {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, buildDefDetailJSON(def))
					return
				}
			}
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "only the readable YAML should be returned")
	assert.Equal(t, "valid.yml", workflows[0].Path)
	assert.Equal(t, "Valid CI", workflows[0].Name)
}
