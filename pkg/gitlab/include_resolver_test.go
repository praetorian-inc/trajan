// pkg/gitlab/include_resolver_test.go
package gitlab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
)

func TestNewIncludeResolver(t *testing.T) {
	client := &Client{} // Mock client
	projectID := 12345
	ref := "main"

	resolver := NewIncludeResolver(client, projectID, ref)

	if resolver == nil {
		t.Fatal("expected resolver to be created")
	}
	if resolver.projectID != projectID {
		t.Errorf("expected projectID %d, got %d", projectID, resolver.projectID)
	}
	if resolver.defaultRef != ref {
		t.Errorf("expected ref %s, got %s", ref, resolver.defaultRef)
	}
	if resolver.maxDepth != 10 {
		t.Errorf("expected maxDepth 10, got %d", resolver.maxDepth)
	}
}

func TestMakeKey(t *testing.T) {
	resolver := NewIncludeResolver(&Client{}, 123, "main")

	tests := []struct {
		name     string
		include  parser.GitLabInclude
		expected string
	}{
		{
			name: "local include",
			include: parser.GitLabInclude{
				Type: parser.IncludeTypeLocal,
				Path: ".gitlab/ci/build.yml",
			},
			expected: "local:123:.gitlab/ci/build.yml:main",
		},
		{
			name: "project include with ref",
			include: parser.GitLabInclude{
				Type:    parser.IncludeTypeProject,
				Project: "other/repo",
				Path:    "templates/deploy.yml",
				Ref:     "v1.2.3",
			},
			expected: "project:other/repo:templates/deploy.yml:v1.2.3",
		},
		{
			name: "project include without ref",
			include: parser.GitLabInclude{
				Type:    parser.IncludeTypeProject,
				Project: "other/repo",
				Path:    "templates/deploy.yml",
				Ref:     "",
			},
			expected: "project:other/repo:templates/deploy.yml:HEAD",
		},
		{
			name: "template include",
			include: parser.GitLabInclude{
				Type:     parser.IncludeTypeTemplate,
				Template: "Auto-DevOps.gitlab-ci.yml",
			},
			expected: "template:0:Auto-DevOps.gitlab-ci.yml",
		},
		{
			name: "unknown include type",
			include: parser.GitLabInclude{
				Type: "unknown_type",
				Path: "some/path.yml",
			},
			expected: "unknown:some/path.yml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := resolver.makeKey(tt.include)
			if key != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, key)
			}
		})
	}
}

func TestGetDisplayPath(t *testing.T) {
	tests := []struct {
		name     string
		include  parser.GitLabInclude
		expected string
	}{
		{
			name: "local include",
			include: parser.GitLabInclude{
				Type: parser.IncludeTypeLocal,
				Path: ".gitlab/ci/build.yml",
			},
			expected: ".gitlab/ci/build.yml",
		},
		{
			name: "local include with colon in path",
			include: parser.GitLabInclude{
				Type: parser.IncludeTypeLocal,
				Path: ".gitlab/ci/backup_2024-01-15_10:30:00.yml",
			},
			expected: ".gitlab/ci/backup_2024-01-15_10:30:00.yml",
		},
		{
			name: "project include",
			include: parser.GitLabInclude{
				Type:    parser.IncludeTypeProject,
				Project: "other/repo",
				Path:    "templates/deploy.yml",
				Ref:     "v1.0",
			},
			expected: "templates/deploy.yml",
		},
		{
			name: "project include with colon in path",
			include: parser.GitLabInclude{
				Type:    parser.IncludeTypeProject,
				Project: "other/repo",
				Path:    "templates/ci:v1.0.yml",
				Ref:     "main",
			},
			expected: "templates/ci:v1.0.yml",
		},
		{
			name: "template include",
			include: parser.GitLabInclude{
				Type:     parser.IncludeTypeTemplate,
				Template: "Security/SAST.gitlab-ci.yml",
			},
			expected: "Security/SAST.gitlab-ci.yml",
		},
		{
			name: "template include with colon in name",
			include: parser.GitLabInclude{
				Type:     parser.IncludeTypeTemplate,
				Template: "Jobs/Build:Docker.gitlab-ci.yml",
			},
			expected: "Jobs/Build:Docker.gitlab-ci.yml",
		},
		{
			name: "remote include",
			include: parser.GitLabInclude{
				Type:   parser.IncludeTypeRemote,
				Remote: "https://example.com/ci.yml",
			},
			expected: "https://example.com/ci.yml",
		},
		{
			name: "unknown type",
			include: parser.GitLabInclude{
				Type: "unknown",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDisplayPath(tt.include)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFetchProject(t *testing.T) {
	mockContent := []byte("deploy:\n  script:\n    - kubectl apply")

	tests := []struct {
		name        string
		projectPath string
		filePath    string
		ref         string
		setupServer func() *httptest.Server
		wantErr     bool
		errContains string
	}{
		{
			name:        "success with ref",
			projectPath: "other/repo",
			filePath:    "templates/deploy.yml",
			ref:         "v1.2.3",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Handle GetProject request
					if r.URL.Path == "/api/v4/projects/other/repo" {
						response := Project{
							ID:                456,
							PathWithNamespace: "other/repo",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}

					// Handle GetWorkflowFile request
					if r.URL.Path == "/api/v4/projects/456/repository/files/templates/deploy.yml" && r.URL.Query().Get("ref") == "v1.2.3" {
						response := FileResponse{
							FileName: "templates/deploy.yml",
							FilePath: "templates/deploy.yml",
							Encoding: "base64",
							Content:  base64.StdEncoding.EncodeToString(mockContent),
							BlobID:   "def456",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}

					http.NotFound(w, r)
				}))
			},
			wantErr: false,
		},
		{
			name:        "project not found",
			projectPath: "nonexistent/repo",
			filePath:    "file.yml",
			ref:         "main",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Return 404 for GetProject
					if r.URL.Path == "/api/v4/projects/nonexistent/repo" {
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte(`{"message":"404 Project Not Found"}`))
						return
					}
					http.NotFound(w, r)
				}))
			},
			wantErr:     true,
			errContains: "getting project",
		},
		{
			name:        "empty project path",
			projectPath: "",
			filePath:    "file.yml",
			ref:         "main",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Should not be reached
					http.NotFound(w, r)
				}))
			},
			wantErr:     true,
			errContains: "project path cannot be empty",
		},
		{
			name:        "empty file path",
			projectPath: "other/repo",
			filePath:    "",
			ref:         "main",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Should not be reached
					http.NotFound(w, r)
				}))
			},
			wantErr:     true,
			errContains: "file path cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			resolver := NewIncludeResolver(client, 123, "main")
			ctx := context.Background()

			content, err := resolver.fetchProject(ctx, tt.projectPath, tt.filePath, tt.ref)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if len(content) == 0 {
					t.Fatal("expected content, got empty")
				}
			}
		})
	}
}

func TestFetchTemplate(t *testing.T) {
	tests := []struct {
		name         string
		templateName string
		wantErr      bool
		errContains  string
		setupServer  func() *httptest.Server
	}{
		{
			name:         "success",
			templateName: "Auto-DevOps.gitlab-ci.yml",
			wantErr:      false,
			setupServer: func() *httptest.Server {
				mockContent := []byte("include:\n  - template: Jobs/Build.gitlab-ci.yml")
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// GetProject for gitlab-org/gitlab
					if r.URL.Path == "/api/v4/projects/gitlab-org/gitlab" {
						response := Project{
							ID:                999,
							PathWithNamespace: "gitlab-org/gitlab",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}

					// GetWorkflowFile for template
					if r.URL.Path == "/api/v4/projects/999/repository/files/lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml" && r.URL.Query().Get("ref") == "master" {
						response := FileResponse{
							FileName: "Auto-DevOps.gitlab-ci.yml",
							FilePath: "lib/gitlab/ci/templates/Auto-DevOps.gitlab-ci.yml",
							Encoding: "base64",
							Content:  base64.StdEncoding.EncodeToString(mockContent),
							BlobID:   "xyz789",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}

					http.NotFound(w, r)
				}))
			},
		},
		{
			name:         "template not found",
			templateName: "NonExistent.gitlab-ci.yml",
			wantErr:      true,
			errContains:  "404",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// GetProject for gitlab-org/gitlab succeeds
					if r.URL.Path == "/api/v4/projects/gitlab-org/gitlab" {
						response := Project{
							ID:                999,
							PathWithNamespace: "gitlab-org/gitlab",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}

					// GetWorkflowFile returns 404
					if r.URL.Path == "/api/v4/projects/999/repository/files/lib/gitlab/ci/templates/NonExistent.gitlab-ci.yml" {
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte(`{"message":"404 File Not Found"}`))
						return
					}

					http.NotFound(w, r)
				}))
			},
		},
		{
			name:         "empty template name",
			templateName: "",
			wantErr:      true,
			errContains:  "template name cannot be empty",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Should not be reached
					http.NotFound(w, r)
				}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			resolver := NewIncludeResolver(client, 123, "main")
			ctx := context.Background()

			content, err := resolver.fetchTemplate(ctx, tt.templateName)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if len(content) == 0 {
					t.Fatal("expected content, got empty")
				}
			}
		})
	}
}

func TestResolveInclude_DepthExceeded(t *testing.T) {
	client := NewClient("http://example.com", "test-token")
	resolver := NewIncludeResolver(client, 123, "main")
	resolver.maxDepth = 2 // Set low limit for testing
	ctx := context.Background()

	inc := parser.GitLabInclude{
		Type: parser.IncludeTypeLocal,
		Path: ".gitlab/ci/build.yml",
	}

	_, err := resolver.resolveInclude(ctx, inc, 3) // depth > maxDepth
	if err == nil {
		t.Fatal("expected depth exceeded error, got nil")
	}
	if !strings.Contains(err.Error(), "max include depth") {
		t.Errorf("expected 'max include depth' error, got %v", err)
	}
}

func TestResolveInclude_MaxDepthExactly10Levels(t *testing.T) {
	// Verify that with maxDepth=10, depth 9 is allowed but depth 10 is rejected
	// maxDepth=10 should allow exactly 10 levels (depth 0-9)
	mockContent := []byte(`build:
  script:
    - echo hello`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GetWorkflowFile request for local include
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
			response := FileResponse{
				FileName: ".gitlab/ci/build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "abc123",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resolver := NewIncludeResolver(client, 123, "main")
	// maxDepth defaults to 10

	ctx := context.Background()
	inc := parser.GitLabInclude{Type: parser.IncludeTypeLocal, Path: ".gitlab/ci/build.yml"}

	// Depth 9 should succeed (10th level, counting from 0)
	_, err := resolver.resolveInclude(ctx, inc, 9)
	if err != nil {
		t.Errorf("depth 9 should be allowed with maxDepth=10, got error: %v", err)
	}

	// Depth 10 should fail (11th level, exceeds limit)
	_, err = resolver.resolveInclude(ctx, inc, 10)
	if err == nil || !strings.Contains(err.Error(), "max include depth") {
		t.Error("depth 10 should be rejected with maxDepth=10")
	}
}

func TestResolveInclude_CycleDetection(t *testing.T) {
	// Test that already-processed includes return nil
	client := NewClient("http://example.com", "test-token")
	resolver := NewIncludeResolver(client, 123, "main")
	resolver.processed["local:123:.gitlab/ci/build.yml:main"] = true
	ctx := context.Background()

	inc := parser.GitLabInclude{
		Type: parser.IncludeTypeLocal,
		Path: ".gitlab/ci/build.yml",
	}

	result, err := resolver.resolveInclude(ctx, inc, 0)
	if err != nil {
		t.Fatalf("expected no error for cycle, got %v", err)
	}
	if result != nil {
		t.Error("expected nil result for already-processed include")
	}
}

func TestResolveInclude_SkipsRemote(t *testing.T) {
	client := NewClient("http://example.com", "test-token")
	resolver := NewIncludeResolver(client, 123, "main")
	ctx := context.Background()

	inc := parser.GitLabInclude{
		Type:   parser.IncludeTypeRemote,
		Remote: "https://example.com/ci.yml",
	}

	result, err := resolver.resolveInclude(ctx, inc, 0)
	if err != nil {
		t.Fatalf("expected no error for remote skip, got %v", err)
	}
	if result != nil {
		t.Error("expected nil result for remote include")
	}
}

func TestResolveInclude_NestedIncludes(t *testing.T) {
	// Test A → B → C nested includes
	contentA := []byte(`include:
  - local: '.gitlab/ci/b.yml'
stageA:
  script:
    - echo A`)

	contentB := []byte(`include:
  - local: '.gitlab/ci/c.yml'
stageB:
  script:
    - echo B`)

	contentC := []byte(`stageC:
  script:
    - echo C`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle file A
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/a.yml" && r.URL.Query().Get("ref") == "main" {
			response := FileResponse{
				FileName: ".gitlab/ci/a.yml",
				FilePath: ".gitlab/ci/a.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(contentA),
				BlobID:   "a123",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle file B
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/b.yml" && r.URL.Query().Get("ref") == "main" {
			response := FileResponse{
				FileName: ".gitlab/ci/b.yml",
				FilePath: ".gitlab/ci/b.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(contentB),
				BlobID:   "b123",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle file C
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/c.yml" && r.URL.Query().Get("ref") == "main" {
			response := FileResponse{
				FileName: ".gitlab/ci/c.yml",
				FilePath: ".gitlab/ci/c.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(contentC),
				BlobID:   "c123",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resolver := NewIncludeResolver(client, 123, "main")
	ctx := context.Background()

	inc := parser.GitLabInclude{
		Type: parser.IncludeTypeLocal,
		Path: ".gitlab/ci/a.yml",
	}

	result, err := resolver.resolveInclude(ctx, inc, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Verify A has nested includes
	if len(result.Includes) != 1 {
		t.Fatalf("expected 1 nested include in A, got %d", len(result.Includes))
	}

	// Verify B is included
	includeB := result.Includes[0]
	if includeB.Type != string(parser.IncludeTypeLocal) {
		t.Errorf("expected B type to be local, got %s", includeB.Type)
	}

	// Verify B has nested includes (C)
	if len(includeB.Includes) != 1 {
		t.Fatalf("expected 1 nested include in B, got %d", len(includeB.Includes))
	}

	// Verify C is included
	includeC := includeB.Includes[0]
	if includeC.Type != string(parser.IncludeTypeLocal) {
		t.Errorf("expected C type to be local, got %s", includeC.Type)
	}

	// Verify C has no nested includes
	if len(includeC.Includes) != 0 {
		t.Errorf("expected 0 nested includes in C, got %d", len(includeC.Includes))
	}

	// Verify the processed map tracked all three files
	if len(resolver.processed) != 3 {
		t.Errorf("expected 3 processed entries, got %d", len(resolver.processed))
	}
}

func TestResolveIncludes(t *testing.T) {
	mockContent1 := []byte(`build:
  script:
    - make build`)
	mockContent2 := []byte(`test:
  script:
    - make test`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle build.yml
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
			response := FileResponse{
				FileName: ".gitlab/ci/build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent1),
				BlobID:   "build123",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Handle test.yml
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/test.yml" && r.URL.Query().Get("ref") == "main" {
			response := FileResponse{
				FileName: ".gitlab/ci/test.yml",
				FilePath: ".gitlab/ci/test.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent2),
				BlobID:   "test123",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resolver := NewIncludeResolver(client, 123, "main")
	ctx := context.Background()

	// The middle include 404s: ResolveIncludes must skip it and still return the
	// two that resolved, rather than failing the whole batch.
	includes := []parser.GitLabInclude{
		{Type: parser.IncludeTypeLocal, Path: ".gitlab/ci/build.yml"},
		{Type: parser.IncludeTypeLocal, Path: ".gitlab/ci/missing.yml"},
		{Type: parser.IncludeTypeLocal, Path: ".gitlab/ci/test.yml"},
	}

	results, err := resolver.ResolveIncludes(ctx, includes)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, want := range []string{".gitlab/ci/build.yml", ".gitlab/ci/test.yml"} {
		if !slices.ContainsFunc(results, func(r *IncludedWorkflow) bool { return r.Path == want }) {
			t.Errorf("expected %q among resolved includes", want)
		}
	}
}

func TestResolveInclude_PreservesContent(t *testing.T) {
	mockContent := []byte(`stages:
  - build
  - test

build-job:
  stage: build
  script:
    - echo "Building the app"
    - make build

test-job:
  stage: test
  script:
    - echo "Running tests"
    - make test`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GetWorkflowFile request for local include
		if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
			response := FileResponse{
				FileName: ".gitlab/ci/build.yml",
				FilePath: ".gitlab/ci/build.yml",
				Encoding: "base64",
				Content:  base64.StdEncoding.EncodeToString(mockContent),
				BlobID:   "abc123",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resolver := NewIncludeResolver(client, 123, "main")
	ctx := context.Background()

	inc := parser.GitLabInclude{
		Type: parser.IncludeTypeLocal,
		Path: ".gitlab/ci/build.yml",
	}

	result, err := resolver.resolveInclude(ctx, inc, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Verify Content field is populated
	if result.Content == nil {
		t.Fatal("expected Content to be populated, got nil")
	}

	if len(result.Content) == 0 {
		t.Fatal("expected Content to have data, got empty")
	}

	// Verify Content matches original YAML
	if string(result.Content) != string(mockContent) {
		t.Errorf("expected Content to match original YAML.\nExpected:\n%s\n\nGot:\n%s", mockContent, result.Content)
	}

	// Verify Workflow is still parsed correctly
	if result.Workflow == nil {
		t.Fatal("expected Workflow to be parsed, got nil")
	}
}

func TestResolveInclude_PathField(t *testing.T) {
	tests := []struct {
		name         string
		include      parser.GitLabInclude
		expectedPath string
		setupServer  func() *httptest.Server
	}{
		{
			name: "local include sets clean path",
			include: parser.GitLabInclude{
				Type: parser.IncludeTypeLocal,
				Path: ".gitlab/ci/build.yml",
			},
			expectedPath: ".gitlab/ci/build.yml",
			setupServer: func() *httptest.Server {
				mockContent := []byte("build:\n  script:\n    - make build")
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab/ci/build.yml" && r.URL.Query().Get("ref") == "main" {
						response := FileResponse{
							FileName: ".gitlab/ci/build.yml",
							FilePath: ".gitlab/ci/build.yml",
							Encoding: "base64",
							Content:  base64.StdEncoding.EncodeToString(mockContent),
							BlobID:   "abc123",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}
					http.NotFound(w, r)
				}))
			},
		},
		{
			name: "project include with colon in path",
			include: parser.GitLabInclude{
				Type:    parser.IncludeTypeProject,
				Project: "other/repo",
				Path:    "templates/ci:v1.0.yml",
				Ref:     "main",
			},
			expectedPath: "templates/ci:v1.0.yml",
			setupServer: func() *httptest.Server {
				mockContent := []byte("ci:\n  script:\n    - make ci")
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/v4/projects/other/repo" {
						response := Project{
							ID:                456,
							PathWithNamespace: "other/repo",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}
					if r.URL.Path == "/api/v4/projects/456/repository/files/templates/ci:v1.0.yml" && r.URL.Query().Get("ref") == "main" {
						response := FileResponse{
							FileName: "ci:v1.0.yml",
							FilePath: "templates/ci:v1.0.yml",
							Encoding: "base64",
							Content:  base64.StdEncoding.EncodeToString(mockContent),
							BlobID:   "def457",
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}
					http.NotFound(w, r)
				}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			resolver := NewIncludeResolver(client, 123, "main")
			ctx := context.Background()

			result, err := resolver.resolveInclude(ctx, tt.include, 0)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if result == nil {
				t.Fatal("expected result, got nil")
			}

			// Verify Path field is set to clean path
			if result.Path != tt.expectedPath {
				t.Errorf("expected Path to be %q, got %q", tt.expectedPath, result.Path)
			}

			// Verify Source field still contains cache key (not just the path)
			if result.Source == result.Path {
				t.Error("expected Source to be cache key, not clean path")
			}

			// Verify Source contains the expected format
			if !strings.Contains(result.Source, ":") {
				t.Errorf("expected Source to be cache key format with colons, got %q", result.Source)
			}
		})
	}
}
