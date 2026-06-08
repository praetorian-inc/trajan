package enumerate

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// TestOutputReposConsole tests the console output formatting for repository enumeration
func TestOutputReposConsole(t *testing.T) {
	tests := []struct {
		name   string
		result *github.ReposEnumerateResult
	}{
		{
			name: "single repository with write access",
			result: &github.ReposEnumerateResult{
				Repositories: []github.RepositoryWithPermissions{
					{
						Repository: platforms.Repository{
							Owner:         "praetorian-inc",
							Name:          "trajan",
							DefaultBranch: "main",
							Private:       true,
							Archived:      false,
							URL:           "https://github.com/praetorian-inc/trajan",
						},
						Permissions: github.RepositoryPermissions{
							Push: true,
						},
					},
				},
				Summary: github.ReposSummary{
					Total:       1,
					Private:     1,
					Public:      0,
					Archived:    0,
					WriteAccess: 1,
					ReadAccess:  0,
				},
			},
		},
		{
			name: "multiple repos with mixed permissions",
			result: &github.ReposEnumerateResult{
				Repositories: []github.RepositoryWithPermissions{
					{
						Repository: platforms.Repository{
							Owner:         "praetorian-inc",
							Name:          "trajan",
							Private:       true,
							Archived:      false,
							DefaultBranch: "main",
						},
						Permissions: github.RepositoryPermissions{
							Push: true,
						},
					},
					{
						Repository: platforms.Repository{
							Owner:         "praetorian-inc",
							Name:          "gato",
							Private:       true,
							Archived:      false,
							DefaultBranch: "main",
						},
						Permissions: github.RepositoryPermissions{
							Admin: true,
						},
					},
					{
						Repository: platforms.Repository{
							Owner:         "praetorian-inc",
							Name:          "legacy-tool",
							Private:       false,
							Archived:      true,
							DefaultBranch: "master",
						},
						Permissions: github.RepositoryPermissions{
							Pull: true,
						},
					},
				},
				Summary: github.ReposSummary{
					Total:       3,
					Private:     2,
					Public:      1,
					Archived:    1,
					WriteAccess: 2,
					ReadAccess:  1,
				},
			},
		},
		{
			name: "empty result",
			result: &github.ReposEnumerateResult{
				Repositories: []github.RepositoryWithPermissions{},
				Summary: github.ReposSummary{
					Total: 0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call outputReposConsole to ensure it doesn't panic
			err := outputReposConsole(tt.result)

			if err != nil {
				t.Errorf("outputReposConsole() returned error: %v", err)
			}
		})
	}
}

// TestOutputReposConsoleAppTokenNoPermissions verifies that repos with all-false
// permissions (as returned by GET /installation/repositories for GitHub App tokens)
// appear in the output rather than being silently dropped.
func TestOutputReposConsoleAppTokenNoPermissions(t *testing.T) {
	result := &github.ReposEnumerateResult{
		Repositories: []github.RepositoryWithPermissions{
			{
				Repository: platforms.Repository{
					Owner:         "trgh-one",
					Name:          "tc01",
					DefaultBranch: "main",
					Private:       true,
				},
				// All permission bits are false — typical for GitHub App installation tokens
				Permissions: github.RepositoryPermissions{
					Admin: false,
					Push:  false,
					Pull:  false,
				},
			},
		},
		Summary: github.ReposSummary{
			Total:   1,
			Private: 1,
		},
	}

	// Capture stdout by swapping os.Stdout with a pipe
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	os.Stdout = w

	callErr := outputReposConsole(result)

	// Restore stdout before reading
	w.Close()
	os.Stdout = origStdout

	var sb strings.Builder
	if _, err := io.Copy(&sb, r); err != nil {
		t.Fatalf("reading captured output: %v", err)
	}
	r.Close()

	if callErr != nil {
		t.Fatalf("outputReposConsole() returned unexpected error: %v", callErr)
	}

	output := sb.String()

	if !strings.Contains(output, "tc01") {
		t.Errorf("output does not contain repo name %q; got:\n%s", "tc01", output)
	}
	if !strings.Contains(output, "permissions not reported") {
		t.Errorf("output does not contain %q; got:\n%s", "permissions not reported", output)
	}
}

// TestFilterRepositoriesByPermission tests filtering repos by permission level
func TestFilterRepositoriesByPermission(t *testing.T) {
	repos := []github.RepositoryWithPermissions{
		{
			Repository: platforms.Repository{Owner: "owner", Name: "admin-repo"},
			Permissions: github.RepositoryPermissions{
				Admin: true,
				Push:  true,
				Pull:  true,
			},
		},
		{
			Repository: platforms.Repository{Owner: "owner", Name: "write-repo"},
			Permissions: github.RepositoryPermissions{
				Admin: false,
				Push:  true,
				Pull:  true,
			},
		},
		{
			Repository: platforms.Repository{Owner: "owner", Name: "read-repo"},
			Permissions: github.RepositoryPermissions{
				Admin: false,
				Push:  false,
				Pull:  true,
			},
		},
	}

	tests := []struct {
		name       string
		permission string
		want       int
	}{
		{"all permissions", "all", 3},
		{"admin only", "admin", 1},
		{"write or higher", "write", 2},
		{"read only", "read", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterByPermission(repos, tt.permission)
			if len(filtered) != tt.want {
				t.Errorf("filterByPermission(%q) = %d repos, want %d", tt.permission, len(filtered), tt.want)
			}
		})
	}
}

// TestFilterRepositoriesByVisibility tests filtering repos by visibility
func TestFilterRepositoriesByVisibility(t *testing.T) {
	repos := []github.RepositoryWithPermissions{
		{
			Repository: platforms.Repository{Owner: "owner", Name: "private-repo", Private: true},
		},
		{
			Repository: platforms.Repository{Owner: "owner", Name: "public-repo", Private: false},
		},
		{
			Repository: platforms.Repository{Owner: "owner", Name: "another-private", Private: true},
		},
	}

	tests := []struct {
		name       string
		visibility string
		want       int
	}{
		{"all repos", "all", 3},
		{"private only", "private", 2},
		{"public only", "public", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterByVisibility(repos, tt.visibility)
			if len(filtered) != tt.want {
				t.Errorf("filterByVisibility(%q) = %d repos, want %d", tt.visibility, len(filtered), tt.want)
			}
		})
	}
}

// TestBuildReposSummary tests summary statistics generation
func TestBuildReposSummary(t *testing.T) {
	repos := []github.RepositoryWithPermissions{
		{
			Repository:  platforms.Repository{Private: true, Archived: false},
			Permissions: github.RepositoryPermissions{Push: true},
		},
		{
			Repository:  platforms.Repository{Private: false, Archived: false},
			Permissions: github.RepositoryPermissions{Push: false, Pull: true},
		},
		{
			Repository:  platforms.Repository{Private: true, Archived: true},
			Permissions: github.RepositoryPermissions{Push: true},
		},
	}

	summary := buildReposSummary(repos)

	if summary.Total != 3 {
		t.Errorf("Total = %d, want 3", summary.Total)
	}
	if summary.Private != 2 {
		t.Errorf("Private = %d, want 2", summary.Private)
	}
	if summary.Public != 1 {
		t.Errorf("Public = %d, want 1", summary.Public)
	}
	if summary.Archived != 1 {
		t.Errorf("Archived = %d, want 1", summary.Archived)
	}
	if summary.WriteAccess != 2 {
		t.Errorf("WriteAccess = %d, want 2", summary.WriteAccess)
	}
	if summary.ReadAccess != 1 {
		t.Errorf("ReadAccess = %d, want 1", summary.ReadAccess)
	}
}
