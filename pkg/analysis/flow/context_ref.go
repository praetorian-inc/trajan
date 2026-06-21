// modules/trajan/pkg/analysis/flow/context_ref.go
package flow

import "strings"

// PlatformContextResolver resolves context references for different platforms
type PlatformContextResolver struct {
	platform     string
	taintedPaths map[string]bool
}

// NewPlatformContextResolver creates a resolver for a specific platform
func NewPlatformContextResolver(platform string) *PlatformContextResolver {
	resolver := &PlatformContextResolver{
		platform:     platform,
		taintedPaths: make(map[string]bool),
	}

	switch platform {
	case "github":
		resolver.initGitHub()
	case "gitlab":
		resolver.initGitLab()
	case "azure":
		resolver.initAzure()
	}

	return resolver
}

// initGitHub sets up GitHub-specific tainted paths
func (r *PlatformContextResolver) initGitHub() {
	tainted := []string{
		"github.event.comment.body",
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.pull_request.head.ref",
		"github.event.pull_request.head.label",
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.discussion.title",
		"github.event.discussion.body",
		"github.event.review.body",
		"github.event.review_comment.body",
		"github.event.workflow_run.head_branch",
		"github.event.workflow_run.head_commit.message",
		"github.event.release.name",
		"github.event.release.body",
		"github.head_ref",
	}
	for _, p := range tainted {
		r.taintedPaths[p] = true
	}
}

// initGitLab sets up GitLab-specific tainted paths
func (r *PlatformContextResolver) initGitLab() {
	tainted := []string{
		// Merge Request fields
		"CI_MERGE_REQUEST_TITLE",
		"CI_MERGE_REQUEST_DESCRIPTION",
		"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
		"CI_COMMIT_MESSAGE",
		"CI_COMMIT_TITLE",
		"CI_COMMIT_DESCRIPTION",
		"CI_COMMIT_TAG_MESSAGE",
		// External trigger data
		"CI_EXTERNAL_PULL_REQUEST_TITLE",
		"CI_EXTERNAL_PULL_REQUEST_DESCRIPTION",
	}
	for _, p := range tainted {
		r.taintedPaths[p] = true
	}
}

// initAzure sets up Azure DevOps-specific tainted paths
func (r *PlatformContextResolver) initAzure() {
	tainted := []string{
		"System.PullRequest.Title",
		"System.PullRequest.Description",
		"System.PullRequest.SourceBranch",
		"Build.SourceBranchName",
		"Build.SourceVersionMessage",
		// Pipeline variables from user input
		"Build.RequestedFor",
		"Build.RequestedForEmail",
	}
	for _, p := range tainted {
		r.taintedPaths[p] = true
	}
}

// IsTainted checks if a context reference is user-controllable
func (r *PlatformContextResolver) IsTainted(ref string) bool {
	// Direct match
	if r.taintedPaths[ref] {
		return true
	}

	// Prefix match for nested paths
	for tainted := range r.taintedPaths {
		if strings.HasPrefix(ref, tainted+".") {
			return true
		}
	}

	return false
}

// Normalize converts a platform-specific reference to a canonical form
func (r *PlatformContextResolver) Normalize(ref string) string {
	// This enables cross-platform analysis by mapping to common concepts
	switch r.platform {
	case "gitlab":
		return r.normalizeGitLab(ref)
	case "azure":
		return r.normalizeAzure(ref)
	default:
		return ref // GitHub is the canonical form
	}
}

func (r *PlatformContextResolver) normalizeGitLab(ref string) string {
	mapping := map[string]string{
		"CI_MERGE_REQUEST_TITLE":              "event.pull_request.title",
		"CI_MERGE_REQUEST_DESCRIPTION":        "event.pull_request.body",
		"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "event.pull_request.head.ref",
		"CI_COMMIT_MESSAGE":                   "event.head_commit.message",
		"CI_COMMIT_SHA":                       "sha",
	}
	if mapped, ok := mapping[ref]; ok {
		return mapped
	}
	return ref
}

func (r *PlatformContextResolver) normalizeAzure(ref string) string {
	mapping := map[string]string{
		"System.PullRequest.Title":        "event.pull_request.title",
		"System.PullRequest.Description":  "event.pull_request.body",
		"System.PullRequest.SourceBranch": "event.pull_request.head.ref",
		"Build.SourceVersion":             "sha",
	}
	if mapped, ok := mapping[ref]; ok {
		return mapped
	}
	return ref
}

// GetAllTaintedPaths returns all tainted paths for the platform
func (r *PlatformContextResolver) GetAllTaintedPaths() []string {
	paths := make([]string, 0, len(r.taintedPaths))
	for path := range r.taintedPaths {
		paths = append(paths, path)
	}
	return paths
}
