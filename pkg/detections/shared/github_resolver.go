// modules/trajan/pkg/detections/shared/github_resolver.go
package shared

import (
	"fmt"
	"strings"
)

// GitHubUsesResolver resolves GitHub Actions "uses" references
type GitHubUsesResolver struct{}

// NewGitHubUsesResolver creates a new GitHub uses resolver
func NewGitHubUsesResolver() *GitHubUsesResolver {
	return &GitHubUsesResolver{}
}

// Parse parses a GitHub Actions "uses" reference
func (r *GitHubUsesResolver) Parse(uses string) (*UsesReference, error) {
	ref := &UsesReference{
		RawValue: uses,
	}

	// Handle docker images
	if strings.HasPrefix(uses, "docker://") {
		ref.Type = UsesTypeDocker
		ref.Repo = strings.TrimPrefix(uses, "docker://")
		ref.IsPinned = strings.Contains(ref.Repo, "@sha256:")
		return ref, nil
	}

	// Handle local actions
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		ref.Type = UsesTypeLocal
		ref.Path = uses
		ref.IsLocal = true
		ref.IsPinned = true // Local actions are inherently version-controlled
		return ref, nil
	}

	// Parse standard action reference: owner/repo@ref or owner/repo/path@ref
	parts := strings.Split(uses, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid action reference format: %s", uses)
	}

	actionPath := parts[0]
	ref.Ref = parts[1]
	ref.Type = UsesTypeAction

	// Split path into owner/repo[/subpath]
	pathParts := strings.SplitN(actionPath, "/", 3)
	if len(pathParts) < 2 {
		return nil, fmt.Errorf("invalid action path: %s", actionPath)
	}

	ref.Owner = pathParts[0]
	ref.Repo = pathParts[1]
	if len(pathParts) > 2 {
		ref.Path = pathParts[2]
	}

	// Check if pinned (40-char hex SHA)
	ref.IsPinned = isValidSHA(ref.Ref)

	return ref, nil
}

// isValidSHA checks if a string is a valid 40-character hex SHA
func isValidSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// GitHubPinValidator validates GitHub-specific pinning
type GitHubPinValidator struct{}

// NewGitHubPinValidator creates a new GitHub pin validator
func NewGitHubPinValidator() *GitHubPinValidator {
	return &GitHubPinValidator{}
}

// IsPinned returns true if the reference is properly pinned
func (v *GitHubPinValidator) IsPinned(ref *UsesReference) bool {
	return ref.IsPinned
}

// ValidateSHA validates GitHub SHA format
func (v *GitHubPinValidator) ValidateSHA(sha string) bool {
	return isValidSHA(sha)
}
