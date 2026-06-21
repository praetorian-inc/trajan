package enumerate

import (
	"fmt"
	"strings"
)

// analyzeBranchFilters checks if branch filters allow exploitation by attackers.
// Returns (isExploitable, reason).
// Ported from ADOScan's internal/api/triggers.go
func analyzeBranchFilters(filters []string) (bool, string) {
	if len(filters) == 0 {
		return true, "no filters (all branches trigger)"
	}

	hasWildcardInclude := false
	includesUserBranches := false
	onlyProtectedBranches := true

	protectedPatterns := map[string]bool{
		"+refs/heads/main":    true,
		"+refs/heads/master":  true,
		"+refs/heads/release": true,
		"+refs/heads/develop": true,
		"+main":               true,
		"+master":             true,
	}

	for _, filter := range filters {
		if filter == "" {
			continue
		}

		// Skip exclude filters
		if filter[0] == '-' {
			continue
		}

		if !protectedPatterns[filter] {
			onlyProtectedBranches = false
		}

		// Check for broad wildcards
		if filter == "*" || filter == "+*" || filter == "+refs/heads/*" {
			hasWildcardInclude = true
		}

		if containsWildcard(filter) {
			if containsUserBranchPattern(filter) {
				includesUserBranches = true
			}
			if !isProtectedWildcard(filter) {
				hasWildcardInclude = true
			}
		}
	}

	if hasWildcardInclude {
		return true, "wildcard pattern allows arbitrary branches"
	}
	if includesUserBranches {
		return true, "pattern includes user-controllable branches"
	}
	if !onlyProtectedBranches {
		for _, f := range filters {
			if len(f) > 0 && f[0] != '-' && containsWildcard(f) && !isProtectedWildcard(f) {
				return true, "pattern may allow attacker-created branches"
			}
		}
	}

	return false, ""
}

// containsWildcard checks if a pattern contains wildcard characters
func containsWildcard(pattern string) bool {
	for _, r := range pattern {
		if r == '*' || r == '?' {
			return true
		}
	}
	return false
}

// containsUserBranchPattern checks if a pattern includes user-controllable branch prefixes
func containsUserBranchPattern(pattern string) bool {
	userPatterns := []string{
		"users/", "user/", "feature/", "feat/",
		"bugfix/", "fix/", "hotfix/", "topic/",
		"dev/", "wip/", "experiment/", "test/",
	}
	lower := strings.ToLower(pattern)
	for _, p := range userPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// isProtectedWildcard checks if a wildcard pattern only matches protected branches
func isProtectedWildcard(pattern string) bool {
	protected := []string{
		"+refs/heads/release/*",
		"+refs/heads/releases/*",
		"+release/*",
		"+releases/*",
	}
	for _, p := range protected {
		if pattern == p {
			return true
		}
	}
	return false
}

// formatBranchFilters truncates a filter list for display
func formatBranchFilters(filters []string, maxDisplay int) string {
	if len(filters) == 0 {
		return "*"
	}
	if len(filters) <= maxDisplay {
		return strings.Join(filters, ", ")
	}
	displayed := strings.Join(filters[:maxDisplay], ", ")
	return fmt.Sprintf("%s +%d more", displayed, len(filters)-maxDisplay)
}

// policyTypeNameMap returns a mapping of well-known policy type UUIDs to display names
func policyTypeNameMap() map[string]string {
	return map[string]string{
		"0609b952-1397-4640-95ec-e00a01b2c241": "Build",
		"fa4e907d-c16b-4a4c-9dfa-4906e5d171dd": "Min Reviewers",
		"40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e": "Work Item",
		"c6a1889d-b943-4856-b76f-9e46bb6b0df2": "Comments",
	}
}

// buildValidationPolicyTypeID is the UUID for build validation policies
const buildValidationPolicyTypeID = "0609b952-1397-4640-95ec-e00a01b2c241"

// Security namespace IDs for permission checks
const (
	buildNamespaceID = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"
	gitNamespaceID   = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
)

// Build permission bits
const (
	buildPermQueueBuilds     = 128
	buildPermViewBuilds      = 1
	buildPermViewDefinitions = 1024
)

// Git permission bits
const (
	gitPermContribute         = 4
	gitPermForcePush          = 8
	gitPermBypassPoliciesPush = 128
	gitPermBypassPoliciesPR   = 32768
)

// Extended build permission bits for detailed analysis
const (
	buildPermEditBuildDefinition   = 2048
	buildPermDeleteBuilds          = 8
	buildPermStopBuilds            = 512
	buildPermAdministerPermissions = 16384
)

// Extended git permission bits for detailed analysis
const (
	gitPermAdminister     = 1
	gitPermRead           = 2
	gitPermCreateBranch   = 16
	gitPermContributeToPR = 16384
)

// formatBool returns "Yes" or "No" for a boolean value
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// truncateString truncates a string with "..." suffix if it exceeds maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
