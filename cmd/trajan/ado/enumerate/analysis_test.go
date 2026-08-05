package enumerate

import "testing"

// === analyzeBranchFilters tests ===

func TestAnalyzeBranchFilters_EmptyFilters(t *testing.T) {
	// Empty filters = all branches trigger = exploitable
	exploitable, reason := analyzeBranchFilters([]string{})
	if !exploitable {
		t.Error("empty filters should be exploitable")
	}
	if reason == "" {
		t.Error("should have a reason")
	}
}

func TestAnalyzeBranchFilters_BroadWildcard(t *testing.T) {
	// Test *, +*, +refs/heads/* patterns
	cases := [][]string{
		{"*"},
		{"+*"},
		{"+refs/heads/*"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if !exploitable {
			t.Errorf("filter %v should be exploitable", filters)
		}
	}
}

func TestAnalyzeBranchFilters_ProtectedOnly(t *testing.T) {
	// Only protected branches = NOT exploitable
	cases := [][]string{
		{"+refs/heads/main"},
		{"+refs/heads/master"},
		{"+refs/heads/main", "+refs/heads/develop"},
		{"+main", "+master"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if exploitable {
			t.Errorf("filter %v should NOT be exploitable", filters)
		}
	}
}

func TestAnalyzeBranchFilters_UserBranches(t *testing.T) {
	// User-controllable patterns = exploitable
	cases := [][]string{
		{"+refs/heads/feature/*"},
		{"+refs/heads/users/*"},
		{"+refs/heads/bugfix/*"},
		{"+refs/heads/fix/*"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if !exploitable {
			t.Errorf("filter %v should be exploitable", filters)
		}
	}
}

func TestAnalyzeBranchFilters_ProtectedWildcard(t *testing.T) {
	// Protected wildcards (release/*, releases/*) are recognized by isProtectedWildcard()
	// and should NOT be exploitable even though they contain wildcards
	cases := [][]string{
		{"+refs/heads/release/*"},
		{"+refs/heads/releases/*"},
	}
	for _, filters := range cases {
		exploitable, _ := analyzeBranchFilters(filters)
		if exploitable {
			t.Errorf("filter %v should NOT be exploitable (protected wildcard)", filters)
		}
	}
}

func TestAnalyzeBranchFilters_ExcludeFiltersIgnored(t *testing.T) {
	// Exclude filters (starting with -) should be skipped
	exploitable, _ := analyzeBranchFilters([]string{"+refs/heads/main", "-refs/heads/develop"})
	if exploitable {
		t.Error("should not be exploitable with only protected include")
	}
}

func TestAnalyzeBranchFilters_MixedProtectedAndWildcard(t *testing.T) {
	// Protected + wildcard = exploitable (wildcard wins)
	exploitable, _ := analyzeBranchFilters([]string{"+refs/heads/main", "+refs/heads/feature/*"})
	if !exploitable {
		t.Error("mixed protected + user wildcard should be exploitable")
	}
}

// === containsUserBranchPattern tests ===

func TestContainsUserBranchPattern(t *testing.T) {
	cases := map[string]bool{
		"+refs/heads/feature/*": true,
		"+refs/heads/users/*":   true,
		"+refs/heads/bugfix/*":  true,
		"+refs/heads/hotfix/*":  true,
		"+refs/heads/main":      false,
		"+refs/heads/release/*": false,
		"feature/my-thing":      true,
		"refs/heads/dev/branch": true,
	}
	for pattern, expected := range cases {
		if containsUserBranchPattern(pattern) != expected {
			t.Errorf("containsUserBranchPattern(%q) = %v, want %v", pattern, !expected, expected)
		}
	}
}
