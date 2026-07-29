package gitlab

import "testing"

// The isHost heuristic decides whether the first locator segment is an instance
// host to strip. A bad decision silently changes the collected scope, so these
// pin the boundary: dotted+scheme, gitlab.com, IP-style (>=2 dots), and the
// single-label case that must NOT be stripped.
func TestParseScopeHostStripping(t *testing.T) {
	cases := []struct {
		arg   string
		group string
	}{
		// Bare gitlab.com host stripped even without a scheme.
		{"gitlab.com/g/p", "g/p"},
		// Self-hosted IP with a scheme: host stripped.
		{"https://3.136.153.111/g/p", "g/p"},
		// Self-hosted IP without a scheme: >=2 dots still reads as a host.
		{"3.136.153.111/g/p", "g/p"},
		// http scheme is honored the same as https.
		{"http://gitlab.example.com/g/p", "g/p"},
		// A first segment with a single dot and no scheme is NOT a host (it's a
		// real group named "my.group"): keep it.
		{"my.group/p", "my.group/p"},
		// A plain single-label first segment is never a host.
		{"g/sub/p", "g/sub/p"},
		// Trailing and doubled slashes collapse away.
		{"https://gitlab.com/g/p/", "g/p"},
		{"g//p", "g/p"},
	}
	for _, c := range cases {
		sc, err := ParseScope(c.arg)
		if err != nil {
			t.Fatalf("ParseScope(%q): %v", c.arg, err)
		}
		if sc.Group != c.group {
			t.Errorf("ParseScope(%q).Group = %q, want %q", c.arg, sc.Group, c.group)
		}
		if sc.path != sc.Group {
			t.Errorf("ParseScope(%q): path %q != Group %q (must match before probe)", c.arg, sc.path, sc.Group)
		}
	}
}

// A host-only locator (nothing after the host) has no scope to collect.
func TestParseScopeHostOnly(t *testing.T) {
	for _, arg := range []string{"https://gitlab.com", "https://gitlab.com/", "3.136.153.111"} {
		if _, err := ParseScope(arg); err == nil {
			t.Errorf("ParseScope(%q) = nil error, want error (no scope)", arg)
		}
	}
}

func TestScopeString(t *testing.T) {
	// Project wins over group once the probe promotes the scope.
	proj := Scope{Kind: ScopeProject, Group: "g/sub", Project: "g/sub/p"}
	if got := scopeString(proj); got != "g/sub/p" {
		t.Errorf("scopeString(project) = %q, want g/sub/p", got)
	}
	grp := Scope{Kind: ScopeGroup, Group: "g/sub"}
	if got := scopeString(grp); got != "g/sub" {
		t.Errorf("scopeString(group) = %q, want g/sub", got)
	}
}
