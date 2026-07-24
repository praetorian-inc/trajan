package gitlab

import "testing"

func TestParseScope(t *testing.T) {
	cases := []struct {
		arg   string
		group string
		slug  string
	}{
		{"trajan-fr-group/trjfx", "trajan-fr-group/trjfx", "trajan-fr-group__trjfx"},
		{"trajan-fr-group", "trajan-fr-group", "trajan-fr-group"},
		{"trajan-fr-group/trjfx/sub", "trajan-fr-group/trjfx/sub", "trajan-fr-group__trjfx__sub"},
		{"https://gitlab.com/trajan-fr-group/trjfx", "trajan-fr-group/trjfx", "trajan-fr-group__trjfx"},
		{"gitlab.com/trajan-fr-group/trjfx", "trajan-fr-group/trjfx", "trajan-fr-group__trjfx"},
		{"https://3.136.153.111/trjfx", "trjfx", "trjfx"},
		{"3.136.153.111/trjfx/proj", "trjfx/proj", "trjfx__proj"},
	}
	for _, c := range cases {
		sc, err := ParseScope(c.arg)
		if err != nil {
			t.Fatalf("ParseScope(%q): %v", c.arg, err)
		}
		if sc.Group != c.group {
			t.Errorf("ParseScope(%q).Group = %q, want %q", c.arg, sc.Group, c.group)
		}
		if sc.Slug != c.slug {
			t.Errorf("ParseScope(%q).Slug = %q, want %q", c.arg, sc.Slug, c.slug)
		}
		if sc.Kind != ScopeGroup {
			t.Errorf("ParseScope(%q).Kind = %d, want provisional ScopeGroup", c.arg, sc.Kind)
		}
	}
}

func TestParseScopeEmpty(t *testing.T) {
	if _, err := ParseScope("   "); err == nil {
		t.Fatal("ParseScope(empty) = nil error, want error")
	}
}
