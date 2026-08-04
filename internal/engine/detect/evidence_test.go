package detect

import "testing"

func TestHumanValue(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"salient name wins", map[string]any{"name": "NPM_TOKEN", "scope": "unknown", "step_index": float64(0)}, "NPM_TOKEN"},
		{"app slug", map[string]any{"app_slug": "fr-app-broad-admin", "permissions": map[string]any{}}, "fr-app-broad-admin"},
		{"no salient key → sorted k=v", map[string]any{"b": "2", "a": "1"}, "a=1 b=2"},
		{"drops internal _ keys, recurses into nested values", map[string]any{
			"_chain":   []any{map[string]any{"source": "x"}},
			"contents": "write",
			"scopes":   []any{"a", "b"},
		}, "contents=write scopes=[a, b]"},
		{"string passthrough", "PLAIN", "PLAIN"},
		{"bool keeps python-str", true, "True"},
	}
	for _, c := range cases {
		if got := humanValue(c.in); got != c.want {
			t.Errorf("%s: humanValue(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestRenderEvidenceListOfRecords(t *testing.T) {
	subject := map[string]any{
		"secrets_referenced": []any{
			map[string]any{"name": "NPM_TOKEN", "scope": "unknown", "step_index": float64(0)},
			map[string]any{"name": "DEPLOY_KEY", "scope": "env", "step_index": float64(2)},
		},
	}
	got := renderEvidence("Secrets exposed: {{ secrets_referenced }}", subject)
	if got != "Secrets exposed: NPM_TOKEN, DEPLOY_KEY" {
		t.Errorf("got %q", got)
	}
}
