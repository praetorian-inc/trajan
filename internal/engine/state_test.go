package engine

import (
	"slices"
	"testing"
)

func TestSetInvocationRedactsCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"token space", []string{"collect", "Org", "--token", "secret"}, []string{"collect", "Org", "--token", "REDACTED"}},
		{"token equals", []string{"collect", "--token=secret", "Org"}, []string{"collect", "--token=REDACTED", "Org"}},
		{"bearer space", []string{"run", "--azure-bearer-token", "jwt"}, []string{"run", "--azure-bearer-token", "REDACTED"}},
		{"bearer equals", []string{"run", "--azure-bearer-token=jwt"}, []string{"run", "--azure-bearer-token=REDACTED"}},
		{"neo4j space", []string{"push", "--neo4j-pass", "pw"}, []string{"push", "--neo4j-pass", "REDACTED"}},
		{"neo4j equals", []string{"push", "--neo4j-pass=pw"}, []string{"push", "--neo4j-pass=REDACTED"}},
		{"non-credential untouched", []string{"collect", "Org", "--concurrency", "8"}, []string{"collect", "Org", "--concurrency", "8"}},
		{"trailing flag without value", []string{"collect", "--token"}, []string{"collect", "--token"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := slices.Clone(tc.in)
			var s State
			s.SetInvocation(tc.in)
			if !slices.Equal(s.Invocation, tc.want) {
				t.Fatalf("SetInvocation(%v) = %v, want %v", tc.in, s.Invocation, tc.want)
			}
			if !slices.Equal(tc.in, orig) {
				t.Fatalf("input slice was mutated: %v", tc.in)
			}
		})
	}
}
