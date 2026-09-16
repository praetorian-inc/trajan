package ado

import "testing"

func TestResourceKeyOfStringifiesNumericIDs(t *testing.T) {
	cases := []struct {
		name  string
		label NodeLabel
		rec   map[string]any
		want  string
	}{
		{"numeric queue id", ProjectAgentPool, map[string]any{"project": "proj", "id": int64(21)}, "proj/21"},
		{"numeric group id", VariableGroup, map[string]any{"owner_project": "proj", "id": int64(2)}, "proj/2"},
		{"guid connection id", ServiceConnection, map[string]any{"owner_project": "proj", "id": "abc"}, "proj/abc"},
		{"environment keys on name", Environment, map[string]any{"project": "proj", "name": "prod"}, "proj/prod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceKeyOf(tc.label, tc.rec); got != tc.want {
				t.Fatalf("resourceKeyOf = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthorizedPipelinesFansOutOnlyForBlanketGrants(t *testing.T) {
	inProject := []int64{1, 2, 3}
	blanket := map[string]any{"all_pipelines": true, "authorized_pipelines": []any{}}
	if got := authorizedPipelines(blanket, inProject); len(got) != 3 {
		t.Fatalf("blanket grant = %v, want every pipeline in the project", got)
	}
	explicit := map[string]any{"all_pipelines": false, "authorized_pipelines": []any{int64(2)}}
	got := authorizedPipelines(explicit, inProject)
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("explicit grant = %v, want [2]", got)
	}
}
