package engine

import (
	"errors"
	"path/filepath"
	"slices"
	"sync"
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

func TestAddSurfaceCoalescesAndNeverDowngrades(t *testing.T) {
	cases := []struct {
		name       string
		calls      [][3]string
		wantStatus string
		wantReason string
	}{
		{"ok stays ok", [][3]string{{"secrets", "ok", ""}, {"secrets", "ok", ""}},
			"ok", ""},
		{"ok escalates to degraded", [][3]string{{"secrets", "ok", ""}, {"secrets", "degraded", "403 on 2 repos"}},
			"degraded", "403 on 2 repos"},
		{"degraded survives a later ok", [][3]string{{"secrets", "degraded", "403 on 2 repos"}, {"secrets", "ok", ""}},
			"degraded", "403 on 2 repos"},
		{"skipped survives a later degraded", [][3]string{{"actions", "skipped", "no permission"}, {"actions", "degraded", "403"}},
			"skipped", "no permission"},
		{"first reason wins", [][3]string{{"secrets", "degraded", "first"}, {"secrets", "degraded", "second"}},
			"degraded", "first"},
		{"a later reason fills an empty one", [][3]string{{"secrets", "degraded", ""}, {"secrets", "skipped", "second"}},
			"degraded", "second"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			timer := StartPhaseTimer(PhaseCollect, "collect")
			for _, c := range tc.calls {
				timer.AddSurface(c[0], c[1], c[2])
			}
			if len(timer.Surfaces) != 1 {
				t.Fatalf("Surfaces = %+v, want one entry", timer.Surfaces)
			}
			got := timer.Surfaces[0]
			if got.Name != tc.calls[0][0] || got.Status != tc.wantStatus || got.Reason != tc.wantReason {
				t.Errorf("Surfaces[0] = %+v, want status %q reason %q", got, tc.wantStatus, tc.wantReason)
			}
		})
	}
}

func TestAddSurfaceKeepsOneEntryPerNameThroughStop(t *testing.T) {
	timer := StartPhaseTimer(PhaseCollect, "collect")
	for _, s := range []SurfaceStatus{
		{"secrets", "ok", ""},
		{"actions", "skipped", "no permission"},
		{"secrets", "degraded", "403 on 2 repos"},
		{"runners", "ok", ""},
	} {
		timer.AddSurface(s.Name, s.Status, s.Reason)
	}
	rec := timer.Stop(nil)
	want := []SurfaceStatus{
		{"secrets", "degraded", "403 on 2 repos"},
		{"actions", "skipped", "no permission"},
		{"runners", "ok", ""},
	}
	if !slices.Equal(rec.Surfaces, want) {
		t.Errorf("Surfaces = %+v, want %+v", rec.Surfaces, want)
	}
}

func TestAddSurfaceFromConcurrentWorkers(t *testing.T) {
	timer := StartPhaseTimer(PhaseCollect, "collect")
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			timer.AddSurface("secrets", "ok", "")
			if i%2 == 0 {
				timer.AddSurface("secrets", "degraded", "403")
			}
			timer.AddSurface("actions", "ok", "")
		})
	}
	wg.Wait()

	if len(timer.Surfaces) != 2 {
		t.Fatalf("Surfaces = %+v, want one entry per name", timer.Surfaces)
	}
	for _, s := range timer.Surfaces {
		if s.Name == "secrets" && s.Status != "degraded" {
			t.Errorf("secrets = %q, want degraded", s.Status)
		}
		if s.Name == "actions" && s.Status != "ok" {
			t.Errorf("actions = %q, want ok", s.Status)
		}
	}
}

func TestCheckPhaseGatesOnTheDeclaredWatermark(t *testing.T) {
	fresh := &State{}
	if err := fresh.CheckPhase(PhaseNormalize); !errors.Is(err, ErrPhaseBackStep) {
		t.Errorf("normalize before collect: err = %v, want ErrPhaseBackStep", err)
	}
	if err := fresh.CheckPhase(PhaseCollect); err != nil {
		t.Errorf("collect on a fresh run: %v", err)
	}
	collected := &State{LastPhase: 1}
	if err := collected.CheckPhase(PhaseNormalize); err != nil {
		t.Errorf("normalize after collect: %v", err)
	}
}

func TestLoadStateRejectsAnotherFormat(t *testing.T) {
	dir := t.TempDir()
	if err := WriteJSON(filepath.Join(dir, "_meta.json"), map[string]any{"run_id": "r", "last_phase": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); !errors.Is(err, ErrRunFormat) {
		t.Fatalf("LoadState = %v, want ErrRunFormat; a stale run directory reads as current", err)
	}

	cur := &State{RunID: "r"}
	if err := cur.Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatalf("LoadState after Save: %v", err)
	}
}
