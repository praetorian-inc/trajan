package engine

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

func TestCheckPhase(t *testing.T) {
	tests := []struct {
		name      string
		lastPhase int
		run       Phase
		wantErr   bool
	}{
		{"re-run same phase", 1, PhaseCollect, false},
		{"forward by one", 1, PhaseScan, false},
		{"forward by one from zero", 0, PhaseCollect, false},
		{"skip ahead by two", 1, PhasePush, true},
		{"skip ahead from zero", 0, PhaseScan, true},
		{"unnumbered never gated", 0, PhaseNormalize, false},
		{"unnumbered from high watermark", 3, PhaseNormalize, false},
		{"re-run earlier phase", 3, PhaseCollect, false},
		{"re-run scan after push", 3, PhaseScan, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{LastPhase: tt.lastPhase}
			err := s.CheckPhase(tt.run)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrPhaseBackStep) {
					t.Fatalf("expected ErrPhaseBackStep, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRecordPhaseWatermark(t *testing.T) {
	s := &State{Phases: []PhaseRecord{}}

	s.RecordPhase(PhaseRecord{Phase: PhaseCollect.Name, Num: PhaseCollect.Num})
	if s.LastPhase != 1 {
		t.Fatalf("after collect: LastPhase = %d, want 1", s.LastPhase)
	}
	s.RecordPhase(PhaseRecord{Phase: PhaseNormalize.Name, Num: PhaseNormalize.Num})
	if s.LastPhase != 1 {
		t.Fatalf("after normalize: LastPhase = %d, want 1 (un-numbered)", s.LastPhase)
	}
	s.RecordPhase(PhaseRecord{Phase: PhaseScan.Name, Num: PhaseScan.Num})
	if s.LastPhase != 2 {
		t.Fatalf("after scan: LastPhase = %d, want 2", s.LastPhase)
	}

	s.RecordPhase(PhaseRecord{Phase: PhaseCollect.Name, Num: PhaseCollect.Num})
	if s.LastPhase != 1 {
		t.Fatalf("after re-run collect: LastPhase = %d, want 1 (lowered)", s.LastPhase)
	}

	if len(s.Phases) != 4 {
		t.Fatalf("len(Phases) = %d, want 4", len(s.Phases))
	}
}

// Every phase downstream of p reads p's output, so re-running p invalidates all
// of them — including the graph, which carries a copy of the findings.
func TestStaleDirs(t *testing.T) {
	s := &State{}
	tests := []struct {
		phase Phase
		want  []string
	}{
		{PhaseCollect, []string{dirNormalize, dirScan, dirGraph}},
		{PhaseNormalize, []string{dirScan, dirGraph}},
		{PhaseScan, []string{dirGraph}},
		{PhaseWhoAmI, nil},
	}
	for _, tt := range tests {
		if got := s.StaleDirs(tt.phase); !slices.Equal(got, tt.want) {
			t.Errorf("StaleDirs(%s) = %v, want %v", tt.phase.Name, got, tt.want)
		}
	}
}

func TestFailedPhaseBlocksTheNextOne(t *testing.T) {
	s := &State{Phases: []PhaseRecord{}}

	collect := StartPhaseTimer(PhaseCollect, "collect")
	collect.Errors = append(collect.Errors, "conf-ci/actions-settings: HTTP 422")
	s.RecordPhase(collect.Stop(nil))
	if s.LastPhase != 1 {
		t.Fatalf("soft-fail errors must not count as failure: LastPhase = %d, want 1", s.LastPhase)
	}
	if err := s.CheckPhase(PhaseScan); err != nil {
		t.Fatalf("scan after a soft-failed collect: %v", err)
	}

	scan := StartPhaseTimer(PhaseScan, "scan")
	s.RecordPhase(scan.Stop(errors.New("load job subjects: unexpected end of JSON input")))
	if s.LastPhase != 1 {
		t.Fatalf("after failed scan: LastPhase = %d, want 1", s.LastPhase)
	}
	if err := s.CheckPhase(PhasePush); !errors.Is(err, ErrPhaseBackStep) {
		t.Fatalf("push after a failed scan: err = %v, want ErrPhaseBackStep", err)
	}

	// A failed collect has already wiped everything downstream, so the watermark
	// has to fall below collect, not merely stop advancing.
	s.LastPhase = 2
	s.RecordPhase(StartPhaseTimer(PhaseCollect, "collect").Stop(errors.New("resolve token")))
	if s.LastPhase != 0 {
		t.Fatalf("after failed collect: LastPhase = %d, want 0", s.LastPhase)
	}
	if err := s.CheckPhase(PhaseScan); !errors.Is(err, ErrPhaseBackStep) {
		t.Fatalf("scan after a failed collect: err = %v, want ErrPhaseBackStep", err)
	}
}

func TestLoadStateMissing(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "2026-06-19-1200-gh-acme")
	s, err := LoadState(runDir)
	if err != nil {
		t.Fatalf("LoadState on missing meta: %v", err)
	}
	if s.RunID != "2026-06-19-1200-gh-acme" {
		t.Errorf("RunID = %q, want basename", s.RunID)
	}
	if s.Phases == nil || len(s.Phases) != 0 {
		t.Errorf("Phases = %v, want empty non-nil", s.Phases)
	}
	if s.LastPhase != 0 {
		t.Errorf("LastPhase = %d, want 0", s.LastPhase)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run1")

	s := &State{
		RunID:     "run1",
		Platform:  "gh",
		Scope:     "acme",
		Org:       "acme",
		LastPhase: 2,
		Phases:    []PhaseRecord{{Phase: "00-collect", Num: 1, Script: "collect"}},
	}
	if err := s.Save(runDir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadState(runDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.RunID != "run1" || got.Platform != "gh" || got.LastPhase != 2 {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if len(got.Phases) != 1 || got.Phases[0].Num != 1 {
		t.Errorf("phases round trip mismatch: %+v", got.Phases)
	}
}

func TestPhaseTimer(t *testing.T) {
	timer := StartPhaseTimer(PhaseCollect, "collect")
	timer.InputFiles = 5
	timer.OutputFiles = 3

	rec := timer.Stop(nil)
	if rec.Phase != "00-collect" || rec.Num != 1 || rec.Script != "collect" {
		t.Errorf("rec identity = %+v", rec)
	}
	if rec.StartedAt == "" || rec.FinishedAt == "" {
		t.Errorf("timestamps empty: started=%q finished=%q", rec.StartedAt, rec.FinishedAt)
	}
	if rec.InputFiles != 5 || rec.OutputFiles != 3 {
		t.Errorf("file counts = in:%d out:%d", rec.InputFiles, rec.OutputFiles)
	}
	if rec.DurationS < 0 {
		t.Errorf("DurationS negative: %f", rec.DurationS)
	}
	if len(rec.Errors) != 0 {
		t.Errorf("Errors = %v, want empty", rec.Errors)
	}

	timer2 := StartPhaseTimer(PhaseScan, "scan")
	rec2 := timer2.Stop(errors.New("boom"))
	if len(rec2.Errors) != 1 || rec2.Errors[0] != "boom" {
		t.Errorf("Errors = %v, want [boom]", rec2.Errors)
	}
}
