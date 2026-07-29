package engine

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/ui"
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

func TestStaleDirs(t *testing.T) {
	s := &State{}
	if got, want := s.StaleDirs(PhaseCollect), []string{dirNormalize, dirScan}; !equalStrs(got, want) {
		t.Errorf("StaleDirs(collect) = %v, want %v", got, want)
	}
	if got, want := s.StaleDirs(PhaseNormalize), []string{dirScan}; !equalStrs(got, want) {
		t.Errorf("StaleDirs(normalize) = %v, want %v", got, want)
	}
	if got := s.StaleDirs(PhaseScan); got != nil {
		t.Errorf("StaleDirs(scan) = %v, want nil", got)
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

// A phase is named for the directory it writes, and only a numeric ordinal is a
// prefix — a name that merely contains a hyphen must survive intact.
func TestPhaseLabel(t *testing.T) {
	for in, want := range map[string]string{
		"00-collect":   "collect",
		"10-normalize": "normalize",
		"20-scan":      "scan",
		"push":         "push",
		"whoami":       "whoami",
		"pre-scan":     "pre-scan",
		"":             "",
	} {
		if got := phaseLabel(in); got != want {
			t.Errorf("phaseLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// A phase that skipped optional surfaces must say so. Silence here is the
// dangerous case: the finding count reads as complete when rules never ran.
func TestPhaseDoneSurfacesSoftFailures(t *testing.T) {
	got := captureStderr(t, func() {
		ui.Init(ui.Human, false)
		PhaseDone(PhaseRecord{
			Phase:  "00-collect",
			Errors: []string{"secure-files Platform-Deploy: 403", "general-settings: 403"},
		})
	})
	want := "collect complete\n" +
		"warning: collect degraded: 2 skipped\n" +
		"  secure-files Platform-Deploy: 403\n" +
		"  general-settings: 403\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPhaseDoneQuietWhenClean(t *testing.T) {
	got := captureStderr(t, func() {
		ui.Init(ui.Human, false)
		PhaseDone(PhaseRecord{Phase: "20-scan", Errors: []string{}}, "findings", 32)
	})
	if got != "scan complete: 32 findings\n" {
		t.Errorf("got %q", got)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
