package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/ui"
)

type State struct {
	RunID      string        `json:"run_id"`
	Platform   string        `json:"platform"`
	Scope      string        `json:"scope"`
	Org        string        `json:"org"`
	Invocation []string      `json:"invocation"`
	StartedAt  string        `json:"started_at"`
	LastPhase  int           `json:"last_phase"`
	Phases     []PhaseRecord `json:"phases"`
}

type PhaseRecord struct {
	Phase       string   `json:"phase"`
	Num         int      `json:"num"`
	Script      string   `json:"script"`
	StartedAt   string   `json:"started_at"`
	FinishedAt  string   `json:"finished_at"`
	DurationS   float64  `json:"duration_s"`
	InputFiles  int      `json:"input_files"`
	OutputFiles int      `json:"output_files"`
	Errors      []string `json:"errors"`
	// Errors also carries soft-fail per-item messages from a phase that succeeded,
	// so only Failed tells you the phase aborted.
	Failed bool `json:"failed"`
}

type Phase struct {
	Num  int
	Name string
}

const PhaseUnnumbered = -1

var (
	PhaseWhoAmI    = Phase{0, "whoami"}
	PhaseCollect   = Phase{1, dirCollect}
	PhaseNormalize = Phase{PhaseUnnumbered, dirNormalize}
	PhaseScan      = Phase{2, dirScan}
	PhaseGraph     = Phase{3, "graph"}
	PhasePush      = Phase{4, "push"}
	PhaseAnalyze   = Phase{PhaseUnnumbered, "analyze"}
	PhaseAttack    = Phase{PhaseUnnumbered, "attack"}
)

// CheckPhase permits a numbered phase to run only when it is at or within one
// step of the watermark; a skip-ahead of more than one is ErrPhaseBackStep.
// Re-running an earlier phase is allowed. Un-numbered phases are never gated.
func (s *State) CheckPhase(p Phase) error {
	if p.Num == PhaseUnnumbered {
		return nil
	}
	if p.Num-s.LastPhase > 1 {
		return fmt.Errorf("%w: cannot run phase %d (%s) when last completed phase is %d",
			ErrPhaseBackStep, p.Num, p.Name, s.LastPhase)
	}
	return nil
}

// RecordPhase sets the watermark to a numbered phase's own number — so re-running
// collect LOWERS it and forces downstream phases to re-run — and leaves it alone
// for un-numbered phases. A failed phase drops the watermark below itself: its
// output is missing or partial, so nothing downstream may run on it. The record is
// always appended.
func (s *State) RecordPhase(rec PhaseRecord) {
	if rec.Num != PhaseUnnumbered {
		if rec.Failed {
			s.LastPhase = min(s.LastPhase, rec.Num-1)
		} else {
			s.LastPhase = rec.Num
		}
	}
	s.Phases = append(s.Phases, rec)
}

// Soft failures are announced, not just recorded: a rule that never fires
// because its input was unreadable makes the finding count look complete.
func PhaseDone(rec PhaseRecord, attrs ...any) {
	slog.Info(phaseLabel(rec.Phase)+" complete", attrs...)
	PhaseIssues(rec)
}

// PhaseIssues is the announcement on its own, for a phase that renders its own
// completion line and still owes the operator its soft failures.
func PhaseIssues(rec PhaseRecord) {
	if len(rec.Errors) == 0 {
		return
	}
	slog.Warn(phaseLabel(rec.Phase)+" degraded", "skipped", len(rec.Errors))
	for _, e := range rec.Errors {
		ui.Item(e)
	}
}

// A phase is named for the directory it writes ("20-scan"); the ordinal is
// the on-disk contract, not something to say out loud.
func phaseLabel(phase string) string {
	num, name, ok := strings.Cut(phase, "-")
	if !ok || num == "" || strings.TrimLeft(num, "0123456789") != "" {
		return phase
	}
	return name
}

// StaleDirs returns the downstream phase directories invalidated when phase p
// re-runs, so a run dir never mixes layers from different inputs. A phase's own
// output dir is its own to clear.
func (s *State) StaleDirs(p Phase) []string {
	switch {
	case p.Num == PhaseCollect.Num:
		return []string{dirNormalize, dirScan, dirGraph}
	case p.Name == dirNormalize:
		return []string{dirScan, dirGraph}
	case p.Num == PhaseScan.Num:
		return []string{dirGraph}
	default:
		return nil
	}
}

func LoadState(runDir string) (*State, error) {
	var s State
	p := filepath.Join(runDir, "_meta.json")
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return &State{RunID: filepath.Base(runDir), Phases: []PhaseRecord{}}, nil
	}
	if err := ReadJSON(p, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *State) Save(runDir string) error {
	return WriteJSON(filepath.Join(runDir, "_meta.json"), s)
}

// IsoformatUTC matches Python's datetime.now(timezone.utc).isoformat(): a
// "+00:00" offset (not "Z"), with the 6-digit microsecond fraction omitted when
// the time lands exactly on a second.
func IsoformatUTC(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05-07:00")
	}
	return t.Format("2006-01-02T15:04:05.000000-07:00")
}

type PhaseTimer struct {
	Phase  Phase
	Script string

	InputFiles  int
	OutputFiles int
	Errors      []string

	startedAt string
	t0        time.Time
}

func StartPhaseTimer(p Phase, script string) *PhaseTimer {
	return &PhaseTimer{
		Phase:     p,
		Script:    script,
		Errors:    []string{},
		startedAt: IsoformatUTC(time.Now()),
		t0:        time.Now(),
	}
}

func (t *PhaseTimer) Stop(err error) PhaseRecord {
	elapsed := time.Since(t.t0).Seconds()
	errs := t.Errors
	if err != nil {
		errs = append(errs, err.Error())
	}
	return PhaseRecord{
		Phase:       t.Phase.Name,
		Num:         t.Phase.Num,
		Script:      t.Script,
		StartedAt:   t.startedAt,
		FinishedAt:  IsoformatUTC(time.Now()),
		DurationS:   math.RoundToEven(elapsed*1000) / 1000,
		InputFiles:  t.InputFiles,
		OutputFiles: t.OutputFiles,
		Errors:      errs,
		Failed:      err != nil,
	}
}
