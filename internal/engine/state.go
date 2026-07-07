package engine

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
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
	PhasePush      = Phase{3, "push"}
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
// for un-numbered phases. The record is always appended.
func (s *State) RecordPhase(rec PhaseRecord) {
	if rec.Num != PhaseUnnumbered {
		s.LastPhase = rec.Num
	}
	s.Phases = append(s.Phases, rec)
}

// StaleDirs returns the phase directories invalidated when phase p re-runs, so a
// run dir never mixes layers from different inputs.
func (s *State) StaleDirs(p Phase) []string {
	switch {
	case p.Num == PhaseCollect.Num:
		return []string{dirNormalize, dirScan}
	case p.Name == dirNormalize:
		return []string{dirScan}
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
	}
}
