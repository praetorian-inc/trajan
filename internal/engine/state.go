package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/trajan/internal/ui"
)

const RunFormat = 2

type State struct {
	Format     int           `json:"format"`
	RunID      string        `json:"run_id"`
	Platform   string        `json:"platform"`
	Scope      string        `json:"scope"`
	Org        string        `json:"org"`
	Invocation []string      `json:"invocation"`
	StartedAt  string        `json:"started_at"`
	LastPhase  int           `json:"last_phase"`
	Phases     []PhaseRecord `json:"phases"`
}

var credentialFlags = map[string]bool{
	"--token":              true,
	"--azure-bearer-token": true,
	"--neo4j-pass":         true,
}

// SetInvocation is the only path that writes Invocation: argv values for
// credential-bearing flags are replaced so _meta.json never stores secrets.
func (s *State) SetInvocation(args []string) {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out); i++ {
		if eq := strings.IndexByte(out[i], '='); eq > 0 && credentialFlags[out[i][:eq]] {
			out[i] = out[i][:eq+1] + "REDACTED"
		} else if credentialFlags[out[i]] && i+1 < len(out) {
			out[i+1] = "REDACTED"
			i++
		}
	}
	s.Invocation = out
}

type SurfaceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type PhaseRecord struct {
	Phase       string          `json:"phase"`
	Num         int             `json:"num"`
	Script      string          `json:"script"`
	StartedAt   string          `json:"started_at"`
	FinishedAt  string          `json:"finished_at"`
	DurationS   float64         `json:"duration_s"`
	InputFiles  int             `json:"input_files"`
	OutputFiles int             `json:"output_files"`
	Errors      []string        `json:"errors"`
	Surfaces    []SurfaceStatus `json:"surfaces,omitempty"`
	// Errors also carries soft-fail messages from a phase that succeeded; only
	// Failed means the phase aborted.
	Failed bool `json:"failed"`
}

type Phase struct {
	Num   int
	Name  string
	Needs int
}

const PhaseUnnumbered = -1

var (
	PhaseWhoAmI    = Phase{Num: 0, Name: "whoami"}
	PhaseCollect   = Phase{Num: 1, Name: DirCollect}
	PhaseNormalize = Phase{Num: PhaseUnnumbered, Name: DirNormalize, Needs: 1}
	PhaseScan      = Phase{Num: 2, Name: DirScan}
	PhaseGraph     = Phase{Num: 3, Name: "graph"}
	PhasePush      = Phase{Num: 4, Name: "push"}
	PhaseAnalyze   = Phase{Num: PhaseUnnumbered, Name: "analyze"}
	PhaseAttack    = Phase{Num: PhaseUnnumbered, Name: "attack"}
)

// A numbered phase may run only at or one step past the watermark; a bigger skip
// ahead is ErrPhaseBackStep. Re-running an earlier phase is allowed. An un-numbered
// phase is gated only on the watermark it declares.
func (s *State) CheckPhase(p Phase) error {
	if s.LastPhase < p.Needs {
		return fmt.Errorf("%w: cannot run %s when last completed phase is %d, want at least %d",
			ErrPhaseBackStep, p.Name, s.LastPhase, p.Needs)
	}
	if p.Num == PhaseUnnumbered {
		return nil
	}
	if p.Num-s.LastPhase > 1 {
		return fmt.Errorf("%w: cannot run phase %d (%s) when last completed phase is %d",
			ErrPhaseBackStep, p.Num, p.Name, s.LastPhase)
	}
	return nil
}

// A numbered phase sets the watermark to its own number, so re-running collect
// LOWERS it and forces downstream phases to re-run; a failed one drops it below
// itself, its output being missing or partial. Un-numbered phases never move it.
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
func PhaseDone(rec PhaseRecord, sink ui.Sink, attrs ...any) {
	slog.Info(phaseLabel(rec.Phase)+" complete", attrs...)
	PhaseIssues(rec, sink)
}

// For a phase that renders its own completion line and still owes the operator its
// soft failures.
func PhaseIssues(rec PhaseRecord, sink ui.Sink) {
	if len(rec.Errors) == 0 {
		return
	}
	slog.Warn(phaseLabel(rec.Phase)+" degraded", "skipped", len(rec.Errors))
	for _, e := range rec.Errors {
		sink.Item(e)
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

// The downstream phase directories invalidated when p re-runs, so a run dir never
// mixes layers from different inputs. A phase's own output dir is its own to clear.
func (s *State) StaleDirs(p Phase) []string {
	switch {
	case p.Num == PhaseCollect.Num:
		return []string{DirNormalize, DirScan, DirGraph}
	case p.Name == DirNormalize:
		return []string{DirScan, DirGraph}
	case p.Num == PhaseScan.Num:
		return []string{DirGraph}
	default:
		return nil
	}
}

// The attack ledger survives its findings: a mutation already made is undone from it.
func ClearStale(runDir string, state *State, p Phase) error {
	dirs := state.StaleDirs(p)
	if len(dirs) == 0 {
		return nil
	}
	for _, d := range dirs {
		if err := os.RemoveAll(filepath.Join(runDir, d)); err != nil {
			return err
		}
	}
	plans, err := os.ReadDir(filepath.Join(runDir, DirAttack))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, plan := range plans {
		if !plan.IsDir() {
			continue
		}
		if err := os.RemoveAll(filepath.Join(runDir, DirAttack, plan.Name(), "findings")); err != nil {
			return err
		}
	}
	return nil
}

var ErrRunFormat = errors.New("run directory format mismatch")

func LoadState(runDir string) (*State, error) {
	var s State
	p := filepath.Join(runDir, "_meta.json")
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return &State{Format: RunFormat, RunID: filepath.Base(runDir), Phases: []PhaseRecord{}}, nil
	}
	if err := ReadJSON(p, &s); err != nil {
		return nil, err
	}
	if s.Format != RunFormat {
		return nil, fmt.Errorf("%w: %s was written as format %d, this build reads format %d; re-collect",
			ErrRunFormat, runDir, s.Format, RunFormat)
	}
	return &s, nil
}

func (s *State) Save(runDir string) error {
	s.Format = RunFormat
	return WriteJSON(filepath.Join(runDir, "_meta.json"), s)
}

// Matches Python's datetime.now(timezone.utc).isoformat(): a "+00:00" offset (not
// "Z"), with the microsecond fraction omitted on a whole second.
func IsoformatUTC(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05-07:00")
	}
	return t.Format("2006-01-02T15:04:05.000000-07:00")
}

// Elapsed formats a phase duration for an Outcome trailer, dropping anything under a
// second so a fast local phase closes without a bare "0s".
func Elapsed(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second)).Round(time.Second)
	if d <= 0 {
		return ""
	}
	return d.String()
}

type PhaseTimer struct {
	Phase  Phase
	Script string

	InputFiles  int
	OutputFiles int
	Errors      []string
	Surfaces    []SurfaceStatus

	mu        sync.Mutex
	startedAt string
	t0        time.Time
}

func (t *PhaseTimer) AddError(msg string) {
	t.mu.Lock()
	t.Errors = append(t.Errors, msg)
	t.mu.Unlock()
}

// One entry per surface kind, however many items report it, and a status escalates away from "ok" but never back.
func (t *PhaseTimer) AddSurface(name, status, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.Surfaces {
		if t.Surfaces[i].Name != name {
			continue
		}
		if t.Surfaces[i].Status == "ok" && status != "ok" {
			t.Surfaces[i].Status = status
		}
		if t.Surfaces[i].Reason == "" {
			t.Surfaces[i].Reason = reason
		}
		return
	}
	t.Surfaces = append(t.Surfaces, SurfaceStatus{Name: name, Status: status, Reason: reason})
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
		Surfaces:    t.Surfaces,
		Failed:      err != nil,
	}
}
