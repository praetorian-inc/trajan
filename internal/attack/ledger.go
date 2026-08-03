package attack

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

type RecordKind string

const (
	// RecordRun is the run header: plan, mode and the authorization assertion.
	RecordRun RecordKind = "run"
	// RecordIntent is written BEFORE a mutating call and carries its inverse, so
	// a process killed between the call and its result still leaves a replayable
	// undo record.
	RecordIntent RecordKind = "intent"
	RecordResult RecordKind = "result"
	// RecordUndo carries an inverse that could not be written ahead of the call
	// because the resource it names did not exist yet — a pull request number, a
	// comment id. It refines the intent it points at.
	RecordUndo RecordKind = "undo"
	// RecordEffect carries consequences that are not reversible GitHub
	// mutations: exfiltrated secret names, minted cloud credentials, triggered
	// run ids, traffic to an out-of-band collector.
	RecordEffect RecordKind = "effect"
)

// UndoStep is one request of an inverse. It is a request rather than a plan step
// because a replay after a kill has no handle graph to bind against, and because
// an asymmetric undo (a release and its tag) is two unrelated endpoints.
type UndoStep struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   any    `json:"body,omitempty"`
	Note   string `json:"note,omitempty"`
	// Partial marks an inverse that leaves something the call put into the
	// customer's environment standing even when the request succeeds: an artifact
	// that survives in reduced form (a pull request closes but is not deleted, a
	// review is dismissed but stays on the timeline), a new state substituted for
	// the prior one (a rejection where an environment was waiting), or content
	// delivered outside the API where no request reaches it (the notification
	// email carrying a comment body).
	//
	// An event the call fired is not partial by itself. Every mutation fires one,
	// none is retractable, and marking them all would empty the reversed bucket
	// and destroy the only distinction a remediation team reads the report for:
	// whether the artifact is still there. The report says so once for every item,
	// and each inverse names the event it fired in its own note.
	Partial bool `json:"partial,omitempty"`
}

type Effect struct {
	Class     string         `json:"class"`
	Summary   string         `json:"summary"`
	Detail    map[string]any `json:"detail,omitempty"`
	ExpiresAt string         `json:"expires_at,omitempty"`
}

type LedgerEntry struct {
	Seq  int        `json:"seq"`
	Kind RecordKind `json:"kind"`
	At   string     `json:"at"`
	// Ref links a result back to the sequence number of its intent.
	Ref int `json:"ref,omitempty"`

	Step     string `json:"step,omitempty"`
	Uses     string `json:"uses,omitempty"`
	Identity string `json:"identity,omitempty"`

	Target  string     `json:"target,omitempty"`
	Method  string     `json:"method,omitempty"`
	Path    string     `json:"path,omitempty"`
	Body    any        `json:"body,omitempty"`
	Inverse []UndoStep `json:"inverse,omitempty"`
	Note    string     `json:"note,omitempty"`

	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`

	Effect *Effect `json:"effect,omitempty"`

	// Run header.
	Plan       string   `json:"plan,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	Scope      []string `json:"scope,omitempty"`
	Authorized bool     `json:"authorized,omitempty"`
	AuthVia    string   `json:"authorized_via,omitempty"`
}

// Ledger is the append-only _ledger.jsonl. Every append is fsynced: the whole
// point of write-ahead intent records is that they survive a kill -9, which a
// buffered write does not.
type Ledger struct {
	f         *os.File
	path      string
	seq       int
	mutations int
	landed    int
	refused   int
}

func OpenLedger(absPath string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, err
	}
	prior, err := ReadLedger(absPath)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(absPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	l := &Ledger{f: f, path: absPath}
	for _, e := range prior {
		l.seq = max(l.seq, e.Seq)
		switch {
		// A declared artifact carries no method: no request was sent for it, so it
		// is not one of the calls this run issued.
		case e.Kind == RecordIntent && e.Method != "":
			l.mutations++
		case e.Kind == RecordResult && e.Error == "":
			l.landed++
		case e.Kind == RecordResult:
			l.refused++
		}
	}
	return l, nil
}

func (l *Ledger) Close() error { return l.f.Close() }

// Mutations counts the mutating calls this ledger has recorded an intent for,
// including any inherited from a prior run of the same plan.
func (l *Ledger) Mutations() int { return l.mutations }

// Outcomes splits the calls that were answered into those that landed and those
// the API refused, inherited counts included. A refused call changed nothing: a
// merge answered 405 as not mergeable is a recorded intent and not a mutation
// this run can claim. A call with no result at all is neither — the process died
// before the answer, so whether it landed is unknown.
func (l *Ledger) Outcomes() (landed, refused int) { return l.landed, l.refused }

func (l *Ledger) append(e LedgerEntry) error {
	l.seq++
	e.Seq = l.seq
	e.At = engine.IsoformatUTC(time.Now())
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return l.f.Sync()
}

func (l *Ledger) Header(e LedgerEntry) error {
	e.Kind = RecordRun
	return l.append(e)
}

// Intent returns the sequence number the matching Result must carry.
func (l *Ledger) Intent(e LedgerEntry) (int, error) {
	e.Kind = RecordIntent
	if err := l.append(e); err != nil {
		return 0, err
	}
	l.mutations++
	return l.seq, nil
}

// Declare records an artifact this run causes without a call of its own, with the
// inverse that clears it. It is not counted as a mutation: nothing was sent, and
// the count is how many requests the run issued.
func (l *Ledger) Declare(e LedgerEntry) (int, error) {
	e.Kind = RecordIntent
	if err := l.append(e); err != nil {
		return 0, err
	}
	return l.seq, nil
}

func (l *Ledger) Result(intentSeq, status int, callErr error) error {
	e := LedgerEntry{Kind: RecordResult, Ref: intentSeq, Status: status}
	if callErr != nil {
		e.Error = callErr.Error()
	}
	if err := l.append(e); err != nil {
		return err
	}
	if callErr == nil {
		l.landed++
	} else {
		l.refused++
	}
	return nil
}

func (l *Ledger) Undo(intentSeq int, target string, steps []UndoStep) error {
	return l.append(LedgerEntry{Kind: RecordUndo, Ref: intentSeq, Target: target, Inverse: steps})
}

// PendingDeclaration returns the sequence of the most recent declared artifact
// whose inverse still aims at undoPath, or zero when none does. It reads the file
// because that is the only place three processes agree: the run that declared the
// inverse, the resume that has to retire it and holds no memory of it, and the
// cleanup that would otherwise replay it.
func (l *Ledger) PendingDeclaration(undoPath string) int {
	entries, err := ReadLedger(l.path)
	if err != nil {
		slog.Warn("read ledger for a declared inverse", "path", l.path, "err", err)
		return 0
	}
	for _, rev := range Reversals(entries) {
		if rev.Method != "" {
			continue
		}
		if slices.ContainsFunc(rev.Steps, func(u UndoStep) bool { return u.Path == undoPath }) {
			return rev.Seq
		}
	}
	return 0
}

func (l *Ledger) Effect(step, uses string, ef Effect) error {
	return l.append(LedgerEntry{Kind: RecordEffect, Step: step, Uses: uses, Effect: &ef})
}

func ReadLedger(absPath string) ([]LedgerEntry, error) {
	f, err := os.Open(absPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []LedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e LedgerEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("parse %s: %w", absPath, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Reversal is one recorded mutation together with the requests that undo it.
// Steps is empty when the mutation has no inverse at all, which is how a merge
// or a delivered notification reaches the cleanup report as irreversible rather
// than going unmentioned.
type Reversal struct {
	Seq      int
	Step     string
	Uses     string
	Identity string
	Target   string
	Method   string
	Path     string
	// Note is the recorded entry's own explanation. It is what an entry with no
	// inverse has to say for itself, and without it the report can only fall back
	// to naming the absence.
	Note  string
	Steps []UndoStep
	// Retired marks an entry a later step of the same run superseded with an empty
	// inverse: the artifact it recorded is gone, so there is nothing to replay and
	// nothing was left behind.
	Retired bool
}

// Reversals returns every recorded mutation in reverse sequence order, each with
// the inverse to replay. An intent with no result is included: the process may
// have died after the call landed. An intent whose result is a 4xx is not: that
// call was refused, so replaying its inverse would undo something this run never
// did. An UNDO record supersedes the intent's own inverse, because it was
// written once the created resource's id was known.
func Reversals(entries []LedgerEntry) []Reversal {
	refused := map[int]bool{}
	resolved := map[int][]UndoStep{}
	for _, e := range entries {
		switch {
		case e.Kind == RecordResult && e.Error != "" && e.Status >= 400 && e.Status < 500:
			refused[e.Ref] = true
		case e.Kind == RecordUndo:
			resolved[e.Ref] = e.Inverse
		}
	}

	var out []Reversal
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Kind != RecordIntent || refused[e.Seq] {
			continue
		}
		steps, retired := e.Inverse, false
		if amended, ok := resolved[e.Seq]; ok {
			steps, retired = amended, len(amended) == 0
		}
		out = append(out, Reversal{
			Seq: e.Seq, Step: e.Step, Uses: e.Uses, Identity: e.Identity, Target: e.Target,
			Method: e.Method, Path: e.Path, Note: e.Note, Steps: steps, Retired: retired,
		})
	}
	return out
}
