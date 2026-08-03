package attack

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Resume continues a run that stopped — killed mid-watch, cancelled, or stopped
// on purpose with --until. Steps the earlier run completed are skipped and their
// handles rehydrated from the step records; a step that was still waiting picks
// up its checkpointed cursor, so the watch resumes instead of the provocation
// being issued a second time. A step the ledger records as having already issued
// a request is not run at all: its record never landed, so what it produced is
// unknown, and repeating a call the API does not treat as idempotent is the one
// thing a resume must not do.
func Resume(ctx context.Context, cfg *engine.Config, opts RunOptions) (*RunResult, error) {
	if opts.RunDir == "" {
		return nil, fmt.Errorf("resume needs a run directory: pass --path")
	}
	planID, err := resolvePlanID(opts.RunDir, opts.PlanID)
	if err != nil {
		return nil, err
	}
	rec, err := readPlanRecord(opts.RunDir, planID)
	if err != nil {
		return nil, err
	}
	if rec.Source == "" {
		return nil, fmt.Errorf("%s records no plan source to reload", planID)
	}
	p, err := LoadPlan(rec.Source)
	if err != nil {
		return nil, fmt.Errorf("reload plan %q: %w", rec.Source, err)
	}
	if p.ID != rec.ID {
		return nil, fmt.Errorf("%s now holds plan %q, but this run recorded %q", rec.Source, p.ID, rec.ID)
	}
	// The values the operator passed on the original invocation are part of what
	// was authorized; they are replayed from the record rather than re-typed, and
	// compared against it so a redeclared input cannot change what a step means.
	p.SetFileValues = rec.Inputs
	if err := sameChain(rec, p); err != nil {
		return nil, err
	}

	opts.prior = &rec
	opts.Execute = rec.Mode == "execute"
	slog.Info("resuming", "plan", rec.ID, "mode", rec.Mode, "authorized_via", rec.AuthorizedVia, "started", rec.StartedAt)
	return Run(ctx, cfg, p, opts)
}

// sameChain refuses a resume whose plan text has moved under the run. It is the
// whole of what stands behind a resumed run's authorization: no new assertion is
// taken, so every part of the text that decides what a step touches — the scope,
// the step order and ids, what each step uses, who it acts as, what gates it,
// its own keys, and the inputs those keys resolve through — must be the text the
// operator authorized. Handles are also rehydrated by step id, so a reordered or
// retyped step would restore a prior run's handle into a step that never
// produced it.
func sameChain(rec PlanRecord, p *Plan) error {
	if !slices.Equal(rec.Scope, p.Scope) {
		return fmt.Errorf("%s now declares scope [%s], but this run was authorized for [%s]; resume needs the plan it ran",
			rec.Source, strings.Join(p.Scope, ", "), strings.Join(rec.Scope, ", "))
	}
	was := slices.Concat(rec.Steps, rec.Cleanup)
	now := planSteps(allSteps(p))
	if len(was) != len(now) {
		return fmt.Errorf("%s now has %d steps, but this run recorded %d; resume needs the plan it ran", rec.Source, len(now), len(was))
	}
	for i := range was {
		if diff := stepDiff(was[i], now[i]); diff != "" {
			return fmt.Errorf("%s step %d (%s) %s; resume needs the plan it ran, and takes no new authorization assertion",
				rec.Source, i+1, cmp.Or(now[i].ID, was[i].ID), diff)
		}
	}
	// The record holds the inputs as resolved, so redeclaring one — a new default,
	// or a new input whose name a step key already spells — shows up here even
	// though no step key changed.
	if errs := p.resolveInputs(); len(errs) == 0 && canonJSON(p.resolvedInputs) != canonJSON(rec.Inputs) {
		return fmt.Errorf("%s now resolves its inputs to %s, but this run recorded %s; resume needs the plan it ran",
			rec.Source, canonJSON(p.resolvedInputs), canonJSON(rec.Inputs))
	}
	return nil
}

func stepDiff(was, now PlanStep) string {
	switch {
	case was.ID != now.ID:
		return fmt.Sprintf("is now id %q, but this run recorded %q", now.ID, was.ID)
	case was.Uses != now.Uses:
		return fmt.Sprintf("now uses %q, but this run recorded %q", now.Uses, was.Uses)
	case was.As != now.As:
		return fmt.Sprintf("now acts as %q, but this run recorded %q", now.As, was.As)
	case was.When != now.When:
		return fmt.Sprintf("is now gated on %q, but this run recorded %q", now.When, was.When)
	case canonJSON(was.Keys) != canonJSON(now.Keys):
		return fmt.Sprintf("now takes %s, but this run recorded %s", canonJSON(now.Keys), canonJSON(was.Keys))
	}
	return ""
}

// canonJSON is how a recorded mapping and a freshly parsed one are compared: the
// record has been through JSON, where a plan's int is a float, and both sides
// encode the same way. It doubles as the text of the mismatch message.
func canonJSON(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf("%v", m)
	}
	return string(b)
}

// sameIdentities refuses a resume that would act as a different principal than
// the run recorded. The ledger names an identity by its plan name, and cleanup
// replays each inverse as the identity that made the change: acting as another
// login would attribute this run's mutations to an account that never made them.
func sameIdentities(was []PlanIdentity, s *Session) error {
	for _, ic := range uniqueIdentities(s.identities) {
		i := slices.IndexFunc(was, func(rec PlanIdentity) bool { return rec.Name == ic.name })
		if i < 0 || was[i].Login == "" || ic.login == "" || was[i].Login == ic.login {
			continue
		}
		return fmt.Errorf("identity %q now resolves to %q, but this run was authorized acting as %q; resume needs the credentials it ran with",
			ic.name, ic.login, was[i].Login)
	}
	return nil
}

// resumeFrom loads what an earlier run of this directory left behind: the step
// records whose handles are replayed, and the write-ahead intents that say which
// steps already issued a request.
func (x *executor) resumeFrom(runDir, planID string) error {
	prior, err := loadStepRecords(runDir, planID)
	if err != nil {
		return err
	}
	entries, err := ReadLedger(filepath.Join(runDir, engine.AttackLedger(planID)))
	if err != nil {
		return err
	}
	x.prior = prior
	x.issued = issuedMutations(entries)
	return nil
}

// issuedMutations maps a step id to the intent record of the first request it
// issued. An intent GitHub refused with a 4xx is left out: that call changed
// nothing, which is the same reading Reversals takes when it decides which
// inverses are worth replaying. A declared artifact carries no method, because
// no request was sent for it.
func issuedMutations(entries []LedgerEntry) map[string]LedgerEntry {
	refused := map[int]bool{}
	for _, e := range entries {
		if e.Kind == RecordResult && e.Error != "" && e.Status >= 400 && e.Status < 500 {
			refused[e.Ref] = true
		}
	}
	out := map[string]LedgerEntry{}
	for _, e := range entries {
		if e.Kind != RecordIntent || e.Step == "" || e.Method == "" || refused[e.Seq] {
			continue
		}
		if _, dup := out[e.Step]; !dup {
			out[e.Step] = e
		}
	}
	return out
}

func readPlanRecord(runDir, planID string) (PlanRecord, error) {
	var rec PlanRecord
	path := filepath.Join(runDir, engine.AttackPlan(planID))
	raw, err := os.ReadFile(path)
	if err != nil {
		return rec, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, fmt.Errorf("parse %s: %w", path, err)
	}
	return rec, nil
}

// loadStepRecords reads what the earlier run wrote, keyed by step id. A record
// that will not parse is dropped with a warning rather than aborting: the step
// it belongs to simply runs again.
func loadStepRecords(runDir, planID string) (map[string]StepRecord, error) {
	dir := filepath.Join(runDir, engine.AttackSteps(planID))
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return map[string]StepRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string]StepRecord, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var rec StepRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			slog.Warn("step record will not parse; the step will run again", "file", e.Name(), "err", err)
			continue
		}
		if rec.ID == "" {
			continue
		}
		if prev, dup := out[rec.ID]; !dup || prev.Seq < rec.Seq {
			out[rec.ID] = rec
		}
	}
	return out, nil
}

// UnmarshalJSON rehydrates the produced handle, which the sealed Handle
// interface cannot decode on its own. HandleKind names the concrete type, and
// every handle is plain JSON with no live pointers, so this is the whole of
// what a resume has to restore.
func (r *StepRecord) UnmarshalJSON(b []byte) error {
	type record StepRecord
	var v struct {
		record
		Handle json.RawMessage `json:"handle"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*r = StepRecord(v.record)
	r.Handle = nil
	if len(v.Handle) == 0 || v.HandleKind == "" {
		return nil
	}
	h, err := decodeHandle(v.HandleKind, v.Handle)
	if err != nil {
		return err
	}
	r.Handle = h
	return nil
}

func decodeHandle(kind HandleKind, raw json.RawMessage) (Handle, error) {
	if kind == KindNone {
		return None{}, nil
	}
	t, known := handleTypes[kind]
	if !known {
		return nil, fmt.Errorf("unknown handle kind %q", kind)
	}
	p := reflect.New(t)
	if err := json.Unmarshal(raw, p.Interface()); err != nil {
		return nil, fmt.Errorf("decode %s handle: %w", kind, err)
	}
	h, ok := p.Elem().Interface().(Handle)
	if !ok {
		return nil, fmt.Errorf("%s does not decode to a handle", kind)
	}
	return h, nil
}
