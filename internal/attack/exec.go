package attack

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v4"

	"github.com/praetorian-inc/trajan/internal/dsl"
	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
)

const (
	statusOK = "ok"
	// statusPlanned is a mutation a dry run rendered instead of issuing.
	statusPlanned = "planned"
	// statusUnresolved is a read a dry run could not issue because its inputs
	// would have come from a mutation that never happened. It is distinct from
	// skipped: nothing is wrong, the run simply did not go far enough to know.
	statusUnresolved = "unresolved"
	statusSkipped    = "skipped"
	statusFailed     = "failed"
	// statusWaiting is what a poll checkpoints while it is still waiting. It only
	// ever survives a kill: a step that returns overwrites it with its outcome,
	// so a record left in this state is what tells resume to resume the watch.
	statusWaiting = "waiting"
)

const dryRunNote = "No request was sent. Reads ahead of the first mutation were issued for real so the " +
	"render could resolve their targets; every mutating step is listed whether or not those reads " +
	"succeeded, because this document is the inventory of what --execute would attempt. Each step's " +
	"body ran with its mutations recorded instead of issued, so `requests` is the real method, path " +
	"and body of every call it would make, with fully-rendered payloads. A value that would have " +
	"come from a response is blank and an object id a run never created reads as all zeroes. A " +
	"target that only exists after a mutation — a fork lands in the acting identity's namespace — " +
	"is re-checked against the scope allowlist at execution time."

type RunOptions struct {
	// RunDir attaches to an existing run directory; empty mints a fresh one from
	// the plan's scope.
	RunDir     string
	Execute    bool
	Authorized bool

	// PlanID selects which plan inside RunDir to resume when it holds several.
	PlanID string
	// Until runs up to and including that step and then stops cleanly, leaving
	// the rest — and the cleanup block — for a later resume. This is the shape a
	// human-paced wait wants: run --until pr, walk away, resume.
	Until string
	// StepDelay sleeps between every step, absorbing GitHub's read-after-write
	// propagation lag without scattering sleeps through plan text.
	StepDelay time.Duration

	// KeepCipher retains the harvest's persisted ciphertext after a successful
	// decrypt instead of discarding it.
	KeepCipher bool

	// prior is the record of the run this one continues. It marks the run as a
	// resume — completed steps are skipped and their handles rehydrated — and it
	// carries the authorization the resume inherits and the identities it must
	// still be acting as, both of which a resume takes no new assertion for.
	prior *PlanRecord
}

type RunResult struct {
	Plan      string
	RunDir    string
	PlanDir   string
	Mode      string
	OK        int
	Planned   int
	Failed    int
	Skipped   int
	Resumed   int
	Mutations int
	// StoppedAt is the --until step the run stopped after; empty when the walk
	// reached the end.
	StoppedAt string
}

type StepRecord struct {
	Seq        int            `json:"seq"`
	ID         string         `json:"id"`
	Uses       string         `json:"uses"`
	Status     string         `json:"status"`
	Mutating   bool           `json:"mutating"`
	Identity   string         `json:"identity,omitempty"`
	Target     string         `json:"target,omitempty"`
	When       string         `json:"when,omitempty"`
	Inputs     map[string]any `json:"inputs"`
	Handle     Handle         `json:"handle,omitempty"`
	HandleKind HandleKind     `json:"handle_kind,omitempty"`
	Empty      bool           `json:"empty,omitempty"`
	Note       string         `json:"note,omitempty"`
	Error      string         `json:"error,omitempty"`
	// Cursor is a waiting step's poll cursor, rewritten every poll. For the run
	// watchers it also carries the full candidate set beside the chosen run, so
	// an ambiguous correlation is visible rather than silently resolved.
	Cursor     any    `json:"cursor,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

type PlannedRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   any    `json:"body,omitempty"`
}

type PlannedMutation struct {
	Seq         int              `json:"seq"`
	Step        string           `json:"step"`
	Uses        string           `json:"uses"`
	Identity    string           `json:"identity,omitempty"`
	Target      string           `json:"target,omitempty"`
	Reversible  bool             `json:"reversible"`
	Destructive bool             `json:"destructive"`
	Inputs      map[string]any   `json:"inputs"`
	Note        string           `json:"note,omitempty"`
	Requests    []PlannedRequest `json:"requests"`
}

type DryRun struct {
	Plan        string            `json:"plan"`
	Title       string            `json:"title,omitempty"`
	GeneratedAt string            `json:"generated_at"`
	Scope       []string          `json:"scope"`
	Note        string            `json:"note"`
	ReadsIssued []string          `json:"reads_issued"`
	Mutations   []PlannedMutation `json:"mutations"`
}

type PlanIdentity struct {
	Name  string `json:"name"`
	From  string `json:"from"`
	Class string `json:"class,omitempty"`
	Login string `json:"login,omitempty"`
	Error string `json:"error,omitempty"`
}

type PlanStep struct {
	ID   string         `json:"id"`
	Uses string         `json:"uses"`
	As   string         `json:"as,omitempty"`
	When string         `json:"when,omitempty"`
	Keys map[string]any `json:"keys"`
}

// PlanRecord is the run's copy of what it was asked to do. Identities appear by
// name only: token material never reaches a run directory.
type PlanRecord struct {
	APIVersion    string         `json:"apiVersion"`
	ID            string         `json:"id"`
	Title         string         `json:"title,omitempty"`
	Source        string         `json:"source,omitempty"`
	Scope         []string       `json:"scope"`
	Orgs          []string       `json:"orgs,omitempty"`
	Collector     string         `json:"collector,omitempty"`
	Rule          string         `json:"rule,omitempty"`
	Encryption    string         `json:"encryption,omitempty"`
	Mode          string         `json:"mode"`
	Authorized    bool           `json:"authorized"`
	AuthorizedVia string         `json:"authorized_via,omitempty"`
	StartedAt     string         `json:"started_at"`
	Identities    []PlanIdentity `json:"identities"`
	Inputs        map[string]any `json:"inputs"`
	Steps         []PlanStep     `json:"steps"`
	Cleanup       []PlanStep     `json:"cleanup"`
}

// Run validates, wires the run directory, and walks the plan once in declaration
// order. Only a condition that makes the run meaningless — an invalid plan, an
// unwritable run dir, an unresolvable identity under --execute, a cancelled
// context — returns an error; a step that fails is recorded and the walk goes on.
func Run(ctx context.Context, cfg *engine.Config, p *Plan, opts RunOptions) (*RunResult, error) {
	var hard []string
	for _, e := range Validate(p) {
		if IsWarning(e) {
			slog.Warn("plan", "warning", e.Error())
			continue
		}
		hard = append(hard, e.Error())
	}
	if len(hard) > 0 {
		return nil, fmt.Errorf("plan %s: %d validation error(s):\n  %s", p.ID, len(hard), strings.Join(hard, "\n  "))
	}

	resume := opts.prior != nil
	mode := "dry-run"
	authVia := ""
	if opts.Execute {
		mode = "execute"
		if resume {
			// A resume takes no new assertion: sameChain has already proven the plan
			// text, its scope and its inputs are the ones that were authorized. The
			// ledger header still has to say which assertion it is standing on.
			authVia = cmp.Or(opts.prior.AuthorizedVia, "unrecorded") + " (inherited by resume)"
		} else {
			var err error
			if authVia, err = assertAuthorization(p, opts.Authorized); err != nil {
				return nil, err
			}
		}
	}
	if opts.Until != "" && !slices.ContainsFunc(allSteps(p), func(st Step) bool { return st.ID == opts.Until }) {
		return nil, fmt.Errorf("--until %q names no step in plan %s", opts.Until, p.ID)
	}

	runDir, err := attackRunDir(cfg, p, opts.RunDir)
	if err != nil {
		return nil, err
	}
	planDir := filepath.Join(runDir, engine.AttackDir(p.ID))
	if err := os.MkdirAll(planDir, 0o755); err != nil {
		return nil, err
	}

	state, err := engine.LoadState(runDir)
	if err != nil {
		return nil, err
	}
	if err := state.CheckPhase(engine.PhaseAttack); err != nil {
		return nil, err
	}
	state.Platform = "gh"
	if state.Scope == "" {
		state.Scope = strings.Join(p.Scope, ",")
	}
	if state.StartedAt == "" {
		state.StartedAt = engine.IsoformatUTC(time.Now())
		state.Invocation = os.Args[1:]
	}

	ledger, err := OpenLedger(filepath.Join(runDir, engine.AttackLedger(p.ID)))
	if err != nil {
		return nil, err
	}
	defer ledger.Close()

	sess, err := NewSession(ctx, p, planDir, ledger, opts.Execute)
	if err != nil {
		return nil, err
	}
	sess.Resumed = resume
	sess.KeepCipher = opts.KeepCipher
	if resume {
		if err := sameIdentities(opts.prior.Identities, sess); err != nil {
			return nil, err
		}
	}

	if err := ledger.Header(LedgerEntry{
		Plan: p.ID, Mode: mode, Scope: p.Scope,
		Authorized: opts.Execute, AuthVia: authVia,
	}); err != nil {
		return nil, err
	}
	// A resumed run inherits the record the original wrote: overwriting it would
	// replace the authorization assertion and the start time of the run the
	// operator actually authorized. The resume itself is recorded by the ledger
	// header above, which names the assertion it inherited.
	if !resume {
		if err := writePlanRecord(runDir, p, sess, mode, opts.Execute, authVia); err != nil {
			return nil, err
		}
	}

	timer := engine.StartPhaseTimer(engine.PhaseAttack, "attack")
	x := &executor{
		plan: p, sess: sess, runDir: runDir, execute: opts.Execute,
		until:    opts.Until,
		delay:    opts.StepDelay,
		handles:  map[string]Handle{},
		subjects: map[string]any{},
		status:   map[string]string{},
		targets:  map[string]string{},
		stepIDs:  map[string]bool{},
		reads:    []string{},
		planned:  []PlannedMutation{},
	}
	for _, st := range allSteps(p) {
		x.stepIDs[st.ID] = true
	}
	if resume {
		if err := x.resumeFrom(runDir, p.ID); err != nil {
			return nil, err
		}
	}

	walkErr := x.walk(ctx, p.Steps)
	// Cleanup runs whatever happened to the steps, in declaration order: a
	// template's cleanup block is already authored as the undo sequence. --until
	// is the one thing that holds it back, because the point of stopping early is
	// that the artifacts must still be there when the operator resumes.
	if !x.stopped {
		if cerr := x.walk(ctx, p.Cleanup); walkErr == nil {
			walkErr = cerr
		}
	}

	if !opts.Execute {
		if err := engine.WriteJSON(filepath.Join(runDir, engine.AttackDryRun(p.ID)), DryRun{
			Plan:        p.ID,
			Title:       p.Title,
			GeneratedAt: engine.IsoformatUTC(time.Now()),
			Scope:       p.Scope,
			Note:        dryRunNote,
			ReadsIssued: x.reads,
			Mutations:   x.planned,
		}); err != nil {
			return nil, err
		}
	}

	// A run stopped by --until has not finished the chain, so there is no finding
	// to assemble yet: the resume that completes it writes one.
	if opts.Execute && !x.stopped {
		if err := x.finalize(p, mode, ledger.Mutations()); err != nil {
			x.errs = append(x.errs, "finalize: "+err.Error())
		}
	}

	timer.Errors = x.errs
	timer.OutputFiles = x.seq
	rec := timer.Stop(walkErr)
	state.RecordPhase(rec)
	if err := state.Save(runDir); err != nil {
		return nil, err
	}
	engine.PhaseDone(rec, "mode", mode, "plan", p.ID)

	res := &RunResult{Plan: p.ID, RunDir: runDir, PlanDir: planDir, Mode: mode, Mutations: ledger.Mutations(), Resumed: x.replayed}
	if x.stopped {
		res.StoppedAt = opts.Until
	}
	for _, st := range x.status {
		switch st {
		case statusOK:
			res.OK++
		case statusPlanned:
			res.Planned++
		case statusFailed:
			res.Failed++
		default:
			res.Skipped++
		}
	}
	return res, walkErr
}

// attackRunDir attaches to an explicit run dir or mints one from the plan's
// allowlist, so the named scope and the executed scope are the same object.
func attackRunDir(cfg *engine.Config, p *Plan, explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("run directory %s: %w", explicit, err)
		}
		return explicit, nil
	}
	sc, err := github.ParseScope(strings.TrimSuffix(p.Scope[0], "/*"))
	if err != nil {
		return "", err
	}
	return engine.MintRunDir(cfg, "gh", sc.Slug)
}

// assertAuthorization is the once-per-run gate every mutation sits behind.
func assertAuthorization(p *Plan, preAsserted bool) (string, error) {
	if preAsserted {
		return "--i-am-authorized", nil
	}
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("--execute requires an authorization assertion; pass --i-am-authorized or run on a terminal")
	}
	fmt.Fprintf(os.Stderr, "Type the target scope %q to assert you are authorized to mutate it: ", p.Scope[0])
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(line) != p.Scope[0] {
		return "", errors.New("authorization assertion did not match the target scope; nothing was sent")
	}
	return "interactive", nil
}

func writePlanRecord(runDir string, p *Plan, s *Session, mode string, authorized bool, via string) error {
	rec := PlanRecord{
		APIVersion: p.APIVersion, ID: p.ID, Title: p.Title, Source: p.Source,
		Scope: p.Scope, Orgs: p.Orgs, Collector: p.collector(), Rule: p.Rule, Encryption: p.Encryption,
		Mode: mode, Authorized: authorized, AuthorizedVia: via,
		StartedAt: engine.IsoformatUTC(time.Now()),
		Inputs:    p.resolvedInputs,
		Steps:     planSteps(p.Steps),
		Cleanup:   planSteps(p.Cleanup),
	}
	for _, ic := range uniqueIdentities(s.identities) {
		pi := PlanIdentity{Name: ic.name, From: ic.from, Class: ic.kind, Login: ic.login}
		if ic.err != nil {
			pi.Error = ic.err.Error()
		}
		rec.Identities = append(rec.Identities, pi)
	}
	return engine.WriteJSON(filepath.Join(runDir, engine.AttackPlan(p.ID)), rec)
}

func planSteps(steps []Step) []PlanStep {
	out := make([]PlanStep, 0, len(steps))
	for _, st := range steps {
		out = append(out, PlanStep{ID: st.ID, Uses: st.Uses, As: st.As, When: st.When, Keys: st.Keys})
	}
	return out
}

type executor struct {
	plan    *Plan
	sess    *Session
	runDir  string
	execute bool
	until   string
	delay   time.Duration

	handles  map[string]Handle
	subjects map[string]any
	status   map[string]string
	targets  map[string]string
	stepIDs  map[string]bool
	prior    map[string]StepRecord
	// issued maps a step id to the write-ahead intent an earlier run of this same
	// run directory left for it. It is populated only on a resume, and it is the
	// only evidence there is that a request went out under a step whose record
	// never landed.
	issued map[string]LedgerEntry

	records  []StepRecord
	seq      int
	replayed int
	stalled  bool
	stopped  bool
	planned  []PlannedMutation
	reads    []string
	errs     []string
}

func (x *executor) walk(ctx context.Context, steps []Step) error {
	for i := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		if x.delay > 0 && x.seq > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(x.delay):
			}
		}
		x.step(ctx, &steps[i])
		if x.until != "" && steps[i].ID == x.until {
			x.stopped = true
			slog.Info("stopped at --until; resume to continue", "step", x.until)
			return nil
		}
	}
	return nil
}

func (x *executor) step(ctx context.Context, st *Step) {
	x.seq++
	if prior, done := x.prior[st.ID]; done && prior.Status == statusOK {
		x.replay(st, prior)
		return
	}
	rec := StepRecord{
		Seq: x.seq, ID: st.ID, Uses: st.Uses, When: st.When,
		Inputs: map[string]any{}, StartedAt: engine.IsoformatUTC(time.Now()),
		// A resumed watch carries its predecessor's cursor from the first line of
		// the record onwards: the write below is unconditional, so a step that dies
		// before its first checkpoint would otherwise erase the correlation the next
		// resume needs.
		Cursor: x.prior[st.ID].Cursor,
	}
	writeRecord := func() error {
		return engine.WriteJSON(filepath.Join(x.runDir, engine.AttackStep(x.plan.ID, rec.Seq, st.ID)), rec)
	}
	defer func() {
		rec.FinishedAt = engine.IsoformatUTC(time.Now())
		x.records = append(x.records, rec)
		x.status[st.ID] = rec.Status
		x.targets[st.ID] = rec.Target
		if rec.Status == statusFailed {
			x.errs = append(x.errs, fmt.Sprintf("step %s (%s): %s", st.ID, st.Uses, rec.Error))
		}
		if err := writeRecord(); err != nil {
			x.errs = append(x.errs, fmt.Sprintf("step %s: write record: %v", st.ID, err))
		}
		slog.Info("step "+rec.Status, "step", st.ID, "uses", st.Uses, "target", rec.Target)
	}()

	e, ok := lookup(st.Uses)
	if !ok {
		rec.Status, rec.Error = statusFailed, "unknown primitive "+st.Uses
		return
	}
	rec.Mutating = e.spec.Mutating

	// The step record is written after the primitive returns, so a step whose
	// record is missing may still have issued its request. The ledger's
	// write-ahead intent is what says whether it did, and a resume that re-ran the
	// step would repeat a call GitHub does not treat as idempotent.
	if intent, alreadyIssued := x.issued[st.ID]; alreadyIssued {
		rec.Status = statusFailed
		rec.Error = fmt.Sprintf("an earlier run of this step already issued %s %s (ledger seq %d) and left no completed record, "+
			"so what it produced is unknown; resume does not repeat a mutation. Reverse this run with "+
			"`trajan gh attack cleanup -p %s`, then start a fresh one",
			intent.Method, intent.Path, intent.Seq, x.runDir)
		return
	}

	deps := x.dependencies(st, e.spec)
	dead := x.firstWith(deps, statusFailed, statusSkipped)
	// A dry run renders every mutating step whatever became of the reads above
	// it: the point of the document is a complete inventory of what --execute
	// would attempt, and that must not depend on whether this machine holds the
	// plan's credentials. Reads, by contrast, stop at the first planned mutation
	// — everything after it would be reading for state that was never created,
	// and an await would block on a run nothing provoked.
	planOnly := !x.execute && e.spec.Mutating
	if dead != "" && !planOnly {
		rec.Status = statusSkipped
		rec.Note = fmt.Sprintf("step %q is %s", dead, x.status[dead])
		return
	}
	pending := !x.execute && x.stalled
	if pending && !planOnly {
		rec.Status = statusUnresolved
		rec.Note = "not evaluated: a mutation above this step was rendered, not issued"
		return
	}

	ic, err := x.sess.identity(ctx, st.As)
	if err != nil && !planOnly {
		rec.Status, rec.Error = statusFailed, err.Error()
		return
	}
	if ic != nil {
		rec.Identity = ic.name
	}

	ports, fields, err := x.bind(st, e, !planOnly)
	if err != nil {
		rec.Status, rec.Error = statusFailed, err.Error()
		return
	}
	rec.Inputs = renderInputs(st, e.spec, fields)
	rec.Target = x.target(st, e.spec, ports, fields)

	if st.When != "" {
		if planOnly && (pending || dead != "") {
			rec.Note = "when: not evaluated in dry run"
		} else {
			gate, err := x.evalWhen(st)
			if err != nil {
				rec.Status, rec.Error = statusFailed, err.Error()
				return
			}
			if !gate {
				rec.Status, rec.Note = statusSkipped, "when: false"
				return
			}
		}
	}

	if planOnly {
		x.stalled = true
		rec.Status = statusPlanned
		if dead != "" {
			rec.Note = note(rec.Note, fmt.Sprintf("rendered from an unresolved chain: step %q is %s", dead, x.status[dead]))
		}
		var requests []PlannedRequest
		if missing := unboundPort(e.spec, ports); missing != "" {
			rec.Note = note(rec.Note, fmt.Sprintf("not rendered: port %q is unbound", missing))
		} else {
			requests = x.render(ctx, st, e, ic, ports, fields, &rec)
		}
		x.planned = append(x.planned, PlannedMutation{
			Seq: rec.Seq, Step: st.ID, Uses: st.Uses, Identity: rec.Identity, Target: rec.Target,
			Reversible: e.spec.Reversible, Destructive: e.spec.Destructive, Inputs: rec.Inputs,
			Note: rec.Note, Requests: requests,
		})
		return
	}
	if e.spec.Mutating && rec.Target != "" && !x.sess.targetAllowed(rec.Target) {
		rec.Status = statusFailed
		rec.Error = fmt.Sprintf("%s is outside the plan scope %s", rec.Target, strings.Join(x.plan.Scope, ", "))
		return
	}

	pval, err := buildParams(e.paramType, fields)
	if err != nil {
		rec.Status, rec.Error = statusFailed, err.Error()
		return
	}

	x.begin(st, ic, &rec, writeRecord)
	h, err := invoke(ctx, e, x.sess, pval, Inputs{ports: ports, fields: fields})
	if err != nil {
		rec.Status, rec.Error = statusFailed, err.Error()
		return
	}

	rec.Status = statusOK
	x.adopt(st, h, &rec)
	if !e.spec.Mutating {
		x.reads = append(x.reads, st.ID+" ("+st.Uses+")")
	}
}

// render runs a mutating body with the session in dry mode: every mutation is
// recorded instead of issued, so the document carries the real requests rather
// than a guess at them, and the predicted handle lets the rest of the chain
// render too.
func (x *executor) render(ctx context.Context, st *Step, e *entry, ic *identityClient, ports map[string]Handle, fields map[string]any, rec *StepRecord) []PlannedRequest {
	pval, err := buildParams(e.paramType, fields)
	if err != nil {
		rec.Note = note(rec.Note, err.Error())
		return nil
	}
	x.begin(st, ic, rec, nil)
	h, err := invoke(ctx, e, x.sess, pval, Inputs{ports: ports, fields: fields})
	requests := x.sess.takePlanned()
	if err != nil {
		rec.Note = note(rec.Note, err.Error())
		return requests
	}
	x.adopt(st, h, rec)
	return requests
}

// begin hands the session everything a primitive body needs that is not an
// input: who is acting, what provoked this step, and the two halves of cursor
// checkpointing. A nil flush means this step cannot checkpoint — a dry run
// renders rather than waits, so there is nothing to resume to.
func (x *executor) begin(st *Step, ic *identityClient, rec *StepRecord, flush func() error) {
	a := actingContext{
		step:  st.ID,
		uses:  st.Uses,
		id:    ic,
		prev:  x.provocation(),
		prior: x.prior[st.ID].Cursor,
	}
	if flush != nil {
		a.save = func(cursor any) error {
			rec.Cursor, rec.Status = cursor, statusWaiting
			return flush()
		}
	}
	x.sess.begin(a)
}

// provocation is the nearest preceding step that could have started a workflow
// run: executed, mutating, and naming a repository. A read causes nothing and a
// skipped step causes nothing, so both are walked past.
func (x *executor) provocation() *Provocation {
	for i := len(x.records) - 1; i >= 0; i-- {
		rec := x.records[i]
		if !rec.Mutating || (rec.Status != statusOK && rec.Status != statusPlanned) {
			continue
		}
		scoped, ok := rec.Handle.(RepoScoped)
		if !ok {
			continue
		}
		p := &Provocation{
			Step: rec.ID, Uses: rec.Uses, Repo: scoped.RepoRef(),
			Events: provokedEvents(rec), At: parseRecordTime(rec.StartedAt),
		}
		switch h := rec.Handle.(type) {
		case PullRequest:
			p.PR, p.Ref = h.Number, h.Head
		case Review:
			p.PR = h.Number
		case DispatchReceipt:
			p.Ref, p.RunID = h.Ref, h.RunID
		}
		if w, isRef := rec.Handle.(WritableRef); isRef && p.Ref == "" {
			p.Ref = strings.TrimPrefix(w.WriteRef().Ref, "refs/heads/")
		}
		return p
	}
	return nil
}

func parseRecordTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now()
	}
	return t
}

// replay puts a step a prior run completed back into the graph without
// re-running it. Every handle is plain JSON, so rehydration is a decode — which
// is what lets a killed watch resume the watch instead of reopening the pull
// request that caused it.
func (x *executor) replay(st *Step, rec StepRecord) {
	x.replayed++
	x.records = append(x.records, rec)
	x.status[st.ID] = rec.Status
	x.targets[st.ID] = rec.Target
	if rec.Handle != nil {
		x.handles[st.ID] = rec.Handle
		x.subjects[st.ID] = toSubject(rec.Handle)
		if id, isIdentity := rec.Handle.(Identity); isIdentity {
			x.sess.alias(st.ID, id.Name)
		}
	}
	slog.Info("step resumed", "step", st.ID, "uses", rec.Uses, "target", rec.Target)
}

func (x *executor) adopt(st *Step, h Handle, rec *StepRecord) {
	rec.Handle, rec.HandleKind = h, h.Kind()
	if text := x.sess.takeNote(); text != "" {
		rec.Note = note(rec.Note, text)
	}
	if reason := x.sess.takeEmpty(); reason != "" {
		rec.Empty = true
		rec.Note = note(rec.Note, reason)
	}
	if rs, scoped := h.(RepoScoped); scoped && rec.Target == "" {
		loc := rs.RepoRef()
		if loc.Owner != "" {
			rec.Target = loc.Owner + "/" + loc.Repo
		}
	}
	x.handles[st.ID] = h
	x.subjects[st.ID] = toSubject(h)
	if id, isIdentity := h.(Identity); isIdentity {
		x.sess.alias(st.ID, id.Name)
	}
}

func unboundPort(spec Spec, ports map[string]Handle) string {
	for _, port := range spec.Ports {
		if port.Required && ports[port.Name] == nil {
			return port.Name
		}
	}
	return ""
}

func note(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// invoke isolates a primitive body: In[T] panics on a binding the validator was
// supposed to have proven, and one such bug must not sink the run.
func invoke(ctx context.Context, e *entry, s *Session, p any, in Inputs) (h Handle, err error) {
	defer func() {
		if r := recover(); r != nil {
			h, err = None{}, fmt.Errorf("panic in %s: %v", e.spec.Name, r)
		}
	}()
	return e.invoke(ctx, s, p, in)
}

func (x *executor) firstWith(deps []string, states ...string) string {
	for _, d := range deps {
		if slices.Contains(states, x.status[d]) {
			return d
		}
	}
	return ""
}

// dependencies is every prior step this one reads: bound ports, an as: naming a
// step, when: references, and field values holding <step>.<field>.
func (x *executor) dependencies(st *Step, spec Spec) []string {
	var out []string
	add := func(id string) {
		if x.stepIDs[id] && id != st.ID && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	// A port names a step whether or not the value was quoted, because bind, target
	// and the rendered inputs all read it that way: registering the edge on the
	// same terms is what keeps a quoted port from binding a handle with no
	// dependency on the step that produced it.
	for _, port := range spec.Ports {
		if id, ok := st.Keys[port.Name].(string); ok {
			add(id)
		}
	}
	add(st.As)
	// A cleanup step's when: is deliberately not an edge. Skipping an undo step
	// because the step it gates on skipped would leave the artifact behind in
	// exactly the case the author wrote the gate for; a cleanup gate instead reads
	// a skipped predecessor's fields as their zero values. Its ports stay edges:
	// a cleanup step whose subject was never created has nothing to undo.
	if !st.isCleanup {
		for _, m := range whenRefRe.FindAllStringSubmatch(stripQuoted(st.When), -1) {
			add(m[1])
		}
	}
	portNames := map[string]bool{}
	for _, port := range spec.Ports {
		portNames[port.Name] = true
	}
	for _, k := range sortedKeys(st.Keys) {
		if portNames[k] || st.quoted[k] {
			continue
		}
		walkStrings(st.Keys[k], func(s string) {
			for _, expr := range append([]string{s}, interpolations(s)...) {
				if id, _, ok := splitDotRef(expr); ok {
					add(id)
				}
			}
		})
	}
	return out
}

// bind separates the step's flat keys into bound handles and resolved field
// values. strict is false while rendering a mutation a dry run will not issue:
// a value that would have come from a step that never ran renders as its source
// text rather than failing the render.
func (x *executor) bind(st *Step, e *entry, strict bool) (map[string]Handle, map[string]any, error) {
	ports := map[string]Handle{}
	fields := map[string]any{}
	portNames := map[string]bool{}
	for _, port := range e.spec.Ports {
		portNames[port.Name] = true
	}
	for _, k := range sortedKeys(st.Keys) {
		if portNames[k] {
			id, _ := st.Keys[k].(string)
			if h, ok := x.handles[id]; ok {
				ports[k] = h
			}
			continue
		}
		v, resolved := x.resolveValue(st.Keys[k], k, st.quoted)
		switch {
		case !resolved && strict:
			return nil, nil, fmt.Errorf("field %q: cannot resolve %v", k, st.Keys[k])
		case !resolved:
			fields[k] = st.Keys[k]
		default:
			fields[k] = v
		}
	}
	if strict {
		for _, port := range e.spec.Ports {
			if port.Required && ports[port.Name] == nil {
				return nil, nil, fmt.Errorf("port %q is unbound", port.Name)
			}
		}
	}
	return ports, fields, nil
}

// resolveValue turns a plan value into the value the primitive receives: a
// quoted scalar is a literal, a bare <step>.<field> reads a produced handle, a
// bare word naming an input is that input, and ${{ }} builds a string. Nested
// maps and lists resolve by the same rules, quote-forcing included: path is the
// key the parser recorded this value's YAML style under.
func (x *executor) resolveValue(raw any, path string, quoted map[string]bool) (any, bool) {
	switch v := raw.(type) {
	case string:
		if quoted[path] {
			return v, true
		}
		if strings.Contains(v, "${{") {
			return x.interpolate(v)
		}
		if id, field, ok := splitDotRef(v); ok && x.stepIDs[id] {
			return x.stepField(id, field)
		}
		if val, has := x.plan.resolvedInputs[v]; has {
			return val, true
		}
		return v, true
	case []any:
		out := make([]any, 0, len(v))
		ok := true
		for i, e := range v {
			r, o := x.resolveValue(e, fmt.Sprintf("%s.%d", path, i), quoted)
			ok = ok && o
			out = append(out, r)
		}
		return out, ok
	case map[string]any:
		out := make(map[string]any, len(v))
		ok := true
		for k, e := range v {
			r, o := x.resolveValue(e, path+"."+k, quoted)
			ok = ok && o
			out[k] = r
		}
		return out, ok
	default:
		return raw, true
	}
}

var interpRe = regexp.MustCompile(`\$\{\{\s*([^}]+?)\s*\}\}`)

func interpolations(s string) []string {
	var out []string
	for _, m := range interpRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// A string that is nothing but one reference keeps that reference's type; any
// other occurrence is building a larger string and stringifies.
func (x *executor) interpolate(s string) (any, bool) {
	if m := interpRe.FindStringSubmatch(s); m != nil && m[0] == s {
		return x.lookupRef(m[1])
	}
	resolved := true
	out := interpRe.ReplaceAllStringFunc(s, func(tok string) string {
		v, ok := x.lookupRef(interpRe.FindStringSubmatch(tok)[1])
		if !ok {
			resolved = false
			return tok
		}
		return dsl.ToStringValue(v)
	})
	return out, resolved
}

func (x *executor) lookupRef(expr string) (any, bool) {
	if id, field, ok := splitDotRef(expr); ok && x.stepIDs[id] {
		return x.stepField(id, field)
	}
	v, has := x.plan.resolvedInputs[expr]
	return v, has
}

// stepField reads a field off a handle a prior step produced. A step that has
// produced nothing yet and a path that misses inside one that has are the same
// answer: the plan asked for a value this run cannot supply, and every caller
// treats that as a refusal rather than as a zero value.
func (x *executor) stepField(id, field string) (any, bool) {
	subj, has := x.subjects[id]
	if !has {
		return nil, false
	}
	v := dsl.GetPath(subj, field)
	return v, v != nil
}

// evalWhen resolves the gate's references before handing the expression to the
// evaluator, so a reference that resolves to nothing fails the step instead of
// reading as nil — the same strictness bind applies to a field, decided by the
// same resolver. A value the chain could not measure fails it for the same
// reason: the step that produced it says so in a note, and this is where acting
// on it is decided. A cleanup gate is the exception: it reads a step that
// produced nothing as that step's zero handle, because "the merge never
// happened" is the state its undo exists for.
func (x *executor) evalWhen(st *Step) (bool, error) {
	subject := map[string]any{}
	for name, v := range x.plan.resolvedInputs {
		subject[name] = v
	}
	// A step id shadows an input of the same name, as it does in a field value.
	for id, s := range x.subjects {
		subject[id] = s
	}
	if st.isCleanup {
		x.zeroSubjects(st, subject)
		return dsl.EvaluatePredicate(st.When, subject)
	}
	for _, m := range whenRefRe.FindAllStringSubmatch(stripQuoted(st.When), -1) {
		v, ok := x.lookupRef(m[0])
		if !ok {
			return false, fmt.Errorf("when: %s resolves to nothing", m[0])
		}
		if why, unestablished := unmeasuredReason(v); unestablished {
			return false, fmt.Errorf("when: %s was not established: %s. This gate decides whether to change the customer's system, so it fails rather than reading the value as false",
				m[0], why)
		}
	}
	return dsl.EvaluatePredicate(st.When, subject)
}

// zeroSubjects gives every step this gate names that produced nothing the zero
// value of the handle its primitive declares, so a gate comparing merge.sha to
// the empty string holds when the merge skipped, rather than reading nil.
func (x *executor) zeroSubjects(st *Step, subject map[string]any) {
	for _, m := range whenRefRe.FindAllStringSubmatch(stripQuoted(st.When), -1) {
		id := m[1]
		if _, produced := subject[id]; produced || !x.stepIDs[id] {
			continue
		}
		subject[id] = zeroSubject(x.plan, id)
	}
}

func zeroSubject(p *Plan, id string) any {
	for _, st := range allSteps(p) {
		if st.ID != id {
			continue
		}
		e, ok := lookup(st.Uses)
		if !ok {
			break
		}
		t := handleTypes[e.spec.Produces]
		if t == nil {
			break
		}
		if h, isHandle := reflect.New(t).Elem().Interface().(Handle); isHandle {
			return toSubject(h)
		}
	}
	return map[string]any{}
}

// target is the repository a step lands in: the origin port's handle when it is
// real, that step's own recorded target when it was only planned, and the
// owner/repo fields for a primitive that roots a repository itself. A fork's
// target is unknowable before the run — it lands in the acting identity's
// namespace — and stays empty.
func (x *executor) target(st *Step, spec Spec, ports map[string]Handle, fields map[string]any) string {
	if spec.OriginFrom != "" {
		if h, ok := ports[spec.OriginFrom]; ok {
			if rs, isScoped := h.(RepoScoped); isScoped {
				loc := rs.RepoRef()
				return loc.Owner + "/" + loc.Repo
			}
		}
		if id, ok := st.Keys[spec.OriginFrom].(string); ok {
			return x.targets[id]
		}
		return ""
	}
	owner, _ := fields["owner"].(string)
	repo, _ := fields["repo"].(string)
	if owner != "" && repo != "" {
		return owner + "/" + repo
	}
	return ""
}

func renderInputs(st *Step, spec Spec, fields map[string]any) map[string]any {
	out := make(map[string]any, len(st.Keys))
	for k, v := range fields {
		out[k] = v
	}
	for _, port := range spec.Ports {
		if id, ok := st.Keys[port.Name].(string); ok {
			out[port.Name] = "step:" + id
		}
	}
	return out
}

// buildParams fills the primitive's param struct from the resolved fields
// through YAML, which is the encoding the struct tags already describe.
func buildParams(t reflect.Type, fields map[string]any) (any, error) {
	ptr := reflect.New(t)
	if len(fields) > 0 {
		b, err := yaml.Marshal(fields)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, ptr.Interface()); err != nil {
			return nil, fmt.Errorf("decode params: %w", err)
		}
	}
	return ptr.Elem().Interface(), nil
}

func toSubject(h Handle) any {
	b, err := json.Marshal(h)
	if err != nil {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{}
	}
	return out
}
