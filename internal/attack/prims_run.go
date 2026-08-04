package attack

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
)

const runPollInterval = 15 * time.Second

// correlationSkew widens the since-cursor to absorb clock drift between this
// host and GitHub, at the price of admitting a run that fired just before the
// provocation. Every admitted run is recorded as a candidate, so the trade is
// visible rather than hidden.
const correlationSkew = time.Minute

// runListPages bounds one listing pass. chooseRun wants the earliest eligible run
// and the endpoint answers newest-first, so a single page loses exactly the run a
// long watch is after; the ceiling is the endpoint's own reachable maximum and
// reaching it is recorded rather than truncating the window silently.
const (
	runListPages    = 10
	runListPageSize = 100
)

// The limits the two dispatch endpoints enforce. A request over one of them is a
// 422 in the customer's audit trail that produces no evidence, so it is refused
// here instead. The payload ceiling is one number for both, said in different
// units: 65,535 characters of workflow_dispatch inputs, and a client_payload of
// under 64KB — which is 65,535 bytes.
//
// maxDispatchInputs is github.com's ceiling. GHES enforces 10, so the constant
// becomes host-dependent the day github.apiBase stops being api.github.com, and 25
// would then pass validation here and 422 on the customer's appliance.
const (
	maxDispatchInputs       = 25
	maxClientPayloadProps   = 10
	maxEventTypeChars       = 100
	maxDispatchPayloadChars = 65535
)

const directBasis = "the run id the dispatch response returned: return_run_details asks the dispatch endpoint " +
	"to answer with workflow_run_id, so the run is the one GitHub named as started by that request. No listing, " +
	"no created-after window, no event filter and no choice between candidates took part in identifying it, and " +
	"there is correspondingly nothing for it to be ambiguous with."

const correlationBasis = "heuristic: the workflow file path, a created-after cursor taken from the provoking " +
	"step, the events that step can fire, and a best-effort pull request number. A run's head_sha is never " +
	"used — for pull_request_target it is the base sha, and pull_requests[] is frequently empty on runs from " +
	"fork pull requests. The listing is re-read on every poll until the run reaches a terminal state, so a " +
	"co-firing run created after the choice is still recorded and still marks the correlation ambiguous. " +
	"Every candidate is recorded so an ambiguous match is visible, never silently resolved."

func init() {
	Register(Spec{
		Name:    "run.await",
		Action:  "await workflow run",
		Summary: "Correlate the immediately-preceding provocation to its workflow run and poll it to a terminal state.",
	}, runAwait)

	Register(Spec{
		Name:       "run.observe",
		Action:     "watch for workflow run",
		Summary:    "Poll for a workflow run the plan did not cause — a human comment, a laundered CI run, a workflow_run cascade.",
		Ports:      []Port{Accepts[RepoScoped]("on", true)},
		OriginFrom: "on",
	}, runObserve)

	Register(Spec{
		Name:       "run.cancel",
		Action:     "cancel workflow run",
		Summary:    "Cancel an in-flight run — blast-radius control and deliberate race-losing.",
		Ports:      []Port{Accepts[WorkflowRun]("run", true)},
		Caps:       []Capability{CapActionsWrite},
		Mutating:   true,
		OriginFrom: "run",
	}, runCancel)

	Register(Spec{
		Name:       "workflow.dispatch",
		Action:     "dispatch workflow",
		Summary:    "Fire workflow_dispatch against a chosen ref with inputs — the cleanest on-demand execution channel.",
		Ports:      []Port{Accepts[RepoScoped]("on", true)},
		Caps:       []Capability{CapActionsWrite},
		Mutating:   true,
		OriginFrom: "on",
	}, workflowDispatch)

	Register(Spec{
		Name:       "repo.dispatch",
		Action:     "dispatch repository event",
		Summary:    "Fire repository_dispatch with an arbitrary client_payload against the default-branch workflows.",
		Ports:      []Port{Accepts[RepoScoped]("on", true)},
		Caps:       []Capability{CapContentsWrite},
		Mutating:   true,
		OriginFrom: "on",
	}, repoDispatch)
}

type runAwaitParams struct {
	Workflow string `yaml:"workflow"`
	Match    string `yaml:"match"`
	Timeout  string `yaml:"timeout"`
}

type runObserveParams struct {
	Workflow string `yaml:"workflow"`
	Ref      string `yaml:"ref"`
	Match    string `yaml:"match"`
	Timeout  string `yaml:"timeout"`
}

type runCancelParams struct{}

type workflowDispatchParams struct {
	Workflow string         `yaml:"workflow"`
	Ref      string         `yaml:"ref"`
	Inputs   map[string]any `yaml:"inputs"`
}

type repoDispatchParams struct {
	EventType     string         `yaml:"event_type"`
	ClientPayload map[string]any `yaml:"client_payload"`
}

// provokes maps a primitive to the workflow events it can fire, for a step that
// declared none of its own. It narrows correlation; it is never a claim that the
// target subscribes to any of them.
var provokes = map[string][]string{
	"comment.create":    {"issue_comment", "pull_request_review_comment"},
	"comment.delete":    {"issue_comment"},
	"commit.code":       {"push", "pull_request", "pull_request_target"},
	"issue.open":        {"issues"},
	"pr.close":          {"pull_request", "pull_request_target"},
	"pr.merge":          {"push", "pull_request", "pull_request_target"},
	"pr.open":           {"pull_request", "pull_request_target"},
	"pr.review.submit":  {"pull_request_review"},
	"ref.create":        {"create", "push"},
	"ref.delete":        {"delete"},
	"ref.update":        {"push", "pull_request", "pull_request_target"},
	"repo.dispatch":     {"repository_dispatch"},
	"repo.fork":         {"fork"},
	"workflow.commit":   {"push", "pull_request", "pull_request_target"},
	"workflow.dispatch": {"workflow_dispatch"},
}

// provokedEvents is the event set a watch correlates against. A step that
// declared a trigger: subscribed the document it committed to exactly those
// events, and the table's broader entry would then either miss the run this chain
// caused or match one it did not — a workflow.commit of a workflow_dispatch
// document fires nothing on push. The table stands in only for a step that
// declared no trigger, where all that is known is the commit's own push and
// whatever the repository already subscribes to it. A trigger: that is present but
// unreadable as a list of event names — a scalar, an empty list, a list holding
// anything else — yields nothing rather than falling back to the table, because
// the table is wider than what the author declared and widening it here is how
// every run of a workflow silently becomes eligible. run.await refuses an empty
// set instead of correlating against one it cannot name.
func provokedEvents(rec StepRecord) []string {
	declared, present := rec.Inputs["trigger"]
	if !present {
		return provokes[rec.Uses]
	}
	list, isList := declared.([]any)
	if !isList {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, ev := range list {
		name, isString := ev.(string)
		if !isString || name == "" {
			return nil
		}
		out = append(out, name)
	}
	return out
}

// runWatch is what both watchers reduce to. run.await fills it from the
// provocation, run.observe from its own keys.
type runWatch struct {
	repo     RepoLoc
	workflow string
	since    time.Time
	events   []string
	ref      string
	pr       int
	match    string
	timeout  string
	from     string
	// runID is the run the provoking request's own response named. When it is set
	// the correlation is already settled and every field above that narrows a
	// listing is unused, because there is no listing.
	runID int64
}

// runCursor is the resumable poll cursor and the correlation record in one
// object. It is checkpointed into the step record after every read, so an
// operator watching a multi-day poll sees the whole candidate set and not only
// the run that was chosen.
type runCursor struct {
	Basis      string         `json:"basis"`
	From       string         `json:"provoked_by,omitempty"`
	Repository string         `json:"repository"`
	Workflow   string         `json:"workflow"`
	Since      string         `json:"since"`
	Events     []string       `json:"events"`
	Ref        string         `json:"ref,omitempty"`
	PR         int            `json:"pull_request,omitempty"`
	Match      string         `json:"match,omitempty"`
	RunID      int64          `json:"run_id,omitempty"`
	State      string         `json:"state,omitempty"`
	Ambiguous  bool           `json:"ambiguous"`
	Candidates []runCandidate `json:"candidates"`
	// OtherRuns counts runs of other workflows the same window held. Without it an
	// empty candidate set reads the same whether the provocation fired nothing or
	// the plan named a workflow path that does not exist.
	OtherRuns int `json:"other_workflow_runs"`
	// Truncated says the listing hit its page ceiling, so a run created early in
	// the window may never have been seen and "nothing correlated" is weaker than
	// it looks.
	Truncated bool   `json:"listing_truncated,omitempty"`
	Polls     int    `json:"polls"`
	At        string `json:"at"`
}

type runCandidate struct {
	ID           int64  `json:"id"`
	Path         string `json:"path"`
	Event        string `json:"event"`
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion"`
	HeadBranch   string `json:"head_branch"`
	HeadSHA      string `json:"head_sha"`
	DisplayTitle string `json:"display_title"`
	CreatedAt    string `json:"created_at"`
	PullRequests []int  `json:"pull_requests"`
	RunAttempt   int    `json:"run_attempt"`
	URL          string `json:"url,omitempty"`
	Chosen       bool   `json:"chosen,omitempty"`
	// Late marks a run that passed every filter but surfaced after the choice was
	// already made. It carries a rejection reason so nothing downstream treats it as
	// the correlated run, and it still counts towards ambiguity: a second eligible
	// run is a second eligible run whichever poll first saw it.
	Late     bool   `json:"late,omitempty"`
	Note     string `json:"note,omitempty"`
	Rejected string `json:"rejected,omitempty"`
}

// eligible reports whether this correlation could have taken the run. A late
// arrival counts: it was rejected for its timing relative to the choice, not for
// failing any filter.
func (c runCandidate) eligible() bool { return c.Rejected == "" || c.Late }

// runAwait watches the run its own chain provoked. Steps are serial, so the
// provocation is the nearest preceding executed mutation and the author names
// only which of the co-firing workflows to watch.
func runAwait(ctx context.Context, s *Session, p runAwaitParams, _ Inputs) (WorkflowRun, error) {
	w, err := awaitWatch(s.Provocation(), p)
	if err != nil {
		return WorkflowRun{}, err
	}
	return watchRun(ctx, s, w)
}

// awaitWatch turns the provocation into the watch that correlates its run. A
// provocation whose own response named the run carries none of the narrowing a
// listing needs: an event set or a created-after window recorded beside a run id
// GitHub handed over reads as though they had a say in which run this is.
func awaitWatch(prev *Provocation, p runAwaitParams) (runWatch, error) {
	if prev == nil {
		return runWatch{}, errors.New("run.await has no preceding executed mutation to correlate against; a run this plan did not cause is run.observe, which binds its repository with an on: port")
	}
	w := runWatch{
		repo:     prev.Repo,
		workflow: p.Workflow,
		match:    p.Match,
		timeout:  p.Timeout,
		from:     prev.Step,
		runID:    prev.RunID,
	}
	if w.runID != 0 {
		return w, nil
	}
	if len(prev.Events) == 0 {
		return runWatch{}, fmt.Errorf("run.await cannot name the events step %q (%s) could fire, so every run of the named workflow in the window would be eligible and the correlation would be a guess dressed as a fact: give that step an explicit trigger: naming the events its document subscribes to, or watch with run.observe, which does not claim the run was provoked",
			prev.Step, prev.Uses)
	}
	w.since, w.events, w.pr = prev.At.Add(-correlationSkew), prev.Events, prev.PR
	return w, nil
}

// runObserve watches a run nothing in the plan caused, so it takes its
// repository from on: and its cursor from the moment the watch starts.
func runObserve(ctx context.Context, s *Session, p runObserveParams, in Inputs) (WorkflowRun, error) {
	return watchRun(ctx, s, runWatch{
		repo:     In[RepoScoped](in, "on").RepoRef(),
		workflow: p.Workflow,
		since:    time.Now().Add(-correlationSkew),
		ref:      p.Ref,
		match:    p.Match,
		timeout:  p.Timeout,
	})
}

func watchRun(ctx context.Context, s *Session, w runWatch) (WorkflowRun, error) {
	if w.workflow == "" {
		return WorkflowRun{}, errors.New("needs workflow: the path of the workflow file, e.g. .github/workflows/ci.yml")
	}
	match, err := compileMatch(w.match)
	if err != nil {
		return WorkflowRun{}, err
	}
	empty := WorkflowRun{RepoLoc: w.repo, WorkflowPath: w.workflow}
	if w.runID != 0 && w.match != "" {
		s.Note(fmt.Sprintf("match: %q narrowed nothing: the provoking response named run %d, so there was no candidate set to narrow", w.match, w.runID))
	}

	client, timeout, live, err := awaitStart(s, w.repo, w.timeout, describeWatch(w))
	if err != nil || !live {
		return empty, err
	}

	cur := runCursor{
		Basis: correlationBasis, From: w.from, Repository: w.repo.Owner + "/" + w.repo.Repo,
		Workflow: w.workflow, Events: w.events,
		Ref: w.ref, PR: w.pr, Match: w.match, RunID: w.runID, Candidates: []runCandidate{},
	}
	if w.runID != 0 {
		cur.Basis = directBasis
	}
	if !w.since.IsZero() {
		cur.Since = engine.IsoformatUTC(w.since)
	}
	// A killed watch resumes the watch: a run already correlated is polled
	// straight back to its terminal state rather than correlated a second time,
	// which could land on a different candidate.
	var prior runCursor
	if s.PriorCursor(&prior) && prior.resumes(w, cur.Repository) {
		cur.RunID, cur.Candidates, cur.Ambiguous = prior.RunID, prior.Candidates, prior.Ambiguous
		slog.Info("resuming a correlated watch", "run", cur.RunID, "workflow", w.workflow)
	}

	// An effect record is only ever written before the cursor naming its run is
	// checkpointed, so the candidates a prior process left behind are exactly the
	// runs it already recorded and a resumed watch does not double-record them.
	recorded := map[int64]bool{}
	for _, c := range cur.Candidates {
		if c.eligible() {
			recorded[c.ID] = true
		}
	}

	found, err := poll(ctx, runPollInterval, timeout, s.Checkpoint,
		func(ctx context.Context) (WorkflowRun, bool, any, error) {
			cur.Polls++
			cur.At = engine.IsoformatUTC(time.Now())

			if w.runID == 0 {
				runs, truncated, err := listRuns(ctx, client, w)
				if err != nil {
					return WorkflowRun{}, false, cur, err
				}
				cur.Truncated = cur.Truncated || truncated
				cur.observe(runs, w, match)
				if cur.RunID == 0 {
					return WorkflowRun{}, false, cur, nil
				}
				// Recorded before the run is read: every candidate here executed whether or
				// not that read succeeds, and a ledger short of one understates what the
				// provocation set in motion.
				if err := recordRunEffects(s, w, &cur, recorded); err != nil {
					return WorkflowRun{}, false, cur, err
				}
			}

			b, err := readRunBody(ctx, client, w.repo, cur.RunID)
			if err != nil {
				return WorkflowRun{}, false, cur, err
			}
			if w.runID != 0 {
				cur.settle(b)
				if err := recordRunEffects(s, w, &cur, recorded); err != nil {
					return WorkflowRun{}, false, cur, err
				}
			}
			cur.State = cmp.Or(b.Conclusion, b.Status)
			return b.handle(w.repo), runTerminal(b.Status), cur, nil
		})

	if cur.Truncated {
		s.Note(fmt.Sprintf("the run listing for %s hit its %d-run ceiling, so a run of %s created early in the window may never have been listed: narrow the watch with a ref:, a match: or a shorter timeout before reading anything into what was or was not found",
			cur.Repository, runListPages*runListPageSize, w.workflow))
	}

	switch {
	case errors.Is(err, errTimedOut) && cur.RunID == 0:
		s.MarkEmpty(fmt.Sprintf("no run of %s correlated within %s: inconclusive, not proof that nothing ran. The window held %d run(s) of that workflow, none eligible, and %d run(s) of other workflows",
			w.workflow, timeout, len(cur.Candidates), cur.OtherRuns))
		return empty, nil
	case errors.Is(err, errTimedOut):
		reason := fmt.Sprintf("run %d was still %s after %s", cur.RunID, cur.State, timeout)
		if amb := cur.ambiguityNote(w.workflow); amb != "" {
			reason = note(reason, amb)
		}
		s.MarkEmpty(reason)
		run, readErr := readRun(ctx, client, w.repo, cur.RunID)
		run.Provoked = w.from != ""
		return run, readErr
	case err != nil:
		return empty, err
	}
	if amb := cur.ambiguityNote(w.workflow); amb != "" {
		s.MarkEmpty(amb)
	}
	// from is set only by run.await, which correlates against a provocation this
	// chain issued. run.observe watches a run the plan did not cause, and nothing
	// downstream may treat that run as ours to cancel or reject.
	found.Provoked = w.from != ""
	return found, nil
}

// observe folds one fresh listing into the cursor. It runs on every poll, not only
// while nothing is correlated: the first poll fires seconds after the provocation,
// so a co-firing run created a moment later would otherwise never be listed and
// ambiguity measured on that one snapshot is ambiguity hidden. A run that arrives
// after the choice is recorded with a rejection reason — this watch is already
// polling another run and switching would be worse — but it still counts towards
// ambiguity, so the report never presents a guess as the run.
func (cur *runCursor) observe(runs []runBody, w runWatch, match *regexp.Regexp) {
	fresh, others := candidates(runs, w, match)
	cur.OtherRuns = others
	was := cur.Ambiguous

	for _, c := range fresh {
		if slices.ContainsFunc(cur.Candidates, func(known runCandidate) bool { return known.ID == c.ID }) {
			continue
		}
		if cur.RunID != 0 && c.Rejected == "" {
			c.Late = true
			c.Rejected = fmt.Sprintf("appeared after run %d was correlated, so this watch polled that one instead", cur.RunID)
		}
		cur.Candidates = append(cur.Candidates, c)
	}
	slices.SortFunc(cur.Candidates, byCreation)

	if cur.RunID == 0 {
		if chosen := chooseRun(cur.Candidates, w.pr); chosen >= 0 {
			cur.Candidates[chosen].Chosen = true
			cur.RunID = cur.Candidates[chosen].ID
		}
	}
	cur.Ambiguous = countEligible(cur.Candidates) > 1
	if cur.Ambiguous && !was {
		slog.Warn("run correlation is ambiguous; the candidate set is in the step record",
			"chose", cur.RunID, "eligible", countEligible(cur.Candidates), "workflow", w.workflow)
	}
}

// settle records the run the provoking response named. Nothing was chosen and
// nothing was passed over, so the read of that one run is the whole candidate
// record — which is still what the irreversible-effect record is written from.
func (cur *runCursor) settle(b runBody) {
	c := b.candidate()
	c.Chosen = true
	cur.Candidates = []runCandidate{c}
}

// resumes reports whether the cursor a killed process checkpointed belongs to
// this same watch. The repository has to match as well as the workflow — a
// re-render can rebind the same step to a different fork, and a run id from the
// wrong repository is not this watch's run — and a watch handed its run id
// resumes only onto that run, never onto whatever an earlier cursor correlated.
func (cur runCursor) resumes(w runWatch, repository string) bool {
	return cur.RunID != 0 && cur.Workflow == w.workflow && cur.Repository == repository &&
		(w.runID == 0 || cur.RunID == w.runID)
}

// ambiguityNote is the one sentence that must reach the record on every path that
// returns a chosen run, the timeout path included — that is the path where the
// choice is most likely to be a guess, so it is the path least able to omit it.
func (cur runCursor) ambiguityNote(workflow string) string {
	if !cur.Ambiguous {
		return ""
	}
	return fmt.Sprintf("correlation was ambiguous: %d runs of %s were eligible and run %d was chosen as the earliest, so it is a best guess and not established as the run; every candidate is in this record",
		countEligible(cur.Candidates), workflow, cur.RunID)
}

// runTerminal ends a watch. A run parked on an environment reviewer or on the
// fork-PR approval gate is a first-class outcome — it is the finding about
// whether that gate held — and not something to wait out.
func runTerminal(status string) bool {
	switch status {
	case "completed", "waiting", "action_required":
		return true
	}
	return false
}

func describeWatch(w runWatch) string {
	if w.runID != 0 {
		what := fmt.Sprintf("run %d of %s in %s/%s, the run id GitHub returned for the provocation", w.runID, w.workflow, w.repo.Owner, w.repo.Repo)
		if w.from != "" {
			what += fmt.Sprintf(" issued by step %q", w.from)
		}
		return what
	}
	var b strings.Builder
	fmt.Fprintf(&b, "a run of %s in %s/%s created after %s", w.workflow, w.repo.Owner, w.repo.Repo, engine.IsoformatUTC(w.since))
	if w.from != "" {
		fmt.Fprintf(&b, ", provoked by step %q", w.from)
	}
	if len(w.events) > 0 {
		fmt.Fprintf(&b, ", event one of %s", strings.Join(w.events, "|"))
	}
	if w.pr != 0 {
		fmt.Fprintf(&b, ", preferring the run that names pull request #%d", w.pr)
	}
	if w.ref != "" {
		fmt.Fprintf(&b, ", on branch %s", w.ref)
	}
	if w.match != "" {
		fmt.Fprintf(&b, ", matching %q", w.match)
	}
	return b.String()
}

// candidates keeps every run of the named workflow inside the window and
// records why each was or was not eligible, so the operator sees what the
// heuristic passed over. The second return counts the window's runs of other
// workflows: without it an empty candidate set reads identically whether the
// provocation fired nothing or the plan named a path no workflow has.
func candidates(runs []runBody, w runWatch, match *regexp.Regexp) ([]runCandidate, int) {
	out := []runCandidate{}
	others := 0
	for _, b := range runs {
		if !sameWorkflow(b.Path, w.workflow) {
			others++
			continue
		}
		c := b.candidate()
		if b.Path != w.workflow {
			c.Note = fmt.Sprintf("correlated by file name only: this run's workflow path is %s and the plan named %s", b.Path, w.workflow)
		}
		switch {
		case b.CreatedAt.Before(w.since):
			c.Rejected = "created before the watch cursor"
		case len(w.events) > 0 && !slices.Contains(w.events, b.Event):
			c.Rejected = fmt.Sprintf("event %q is not one the provocation fires (%s)", b.Event, strings.Join(w.events, ", "))
		case w.ref != "" && b.HeadBranch != w.ref:
			c.Rejected = fmt.Sprintf("head branch %q is not %q", b.HeadBranch, w.ref)
		case match != nil && !matchesRun(match, b):
			c.Rejected = "match did not appear in the display title, workflow name or head branch"
		}
		out = append(out, c)
	}
	return out, others
}

// byCreation is the order chooseRun reads as earliest-first. IsoformatUTC is
// fixed-width per precision, so the string compare is chronological, and run ids
// increase monotonically, which settles a same-second tie.
func byCreation(a, b runCandidate) int {
	return cmp.Or(cmp.Compare(a.CreatedAt, b.CreatedAt), cmp.Compare(a.ID, b.ID))
}

// chooseRun takes the earliest eligible run — the one a provocation would have
// started first — and prefers one that names the pull request when GitHub
// bothered to fill pull_requests[] in. cands must be in byCreation order.
func chooseRun(cands []runCandidate, pr int) int {
	best := -1
	for i := range cands {
		if cands[i].Rejected != "" {
			continue
		}
		switch {
		case best < 0:
			best = i
		case pr != 0 && slices.Contains(cands[i].PullRequests, pr) && !slices.Contains(cands[best].PullRequests, pr):
			best = i
		}
	}
	return best
}

// countEligible counts the runs this correlation could have taken. More than one
// is what ambiguity means.
func countEligible(cands []runCandidate) int {
	n := 0
	for _, c := range cands {
		if c.eligible() {
			n++
		}
	}
	return n
}

func matchesRun(re *regexp.Regexp, b runBody) bool {
	return re.MatchString(b.DisplayTitle) || re.MatchString(b.Name) || re.MatchString(b.HeadBranch)
}

// sameWorkflow compares the run's own workflow path with the one the author
// named. A bare file name still correlates, because every workflow file lives
// in one directory — unlike the YAML name:, which GitHub does not require to be
// unique and which is why this keys on the path at all.
func sameWorkflow(runPath, want string) bool {
	return runPath == want || path.Base(runPath) == path.Base(want)
}

// listRuns walks the window rather than taking the newest page of it. The endpoint
// answers newest-first and chooseRun wants the earliest eligible run, so on a busy
// repository the target is the first thing to fall off page one; the bool reports
// that the ceiling was reached, which is the difference between "nothing ran" and
// "the list did not reach far enough back to say".
func listRuns(ctx context.Context, c *github.Client, w runWatch) ([]runBody, bool, error) {
	params := url.Values{
		"per_page": []string{strconv.Itoa(runListPageSize)},
		// created: is search syntax, which takes YYYY-MM-DDTHH:MM:SSZ as well as the
		// +00:00 offset spelling, so RFC3339 in UTC is a form the filter parses and the
		// page ceiling below really does bound a window rather than the whole history.
		"created": []string{">=" + w.since.UTC().Format(time.RFC3339)},
	}
	if w.ref != "" {
		params.Set("branch", w.ref)
	}
	var out []runBody
	for page := 1; page <= runListPages; page++ {
		params.Set("page", strconv.Itoa(page))
		raw, _, err := c.Get(ctx, fmt.Sprintf("/repos/%s/%s/actions/runs", w.repo.Owner, w.repo.Repo), params, false)
		if err != nil {
			return nil, false, err
		}
		var body struct {
			TotalCount   int       `json:"total_count"`
			WorkflowRuns []runBody `json:"workflow_runs"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, false, err
		}
		out = append(out, body.WorkflowRuns...)
		if len(body.WorkflowRuns) < runListPageSize || len(out) >= body.TotalCount {
			return out, false, nil
		}
	}
	return out, true, nil
}

func readRun(ctx context.Context, c *github.Client, loc RepoLoc, id int64) (WorkflowRun, error) {
	b, err := readRunBody(ctx, c, loc, id)
	if err != nil {
		return WorkflowRun{}, err
	}
	return b.handle(loc), nil
}

func readRunBody(ctx context.Context, c *github.Client, loc RepoLoc, id int64) (runBody, error) {
	raw, _, err := c.Get(ctx, fmt.Sprintf("/repos/%s/%s/actions/runs/%d", loc.Owner, loc.Repo, id), nil, false)
	if err != nil {
		return runBody{}, err
	}
	var b runBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return runBody{}, err
	}
	return b, nil
}

// recordRunEffects writes one effect record per run this correlation could have
// taken, not only the one it went on to poll. A provocation that fired several runs
// executed all of them on the customer's system and none can be untriggered, so a
// ledger holding one of them understates what the engagement set in motion. A
// run.observe watch provoked nothing, so it records only the run it watched:
// enumerating the customer's own runs as consequences of this engagement would
// overstate it in the other direction.
func recordRunEffects(s *Session, w runWatch, cur *runCursor, recorded map[int64]bool) error {
	for _, c := range cur.Candidates {
		chosen := c.ID == cur.RunID
		if recorded[c.ID] || (!chosen && (w.from == "" || !c.eligible())) {
			continue
		}
		if err := recordRunEffect(s, w, c, *cur); err != nil {
			return err
		}
		recorded[c.ID] = true
	}
	return nil
}

func recordRunEffect(s *Session, w runWatch, c runCandidate, cur runCursor) error {
	summary := fmt.Sprintf("workflow run %d of %s in %s on %s executed; a run cannot be untriggered",
		c.ID, c.Path, cur.Repository, c.Event)
	if c.ID != cur.RunID {
		summary = fmt.Sprintf("workflow run %d of %s in %s on %s executed and was eligible for the same correlation as run %d, which this watch polled instead; a run cannot be untriggered",
			c.ID, c.Path, cur.Repository, c.Event, cur.RunID)
	}
	// The ledger is append-only and a record written on the first poll cannot be
	// amended by the third, so nothing here may be a count or a flag a later poll
	// can move. How many runs a provocation set off is answered by how many of these
	// records there are; the correlation each one stood in is stated per run.
	return s.RecordEffect(Effect{
		Class:   "workflow_run",
		Summary: summary,
		Detail: map[string]any{
			"run_id":      c.ID,
			"repository":  cur.Repository,
			"workflow":    c.Path,
			"event":       c.Event,
			"attempt":     c.RunAttempt,
			"url":         c.URL,
			"correlated":  c.ID == cur.RunID,
			"provoked_by": w.from,
			"correlation": cur.Basis,
		},
	})
}

func runCancel(ctx context.Context, s *Session, _ runCancelParams, in Inputs) (WorkflowRun, error) {
	run := In[WorkflowRun](in, "run")
	if run.ID == 0 {
		s.MarkEmpty("no run id to cancel")
		return run, nil
	}
	// Provoked is set only by a correlated run.await. run.observe yields a
	// WorkflowRun that satisfies this same port, and the repository allowlist is no
	// gate here because it contains that repository by construction — so the
	// invariant is enforced on the handle: a run this chain did not cause is the
	// customer's own work, and canceling it would interrupt their release.
	if !run.Provoked {
		return run, fmt.Errorf("run %d in %s/%s was observed, not provoked by this plan, so it is not this chain's to cancel: canceling a run the customer started would interrupt their own work. Only a run correlated by run.await may be canceled",
			run.ID, run.Owner, run.Repo)
	}
	client, err := s.Client()
	if err != nil && s.Execute {
		return run, err
	}
	if client != nil {
		current, err := readRun(ctx, client, run.RepoRef(), run.ID)
		if err := s.SoftRead(err, "read run"); err != nil {
			return run, err
		}
		current.Provoked = run.Provoked
		if current.Status == "completed" {
			s.MarkEmpty(fmt.Sprintf("run %d already finished; there is nothing to cancel", run.ID))
			return current, nil
		}
		if current.ID != 0 {
			run = current
		}
	}

	if _, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/actions/runs/%d/cancel", run.Owner, run.Repo, run.ID),
		Target: run.Owner + "/" + run.Repo,
		Note: "cancellation is cooperative and not instantaneous: if: always() steps, continue-on-error steps " +
			"and composite post-steps still execute, so a canceled job is not a job that did nothing",
	}); err != nil {
		if !isConflict(err) {
			return run, err
		}
		// 202 and 409 are the only answers this endpoint documents and it never says
		// what the conflict stands for, so the run is read back and the record carries
		// what that read measured rather than what the status code might have meant. The
		// step yields no cancellation either way, which is the same outcome the pre-read
		// above produces for a run that had already finished.
		reason := fmt.Sprintf("canceling run %d was refused with 409, the only failure this endpoint documents, and it documents no meaning for it", run.ID)
		if client != nil {
			current, readErr := readRun(ctx, client, run.RepoRef(), run.ID)
			switch {
			case readErr != nil:
				reason = note(reason, "reading the run back afterwards failed too, so its state is unestablished: "+readErr.Error())
			case current.ID != 0:
				current.Provoked = run.Provoked
				run = current
				reason = note(reason, fmt.Sprintf("read back after the refusal the run is %s", cmp.Or(current.Conclusion, current.Status)))
			}
		}
		s.MarkEmpty(reason)
		return run, nil
	}
	// A dry run sent no cancellation, so the handle must not claim a state the run
	// never reached.
	if s.Execute {
		run.Status = "canceling"
	}
	return run, nil
}

func isConflict(err error) bool {
	var ghErr *github.GhError
	return errors.As(err, &ghErr) && ghErr.Status == http.StatusConflict
}

func workflowDispatch(ctx context.Context, s *Session, p workflowDispatchParams, in Inputs) (DispatchReceipt, error) {
	on := In[RepoScoped](in, "on").RepoRef()
	switch {
	case p.Workflow == "":
		return DispatchReceipt{}, errors.New("workflow.dispatch needs workflow: the path of the workflow file, e.g. .github/workflows/ci.yml")
	case p.Ref == "":
		return DispatchReceipt{}, errors.New("workflow.dispatch needs ref: the ref whose workflow BODY runs")
	case len(p.Inputs) > maxDispatchInputs:
		return DispatchReceipt{}, fmt.Errorf("workflow_dispatch takes at most %d top-level inputs, got %d", maxDispatchInputs, len(p.Inputs))
	}
	inputs := orEmpty(p.Inputs)
	encoded, err := json.Marshal(inputs)
	if err != nil {
		return DispatchReceipt{}, fmt.Errorf("workflow.dispatch inputs are not encodable as JSON: %w", err)
	}
	if chars := utf8.RuneCount(encoded); chars > maxDispatchPayloadChars {
		return DispatchReceipt{}, fmt.Errorf("workflow_dispatch inputs are capped at %d characters and these encode to %d", maxDispatchPayloadChars, chars)
	}
	file := path.Base(p.Workflow)
	receipt := DispatchReceipt{
		RepoLoc:     on,
		Ref:         p.Ref,
		RequestedAt: engine.IsoformatUTC(time.Now()),
		Marker:      markerOf(p.Inputs),
	}

	// The trigger registration lives on the default branch even though the body
	// that runs comes from the dispatched ref, and a disabled workflow accepts
	// nothing. Both answers come from one read, which keeps a request the target
	// would refuse out of the customer's audit log.
	client, err := s.Client()
	if err != nil && s.Execute {
		return DispatchReceipt{}, err
	}
	if client != nil {
		raw, _, err := client.Get(ctx, fmt.Sprintf("/repos/%s/%s/actions/workflows/%s", on.Owner, on.Repo, url.PathEscape(file)), nil, false)
		if readErr := s.SoftRead(err, "read workflow "+file); readErr != nil {
			// Only a 404 says anything about the customer's repository. A 500, a DNS
			// failure or a canceled context says something about the network, and
			// asserting a configuration fact from one of those puts a claim in the run
			// record the run never established.
			var ghErr *github.GhError
			if errors.As(readErr, &ghErr) && ghErr.Status == http.StatusNotFound {
				return DispatchReceipt{}, fmt.Errorf("workflow %s is not registered on the default branch of %s/%s, so it accepts no dispatch: %w", file, on.Owner, on.Repo, readErr)
			}
			return DispatchReceipt{}, fmt.Errorf("reading workflow %s in %s/%s failed, so whether it is registered and active is unknown and no dispatch was sent: %w", file, on.Owner, on.Repo, readErr)
		}
		var wf struct {
			State string `json:"state"`
		}
		if json.Unmarshal(raw, &wf) == nil && wf.State != "" && wf.State != "active" {
			return DispatchReceipt{}, fmt.Errorf("workflow %s is %s and accepts no dispatch", file, wf.State)
		}
	}

	raw, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/actions/workflows/%s/dispatches", on.Owner, on.Repo, url.PathEscape(file)),
		Body:   map[string]any{"ref": p.Ref, "inputs": inputs, "return_run_details": true},
		Target: on.Owner + "/" + on.Repo,
		Note: "return_run_details asks the endpoint to answer 200 with the id of the run it starts, which is " +
			"what run.await polls instead of correlating one out of the run listing; the run itself is not " +
			"retractable and run.cancel is the only lever over it",
	})
	if err != nil {
		return receipt, err
	}
	receipt.RunID = dispatchedRunID(raw)
	if s.Execute && receipt.RunID == 0 {
		s.Note("the dispatch answered without a workflow_run_id, so the run it started is correlated out of the run listing by run.await rather than taken from the response")
	}
	return receipt, nil
}

// dispatchedRunID reads the id of the started run out of a dispatch response.
// return_run_details asks for a 200 carrying it, and an empty 204 is still a
// documented answer to that request, so an absent id falls back to correlation
// rather than failing the step.
func dispatchedRunID(raw json.RawMessage) int64 {
	var body struct {
		WorkflowRunID int64 `json:"workflow_run_id"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return 0
	}
	return body.WorkflowRunID
}

func repoDispatch(ctx context.Context, s *Session, p repoDispatchParams, in Inputs) (DispatchReceipt, error) {
	bound := In[RepoScoped](in, "on")
	on := bound.RepoRef()
	switch chars := utf8.RuneCountInString(p.EventType); {
	case p.EventType == "":
		return DispatchReceipt{}, errors.New("repo.dispatch needs an event_type: value")
	case chars > maxEventTypeChars:
		return DispatchReceipt{}, fmt.Errorf("repository_dispatch event_type must be %d characters or fewer, this one is %d", maxEventTypeChars, chars)
	case len(p.ClientPayload) > maxClientPayloadProps:
		return DispatchReceipt{}, fmt.Errorf("repository_dispatch client_payload takes at most %d top-level properties, got %d", maxClientPayloadProps, len(p.ClientPayload))
	}
	clientPayload := orEmpty(p.ClientPayload)
	encoded, err := json.Marshal(clientPayload)
	if err != nil {
		return DispatchReceipt{}, fmt.Errorf("repo.dispatch client_payload is not encodable as JSON: %w", err)
	}
	if len(encoded) > maxDispatchPayloadChars {
		return DispatchReceipt{}, fmt.Errorf("repository_dispatch client_payload must stay under 64KB and this one encodes to %d bytes", len(encoded))
	}

	branch, err := defaultBranch(ctx, s, bound)
	if err != nil {
		s.Note(fmt.Sprintf("the default branch of %s/%s could not be read (%v), so this receipt names no ref; the dispatch still runs only default-branch workflow bodies, and a correlated run's own head_branch is what names the ref it ran on",
			on.Owner, on.Repo, err))
	}
	receipt := DispatchReceipt{
		RepoLoc:     on,
		Ref:         branch,
		RequestedAt: engine.IsoformatUTC(time.Now()),
		Marker:      markerOf(p.ClientPayload),
	}

	if _, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/dispatches", on.Owner, on.Repo),
		Body:   map[string]any{"event_type": p.EventType, "client_payload": clientPayload},
		Target: on.Owner + "/" + on.Repo,
		Note: "answers 204 with no run id and runs only default-branch workflow bodies; the marker travels in " +
			"client_payload so run.await can correlate the run it starts",
	}); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// markerOf lifts an author-supplied marker out of the dispatch payload so the
// receipt can carry it. Nothing is injected: a workflow_dispatch input the
// workflow does not declare is a 422.
func markerOf(m map[string]any) string {
	if v, ok := m["marker"]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

type runBody struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Event        string    `json:"event"`
	Status       string    `json:"status"`
	Conclusion   string    `json:"conclusion"`
	HeadBranch   string    `json:"head_branch"`
	HeadSHA      string    `json:"head_sha"`
	DisplayTitle string    `json:"display_title"`
	CreatedAt    time.Time `json:"created_at"`
	RunAttempt   int       `json:"run_attempt"`
	HTMLURL      string    `json:"html_url"`
	PullRequests []struct {
		Number int `json:"number"`
	} `json:"pull_requests"`
}

func (b runBody) handle(loc RepoLoc) WorkflowRun {
	return WorkflowRun{
		RepoLoc:      loc,
		ID:           b.ID,
		WorkflowPath: b.Path,
		Event:        b.Event,
		Status:       b.Status,
		Conclusion:   b.Conclusion,
		HeadSHA:      b.HeadSHA,
		RunAttempt:   b.RunAttempt,
	}
}

func (b runBody) candidate() runCandidate {
	prs := make([]int, 0, len(b.PullRequests))
	for _, pr := range b.PullRequests {
		prs = append(prs, pr.Number)
	}
	return runCandidate{
		ID: b.ID, Path: b.Path, Event: b.Event, Status: b.Status, Conclusion: b.Conclusion,
		HeadBranch: b.HeadBranch, HeadSHA: b.HeadSHA, DisplayTitle: b.DisplayTitle,
		CreatedAt: engine.IsoformatUTC(b.CreatedAt), PullRequests: prs,
		RunAttempt: b.RunAttempt, URL: b.HTMLURL,
	}
}

// awaitStart is the front of every wait: it refuses a subject outside the plan
// scope before the first read, and renders instead of blocking under a dry run,
// because a dry run that hangs on a run nothing provoked is not a dry run.
func awaitStart(s *Session, repo RepoLoc, rawTimeout, what string) (*github.Client, time.Duration, bool, error) {
	timeout, err := parseTimeout(rawTimeout)
	if err != nil {
		return nil, 0, false, err
	}
	target := repo.Owner + "/" + repo.Repo
	if !s.targetAllowed(target) {
		return nil, 0, false, fmt.Errorf("%s is outside the plan scope %s", target, strings.Join(s.Plan.Scope, ", "))
	}
	if !s.Execute {
		s.MarkEmpty(fmt.Sprintf("dry run: would wait %s for %s, sending nothing", boundText(timeout), what))
		return nil, timeout, false, nil
	}
	client, err := s.Client()
	if err != nil {
		return nil, 0, false, err
	}
	return client, timeout, true, nil
}
