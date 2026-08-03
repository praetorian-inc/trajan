package attack

import (
	"cmp"
	"encoding/json"
	"fmt"
	"reflect"
)

// Handle is a sealed sum: concrete handles are structs with value receivers, so
// a resumed run rehydrates them from plain JSON with no live pointers. The
// unexported handle() keeps the set closed to this package.
type Handle interface {
	Kind() HandleKind
	handle()
}

type HandleKind string

const (
	KindIdentity        HandleKind = "identity"
	KindRepo            HandleKind = "repo"
	KindWritableRepo    HandleKind = "writable_repo"
	KindFork            HandleKind = "fork"
	KindBranch          HandleKind = "branch"
	KindCommit          HandleKind = "commit"
	KindPullRequest     HandleKind = "pull_request"
	KindIssue           HandleKind = "issue"
	KindComment         HandleKind = "comment"
	KindReview          HandleKind = "review"
	KindReviewState     HandleKind = "review_state"
	KindMergeability    HandleKind = "mergeability"
	KindWorkflowRun     HandleKind = "workflow_run"
	KindDispatchReceipt HandleKind = "dispatch_receipt"
	KindLoot            HandleKind = "loot"
	KindRef             HandleKind = "ref"
	KindStatus          HandleKind = "status"
	KindCheckRun        HandleKind = "check_run"
	KindCacheEntry      HandleKind = "cache_entry"
	KindOrg             HandleKind = "org"
	KindRunnerInventory HandleKind = "runner_inventory"
	KindPendingDeploy   HandleKind = "pending_deployment"
	KindNone            HandleKind = "none"
)

// The port lattice, capped at three. WritableRef and Commentable embed
// RepoScoped so a step cannot bind handles from two different repositories:
// RepoScoped is the floor every port target names a repository through, which is
// what the same-repository check reads.
type RepoScoped interface {
	Handle
	RepoRef() RepoLoc
}
type WritableRef interface {
	RepoScoped
	WriteRef() RefLoc
}
type Commentable interface {
	RepoScoped
	IssueRef() IssueLoc
}

type RepoLoc struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}
type RefLoc struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
	Ref   string `json:"ref"`
	SHA   string `json:"sha"`
}
type IssueLoc struct {
	Owner  string `json:"owner"`
	Repo   string `json:"repo"`
	Number int    `json:"number"`
}

func (l RepoLoc) RepoRef() RepoLoc    { return l }
func (l RefLoc) RepoRef() RepoLoc     { return RepoLoc{Owner: l.Owner, Repo: l.Repo} }
func (l RefLoc) WriteRef() RefLoc     { return l }
func (l IssueLoc) RepoRef() RepoLoc   { return RepoLoc{Owner: l.Owner, Repo: l.Repo} }
func (l IssueLoc) IssueRef() IssueLoc { return l }

// Measurement is a boolean fact together with whether it was measured at all. A
// comparison the run could not make must not reach a plan as false: false is
// what the negative measurement looks like, so a gate reading `stale == false`
// would mutate the customer's repository on a fact nobody established. The zero
// value is unmeasured, so a producer that never sets one cannot claim a negative.
type Measurement struct {
	Value bool
	Known bool
	// Reason is why the comparison was not made, in the words the operator reading
	// the step record — or the step that a gate refused — needs.
	Reason string
}

func Measured(v bool) Measurement { return Measurement{Value: v, Known: true} }

func Unmeasured(why string) Measurement { return Measurement{Reason: why} }

const undeterminedKey = "undetermined"

// MarshalJSON keeps a measured value a bare boolean, so a plan still reads
// `stale == false`, and gives an unmeasured one a shape no predicate can mistake
// for one — carrying the reason into the step record, which is the only place a
// resumed run can read it back from.
func (m Measurement) MarshalJSON() ([]byte, error) {
	if m.Known {
		return json.Marshal(m.Value)
	}
	return json.Marshal(map[string]string{undeterminedKey: m.Reason})
}

// A bare null decodes as unmeasured rather than as false, so a record an older
// run or a hand edit left with no value cannot promote a missing measurement to
// a negative one on resume.
func (m *Measurement) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*m = Unmeasured("")
		return nil
	}
	var v bool
	if err := json.Unmarshal(b, &v); err == nil {
		*m = Measured(v)
		return nil
	}
	var undetermined struct {
		Reason string `json:"undetermined"`
	}
	if err := json.Unmarshal(b, &undetermined); err != nil {
		return fmt.Errorf("a measurement is true, false or {%q: <reason>}, not %s", undeterminedKey, b)
	}
	*m = Unmeasured(undetermined.Reason)
	return nil
}

// unmeasuredReason reads an unmeasured Measurement out of a decoded subject — the
// JSON form rather than the typed handle, because a gate on a resumed run reads
// handles that came back through the step records. A path projected across a list
// is undecidable as soon as one element was not measured.
func unmeasuredReason(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		why, marked := t[undeterminedKey]
		if !marked {
			return "", false
		}
		text, _ := why.(string)
		return cmp.Or(text, "the step that produced it did not measure it"), true
	case []any:
		for _, item := range t {
			if why, marked := unmeasuredReason(item); marked {
				return why, true
			}
		}
	}
	return "", false
}

type sealed struct{}

func (sealed) handle() {}

// None is the produced handle of a primitive that yields nothing (a delete or a
// cleanup step). It satisfies no port interface, so nothing can bind it; it is
// deliberately absent from handleTypes for the same reason.
type None struct{ sealed }

func (None) Kind() HandleKind { return KindNone }

type Identity struct {
	sealed
	Name   string   `json:"name"`
	IDKind string   `json:"id_kind"`
	Login  string   `json:"login"`
	Scopes []string `json:"scopes"`
}

func (Identity) Kind() HandleKind { return KindIdentity }

type Repo struct {
	sealed
	RepoLoc
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	Perms         Perms  `json:"perms"`
}

type Perms struct {
	Admin bool `json:"admin"`
	Push  bool `json:"push"`
	Pull  bool `json:"pull"`
}

func (Repo) Kind() HandleKind { return KindRepo }

// WritableRepo is the in-repo write-collaborator target: RepoScoped and
// WritableRef, but produced only by repo.writable after it reads Perms.Push, so
// a bare Repo can never bind a write port.
type WritableRepo struct {
	sealed
	RepoLoc
	DefaultBranch string `json:"default_branch"`
}

func (WritableRepo) Kind() HandleKind { return KindWritableRepo }
func (w WritableRepo) WriteRef() RefLoc {
	return RefLoc{Owner: w.Owner, Repo: w.Repo, Ref: "refs/heads/" + w.DefaultBranch}
}

type Fork struct {
	sealed
	RepoLoc
	Upstream      RepoLoc `json:"upstream"`
	DefaultBranch string  `json:"default_branch"`
	Created       bool    `json:"created"`
}

func (Fork) Kind() HandleKind { return KindFork }
func (f Fork) WriteRef() RefLoc {
	return RefLoc{Owner: f.Owner, Repo: f.Repo, Ref: "refs/heads/" + f.DefaultBranch}
}

type Branch struct {
	sealed
	RefLoc
	FromRef string `json:"from_ref"`
	Created bool   `json:"created"`
}

func (Branch) Kind() HandleKind { return KindBranch }

type Commit struct {
	sealed
	RefLoc
	Parents   []string `json:"parents"`
	Tree      string   `json:"tree"`
	Files     []string `json:"files"`
	Message   string   `json:"message"`
	Verified  bool     `json:"verified"`
	CreatedAt string   `json:"created_at"`
	MergedAt  string   `json:"merged_at"`
}

func (Commit) Kind() HandleKind { return KindCommit }

type PullRequest struct {
	sealed
	IssueLoc
	Head           string `json:"head"`
	Base           string `json:"base"`
	HeadLabel      string `json:"head_label"`
	State          string `json:"state"`
	Merged         bool   `json:"merged"`
	MergeableState string `json:"mergeable_state"`
	CreatedAt      string `json:"created_at"`
}

func (PullRequest) Kind() HandleKind { return KindPullRequest }

// Mergeability is separate from PullRequest because mergeable_state is computed
// asynchronously: Computed distinguishes "GitHub has not answered yet" from "it
// cannot be merged".
type Mergeability struct {
	sealed
	RepoLoc
	Number         int    `json:"number"`
	Mergeable      bool   `json:"mergeable"`
	MergeableState string `json:"mergeable_state"`
	Clean          bool   `json:"clean"`
	Computed       bool   `json:"computed"`
}

func (Mergeability) Kind() HandleKind { return KindMergeability }

type Issue struct {
	sealed
	IssueLoc
	Title  string `json:"title"`
	State  string `json:"state"`
	IsPull bool   `json:"is_pull"`
}

func (Issue) Kind() HandleKind { return KindIssue }

// Comment is RepoScoped only, deliberately not Commentable: you comment on a PR
// or an Issue, never on another comment.
type Comment struct {
	sealed
	RepoLoc
	Number    int    `json:"number"`
	ID        int64  `json:"id"`
	Author    string `json:"author"`
	BodySHA   string `json:"body_sha"`
	HTMLURL   string `json:"html_url"`
	CreatedAt string `json:"created_at"`
}

func (Comment) Kind() HandleKind { return KindComment }

type Review struct {
	sealed
	RepoLoc
	Number    int    `json:"number"`
	ID        int64  `json:"id"`
	State     string `json:"state"`
	Reviewer  string `json:"reviewer"`
	CommitSHA string `json:"commit_sha"`
	// Stale is the comparison of CommitSHA with the head the review was read
	// against, which is unmeasurable when either side is missing.
	Stale     Measurement `json:"stale"`
	Dismissed bool        `json:"dismissed"`
}

func (Review) Kind() HandleKind { return KindReview }

type ReviewState struct {
	sealed
	RepoLoc
	ReviewDecision string   `json:"review_decision"`
	Reviews        []Review `json:"reviews"`
	// DismissStaleReviews is read off the base branch's protection, which needs
	// admin: unreadable is a distinct answer from off.
	DismissStaleReviews Measurement `json:"dismiss_stale_reviews"`
}

func (ReviewState) Kind() HandleKind { return KindReviewState }

type WorkflowRun struct {
	sealed
	RepoLoc
	ID           int64  `json:"id"`
	WorkflowPath string `json:"workflow_path"`
	Event        string `json:"event"`
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion"`
	HeadSHA      string `json:"head_sha"`
	RunAttempt   int    `json:"run_attempt"`
	// Provoked distinguishes a run this chain caused, correlated by run.await,
	// from one it merely watched. It decides whether cleanup may touch the run:
	// rejecting a waiting deployment on the customer's own run would sabotage it.
	Provoked bool `json:"provoked"`
}

func (WorkflowRun) Kind() HandleKind { return KindWorkflowRun }

type DispatchReceipt struct {
	sealed
	RepoLoc
	Ref         string `json:"ref"`
	RequestedAt string `json:"requested_at"`
	Marker      string `json:"marker"`
	// RunID is the run the dispatch response named, zero when the response carried
	// none. It is what lets run.await poll the run GitHub said it started instead of
	// correlating one out of the run listing, and it is on the handle rather than in
	// the step's own cursor so a resumed run reads it back with the receipt.
	RunID int64 `json:"run_id,omitempty"`
}

func (DispatchReceipt) Kind() HandleKind { return KindDispatchReceipt }

// Loot is not RepoScoped: harvested evidence has no single repository.
type Loot struct {
	sealed
	Source         string     `json:"source"`
	RunID          int64      `json:"run_id"`
	Classification string     `json:"classification"`
	MarkerSeen     bool       `json:"marker_seen"`
	Encrypted      bool       `json:"encrypted"`
	Items          []LootItem `json:"items"`
	RawPath        string     `json:"raw_path"`
	// Matched is the scalar run.harvest's match: produces, so a downstream when:
	// gates on one boolean instead of quantifying over Items.
	Matched bool `json:"matched"`
}

type LootItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Kind  string `json:"kind"`
	// Durable says a later step may act as this material; ExpiresAt is the expiry
	// that decided it. The expiry is carried per item rather than inferred from a
	// sibling item later, because one fragment can emit several credentials and
	// the wrong expiry would be attributed to the wrong one.
	Durable   bool   `json:"durable"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func (Loot) Kind() HandleKind { return KindLoot }

// Ref carries PreviousSHA, the only clean undo in the system.
type Ref struct {
	sealed
	RefLoc
	PreviousSHA string `json:"previous_sha"`
	Forced      bool   `json:"forced"`
}

func (Ref) Kind() HandleKind { return KindRef }

// CacheEntry is record-only: the write itself lands via a job. The handle exists
// so the ledger and the finding can name a poisoned entry. Scope is the git ref
// the entry is written on, which is what decides who can restore it: an entry
// written on a branch is visible to that branch and its descendants.
type CacheEntry struct {
	sealed
	RepoLoc
	Scope            string `json:"scope"`
	Key              string `json:"key"`
	RestoreKeyPrefix string `json:"restore_key_prefix"`
	Bytes            int    `json:"bytes"`
}

func (CacheEntry) Kind() HandleKind { return KindCacheEntry }

// Org has no single repository; it is gated by the plan's orgs allowlist, not by
// a fourth port interface.
type Org struct {
	sealed
	Owner string `json:"owner"`
}

func (Org) Kind() HandleKind { return KindOrg }

// RunnerInventory is not RepoScoped: the same inventory is read from a repository
// or from an organization, and an organization names no repository. Target carries
// whichever it was, as one string, so no consumer can read a repo out of an org
// inventory.
type RunnerInventory struct {
	sealed
	Scope   string   `json:"scope"`
	Target  string   `json:"target"`
	Runners []Runner `json:"runners"`
	// Labels is the union across every runner, so a when: gates on one field
	// instead of quantifying over Runners. CustomLabels is the subset an operator
	// assigned: the rest are applied automatically when a runner is configured, so
	// they name no runner anybody chose to make reachable by runs-on.
	Labels       []string `json:"labels"`
	CustomLabels []string `json:"custom_labels"`
	Online       int      `json:"online"`
	Busy         int      `json:"busy"`
	// AnyPersistent folds the per-runner readings into the one a when: gates on.
	// One runner reported as not ephemeral settles it; a negative needs every
	// runner to have reported the field, which the schema leaves optional.
	AnyPersistent Measurement `json:"any_persistent"`
}

func (RunnerInventory) Kind() HandleKind { return KindRunnerInventory }

// Runner is one entry of an inventory, not a handle: nothing binds a single
// runner, and the port lattice has no place for a machine.
type Runner struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"`
	OS           string   `json:"os"`
	Status       string   `json:"status"`
	Busy         bool     `json:"busy"`
	Labels       []string `json:"labels"`
	CustomLabels []string `json:"custom_labels"`
	// Ephemeral is the --ephemeral the runner registered with. The field is
	// optional in the runner schema, so a runner that reports none is unmeasured:
	// false is what a runner that keeps its state for the next job looks like.
	Ephemeral Measurement `json:"ephemeral"`
	GroupID   int64       `json:"group_id"`
	Group     string      `json:"group"`
}

type Status struct {
	sealed
	RepoLoc
	ID      int64  `json:"id"`
	SHA     string `json:"sha"`
	Context string `json:"context"`
	State   string `json:"state"`
	// PreviousState is the combined state on this (sha, context) before the post.
	// It is the only thing an inverse could aim at, and posting it back adds a
	// third entry to a history that keeps all of them.
	PreviousState string `json:"previous_state"`
	Description   string `json:"description"`
	TargetURL     string `json:"target_url"`
	CreatedAt     string `json:"created_at"`
}

func (Status) Kind() HandleKind { return KindStatus }

type CheckRun struct {
	sealed
	RepoLoc
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	DetailsURL string `json:"details_url"`
	// AppSlug names the App the check run is attributed to. A check run has no
	// author a plan can choose: it belongs to the App whose installation token
	// created it, which is why the identity is a port rather than a field.
	AppSlug   string `json:"app_slug"`
	AppID     int64  `json:"app_id"`
	StartedAt string `json:"started_at"`
}

func (CheckRun) Kind() HandleKind { return KindCheckRun }

// PendingDeployment is one run's whole waiting set: every environment blocking it,
// who may release each one, and whether the identity reading it may. It is one
// handle rather than one per environment because the run is what waits.
type PendingDeployment struct {
	sealed
	RepoLoc
	RunID  int64  `json:"run_id"`
	Status string `json:"status"`
	// TriggeringActor beside CanApprove is the measurement: a configuration flag
	// says reviewers are required, this says the account that provoked the run is
	// one of them.
	TriggeringActor string               `json:"triggering_actor"`
	ActingLogin     string               `json:"acting_login"`
	Environments    []PendingEnvironment `json:"environments"`
	CanApprove      bool                 `json:"can_approve"`
	// SelfApproval compares TriggeringActor with ActingLogin, which is unmeasurable
	// when either is blank — an App installation token reports no login at all.
	SelfApproval Measurement `json:"self_approval"`
	Provoked     bool        `json:"provoked"`
}

func (PendingDeployment) Kind() HandleKind { return KindPendingDeploy }

type PendingEnvironment struct {
	Name                  string   `json:"name"`
	ID                    int64    `json:"id"`
	WaitTimer             int      `json:"wait_timer"`
	WaitTimerStartedAt    string   `json:"wait_timer_started_at"`
	CurrentUserCanApprove bool     `json:"current_user_can_approve"`
	Reviewers             []string `json:"reviewers"`
}

// Compile-time proof of the edges the validator later reads back via reflect.
var (
	_ WritableRef = Commit{}
	_ WritableRef = Fork{}
	_ WritableRef = Branch{}
	_ WritableRef = WritableRepo{}
	_ WritableRef = Ref{}
	_ Commentable = PullRequest{}
	_ Commentable = Issue{}
	_ RepoScoped  = Repo{} // Repo is RepoScoped but deliberately NOT WritableRef.
	_ RepoScoped  = Comment{}
	_ RepoScoped  = Review{}
	_ RepoScoped  = ReviewState{}
	_ RepoScoped  = Mergeability{}
	_ RepoScoped  = WorkflowRun{}
	_ RepoScoped  = DispatchReceipt{}
	_ RepoScoped  = CacheEntry{}
	_ RepoScoped  = Status{}
	_ RepoScoped  = CheckRun{}
	_ RepoScoped  = PendingDeployment{}
)

// handleTypes maps every kind to its concrete Go type, so the catalog can
// enumerate which handles satisfy a port and the validator can introspect a
// producer's fields. O in Register is the single source of truth for a spec's
// Produces, so this table can never disagree with the registered primitives.
var handleTypes = map[HandleKind]reflect.Type{
	KindIdentity:        reflect.TypeFor[Identity](),
	KindRepo:            reflect.TypeFor[Repo](),
	KindWritableRepo:    reflect.TypeFor[WritableRepo](),
	KindFork:            reflect.TypeFor[Fork](),
	KindBranch:          reflect.TypeFor[Branch](),
	KindCommit:          reflect.TypeFor[Commit](),
	KindPullRequest:     reflect.TypeFor[PullRequest](),
	KindIssue:           reflect.TypeFor[Issue](),
	KindComment:         reflect.TypeFor[Comment](),
	KindReview:          reflect.TypeFor[Review](),
	KindReviewState:     reflect.TypeFor[ReviewState](),
	KindMergeability:    reflect.TypeFor[Mergeability](),
	KindWorkflowRun:     reflect.TypeFor[WorkflowRun](),
	KindDispatchReceipt: reflect.TypeFor[DispatchReceipt](),
	KindLoot:            reflect.TypeFor[Loot](),
	KindRef:             reflect.TypeFor[Ref](),
	KindStatus:          reflect.TypeFor[Status](),
	KindCheckRun:        reflect.TypeFor[CheckRun](),
	KindCacheEntry:      reflect.TypeFor[CacheEntry](),
	KindOrg:             reflect.TypeFor[Org](),
	KindRunnerInventory: reflect.TypeFor[RunnerInventory](),
	KindPendingDeploy:   reflect.TypeFor[PendingDeployment](),
}
