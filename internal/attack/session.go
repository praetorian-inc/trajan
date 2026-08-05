package attack

import (
	"cmp"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/attack/payload"
	"github.com/praetorian-inc/trajan/internal/github"
)

// plannedSHA stands in for an object id a dry run did not create. It is
// obviously synthetic and still the right shape, so a body that reads a sha out
// of a response keeps building the rest of the request sequence.
var plannedSHA = strings.Repeat("0", 40)

// Session holds what a primitive body needs and the run does not write down: one
// client per identity, the acting identity of the step in flight, and the
// ephemeral keypair. Steps are serial, so the acting context is a field rather
// than a parameter threaded through every signature.
type Session struct {
	Plan    *Plan
	PlanDir string
	Ledger  *Ledger
	Execute bool

	// Resumed marks a run continued in a new process. It changes only how the
	// harvest reports a seal it cannot unwrap: the per-run key is gone with the
	// process that minted it, which is a distinct outcome from a corrupt stream.
	Resumed bool
	// KeepCipher retains the persisted ciphertext after a successful decrypt
	// instead of discarding it.
	KeepCipher bool

	// StartedAt bounds how far back a watch may reach for a run this plan did not
	// issue. A resumed run keeps the original moment, so a watch restarted in a new
	// process still reaches the run the first process provoked.
	StartedAt time.Time

	identities map[string]*identityClient
	aliases    map[string]string
	acting     actingContext

	// extraScope holds repositories this run brought into existence in the
	// acting identity's own namespace — a fork of an in-scope upstream. They
	// cannot be named in the plan text, because the namespace is whichever
	// account the operator ran as.
	extraScope map[string]string

	// privateKey is the per-run half of the rsa-oaep-hybrid scheme. The engine
	// that mints it and unwraps harvested loot lands with run.harvest; it is
	// held here because the public half is injected into rendered payloads and
	// the private half must never touch disk.
	privateKey *rsa.PrivateKey

	// publicKeyPEM is derived once at mint time: PayloadEnv cannot report a
	// failure, and an empty value there composes a job that skips sealing.
	publicKeyPEM string
}

type identityClient struct {
	name   string
	from   string
	kind   string
	login  string
	scopes []string
	client *github.Client
	err    error
}

type actingContext struct {
	step    string
	uses    string
	id      *identityClient
	empty   string
	note    string
	planned []PlannedRequest

	// prev is the step this one immediately follows, which is the only thing
	// run.await has to correlate a run against.
	prev *Provocation
	// prior is the poll cursor an earlier, killed run of this same step
	// checkpointed. save writes the live cursor back into the step record.
	prior any
	save  func(cursor any) error
}

// Provocation is what the nearest preceding executed mutation did. GitHub
// exposes no link from a trigger to the run it started, which is why this is a
// derived record rather than a typed port.
type Provocation struct {
	Step string  `json:"step"`
	Uses string  `json:"uses"`
	Repo RepoLoc `json:"repo"`
	Ref  string  `json:"ref,omitempty"`
	PR   int     `json:"pull_request,omitempty"`
	// RunID is set only when the provoking request's own response named the run it
	// started, which settles the correlation and leaves the fields below with nothing
	// to narrow.
	RunID  int64     `json:"run_id,omitempty"`
	Events []string  `json:"events,omitempty"`
	At     time.Time `json:"at"`
}

func NewSession(ctx context.Context, p *Plan, planDir string, ledger *Ledger, execute bool) (*Session, error) {
	s := &Session{
		Plan:       p,
		PlanDir:    planDir,
		Ledger:     ledger,
		Execute:    execute,
		StartedAt:  time.Now(),
		identities: map[string]*identityClient{},
		aliases:    map[string]string{},
		extraScope: map[string]string{},
	}

	def, err := s.resolveIdentity(ctx, "", cmp.Or(p.Identity, kindEnv))
	if err != nil && execute {
		return nil, err
	}
	s.acting.id = def

	for _, spec := range p.Identities {
		if _, err := s.resolveIdentity(ctx, spec.Name, cmp.Or(spec.From, kindEnv)); err != nil && execute {
			return nil, err
		}
	}
	for _, st := range allSteps(p) {
		if st.As == "" || s.identities[st.As] != nil {
			continue
		}
		if st.As == kindEnv || strings.Contains(st.As, ":") {
			if _, err := s.resolveIdentity(ctx, st.As, st.As); err != nil && execute {
				return nil, err
			}
		}
	}

	s.preflight(p)

	// The keypair is minted here, per run and in memory, whenever the plan opts
	// into encryption — on a resumed run too, because a not-yet-committed
	// workflow.commit still needs a public half to seal with, and an empty one
	// would compose a job that prints plaintext. Loot sealed by an earlier
	// process is unreachable to this fresh key, which the harvest reports.
	if enc := strings.TrimSpace(p.Encryption); enc != "" && enc != "none" {
		key, err := mintRunKey()
		if err != nil {
			return nil, fmt.Errorf("mint run keypair: %w", err)
		}
		pub, err := publicKeyPEM(key)
		if err != nil {
			return nil, fmt.Errorf("encode run public key: %w", err)
		}
		s.privateKey = key
		s.publicKeyPEM = pub
	}

	return s, nil
}

// resolveIdentity builds and caches one client. In dry-run mode an unresolvable
// credential is recorded on the entry rather than returned, so a plan can still
// be rendered on a machine that holds none of its identities.
func (s *Session) resolveIdentity(ctx context.Context, name, from string) (*identityClient, error) {
	ic := &identityClient{name: cmp.Or(name, from), from: from}
	s.identities[name] = ic
	if name != ic.name {
		s.identities[ic.name] = ic
	}

	token, kind, err := resolveCredential(ctx, from)
	if err != nil {
		ic.err = err
		slog.Warn("identity unresolved", "identity", ic.name, "from", from, "err", err)
		return ic, err
	}
	ic.kind = kind
	ic.client = github.NewClient(token)
	ic.login, ic.scopes = whoami(ctx, ic.client)
	// Debug, not Info: the run's head block names every identity it resolved, and
	// resolution happens before there is a head to sit under.
	slog.Debug("identity resolved", "identity", ic.name, "login", ic.login, "class", ic.kind)
	return ic, nil
}

// adoptCredential registers a client for a credential this run harvested, named
// after the step that adopted it so `as: <step-id>` reaches it through the alias
// the executor registers when the handle lands. Empty material registers the
// entry and builds no client: a dry run adopts nothing and must still resolve the
// steps that name this identity.
func (s *Session) adoptCredential(ctx context.Context, token string) *identityClient {
	ic := &identityClient{name: "adopted/" + s.acting.step, from: "loot"}
	s.identities[ic.name] = ic
	if token == "" {
		return ic
	}
	ic.kind = tokenClass(token)
	ic.client = github.NewClient(token)
	ic.login, ic.scopes = whoami(ctx, ic.client)
	slog.Info("identity adopted from harvested evidence", "identity", ic.name, "login", ic.login, "class", ic.kind)
	return ic
}

// whoami is best-effort: an App installation token cannot call /user, and a
// fine-grained PAT reports no scopes. Neither is a failure.
func whoami(ctx context.Context, c *github.Client) (login string, scopes []string) {
	raw, hdr, err := c.Get(ctx, "/user", nil, false)
	if err != nil {
		return "", nil
	}
	var user struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(raw, &user); err != nil {
		return "", nil
	}
	return user.Login, parseScopes(hdr)
}

func parseScopes(hdr http.Header) []string {
	raw := hdr.Get("X-OAuth-Scopes")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// classicScope maps a primitive capability onto the classic-PAT scope that grants
// it. Fine-grained PATs and Apps expose no scope header at all, which is why the
// preflight built on this can only ever warn.
var classicScope = map[Capability]string{
	CapContentsWrite:  "repo",
	CapActionsWrite:   "repo",
	CapPullRequests:   "repo",
	CapIssues:         "repo",
	CapChecksWrite:    "repo",
	CapDeployments:    "repo",
	CapAdministration: "repo",
	CapWorkflow:       "workflow",
	CapDeleteRepo:     "delete_repo",
}

func (s *Session) preflight(p *Plan) {
	var caps []Capability
	for _, st := range allSteps(p) {
		if e, ok := lookup(st.Uses); ok {
			caps = append(caps, e.spec.Caps...)
		}
	}
	for _, ic := range uniqueIdentities(s.identities) {
		if len(ic.scopes) == 0 {
			continue
		}
		var missing []string
		for _, c := range caps {
			want := classicScope[c]
			if want != "" && !slices.Contains(ic.scopes, want) && !slices.Contains(missing, want) {
				missing = append(missing, want)
			}
		}
		// A guess from the capability declarations, not a reading of what the plan
		// will ask this identity for, so it fires on scopes a run never needs. It goes
		// out at debug: a step that really cannot act fails with the API's own words.
		if len(missing) > 0 {
			slog.Debug("identity may lack a scope this plan needs",
				"identity", ic.name, "missing", strings.Join(missing, ","), "has", strings.Join(ic.scopes, ","))
		}
	}
}

func uniqueIdentities(m map[string]*identityClient) []*identityClient {
	seen := map[*identityClient]bool{}
	var out []*identityClient
	for _, name := range slices.Sorted(maps.Keys(m)) {
		ic := m[name]
		if ic == nil || seen[ic] {
			continue
		}
		seen[ic] = true
		out = append(out, ic)
	}
	return out
}

// identity resolves a step's as: value. A bare name matches a declared identity
// or an alias registered by an identity-producing step; anything containing ':'
// is a from-spec resolved on the spot.
func (s *Session) identity(ctx context.Context, ref string) (*identityClient, error) {
	if ref == "" {
		if s.acting.id == nil {
			return nil, errors.New("plan has no default identity")
		}
		return s.acting.id, nil
	}
	if alias, ok := s.aliases[ref]; ok {
		ref = alias
	}
	if ic, ok := s.identities[ref]; ok {
		return ic, ic.err
	}
	if ref == kindEnv || strings.Contains(ref, ":") {
		return s.resolveIdentity(ctx, ref, ref)
	}
	return nil, fmt.Errorf("identity %q is neither declared nor produced by a prior step", ref)
}

// alias binds a step id to the identity that step produced, which is what makes
// `as: <step-id>` a real dependency edge rather than a silent fallback to the
// default identity.
func (s *Session) alias(stepID, identityName string) { s.aliases[stepID] = identityName }

func (s *Session) begin(a actingContext) { s.acting = a }

// Provocation is the step this one follows. It is nil when nothing this run
// executed could have caused anything, which is the case run.observe exists for.
func (s *Session) Provocation() *Provocation { return s.acting.prev }

// Checkpoint writes a poll cursor into the in-flight step record and flushes it
// to disk. A watch is only resumable because this happens during the wait
// rather than after it.
func (s *Session) Checkpoint(cursor any) error {
	if s.acting.save == nil {
		return nil
	}
	return s.acting.save(cursor)
}

// PriorCursor decodes the cursor an earlier run of this step checkpointed
// before it was killed, and reports whether there was one.
func (s *Session) PriorCursor(into any) bool {
	if s.acting.prior == nil {
		return false
	}
	b, err := json.Marshal(s.acting.prior)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, into) == nil
}

// Client returns the acting identity's client. It returns an error rather than a
// nil client so a read primitive fails as a step failure instead of panicking.
func (s *Session) Client() (*github.Client, error) {
	if s.acting.id == nil {
		return nil, errors.New("no acting identity")
	}
	if s.acting.id.err != nil {
		return nil, s.acting.id.err
	}
	if s.acting.id.client == nil {
		return nil, fmt.Errorf("identity %q has no client", s.acting.id.name)
	}
	return s.acting.id.client, nil
}

// Login is the acting identity's login, empty for an installation token.
func (s *Session) Login() string {
	if s.acting.id == nil {
		return ""
	}
	return s.acting.id.login
}

func (s *Session) ActingName() string {
	if s.acting.id == nil {
		return ""
	}
	return s.acting.id.name
}

// ActingKind is the credential class of the acting identity — the store's
// recorded kind, or the class read off the token prefix for an env credential.
// It is what distinguishes principals GitHub treats differently from a user.
func (s *Session) ActingKind() string {
	if s.acting.id == nil {
		return ""
	}
	return s.acting.id.kind
}

// MarkEmpty says the step produced nothing: the handle it returns is a zero
// value or an empty set, and the reason lands in the step record, which is where
// the mark lives because no handle carries a field for it. A step that produces a
// populated handle and merely has something to say uses Note — recording it as
// empty would tell the operator the chain stopped there.
//
// Reasons accumulate. One step can soft-fail two reads, and the second cause is
// not a correction of the first.
func (s *Session) MarkEmpty(reason string) { s.acting.empty = note(s.acting.empty, reason) }

func (s *Session) takeEmpty() string {
	reason := s.acting.empty
	s.acting.empty = ""
	return reason
}

// Note puts a sentence in the step record of a step that did produce a handle:
// a trigger the call fired, an ordering hazard the operator has to see. MarkEmpty
// cannot carry it, because that marks the step as having produced nothing.
func (s *Session) Note(text string) { s.acting.note = note(s.acting.note, text) }

func (s *Session) takeNote() string {
	text := s.acting.note
	s.acting.note = ""
	return text
}

// SoftRead downgrades a read failure to a blank value while a dry run is
// rendering. The document a dry run produces is the inventory of what --execute
// would attempt, so a value that would have come from the target is simply
// blank — including on a machine that holds none of the plan's credentials.
// Under --execute the error is returned unchanged.
func (s *Session) SoftRead(err error, what string) error {
	if err == nil || s.Execute {
		return err
	}
	s.MarkEmpty(what + ": " + err.Error())
	return nil
}

// AllowFork brings a repository the run itself created into the runtime scope.
// A fork lands in whichever account the operator ran as, which the plan text
// cannot name, so the allowlist is extended only for a fork of an already
// in-scope upstream sitting in the acting identity's own namespace.
func (s *Session) AllowFork(fork, upstream RepoLoc) error {
	up := upstream.Owner + "/" + upstream.Repo
	if !scopeAllows(s.Plan.Scope, up) {
		return fmt.Errorf("%s is outside the plan scope %s", up, strings.Join(s.Plan.Scope, ", "))
	}
	target := fork.Owner + "/" + fork.Repo
	if s.extraScope[target] == "" {
		slog.Debug("scope extended to a fork this run owns", "fork", target, "upstream", up, "identity", s.ActingName())
	}
	s.extraScope[target] = up
	return nil
}

func (s *Session) targetAllowed(target string) bool {
	return scopeAllows(s.Plan.Scope, target) || s.extraScope[target] != ""
}

// OrgAllowed gates an organization-scoped read on the plan's orgs: list. That is a
// separate allowlist from scope: because an Org handle names no repository, so the
// port lattice — whose floor is a repository — has nothing to check it against.
func (s *Session) OrgAllowed(owner string) error {
	if orgAllows(s.Plan.Orgs, owner) {
		return nil
	}
	if len(s.Plan.Orgs) == 0 {
		return fmt.Errorf("organization %q is out of scope: this plan's orgs: allowlist is empty", owner)
	}
	return fmt.Errorf("organization %q is not in this plan's orgs: allowlist (%s)", owner, strings.Join(s.Plan.Orgs, ", "))
}

// PayloadEnv is what the engine, rather than the plan author, supplies to every
// rendered fragment. The public half of the run keypair lands here with the
// encryption engine.
func (s *Session) PayloadEnv() payload.Env {
	return payload.Env{PubKey: s.publicKeyPEM, Collector: s.Plan.collector()}
}

// Mutation is one state change: the request, the repository it lands in, and the
// requests that undo it.
type Mutation struct {
	Method  string
	Path    string
	Body    any
	Target  string // owner/repo — checked against the plan's allowlist before the call
	Inverse []UndoStep
	Note    string

	// InverseFrom derives the undo from the response, for a resource whose
	// identity does not exist until it has been created. The write-ahead intent
	// still lands before the call; the resolved undo is appended the moment the
	// id is known.
	InverseFrom func(raw json.RawMessage) []UndoStep

	// ReadBack answers the one question a 5xx leaves open: the request reached
	// GitHub, so the change may have landed, and for a created resource there is
	// no id in the reply to derive an inverse from. It reads the collection the
	// call posts into and returns the same inverse InverseFrom would have — found
	// by reading rather than by trusting an answer that never came. Every mutation
	// that carries InverseFrom needs one, because for those and only those the
	// write-ahead intent is inverse-less by construction.
	//
	// No steps and no error means the read established the artifact is not there.
	// An error means the question is still open, which is a different sentence in
	// the report and must not be swallowed into the first.
	ReadBack func(ctx context.Context) ([]UndoStep, error)
}

// Mutate is the single choke point for every state change: it is the only route
// to the write client. It rejects a target outside the allowlist, records the
// request instead of sending it unless --execute was passed, and otherwise
// writes the undo record before the call and the outcome after it.
func (s *Session) Mutate(ctx context.Context, m Mutation) (json.RawMessage, int, error) {
	if m.Target == "" {
		return nil, 0, fmt.Errorf("step %q: mutation %s %s names no target repository", s.acting.step, m.Method, m.Path)
	}
	if !s.targetAllowed(m.Target) {
		return nil, 0, fmt.Errorf("step %q: %s is outside the plan scope %s", s.acting.step, m.Target, strings.Join(s.Plan.Scope, ", "))
	}
	// A dry run records the request and answers with an obviously synthetic
	// object so the body keeps building the rest of the sequence. Nothing is
	// sent, nothing is written to the ledger, and the render covers every
	// request the step would issue rather than only its first.
	if !s.Execute {
		s.acting.planned = append(s.acting.planned, PlannedRequest{Method: m.Method, Path: m.Path, Body: m.Body})
		return json.RawMessage(`{"sha":"` + plannedSHA + `","id":0,"number":0,"html_url":"","node_id":""}`), 0, nil
	}
	client, err := s.Client()
	if err != nil {
		return nil, 0, err
	}

	seq, err := s.Ledger.Intent(LedgerEntry{
		Step:     s.acting.step,
		Uses:     s.acting.uses,
		Identity: s.ActingName(),
		Target:   m.Target,
		Method:   m.Method,
		Path:     m.Path,
		Body:     m.Body,
		Inverse:  m.Inverse,
		Note:     m.Note,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("ledger: %w", err)
	}

	raw, status, callErr := client.Mutate(ctx, m.Method, m.Path, m.Body)
	if err := s.Ledger.Result(seq, status, callErr); err != nil {
		return raw, status, errors.Join(callErr, fmt.Errorf("ledger: %w", err))
	}
	if errors.Is(callErr, github.ErrAmbiguous) {
		return raw, status, errors.Join(callErr, s.resolveUnknown(ctx, seq, m, status))
	}
	if callErr == nil && m.InverseFrom != nil {
		if undo := m.InverseFrom(raw); len(undo) > 0 {
			if err := s.Ledger.Undo(seq, m.Target, undo); err != nil {
				return raw, status, fmt.Errorf("ledger: %w", err)
			}
		}
	}
	return raw, status, callErr
}

// resolveUnknown handles the one outcome that can leave an artifact no record
// names: the request reached GitHub, the answer was a 5xx, and the intent written
// ahead of it carries no inverse because the id did not exist yet. The read-back
// the mutation declares establishes what is actually there, and whatever it finds
// — or fails to find — is recorded, so the cleanup report names the artifact
// instead of omitting it. The step still fails: an unknown outcome is not a
// measurement, and no handle may be built on one.
func (s *Session) resolveUnknown(ctx context.Context, seq int, m Mutation, status int) error {
	var undo []UndoStep
	var readErr error
	if m.ReadBack != nil {
		undo, readErr = m.ReadBack(ctx)
	}
	byHand := "an artifact it may have created cannot be named — look for one under " + m.Target + " by hand"
	summary := fmt.Sprintf("%s %s answered %d, so whether it applied is unknown", m.Method, m.Path, status)
	switch {
	case len(undo) > 0:
		if err := s.Ledger.Undo(seq, m.Target, undo); err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
		summary += fmt.Sprintf("; a read-back found what it created, and the inverse recorded against intent %d reverses it", seq)
	case readErr != nil:
		slog.Warn("the read-back of a mutation with an unknown outcome failed",
			"step", s.acting.step, "uses", s.acting.uses, "method", m.Method, "path", m.Path, "err", readErr)
		summary += "; the read-back that would have established what it created failed (" + readErr.Error() + "), so " + byHand
	case m.ReadBack != nil:
		summary += "; a read-back found nothing it could have created"
	default:
		slog.Warn("a mutation with an unknown outcome declares no read-back",
			"step", s.acting.step, "uses", s.acting.uses, "method", m.Method, "path", m.Path, "status", status)
		summary += "; this call declares no read-back, so " + byHand
	}
	if err := s.RecordEffect(Effect{
		Class:   "unknown_outcome",
		Summary: summary,
		Detail:  map[string]any{"target": m.Target, "method": m.Method, "path": m.Path, "status": status, "intent": seq},
	}); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	return nil
}

// Declare records a change this run causes through a channel that is not a
// request of ours — a cache entry a job writes, a deployment left waiting in the
// customer's approvals queue — together with the requests that clear it. Nothing
// is sent; the point is that cleanup has a lever over an artifact no call of ours
// created. It sits behind the same allowlist as Mutate and returns the sequence
// it wrote; a later step that makes the artifact moot retires that inverse
// through DeclaredInverse, which finds it whichever process declared it.
func (s *Session) Declare(m Mutation) (int, error) {
	if m.Target == "" {
		return 0, fmt.Errorf("step %q: declared artifact names no target repository", s.acting.step)
	}
	if !s.targetAllowed(m.Target) {
		return 0, fmt.Errorf("step %q: %s is outside the plan scope %s", s.acting.step, m.Target, strings.Join(s.Plan.Scope, ", "))
	}
	if !s.Execute {
		return 0, nil
	}
	return s.Ledger.Declare(LedgerEntry{
		Step:     s.acting.step,
		Uses:     s.acting.uses,
		Identity: s.ActingName(),
		Target:   m.Target,
		Inverse:  m.Inverse,
		Note:     m.Note,
	})
}

// Retire supersedes a declared artifact's inverse once the artifact is gone. The
// ledger's undo record already means "this is the inverse to replay"; an empty one
// means there is nothing left to replay, which is how cleanup reports a released
// deployment as cleared by this run rather than as an artifact left waiting.
func (s *Session) Retire(seq int, target string) error {
	if seq == 0 || !s.Execute {
		return nil
	}
	return s.Ledger.Undo(seq, target, nil)
}

// DeclaredInverse reports whether the inverse this run declared for an artifact
// is still standing, naming it by the request that would clear it. The answer
// comes from the ledger and not from this process: the declaration a resumed run
// has to retire was written by the process before it, and a step that only
// replays its predecessor's record never runs the body that declared it.
func (s *Session) DeclaredInverse(undoPath string) int {
	if !s.Execute || s.Ledger == nil {
		return 0
	}
	return s.Ledger.PendingDeclaration(undoPath)
}

func (s *Session) takePlanned() []PlannedRequest {
	out := s.acting.planned
	s.acting.planned = nil
	return out
}

// RecordEffect logs a consequence that is not a reversible GitHub mutation.
func (s *Session) RecordEffect(ef Effect) error {
	return s.Ledger.Effect(s.acting.step, s.acting.uses, ef)
}

// GitData is the blob → tree → commit → ref write path. Commits go through it
// rather than git push because it is one code path for every commit mode, it can
// express deletions, and API-created commits are web-flow signed.
type GitData struct {
	s     *Session
	Owner string
	Repo  string
}

func (s *Session) GitData(owner, repo string) GitData {
	return GitData{s: s, Owner: owner, Repo: repo}
}

func (g GitData) target() string { return g.Owner + "/" + g.Repo }

func (g GitData) api(parts ...string) string {
	return "/repos/" + g.Owner + "/" + g.Repo + "/git/" + strings.Join(parts, "/")
}

// TreeFile is one blob this commit writes. Exec marks a file the consuming job
// invokes directly rather than through an interpreter.
type TreeFile struct {
	Bytes []byte
	Exec  bool
}

// TreeChange is everything one commit does to the tree. Deletions and copies are
// tree entries rather than separate pushes: two pushes are two synchronize
// events, and a chain that has just been approved needs to be quiet.
type TreeChange struct {
	Files     map[string]TreeFile
	Deletions []string
	// Copies maps a destination path to an existing blob sha, which is how a
	// rename lands as one tree operation with no content transfer.
	Copies map[string]string
}

func (c TreeChange) empty() bool {
	return len(c.Files) == 0 && len(c.Deletions) == 0 && len(c.Copies) == 0
}

func (c TreeChange) paths() []string {
	out := slices.Collect(maps.Keys(c.Files))
	out = append(out, c.Deletions...)
	out = append(out, slices.Collect(maps.Keys(c.Copies))...)
	slices.Sort(out)
	return out
}

// blobMode keeps the mode a path already carries instead of reasserting the default.
// Editing a file is not a decision about its mode: rewriting a script the target
// invokes directly — ./scripts/setup-env.sh and every payload that works that way —
// at 100644 leaves the content in place and the job failing on the exec bit before it
// runs a line of it, which reads as a payload that did not work.
//
// Only the two regular blob modes carry forward. A path the tree records as a symlink
// or a submodule is not something a staged blob should inherit.
func blobMode(existing map[string]string, path string, exec bool) string {
	if exec {
		return "100755"
	}
	switch existing[path] {
	case "100644", "100755":
		return existing[path]
	}
	return "100644"
}

// existingModes reads the modes of the tree this commit lays over. A failure is a note
// rather than an error: the commit still lands, and saying so is better than a mode
// change nobody asked for going unmentioned.
func (g GitData) existingModes(ctx context.Context, treeSHA string, ch TreeChange) map[string]string {
	if treeSHA == "" || len(ch.Files) == 0 {
		return nil
	}
	modes, truncated, err := g.Tree(ctx, treeSHA)
	if err != nil {
		g.s.Note(fmt.Sprintf("the base tree was unreadable (%s), so no edited file's existing mode was preserved; a file the target invokes directly may land non-executable", apiMessage(err)))
		return nil
	}
	if truncated {
		g.s.Note("the base tree listing was truncated, so an edited file past the cut may not have kept its existing mode")
	}
	return modes
}

// Commit stages files as blobs, lays them over the ref's current tree, creates
// the commit and fast-forwards the ref. The ref is read first for three reasons:
// the undo record needs the SHA to restore, expect can refuse a ref that moved,
// and a ref that does not exist fails here rather than after three unreachable
// objects have been created.
func (g GitData) Commit(ctx context.Context, ref, message string, ch TreeChange, expect string) (Commit, error) {
	shortRef := strings.TrimPrefix(ref, "refs/")
	var head, baseTree string

	client, err := g.s.Client()
	if err := g.s.SoftRead(err, "read "+ref); err != nil {
		return Commit{}, err
	}
	if client != nil {
		head, err = getString(ctx, client, g.api("ref", shortRef), "object", "sha")
		if err := g.s.SoftRead(err, "read "+ref); err != nil {
			return Commit{}, fmt.Errorf("read %s: %w", ref, err)
		}
		if expect != "" && head != "" && head != expect {
			return Commit{}, fmt.Errorf("%s moved: expected %s, found %s", ref, expect, head)
		}
		if head != "" {
			baseTree, err = getString(ctx, client, g.api("commits", head), "tree", "sha")
			if err := g.s.SoftRead(err, "read commit "+head); err != nil {
				return Commit{}, fmt.Errorf("read commit %s: %w", head, err)
			}
		}
	}

	existing := g.existingModes(ctx, baseTree, ch)

	entries := make([]map[string]any, 0, len(ch.Files)+len(ch.Deletions)+len(ch.Copies))
	for _, path := range slices.Sorted(maps.Keys(ch.Files)) {
		blob, _, err := g.s.Mutate(ctx, Mutation{
			Method: http.MethodPost, Path: g.api("blobs"), Target: g.target(),
			Body: map[string]any{"content": base64.StdEncoding.EncodeToString(ch.Files[path].Bytes), "encoding": "base64"},
			Note: "unreachable object until the ref moves",
		})
		if err != nil {
			return Commit{}, err
		}
		sha, err := field(blob, "sha")
		if err != nil {
			return Commit{}, err
		}
		entries = append(entries, map[string]any{"path": path, "mode": blobMode(existing, path, ch.Files[path].Exec), "type": "blob", "sha": sha})
	}
	for _, path := range slices.Sorted(maps.Keys(ch.Copies)) {
		entries = append(entries, map[string]any{"path": path, "mode": "100644", "type": "blob", "sha": ch.Copies[path]})
	}
	for _, path := range slices.Sorted(slices.Values(ch.Deletions)) {
		entries = append(entries, map[string]any{"path": path, "mode": "100644", "type": "blob", "sha": nil})
	}

	treeRaw, _, err := g.s.Mutate(ctx, Mutation{
		Method: http.MethodPost, Path: g.api("trees"), Target: g.target(),
		Body: map[string]any{"base_tree": baseTree, "tree": entries},
		Note: "unreachable object until the ref moves",
	})
	if err != nil {
		return Commit{}, err
	}
	tree, err := field(treeRaw, "sha")
	if err != nil {
		return Commit{}, err
	}

	commitRaw, _, err := g.s.Mutate(ctx, Mutation{
		Method: http.MethodPost, Path: g.api("commits"), Target: g.target(),
		Body: map[string]any{"message": message, "tree": tree, "parents": []string{head}},
		Note: "unreachable object until the ref moves",
	})
	if err != nil {
		return Commit{}, err
	}
	var made struct {
		SHA          string `json:"sha"`
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
		Committer struct {
			Date string `json:"date"`
		} `json:"committer"`
	}
	if err := json.Unmarshal(commitRaw, &made); err != nil {
		return Commit{}, err
	}

	if _, _, err := g.s.Mutate(ctx, Mutation{
		Method: http.MethodPatch, Path: g.api("refs", shortRef), Target: g.target(),
		Body: map[string]any{"sha": made.SHA},
		Note: "pre-state tree " + baseTree,
		Inverse: []UndoStep{{
			Method: http.MethodPatch, Path: g.api("refs", shortRef),
			Body: map[string]any{"sha": head, "force": true},
			Note: "restores the ref to " + head + "; the commit object and the push event persist",
		}},
	}); err != nil {
		return Commit{}, err
	}

	return Commit{
		RefLoc:    RefLoc{Owner: g.Owner, Repo: g.Repo, Ref: ref, SHA: made.SHA},
		Parents:   []string{head},
		Tree:      tree,
		Files:     ch.paths(),
		Message:   message,
		Verified:  made.Verification.Verified,
		CreatedAt: made.Committer.Date,
	}, nil
}

// Tree lists the blob paths reachable from a commit, which is what suppression
// needs to know before it can delete every workflow it did not write.
// Tree maps every blob path at a commit to its mode. Truncated says GitHub cut the
// listing short, which is not the same answer as a path being absent: a caller that
// reads a miss as "this path is new" would be wrong about every path past the cut.
func (g GitData) Tree(ctx context.Context, commitSHA string) (modes map[string]string, truncated bool, err error) {
	client, err := g.s.Client()
	if err != nil {
		return nil, false, err
	}
	raw, _, err := client.Get(ctx, g.api("trees", commitSHA)+"?recursive=1", nil, false)
	if err != nil {
		return nil, false, err
	}
	var body struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			Mode string `json:"mode"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, false, err
	}
	out := make(map[string]string, len(body.Tree))
	for _, e := range body.Tree {
		if e.Type == "blob" {
			out[e.Path] = e.Mode
		}
	}
	return out, body.Truncated, nil
}

// BlobSHA reads the blob sha of one path at a ref, which is what a rename needs
// to place existing content at a new path without transferring it.
func (g GitData) BlobSHA(ctx context.Context, path, ref string) (string, error) {
	client, err := g.s.Client()
	if err != nil {
		return "", err
	}
	return getString(ctx, client, "/repos/"+g.Owner+"/"+g.Repo+"/contents/"+path+"?ref="+url.QueryEscape(ref), "sha")
}

// FileBytes reads one path's decoded content at a ref, which patch mode needs
// before it can apply a hunk.
func (g GitData) FileBytes(ctx context.Context, path, ref string) ([]byte, error) {
	client, err := g.s.Client()
	if err != nil {
		return nil, err
	}
	raw, _, err := client.Get(ctx, "/repos/"+g.Owner+"/"+g.Repo+"/contents/"+path+"?ref="+url.QueryEscape(ref), nil, false)
	if err != nil {
		return nil, err
	}
	var body struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if body.Encoding != "base64" {
		return nil, fmt.Errorf("%s: unexpected content encoding %q", path, body.Encoding)
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(body.Content, "\n", ""))
}

func getString(ctx context.Context, c *github.Client, path string, keys ...string) (string, error) {
	raw, _, err := c.Get(ctx, path, nil, false)
	if err != nil {
		return "", err
	}
	var cur any
	if err := json.Unmarshal(raw, &cur); err != nil {
		return "", err
	}
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s: no %q in response", path, k)
		}
		cur = m[k]
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("%s: %s is not a string", path, strings.Join(keys, "."))
	}
	return s, nil
}

func field(raw json.RawMessage, key string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	s, ok := m[key].(string)
	if !ok {
		return "", fmt.Errorf("response carries no %q", key)
	}
	return s, nil
}

func allSteps(p *Plan) []Step {
	return append(append([]Step{}, p.Steps...), p.Cleanup...)
}
