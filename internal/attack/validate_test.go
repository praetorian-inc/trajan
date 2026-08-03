package attack

import (
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, y string) *Plan {
	t.Helper()
	p, err := parsePlan([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.ID == "" {
		p.ID = "test"
	}
	return p
}

// hardErrs returns the non-warning validation errors as strings.
func hardErrs(p *Plan) []string {
	var out []string
	for _, e := range Validate(p) {
		if !IsWarning(e) {
			out = append(out, e.Error())
		}
	}
	return out
}

func hasSubstr(errs []string, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

// A well-formed one-repo pwn chain with an out-of-scope and a broken variant
// share this preamble.
const okHeader = `apiVersion: trajan.attack/v1
scope: [acme/widget]
`

func TestValidateAcceptsAWellFormedChain(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: pr, uses: pr.open, head: branch, base: target, title: t }
`)
	if errs := hardErrs(p); len(errs) != 0 {
		t.Fatalf("expected zero errors, got %v", errs)
	}
}

func TestValidateUnknownPrimitiveListsNearMisses(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.reslove, owner: acme, repo: widget }
`)
	errs := hardErrs(p)
	if !hasSubstr(errs, `unknown primitive "repo.reslove"`) {
		t.Fatalf("want unknown primitive, got %v", errs)
	}
	if !hasSubstr(errs, "repo.resolve") {
		t.Fatalf("want near-miss repo.resolve, got %v", errs)
	}
}

func TestValidateUnknownInputKey(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget, nonsense: 1 }
`)
	if !hasSubstr(hardErrs(p), `has no input "nonsense"`) {
		t.Fatalf("want unknown input key, got %v", hardErrs(p))
	}
}

func TestValidatePortBoundToInput(t *testing.T) {
	p := mustParse(t, okHeader+`
inputs:
  base_ref: { default: main }
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: base_ref, name: x }
`)
	if !hasSubstr(hardErrs(p), `port "on" must name a prior step; "base_ref" is an input`) {
		t.Fatalf("want port-bound-to-input, got %v", hardErrs(p))
	}
}

func TestValidateForwardAndDanglingReference(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: a, uses: ref.create, on: b, name: x }
  - { id: b, uses: repo.writable, repo: nowhere }
`)
	errs := hardErrs(p)
	if !hasSubstr(errs, `"on" references "b" which is not a prior step`) {
		t.Fatalf("want forward reference, got %v", errs)
	}
}

func TestValidateSelfReference(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: a, uses: ref.create, on: a, name: x }
`)
	if !hasSubstr(hardErrs(p), `"on" references "a" which is not a prior step`) {
		t.Fatalf("want self reference rejected, got %v", hardErrs(p))
	}
}

// Adjacency: step N produces a handle step N+1's port cannot accept.
func TestValidateAdjacencyWrongHandleType(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: branch, uses: ref.create, on: target, name: x }
`)
	errs := hardErrs(p)
	if !hasSubstr(errs, `port "on" needs writable_ref, but step "target" produces repo`) {
		t.Fatalf("want adjacency/port-type error, got %v", errs)
	}
}

func TestValidateDuplicateStepID(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: target, uses: repo.writable, repo: target }
`)
	if !hasSubstr(hardErrs(p), "duplicate id") {
		t.Fatalf("want duplicate id, got %v", hardErrs(p))
	}
}

func TestValidateBadAPIVersionAndEmptyScope(t *testing.T) {
	p := mustParse(t, `apiVersion: v2
scope: []
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
`)
	errs := hardErrs(p)
	if !hasSubstr(errs, "apiVersion must be") {
		t.Errorf("want apiVersion error, got %v", errs)
	}
	if !hasSubstr(errs, "scope must list at least one") {
		t.Errorf("want empty-scope error, got %v", errs)
	}
}

// Validate returns EVERY error at once, not the first.
func TestValidateReturnsEveryError(t *testing.T) {
	p := mustParse(t, `apiVersion: v2
scope: []
steps:
  - { id: a, uses: not.a.primitive }
  - { id: b, uses: repo.resolve, owner: acme, repo: widget, bogus: 1 }
`)
	errs := hardErrs(p)
	for _, want := range []string{"apiVersion must be", "scope must list", "unknown primitive", `has no input "bogus"`} {
		if !hasSubstr(errs, want) {
			t.Errorf("missing %q in %v", want, errs)
		}
	}
}

// The interface-satisfaction mechanism the validator reads back via reflect: a
// throwaway type that does and does not implement WritableRef.
type doesWrite struct{ sealed }

func (doesWrite) Kind() HandleKind { return "does_write" }
func (doesWrite) RepoRef() RepoLoc { return RepoLoc{} }
func (doesWrite) WriteRef() RefLoc { return RefLoc{} }

type onlyScoped struct{ sealed }

func (onlyScoped) Kind() HandleKind { return "only_scoped" }
func (onlyScoped) RepoRef() RepoLoc { return RepoLoc{} }

func TestInterfaceSatisfactionUnderReflect(t *testing.T) {
	wr := reflect.TypeFor[WritableRef]()
	if !reflect.TypeFor[doesWrite]().Implements(wr) {
		t.Error("doesWrite must implement WritableRef")
	}
	if reflect.TypeFor[onlyScoped]().Implements(wr) {
		t.Error("onlyScoped must NOT implement WritableRef")
	}
	if !reflect.TypeFor[onlyScoped]().Implements(reflect.TypeFor[RepoScoped]()) {
		t.Error("onlyScoped must implement RepoScoped")
	}
}

// A bare word inside a predicate is a read, not a literal: a typo'd path
// evaluates false, skips the step and everything under it, and the operator reads
// the gate's negative case as a measurement. It has to be an offline error.
func TestValidateWhenFieldPathIsCheckedAgainstTheProducer(t *testing.T) {
	plan := func(predicate string) *Plan {
		return mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: pr, uses: pr.open, head: branch, base: target, title: t }
  - { id: survived, uses: pr.review.state, on: pr }
  - { id: merge, uses: pr.merge, when: "`+predicate+`", pr: pr, method: squash }
`)
	}
	if errs := hardErrs(plan("survived.review_decision == 'APPROVED'")); len(errs) != 0 {
		t.Fatalf("the field a review_state carries must validate, got %v", errs)
	}
	errs := hardErrs(plan("survived.review_decisionn == 'APPROVED'"))
	if !hasSubstr(errs, `handle review_state has no field "review_decisionn"`) {
		t.Fatalf("want the typo'd gate path rejected, got %v", errs)
	}
	if !hasSubstr(errs, `step "merge"`) {
		t.Fatalf("the error must name the step whose gate is broken, got %v", errs)
	}
}

// The seal is applied to the job envelope, so a plan that attaches only
// shell-flavor fragments cannot be sealed however it is spelled. Declaring
// encryption there is a claim about the customer's run log that the run breaks.
func TestValidateEncryptionNeedsAJobToSeal(t *testing.T) {
	shell := `
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: issue, uses: issue.open, repo: target, title: t, body: b }
  - id: comment
    uses: comment.create
    on: issue
    template: t-08/expression-injection
    params: { marker: m }
`
	composed := `
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - id: job
    uses: workflow.commit
    on: branch
    path: .github/workflows/trajan.yml
    template: t-00/canary-noop
    params: { marker: m }
`
	cases := []struct {
		name, header, steps, want string
	}{
		{"shell fragments cannot be sealed", "encryption: rsa-oaep-hybrid\n", shell, "cannot be sealed"},
		{"a composed job can", "encryption: rsa-oaep-hybrid\n", composed, ""},
		{"no declaration, no check", "", shell, ""},
		{"none is off", "encryption: none\n", shell, ""},
		{"an unknown algorithm is not silently on", "encryption: aes\n", composed, `encryption "aes" must be`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := hardErrs(mustParse(t, okHeader+c.header+c.steps))
			switch {
			case c.want == "" && len(errs) != 0:
				t.Errorf("expected no error, got %v", errs)
			case c.want != "" && !hasSubstr(errs, c.want):
				t.Errorf("expected an error containing %q, got %v", c.want, errs)
			}
		})
	}
}

// A cache entry is restorable from the ref it was written on, and from every ref
// only when that ref is the default branch. Any other pairing is a chain that
// mutates the target and harvests nothing.
func TestValidateCacheScopeAgainstTheAwaitedRun(t *testing.T) {
	plan := func(poisonOn, observeRef string) *Plan {
		return mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: chore/warm-cache }
  - { id: poison, uses: cache.poison, on: `+poisonOn+`, key: node-deps-trajan, restore_key_prefix: node-deps, bytes: 64 }
  - { id: victim, uses: run.observe, on: target, workflow: .github/workflows/build.yml, ref: `+observeRef+` }
`)
	}
	warnings := func(p *Plan) []string {
		var out []string
		for _, e := range Validate(p) {
			if IsWarning(e) {
				out = append(out, e.Error())
			}
		}
		return out
	}
	if got := warnings(plan("branch", "main")); !hasSubstr(got, "restorable only from that branch") {
		t.Errorf("a branch-scoped entry with a run on main must warn, got %v", got)
	}
	if got := warnings(plan("branch", "chore/warm-cache")); len(got) != 0 {
		t.Errorf("a run on the poisoned branch restores it, got %v", got)
	}
	if got := warnings(plan("writable", "main")); len(got) != 0 {
		t.Errorf("a default-branch entry is restorable everywhere, got %v", got)
	}
	if got := hardErrs(plan("branch", "main")); len(got) != 0 {
		t.Errorf("the scope mismatch is a warning, not a refusal, got %v", got)
	}
}

// WritableRepo.WriteRef() names refs/heads/<default branch>, so a ref.delete that
// accepts any writable ref accepts the customer's default branch.
func TestRefDeleteTakesOnlyABranchThisChainCreated(t *testing.T) {
	plan := func(ref string) *Plan {
		return mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: nuke, uses: ref.delete, ref: `+ref+` }
`)
	}
	if errs := hardErrs(plan("writable")); !hasSubstr(errs, `port "ref" needs branch`) {
		t.Fatalf("ref.delete must refuse a repository handle whose ref is the default branch, got %v", errs)
	}
	if errs := hardErrs(plan("branch")); len(errs) != 0 {
		t.Fatalf("deleting a branch this chain created must still validate, got %v", errs)
	}
}

// A payload param is resolved the same way a field is before its content is
// checked, so a reference must not be reported as a malformed value and a literal
// must not escape checking by looking like one.
func TestValidatePayloadParamsResolveBeforeScreening(t *testing.T) {
	plan := func(params string) *Plan {
		return mustParse(t, okHeader+`
inputs:
  size: { type: int, default: 512 }
  keys: { type: list, default: [node-deps-, v1/npm/] }
  marker_in: { default: run-marker }
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - id: job
    uses: workflow.commit
    on: branch
    path: .github/workflows/trajan.yml
    template: t-04/cache-handoff
    params: `+params+`
`)
	}
	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"input refs resolve to their values", `{ marker: marker_in, role: reader, restore_keys: keys, payload_bytes: size }`, ""},
		{"handle field is unknown offline", `{ marker: branch.ref, role: reader, restore_keys: keys }`, ""},
		{"literals are checked", `{ marker: m, role: reader, restore_keys: keys, payload_bytes: abc }`, `want int, got "abc"`},
		{"a line break in a literal", "{ marker: \"m\\n- name: pwned\", role: reader, restore_keys: keys }", `no quoting contains`},
		{"an element a raw position cannot hold", `{ marker: m, role: reader, restore_keys: ["$(id)"] }`, `interpolated raw`},
		{"a reference to nothing", `{ marker: "${{ secrets.AWS_KEY }}", role: reader, restore_keys: keys }`, `names neither a prior step nor an input`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := hardErrs(plan(c.params))
			switch {
			case c.want == "" && len(errs) > 0:
				t.Errorf("expected no error, got %v", errs)
			case c.want != "" && !hasSubstr(errs, c.want):
				t.Errorf("expected an error containing %q, got %v", c.want, errs)
			}
		})
	}
}
