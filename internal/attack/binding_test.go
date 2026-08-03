package attack

import (
	"reflect"
	"testing"
)

func TestBindingHandleBoundToFieldIsError(t *testing.T) {
	// `message` is a field; binding the whole `target` handle to it is a mistake.
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: c, uses: commit.code, on: branch, message: target }
`)
	if !hasSubstr(hardErrs(p), `field "message" got the handle "target"`) {
		t.Fatalf("want handle-bound-to-field, got %v", hardErrs(p))
	}
}

func TestBindingQuotingForcesLiteral(t *testing.T) {
	// The same spelling quoted is the literal string, not a reference.
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: c, uses: commit.code, on: branch, message: "target" }
`)
	if errs := hardErrs(p); len(errs) != 0 {
		t.Fatalf("quoted literal must not be read as a handle reference, got %v", errs)
	}
}

// Quote-to-force-literal has to reach inside a files: map and a params: object:
// a literal colliding with an input name is otherwise silently reinterpreted as
// that input's value, which is the one thing the quote rule exists to prevent.
func TestBindingQuotingForcesLiteralInsideANestedValue(t *testing.T) {
	p := testPlan(t, `apiVersion: trajan.attack/v1
scope: [acme/lab]
inputs:
  main: { default: refs/heads/release }
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: lab }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - id: c
    uses: commit.code
    on: branch
    message: m
    params: { marker: "main", fallback: main, tags: ["main", main] }
`)
	x := newTestExecutor(t, p, t.TempDir())
	x.seedHandle("branch", Branch{RefLoc: RefLoc{Owner: "acme", Repo: "lab", Ref: "refs/heads/x"}}, statusOK)
	e, _ := lookup("commit.code")

	_, fields, err := x.bind(testStep(t, p, "c"), e, true)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	params, _ := fields["params"].(map[string]any)
	if params["marker"] != "main" {
		t.Errorf("a quoted nested scalar is the literal, got %#v", params["marker"])
	}
	if params["fallback"] != "refs/heads/release" {
		t.Errorf("an unquoted nested scalar still reads the input, got %#v", params["fallback"])
	}
	tags, _ := params["tags"].([]any)
	if len(tags) != 2 || tags[0] != "main" || tags[1] != "refs/heads/release" {
		t.Errorf("quoting must reach a sequence element too, got %#v", params["tags"])
	}
}

func TestBindingTypoedHandleFieldName(t *testing.T) {
	// target is a Repo; Repo has no field "sha".
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: c, uses: commit.code, on: branch, message: target.sha }
`)
	if !hasSubstr(hardErrs(p), `handle repo has no field "sha"`) {
		t.Fatalf("want typo'd field error, got %v", hardErrs(p))
	}
}

func TestBindingHandleFieldRefResolves(t *testing.T) {
	// Repo does carry default_branch, so this reference is legal.
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x, from: target.default_branch }
`)
	if errs := hardErrs(p); len(errs) != 0 {
		t.Fatalf("a valid <id>.<field> reference must pass, got %v", errs)
	}
}

func TestBindingLiteralTypeMismatch(t *testing.T) {
	// suppress is a bool field; a non-bool literal must fail its declared type.
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: c, uses: commit.code, on: branch, suppress: perhaps }
`)
	if !hasSubstr(hardErrs(p), `field "suppress" wants bool`) {
		t.Fatalf("want bool type mismatch, got %v", hardErrs(p))
	}
}

func TestBindingBoolLiteralAccepted(t *testing.T) {
	p := mustParse(t, okHeader+`
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
  - { id: c, uses: commit.code, on: branch, suppress: true }
`)
	if errs := hardErrs(p); len(errs) != 0 {
		t.Fatalf("a real bool must be accepted, got %v", errs)
	}
}

// A non-string field fed a bare input reference is checked against the input's
// declared type at the input boundary, where the plan text is still readable —
// there is nothing left to check it against once the value has been coerced.
func TestInputRefTypeMustMatchField(t *testing.T) {
	p := &Plan{Inputs: map[string]InputSpec{"n": {Type: "string"}}}
	if errs := typeCheckInputRef("step", "count", reflect.Bool, "n", p); len(errs) == 0 {
		t.Error("a bool field fed a string input must fail")
	}
	if errs := typeCheckInputRef("step", "title", reflect.String, "n", p); len(errs) != 0 {
		t.Errorf("a string field accepts any input, got %v", errs)
	}
}
