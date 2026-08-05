package attack

import "testing"

func TestScopeOutOfScopeTargetRejected(t *testing.T) {
	// The literal repo the writable resolves to is not in scope.
	p := mustParse(t, `apiVersion: trajan.attack/v1
scope: [acme/widget]
steps:
  - { id: target, uses: repo.resolve, owner: evil, repo: corp }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
`)
	if !hasSubstr(hardErrs(p), "mutates evil/corp which is not in scope") {
		t.Fatalf("want out-of-scope rejection, got %v", hardErrs(p))
	}
}

func TestScopeWildcardOwnerAllowed(t *testing.T) {
	p := mustParse(t, `apiVersion: trajan.attack/v1
scope: [acme/*]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: writable, uses: repo.writable, repo: target }
  - { id: branch, uses: ref.create, on: writable, name: x }
`)
	if errs := hardErrs(p); len(errs) != 0 {
		t.Fatalf("owner/* must allow the target, got %v", errs)
	}
}

func TestScopeSameRepoStraddleRejected(t *testing.T) {
	p := mustParse(t, `apiVersion: trajan.attack/v1
scope: [acme/widget, other/thing]
steps:
  - { id: t1, uses: repo.resolve, owner: acme, repo: widget }
  - { id: w1, uses: repo.writable, repo: t1 }
  - { id: b1, uses: ref.create, on: w1, name: x }
  - { id: c1, uses: commit.code, on: b1, message: hi }
  - { id: t2, uses: repo.resolve, owner: other, repo: thing }
  - { id: w2, uses: repo.writable, repo: t2 }
  - { id: b2, uses: ref.create, on: w2, name: y }
  - { id: pr2, uses: pr.open, head: b2, base: t2, title: t }
  - { id: bad, uses: pr.review.submit, pr: pr2, commit: c1 }
`)
	if !hasSubstr(hardErrs(p), "is not cross-repo") {
		t.Fatalf("want same-repo straddle rejection, got %v", hardErrs(p))
	}
}

// pr.open with a fork head and an upstream base is the one legitimate
// cross-repository binding.
func TestScopeCrossForkPROpenPasses(t *testing.T) {
	p := mustParse(t, `apiVersion: trajan.attack/v1
scope: [acme/widget]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: fork, uses: repo.fork, repo: target }
  - { id: branch, uses: ref.create, on: fork, name: x }
  - { id: pr, uses: pr.open, head: branch, base: target, title: t }
`)
	if errs := hardErrs(p); len(errs) != 0 {
		t.Fatalf("cross-fork pr.open must pass, got %v", errs)
	}
}

func TestScopeCredentialLiteralAnywhereIncludingParams(t *testing.T) {
	p := mustParse(t, `apiVersion: trajan.attack/v1
scope: [acme/widget]
steps:
  - { id: target, uses: repo.resolve, owner: acme, repo: widget }
  - { id: fork, uses: repo.fork, repo: target }
  - { id: branch, uses: ref.create, on: fork, name: x }
  - id: c
    uses: commit.code
    on: branch
    message: hi
    params: { token: ghp_0123456789abcdefghijklmnopqrstuvwx }
`)
	if !hasSubstr(hardErrs(p), "looks like a credential") {
		t.Fatalf("want credential-literal rejection inside params, got %v", hardErrs(p))
	}
}

func TestScopePEMPrivateKeyRejected(t *testing.T) {
	p := mustParse(t, `apiVersion: trajan.attack/v1
scope: [acme/widget]
steps:
  - id: target
    uses: repo.resolve
    owner: acme
    repo: widget
  - id: fork
    uses: repo.fork
    repo: target
  - id: branch
    uses: ref.create
    on: fork
    name: x
  - id: c
    uses: commit.code
    on: branch
    message: "-----BEGIN RSA PRIVATE KEY-----"
`)
	if !hasSubstr(hardErrs(p), "looks like a credential") {
		t.Fatalf("want PEM private key rejection, got %v", hardErrs(p))
	}
}
