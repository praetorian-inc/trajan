package attack

import (
	"slices"
	"strings"
	"testing"
)

func hardEnvelopeErrs(t *testing.T, p workflowCommitParams) []string {
	t.Helper()
	var out []string
	for _, e := range p.envelopeErrors() {
		if !IsWarning(e) {
			out = append(out, e.Error())
		}
	}
	return out
}

// The permissions vocabulary is not uniform across scopes: id-token has no read
// level and vulnerability-alerts has no write level, so a value the general set
// admits still produces a document GitHub refuses at startup — a failed run in the
// customer's audit trail that yields no evidence.
func TestPermissionValueVocabularyIsPerScope(t *testing.T) {
	cases := []struct {
		scope, value string
		refused      bool
	}{
		{"id-token", "write", false},
		{"id-token", "none", false},
		{"id-token", "read", true},
		{"vulnerability-alerts", "read", false},
		{"vulnerability-alerts", "none", false},
		{"vulnerability-alerts", "write", true},
		{"contents", "read", false},
		{"contents", "write", false},
		{"contents", "none", false},
		{"contents", "admin", true},
	}
	for _, c := range cases {
		t.Run(c.scope+":"+c.value, func(t *testing.T) {
			// t-00 declares no scopes of its own, so only the value check can fire.
			p := workflowCommitParams{
				Template:    "t-00/canary-noop",
				Params:      map[string]any{"marker": "m"},
				Permissions: map[string]string{c.scope: c.value},
			}
			errs := hardEnvelopeErrs(t, p)
			refused := false
			for _, e := range errs {
				if strings.Contains(e, "permissions["+c.scope+"]:") {
					refused = true
				}
			}
			if refused != c.refused {
				t.Errorf("%s: %s refused=%v, want %v (%v)", c.scope, c.value, refused, c.refused, errs)
			}
		})
	}
}

// Specifying any permission sets every unspecified one to none, so a block written
// for one purpose silently strips what a bound fragment needs. The failure lands on
// the customer's system from a plan that validated clean, which is what makes this a
// validation-time concern rather than a runtime one.
func TestPermissionBlockCannotStripABoundFragmentsScope(t *testing.T) {
	consumer := map[string]any{
		"marker": "m", "role": "consumer",
		"artifact_name": "a", "consumer_mode": "workflow_run",
	}

	cases := []struct {
		name        string
		params      map[string]any
		permissions map[string]string
		wantScope   string
	}{
		{
			"a block omitting the scope strips it",
			consumer,
			map[string]string{"contents": "read"},
			"actions",
		},
		{
			"none is not a grant",
			consumer,
			map[string]string{"contents": "read", "actions": "none"},
			"actions",
		},
		{
			"the scope granted at read is satisfied",
			consumer,
			map[string]string{"contents": "read", "actions": "read"},
			"",
		},
		{
			"write satisfies a read requirement",
			consumer,
			map[string]string{"actions": "write"},
			"",
		},
		{
			"no block at all leaves the inherited default in force",
			consumer,
			nil,
			"",
		},
		{
			"the producer is not charged the consumer's scope",
			map[string]any{"marker": "m", "role": "producer", "artifact_name": "a"},
			map[string]string{"contents": "read"},
			"",
		},
		{
			"a same-run consumer reads through the runner",
			map[string]any{"marker": "m", "role": "consumer", "artifact_name": "a"},
			map[string]string{"contents": "read"},
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := workflowCommitParams{
				Template:    "t-05/artifact-handoff",
				Params:      c.params,
				Permissions: c.permissions,
			}
			errs := hardEnvelopeErrs(t, p)
			var got []string
			for _, e := range errs {
				if strings.Contains(e, "t-05/artifact-handoff") {
					got = append(got, e)
				}
			}
			if c.wantScope == "" {
				if len(got) > 0 {
					t.Errorf("refused a satisfied envelope: %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("a stripped %s was not reported: %v", c.wantScope, errs)
			}
			// The message has to name both, or the operator cannot act on it.
			if !strings.Contains(got[0], c.wantScope) {
				t.Errorf("message does not name the scope %q: %s", c.wantScope, got[0])
			}
		})
	}
}

// id-token is never inherited from a repository or organisation default, so a
// fragment needing it is unsatisfiable unless the plan spells it out. Without this
// the run starts, mints nothing, and reports the negative observation as though it
// were a fact about the target.
func TestNeverInheritedScopeMustBeExplicit(t *testing.T) {
	oidc := func(perms map[string]string) []string {
		return hardEnvelopeErrs(t, workflowCommitParams{
			Template:    "t-03/oidc-subject-claim",
			Params:      map[string]any{"marker": "m"},
			Permissions: perms,
		})
	}

	errs := oidc(nil)
	if len(errs) == 0 {
		t.Error("a job composing t-03 with no permissions: block can never mint a token")
	}
	for _, e := range errs {
		if !strings.Contains(e, "id-token") || !strings.Contains(e, "t-03/oidc-subject-claim") {
			t.Errorf("message names neither the scope nor the fragment: %s", e)
		}
	}

	if errs := oidc(map[string]string{"id-token": "write"}); len(errs) > 0 {
		t.Errorf("an explicit id-token: write is the satisfied case: %v", errs)
	}
	if errs := oidc(map[string]string{"contents": "read"}); len(errs) == 0 {
		t.Error("a block granting something else still strips id-token")
	}
}

// A permissions: key GitHub does not recognise is a document it refuses to parse,
// the same failure an out-of-vocabulary value produces. The near miss is the case
// worth catching — pull-request is not pull-requests, and a job naming it sets
// nothing while looking as though it set something — and repository-projects is the
// stale case, gone with classic projects.
func TestUnknownPermissionScopeIsRefused(t *testing.T) {
	for _, scope := range []string{"pull-request", "content", "repository-projects", "Contents"} {
		t.Run(scope, func(t *testing.T) {
			errs := hardEnvelopeErrs(t, workflowCommitParams{
				Template:    "t-00/canary-noop",
				Params:      map[string]any{"marker": "m"},
				Permissions: map[string]string{scope: "read"},
			})
			if !slices.ContainsFunc(errs, func(e string) bool { return strings.Contains(e, "permissions["+scope+"]") }) {
				t.Errorf("%q is not a token permission scope and must be refused offline, got %v", scope, errs)
			}
		})
	}
}

// A fragment bound through files: composes into the same job as the template, so its
// scopes are stripped by the same block.
func TestBoundFragmentsIncludeFilesEntries(t *testing.T) {
	p := workflowCommitParams{
		Path: ".github/workflows/w.yml",
		Files: map[string]any{
			".github/workflows/w.yml": map[string]any{
				"template": "t-03/oidc-subject-claim",
				"params":   map[string]any{"marker": "m"},
			},
		},
		Permissions: map[string]string{"contents": "read"},
	}
	errs := hardEnvelopeErrs(t, p)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "id-token") && strings.Contains(e, "t-03/oidc-subject-claim") {
			found = true
		}
	}
	if !found {
		t.Errorf("a fragment attached through files: must be screened too: %v", errs)
	}
}

// Editing a file is not a decision about its mode. A payload's whole effect can rest
// on the target invoking a script directly — ./.platform/scripts/setup-env.sh in the
// reusable-workflow case — and rewriting that script at 100644 leaves the content in
// place with the job failing on the exec bit before it runs a line of it, which is
// indistinguishable from a payload that did not work.
func TestBlobModeKeepsTheModeAPathAlreadyHas(t *testing.T) {
	tree := map[string]string{
		"scripts/setup-env.sh": "100755",
		"README.md":            "100644",
		"vendor/link":          "120000",
		"vendor/submodule":     "160000",
	}
	cases := []struct {
		name string
		path string
		exec bool
		want string
	}{
		{"an executable file stays executable", "scripts/setup-env.sh", false, "100755"},
		{"a regular file stays regular", "README.md", false, "100644"},
		{"a new path defaults to regular", "scripts/new.sh", false, "100644"},
		{"a staged shell payload is executable wherever it lands", "scripts/new.sh", true, "100755"},
		// A staged blob must not inherit a mode that does not describe a blob, or the
		// tree write substitutes file content for a symlink target or a gitlink.
		{"a symlink path is not inherited", "vendor/link", false, "100644"},
		{"a submodule path is not inherited", "vendor/submodule", false, "100644"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := blobMode(tree, tc.path, tc.exec); got != tc.want {
				t.Errorf("blobMode(%q, exec=%v) = %s, want %s", tc.path, tc.exec, got, tc.want)
			}
		})
	}

	// A tree that could not be read must not be read as "every path is new": the
	// caller falls back to the default rather than to a wrong preserved mode.
	if got := blobMode(nil, "scripts/setup-env.sh", false); got != "100644" {
		t.Errorf("with no tree read, blobMode = %s, want the 100644 default", got)
	}
}
