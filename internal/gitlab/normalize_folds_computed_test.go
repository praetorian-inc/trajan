package gitlab

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// These cover the effective-fold booleans that were previously hardcoded false
// while a non-deferred rule reads them true (LAB-4288 fold sweep). Each fold has a
// firing case AND a benign twin, so a regression to constant-true is caught too.

func writeCIConfig(t *testing.T, prior engine.PriorPhase, fp, yaml string) {
	t.Helper()
	cp := engine.CurrentPhase(prior)
	if err := cp.WriteRaw(engine.CollectGLCIConfig(fp, ".gitlab-ci.yml"), []byte(yaml)); err != nil {
		t.Fatalf("write ci-config: %v", err)
	}
}

// cat-14/01,02,04,12 editor_below_credential_trust: a write credential is attached
// AND a Maintainer (project) editor exists below the credential-setter's trust.
func TestEditorBelowCredentialTrustFold(t *testing.T) {
	maintainerRoster := []any{
		map[string]any{"access_level": accessMaintainer},
		map[string]any{"access_level": accessOwner},
	}
	ownerOnlyRoster := []any{map[string]any{"access_level": accessOwner}}

	hasMaintainer := hasMemberAtLevel(maintainerRoster, accessMaintainer)
	noMaintainer := hasMemberAtLevel(ownerOnlyRoster, accessMaintainer)
	if !hasMaintainer || noMaintainer {
		t.Fatalf("member existential wrong: maint=%v ownerOnly=%v", hasMaintainer, noMaintainer)
	}

	// webhook with a secret token + a Maintainer editor → fold true.
	tokenHook := map[string]any{"id": 1, "token_present": true, "push_events": true}
	rec := webhookRec(tokenHook, false, hasMaintainer)
	if rec["editor_below_credential_trust"] != true {
		t.Error("webhook: token + Maintainer editor must be editor_below_credential_trust")
	}

	// benign twin A: same hook, no Maintainer editor (Owner-only roster) → false.
	if webhookRec(tokenHook, false, noMaintainer)["editor_below_credential_trust"] != false {
		t.Error("webhook: no Maintainer editor must NOT be editor_below_credential_trust")
	}
	// benign twin B: Maintainer editor but NO credential attached → false.
	bareHook := map[string]any{"id": 2, "push_events": true}
	if webhookRec(bareHook, false, hasMaintainer)["editor_below_credential_trust"] != false {
		t.Error("webhook: no credential must NOT be editor_below_credential_trust")
	}

	// custom-header credential path (cat-14/02).
	hdrHook := map[string]any{"id": 3, "custom_headers": []any{map[string]any{"key": "Authorization"}}, "push_events": true}
	if webhookRec(hdrHook, false, hasMaintainer)["editor_below_credential_trust"] != true {
		t.Error("webhook: custom header + Maintainer editor must be editor_below_credential_trust")
	}

	// integration (cat-14/12): active + token_present.
	activeInt := map[string]any{"active": true, "token_present": true, "pipeline_events": true}
	if integrationRec(activeInt, false, hasMaintainer)["editor_below_credential_trust"] != true {
		t.Error("integration: active credential + Maintainer editor must be editor_below_credential_trust")
	}
	// benign twin: inactive integration → no credential trust to recapture.
	inactiveInt := map[string]any{"active": false, "token_present": true, "pipeline_events": true}
	if integrationRec(inactiveInt, false, hasMaintainer)["editor_below_credential_trust"] != false {
		t.Error("integration: inactive must NOT be editor_below_credential_trust")
	}
}

// cat-06/09 named_scanner_absent: a policy scanner has no matching job/template in
// the resolved pipeline.
func TestNamedScannerAbsentFold(t *testing.T) {
	fp := "g/p"

	// Pipeline wires sast (job) but not dependency_scanning.
	prior := engine.PriorPhase{RunDir: t.TempDir()}
	writeCIConfig(t, prior, fp, "sast:\n  script: [scan]\nbuild:\n  script: [make]\n")

	if !namedScannerAbsent(prior, fp, []any{"sast", "dependency_scanning"}) {
		t.Error("dependency_scanning absent from pipeline must be named_scanner_absent")
	}
	// benign twin: only the present scanner is named → not absent.
	if namedScannerAbsent(prior, fp, []any{"sast"}) {
		t.Error("sast IS present (job) → must NOT be named_scanner_absent")
	}
	// no named scanners → nothing can be absent.
	if namedScannerAbsent(prior, fp, []any{}) {
		t.Error("no named scanners must NOT be named_scanner_absent")
	}

	// scanner wired via a managed security template include → present.
	prior2 := engine.PriorPhase{RunDir: t.TempDir()}
	writeCIConfig(t, prior2, fp, "include:\n  - template: Security/Dependency-Scanning.gitlab-ci.yml\nbuild:\n  script: [make]\n")
	if namedScannerAbsent(prior2, fp, []any{"dependency_scanning"}) {
		t.Error("dependency_scanning via template include must NOT be named_scanner_absent")
	}
}

// cat-06/13 required_jobs_evadable: every job is author-conditionally gated, so an
// MR can produce a skipped/empty pipeline.
func TestRequiredJobsEvadableFold(t *testing.T) {
	fp := "g/p"

	// All jobs gated behind rules:/only: → evadable.
	prior := engine.PriorPhase{RunDir: t.TempDir()}
	writeCIConfig(t, prior, fp, "test:\n  script: [t]\n  rules:\n    - if: '$RUN == \"1\"'\nlint:\n  script: [l]\n  only: [merge_requests]\n")
	if !requiredJobsEvadable(prior, fp) {
		t.Error("all-conditional pipeline must be required_jobs_evadable")
	}

	// benign twin: one unconditional job always runs → not evadable.
	prior2 := engine.PriorPhase{RunDir: t.TempDir()}
	writeCIConfig(t, prior2, fp, "test:\n  script: [t]\n  rules:\n    - if: '$RUN == \"1\"'\nbuild:\n  script: [make]\n")
	if requiredJobsEvadable(prior2, fp) {
		t.Error("an unconditional job means NOT required_jobs_evadable")
	}

	// no pipeline at all → nothing required to evade.
	prior3 := engine.PriorPhase{RunDir: t.TempDir()}
	if requiredJobsEvadable(prior3, fp) {
		t.Error("absent pipeline must NOT be required_jobs_evadable")
	}
}
