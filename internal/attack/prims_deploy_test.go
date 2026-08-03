package attack

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// newProcess is a fresh Session over a run directory an earlier process wrote,
// which is what a resume is: the ledger is on disk and nothing else survived.
func newProcess(t *testing.T, runDir, step, uses string) *Session {
	t.Helper()
	l, err := OpenLedger(filepath.Join(runDir, engine.AttackLedger(bucketPlan)))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	s := &Session{
		Plan:       &Plan{ID: bucketPlan, Scope: []string{"acme/lab"}},
		Ledger:     l,
		Execute:    true,
		identities: map[string]*identityClient{},
		aliases:    map[string]string{},
		extraScope: map[string]string{},
	}
	s.begin(actingContext{step: step, uses: uses, id: &identityClient{name: "operator"}})
	return s
}

func waitingOn(names ...string) PendingDeployment {
	envs := make([]PendingEnvironment, 0, len(names))
	for i, n := range names {
		envs = append(envs, PendingEnvironment{Name: n, ID: int64(100 + i), CurrentUserCanApprove: true})
	}
	return PendingDeployment{
		RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, RunID: 42, Status: "waiting",
		Environments: envs, CanApprove: true, Provoked: true,
	}
}

func provokedRun() WorkflowRun {
	return WorkflowRun{RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, ID: 42, Provoked: true}
}

func cleanupOf(t *testing.T, runDir string) *CleanupReport {
	t.Helper()
	if err := engine.WriteJSON(filepath.Join(runDir, engine.AttackPlan(bucketPlan)), PlanRecord{
		ID: bucketPlan, Scope: []string{"acme/lab"}, Mode: "execute",
	}); err != nil {
		t.Fatalf("plan record: %v", err)
	}
	return replay(t, runDir)
}

func rejections(report *CleanupReport) []CleanupItem {
	var out []CleanupItem
	for _, bucket := range [][]CleanupItem{report.Reversed, report.Partial, report.Failed} {
		for _, it := range bucket {
			if strings.HasSuffix(it.Path, "/pending_deployments") {
				out = append(out, it)
			}
		}
	}
	return out
}

// The sequence that put a released deployment in the failed bucket: one process
// declares the rejection and stops on --until, a second resumes — replaying the
// step that declared it, so its body never runs — and approves. Nothing in the
// second process's memory knows the declaration exists, so the retirement has to
// come off the ledger, or cleanup replays a rejection against an environment
// that is no longer waiting and reports the customer's deployment as stuck.
func TestAResumedChainRetiresTheRejectionItReleased(t *testing.T) {
	runDir := t.TempDir()
	pd := waitingOn("prod")

	if err := declareAbandonment(newProcess(t, runDir, "pending", "deployment.pending.list"), provokedRun(), pd); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if err := retireAbandonment(newProcess(t, runDir, "review", "deployment.review"), pd, []string{"prod"}, pd.Environments); err != nil {
		t.Fatalf("retire: %v", err)
	}

	report := cleanupOf(t, runDir)

	if got := rejections(report); len(got) != 0 {
		t.Fatalf("cleanup must not reject a deployment this chain released, got %+v", got)
	}
	item := onlyItem(t, "irreversible", report.Irreversible)
	if !strings.Contains(item.Detail, "nothing left to replay") {
		t.Errorf("the released deployment must be explained, detail = %q", item.Detail)
	}
}

// A review that releases one of two waiting environments leaves the other one
// waiting, and the rejection that clears it must survive.
func TestAPartialReleaseKeepsTheRejection(t *testing.T) {
	runDir := t.TempDir()
	pd := waitingOn("staging", "prod")

	if err := declareAbandonment(newProcess(t, runDir, "pending", "deployment.pending.list"), provokedRun(), pd); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if err := retireAbandonment(newProcess(t, runDir, "review", "deployment.review"), pd, []string{"staging"}, pd.Environments); err != nil {
		t.Fatalf("retire: %v", err)
	}

	if got := rejections(cleanupOf(t, runDir)); len(got) != 1 {
		t.Fatalf("prod is still waiting, so its rejection must still be replayed; got %+v", got)
	}
}

// A run this chain did not provoke is the customer's own: rejecting the
// deployment it waits on would sabotage their release.
func TestAnUnprovokedRunDeclaresNoRejection(t *testing.T) {
	runDir := t.TempDir()
	run := provokedRun()
	run.Provoked = false
	pd := waitingOn("prod")
	pd.Provoked = false

	if err := declareAbandonment(newProcess(t, runDir, "pending", "deployment.pending.list"), run, pd); err != nil {
		t.Fatalf("declare: %v", err)
	}

	report := cleanupOf(t, runDir)
	if n := len(report.Reversed) + len(report.Partial) + len(report.Irreversible) + len(report.Failed); n != 0 {
		t.Fatalf("nothing was declared for a run this chain did not cause, got %d item(s): %+v", n, report)
	}
}

// Declaring twice for the same run would leave a second rejection to replay after
// the first was retired. The ledger is the only thing that remembers across a
// resume, so it has to be what the guard reads.
func TestAbandonmentIsDeclaredOncePerRun(t *testing.T) {
	runDir := t.TempDir()
	pd := waitingOn("prod")

	for range 2 {
		if err := declareAbandonment(newProcess(t, runDir, "pending", "deployment.pending.list"), provokedRun(), pd); err != nil {
			t.Fatalf("declare: %v", err)
		}
	}

	if got := rejections(cleanupOf(t, runDir)); len(got) != 1 {
		t.Fatalf("one waiting run is one rejection, got %d: %+v", len(got), got)
	}
}

// self_approval is the comparison the primitive exists to make. An App
// installation token reports no login at all, which is exactly the principal
// whose self-approval is interesting: unreadable must not read as "no".
func TestSelfApprovalDistinguishesUnreadableFromNo(t *testing.T) {
	for _, tc := range []struct {
		name              string
		acting, actor     string
		canApprove        bool
		self, established bool
	}{
		{"same account", "ci-bot", "ci-bot", true, true, true},
		{"same account, different case", "CI-Bot", "ci-bot", true, true, true},
		{"different accounts", "reviewer", "ci-bot", true, false, true},
		{"same account but not a reviewer", "ci-bot", "ci-bot", false, false, true},
		{"installation token has no login", "", "ci-bot", true, false, false},
		{"run record would not load", "ci-bot", "", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pd := PendingDeployment{RunID: 42, ActingLogin: tc.acting, TriggeringActor: tc.actor, CanApprove: tc.canApprove}
			got := selfApproval(pd)
			if got.Value != tc.self || got.Known != tc.established {
				t.Fatalf("selfApproval = %+v, want value %t established %t", got, tc.self, tc.established)
			}
			// The reason is what the note, the ledger record and a refused gate all
			// print; without it the unestablished case is indistinguishable from a no.
			if !got.Known && got.Reason == "" {
				t.Error("an unestablished comparison must say why it could not be made")
			}
		})
	}
}

// What reaches the ledger is what reaches the report. An unestablished comparison
// recorded as false says the account that caused the deployment did not release
// it, which nobody measured.
func TestTheReviewEffectDoesNotRecordAnUnmeasuredSelfApproval(t *testing.T) {
	runDir := t.TempDir()
	s := newProcess(t, runDir, "review", "deployment.review")
	pd := waitingOn("prod")
	pd.ActingLogin, pd.TriggeringActor = "", "ci-bot"
	pd.SelfApproval = selfApproval(pd)

	if err := recordReviewEffect(s, pd, []string{"prod"}, "approved"); err != nil {
		t.Fatalf("record effect: %v", err)
	}

	entries, err := ReadLedger(filepath.Join(runDir, engine.AttackLedger(bucketPlan)))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var detail map[string]any
	for _, e := range entries {
		if e.Kind == RecordEffect && e.Effect != nil {
			detail = e.Effect.Detail
		}
	}
	if detail == nil {
		t.Fatal("no effect was recorded")
	}
	if v, present := detail["self_approval"]; present {
		t.Errorf("self_approval was recorded as %v, but neither login was readable", v)
	}
	why, present := detail["self_approval_undetermined"].(string)
	if !present || why == "" {
		t.Errorf("the record must say the comparison was not established and why, got %v", detail)
	}
}

// POST /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments needs
// "Deployments" repository permissions (write). Its sibling GET is "Actions" (read),
// which is where the wrong declaration came from: with actions:write declared, the
// preflight asserted a grant that does not authorize the call, so a plan passed
// preflight and failed at the request — on a path that is Destructive, where a
// mis-stated requirement costs most.
func TestDeploymentReviewDeclaresDeploymentsWrite(t *testing.T) {
	e, found := lookup("deployment.review")
	if !found {
		t.Fatal("deployment.review is not registered")
	}
	if !slices.Contains(e.spec.Caps, CapDeployments) {
		t.Errorf("deployment.review must declare %q, declares %v", CapDeployments, e.spec.Caps)
	}
	if slices.Contains(e.spec.Caps, CapActionsWrite) {
		t.Errorf("actions:write does not authorize this call; declares %v", e.spec.Caps)
	}
}

// The preflight compares capabilities against a classic PAT's scope header through
// classicScope, so a capability missing from that table is one the preflight silently
// ignores: the primitive would declare a requirement nothing ever checks.
func TestEveryDeclaredCapabilityIsKnownToThePreflight(t *testing.T) {
	for _, spec := range Catalog() {
		for _, c := range spec.Caps {
			if _, known := classicScope[c]; !known {
				t.Errorf("%s declares %q, which classicScope does not map, so the preflight cannot act on it", spec.Name, c)
			}
		}
	}
}
