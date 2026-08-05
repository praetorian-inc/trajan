package attack

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/finding"
)

// mergeChain is a chain whose last mutation is the merge the plan exists to
// measure: the earlier calls all land, and only the answer to the merge differs
// between the two cases below.
func mergeChain(t *testing.T, mergeStatus int, mergeErr error) (*executor, *Plan, string) {
	t.Helper()
	runDir := t.TempDir()
	p := &Plan{ID: bucketPlan, Title: "merge gate bypass", Scope: []string{"acme/lab"}}

	l, err := OpenLedger(filepath.Join(runDir, engine.AttackLedger(p.ID)))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	push, err := l.Intent(LedgerEntry{Step: "push", Target: "acme/lab", Method: http.MethodPatch, Path: "/repos/acme/lab/git/refs/heads/x"})
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	if err := l.Result(push, 200, nil); err != nil {
		t.Fatalf("result: %v", err)
	}
	merge, err := l.Intent(LedgerEntry{Step: "merge", Target: "acme/lab", Method: http.MethodPut, Path: "/repos/acme/lab/pulls/7/merge"})
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	if err := l.Result(merge, mergeStatus, mergeErr); err != nil {
		t.Fatalf("result: %v", err)
	}

	x := &executor{
		plan: p, runDir: runDir, execute: true,
		sess: &Session{Plan: p, Ledger: l, Execute: true},
		records: []StepRecord{
			{ID: "push", Uses: "ref.update", Status: statusOK, Mutating: true, Target: "acme/lab"},
			{ID: "merge", Uses: "pr.merge", Status: statusOK, Mutating: true, Target: "acme/lab"},
		},
	}
	return x, p, runDir
}

func readFinding(t *testing.T, runDir string) finding.Finding {
	t.Helper()
	dir := filepath.Join(runDir, engine.AttackDir(bucketPlan), "findings")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("want exactly one finding in %s: %v (%d entries)", dir, err, len(entries))
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read finding: %v", err)
	}
	var f finding.Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse finding: %v", err)
	}
	return f
}

// A merge GitHub refused as not mergeable is a successful step by design — the
// step has to return so cleanup runs — so the finding cannot key on step failures
// alone. Nothing was merged, and a chain that merged nothing has not established
// that the gate can be bypassed.
func TestARefusedCallLeavesTheFindingUnestablished(t *testing.T) {
	x, p, runDir := mergeChain(t, http.StatusMethodNotAllowed, &github405{})

	if err := x.finalize(p, "execute", x.sess.Ledger.Mutations()); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	f := readFinding(t, runDir)
	if f.Confidence != "low" {
		t.Errorf("confidence = %q, want low: the merge this chain measures was refused", f.Confidence)
	}
	if f.Severity != "info" {
		t.Errorf("severity = %q, want info for a chain that established nothing", f.Severity)
	}
	if got := f.Provenance["mutations_refused"]; got != float64(1) && got != 1 {
		t.Errorf("mutations_refused = %v, want 1", got)
	}
	if got := f.Provenance["mutations_landed"]; got != float64(1) && got != 1 {
		t.Errorf("mutations_landed = %v, want 1 of the 2 issued", got)
	}
}

// The control: the identical chain whose merge landed.
func TestALandedChainIsEstablished(t *testing.T) {
	x, p, runDir := mergeChain(t, http.StatusOK, nil)

	if err := x.finalize(p, "execute", x.sess.Ledger.Mutations()); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	if f := readFinding(t, runDir); f.Confidence != "high" {
		t.Errorf("confidence = %q, want high: every mutation landed", f.Confidence)
	}
}

// A declared artifact is not a request, so it must not count as a mutation this
// run issued — including when a later process reads the ledger back.
func TestADeclarationIsNotCountedAsAMutation(t *testing.T) {
	runDir := t.TempDir()
	path := filepath.Join(runDir, engine.AttackLedger(bucketPlan))

	first, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if _, err := first.Declare(LedgerEntry{Step: "pending", Target: "acme/lab", Inverse: []UndoStep{{Method: http.MethodPost, Path: "/x"}}}); err != nil {
		t.Fatalf("declare: %v", err)
	}
	if first.Mutations() != 0 {
		t.Fatalf("a declaration sends nothing, got %d mutation(s)", first.Mutations())
	}
	first.Close()

	resumed, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { resumed.Close() })
	if resumed.Mutations() != 0 {
		t.Fatalf("the resumed count inherited %d mutation(s) from a declaration", resumed.Mutations())
	}
}

type github405 struct{}

func (*github405) Error() string { return "405 Method Not Allowed: Pull Request is not mergeable" }
