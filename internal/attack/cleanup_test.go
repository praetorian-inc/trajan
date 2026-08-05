package attack

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

const bucketPlan = "gate-bypass"

// writeLedger lays a hand-built ledger and the plan record beside it, which is
// the whole of what a cleanup replay reads.
func writeLedger(t *testing.T, entries []LedgerEntry) string {
	t.Helper()
	runDir := t.TempDir()
	if err := engine.WriteJSON(filepath.Join(runDir, engine.AttackPlan(bucketPlan)), PlanRecord{
		ID: bucketPlan, Scope: []string{"acme/lab"}, Mode: "execute",
	}); err != nil {
		t.Fatalf("plan record: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(runDir, engine.AttackLedger(bucketPlan)), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return runDir
}

func replay(t *testing.T, runDir string) *CleanupReport {
	t.Helper()
	report, err := Cleanup(t.Context(), CleanupOptions{RunDir: runDir, PlanID: bucketPlan, DryRun: true})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	return report
}

func steps(items []CleanupItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Step)
	}
	slices.Sort(out)
	return out
}

func onlyItem(t *testing.T, bucket string, items []CleanupItem) CleanupItem {
	t.Helper()
	if len(items) != 1 {
		t.Fatalf("%s holds %d item(s), want exactly one: %+v", bucket, len(items), items)
	}
	return items[0]
}

// Every inverse must land in the bucket its own flag claims, because those four
// words are what a remediation team acts on: reversed means there is nothing left
// to look at, and partial means there is.
func TestEachInverseLandsInTheBucketItClaims(t *testing.T) {
	runDir := writeLedger(t, []LedgerEntry{
		{Seq: 1, Kind: RecordRun, Plan: bucketPlan, Mode: "execute", Authorized: true},
		{
			Seq: 2, Kind: RecordIntent, Step: "label", Uses: "label.add", Target: "acme/lab",
			Method: http.MethodPost, Path: "/repos/acme/lab/issues/7/labels",
			Inverse: []UndoStep{{Method: http.MethodDelete, Path: "/repos/acme/lab/issues/7/labels/ci-run"}},
		},
		{Seq: 3, Kind: RecordResult, Ref: 2, Status: 200},
		{
			Seq: 4, Kind: RecordIntent, Step: "carrier", Uses: "comment.create", Target: "acme/lab",
			Method: http.MethodPost, Path: "/repos/acme/lab/issues/7/comments",
			Inverse: []UndoStep{{Method: http.MethodDelete, Path: "/repos/acme/lab/issues/comments/91", Partial: true}},
		},
		{Seq: 5, Kind: RecordResult, Ref: 4, Status: 201},
		{
			Seq: 6, Kind: RecordIntent, Step: "merge", Uses: "pr.merge", Target: "acme/lab",
			Method: http.MethodPut, Path: "/repos/acme/lab/pulls/7/merge",
			Note: "a merge has no inverse: restoring the base needs a force-update a protected branch refuses",
		},
		{Seq: 7, Kind: RecordResult, Ref: 6, Status: 200},
	})

	report := replay(t, runDir)

	if got := steps(report.Reversed); !slices.Equal(got, []string{"label"}) {
		t.Errorf("reversed = %v, want only the label removal: its inverse restores the label set exactly", got)
	}
	if got := steps(report.Partial); !slices.Equal(got, []string{"carrier"}) {
		t.Errorf("partial = %v, want only the comment: deleting it does not recall the notification that carried the body", got)
	}
	if got := steps(report.Irreversible); !slices.Equal(got, []string{"merge"}) {
		t.Errorf("irreversible = %v, want only the merge", got)
	}
	if len(report.Failed) != 0 {
		t.Errorf("failed = %+v, want none: nothing was refused", report.Failed)
	}
}

// A call the API refused changed nothing, so replaying its inverse would undo
// something this run never did.
func TestARefusedCallIsNotReversed(t *testing.T) {
	runDir := writeLedger(t, []LedgerEntry{
		{
			Seq: 1, Kind: RecordIntent, Step: "merge", Uses: "pr.merge", Target: "acme/lab",
			Method: http.MethodPut, Path: "/repos/acme/lab/pulls/7/merge",
			Inverse: []UndoStep{{Method: http.MethodPatch, Path: "/repos/acme/lab/git/refs/heads/main"}},
		},
		{Seq: 2, Kind: RecordResult, Ref: 1, Status: 405, Error: "405 Not Found: pull request is not mergeable"},
	})

	report := replay(t, runDir)

	if n := len(report.Reversed) + len(report.Partial) + len(report.Irreversible) + len(report.Failed); n != 0 {
		t.Fatalf("a refused call must appear in no bucket, got %d item(s): %+v", n, report)
	}
}

// An entry with nothing to replay has more than one cause, and the report has to
// say which: a call that never had an inverse is an artifact still standing, and a
// declared artifact a later step released is the opposite.
func TestNothingToReplayNamesItsCause(t *testing.T) {
	const waiting = "run 42, which this chain provoked, is waiting on prod"
	runDir := writeLedger(t, []LedgerEntry{
		{
			Seq: 1, Kind: RecordIntent, Step: "pending", Uses: "deployment.pending.list", Target: "acme/lab",
			Note:    waiting,
			Inverse: []UndoStep{{Method: http.MethodPost, Path: "/repos/acme/lab/actions/runs/42/pending_deployments", Partial: true}},
		},
		{Seq: 2, Kind: RecordUndo, Ref: 1, Target: "acme/lab"},
	})

	item := onlyItem(t, "irreversible", replay(t, runDir).Irreversible)

	if strings.Contains(item.Detail, "no inverse was recorded for this call") {
		t.Errorf("a retired declaration is not a call with no inverse; detail = %q", item.Detail)
	}
	if !strings.Contains(item.Detail, waiting) {
		t.Errorf("detail = %q, want the entry's own note explaining what was declared", item.Detail)
	}
	if !strings.Contains(item.Detail, "nothing left to replay") {
		t.Errorf("detail = %q, want it to say the artifact is gone", item.Detail)
	}
}

// A declaration nothing superseded is still standing, and cleanup must replay it.
func TestAStandingDeclarationIsReplayed(t *testing.T) {
	runDir := writeLedger(t, []LedgerEntry{
		{
			Seq: 1, Kind: RecordIntent, Step: "pending", Uses: "deployment.pending.list", Target: "acme/lab",
			Inverse: []UndoStep{{
				Method: http.MethodPost, Path: "/repos/acme/lab/actions/runs/42/pending_deployments", Partial: true,
			}},
		},
	})

	item := onlyItem(t, "partial", replay(t, runDir).Partial)

	if item.Path != "/repos/acme/lab/actions/runs/42/pending_deployments" {
		t.Fatalf("the rejection that clears the approvals queue must be replayed, got %+v", item)
	}
}
