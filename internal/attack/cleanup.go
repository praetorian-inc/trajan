package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
)

const cleanupNote = "Replayed the ledger's recorded inverses in reverse sequence order. This is a " +
	"different mechanism from a plan's cleanup: block, which the executor runs in declaration order " +
	"because an authored undo sequence already reads top-down. Nothing outside this ledger is touched. " +
	"reversed means the prior state was restored; partial means the request succeeded but the effect " +
	"was not undone; irreversible means there was never an inverse to replay; failed means the " +
	"reversal was attempted and refused, so the artifact is still there. No reversal in any of these " +
	"buckets retracts an event: a webhook delivery, a workflow run a trigger started, an audit log " +
	"entry and a notification already delivered stand whatever became of the request that caused " +
	"them, and each item below names the ones its own call fired."

type CleanupOptions struct {
	// PlanID selects one plan inside RunDir when the directory holds more than one.
	RunDir string
	PlanID string
	DryRun bool
	Token  string // explicit --token; env still outranks via resolveCredential
}

type CleanupItem struct {
	Step     string `json:"step,omitempty"`
	Uses     string `json:"uses,omitempty"`
	Identity string `json:"identity,omitempty"`
	Target   string `json:"target,omitempty"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Status   int    `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
}

type CleanupReport struct {
	Plan         string        `json:"plan"`
	PlanDir      string        `json:"plan_dir"`
	Mode         string        `json:"mode"`
	GeneratedAt  string        `json:"generated_at"`
	Note         string        `json:"note"`
	Reversed     []CleanupItem `json:"reversed"`
	Partial      []CleanupItem `json:"partial"`
	Irreversible []CleanupItem `json:"irreversible"`
	Failed       []CleanupItem `json:"failed"`
}

// Cleanup replays the recorded inverses of one plan's run and reports what was
// and was not undone. It never claims more than it did: a pull request closes
// but is not deleted, a fork usually cannot be removed at all, and everything
// off-platform is irreversible by construction.
func Cleanup(ctx context.Context, opts CleanupOptions) (*CleanupReport, error) {
	planID, err := resolvePlanID(opts.RunDir, opts.PlanID)
	if err != nil {
		return nil, err
	}
	planDir := filepath.Join(opts.RunDir, engine.AttackDir(planID))

	var rec PlanRecord
	planFile := filepath.Join(opts.RunDir, engine.AttackPlan(planID))
	raw, err := os.ReadFile(planFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", planFile, err)
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("parse %s: %w", planFile, err)
	}

	entries, err := ReadLedger(filepath.Join(opts.RunDir, engine.AttackLedger(planID)))
	if err != nil {
		return nil, err
	}

	report := &CleanupReport{
		Plan: rec.ID, PlanDir: planDir, Mode: "execute", Note: cleanupNote,
		GeneratedAt: engine.IsoformatUTC(time.Now()),
		Reversed:    []CleanupItem{}, Partial: []CleanupItem{},
		Irreversible: []CleanupItem{}, Failed: []CleanupItem{},
	}
	if opts.DryRun {
		report.Mode = "dry-run"
	}

	clients := cleanupClients(ctx, rec, opts.Token)
	// A run's own ledger is the whole allowlist for a replay: every target it
	// names is one this run recorded a mutation against, which covers the fork
	// that landed in the acting identity's namespace and nothing else.
	recorded := map[string]bool{}
	for _, e := range entries {
		if e.Kind == RecordIntent && e.Target != "" {
			recorded[e.Target] = true
		}
	}

	for _, rev := range Reversals(entries) {
		if len(rev.Steps) == 0 {
			report.Irreversible = append(report.Irreversible, CleanupItem{
				Step: rev.Step, Uses: rev.Uses, Target: rev.Target, Method: rev.Method, Path: rev.Path,
				Detail: nothingToReplay(rev),
			})
			continue
		}
		for _, undo := range rev.Steps {
			item := CleanupItem{
				Step: rev.Step, Uses: rev.Uses, Identity: rev.Identity, Target: rev.Target,
				Method: undo.Method, Path: undo.Path, Detail: undo.Note,
			}
			if !scopeAllows(rec.Scope, rev.Target) && !recorded[rev.Target] {
				item.Error = "target is neither in the plan scope nor recorded in this ledger"
				report.Failed = append(report.Failed, item)
				continue
			}
			if opts.DryRun {
				report.bucket(undo.Partial, item)
				continue
			}
			client, ok := clients[rev.Identity]
			if !ok || client == nil {
				item.Error = fmt.Sprintf("identity %q could not be resolved", rev.Identity)
				report.Failed = append(report.Failed, item)
				continue
			}
			_, status, err := client.Mutate(ctx, undo.Method, undo.Path, undo.Body)
			item.Status = status
			switch {
			case err == nil:
				report.bucket(undo.Partial, item)
			case status == http.StatusNotFound || status == http.StatusGone:
				item.Detail = strings.TrimSpace(item.Detail + " (already absent)")
				report.Reversed = append(report.Reversed, item)
			default:
				item.Error = err.Error()
				report.Failed = append(report.Failed, item)
			}
		}
	}

	for _, e := range entries {
		if e.Kind != RecordEffect || e.Effect == nil {
			continue
		}
		report.Irreversible = append(report.Irreversible, CleanupItem{
			Step: e.Step, Uses: e.Uses, Detail: e.Effect.Class + ": " + e.Effect.Summary,
		})
	}

	if err := engine.WriteJSON(filepath.Join(opts.RunDir, engine.AttackCleanup(planID)), report); err != nil {
		return report, err
	}
	return report, nil
}

// nothingToReplay says why an entry has no inverse, which is not one answer. A
// call can have had no inverse in the first place; a declared artifact — no
// request of ours, so no method and no path — can have been released by a later
// step of the same run, which is the opposite of something left behind. Either
// way the entry's own note is the explanation, and dropping it leaves the report
// asserting an unexplained irreversible call.
func nothingToReplay(rev Reversal) string {
	switch {
	case rev.Retired:
		return note(rev.Note, "a later step of this run cleared this artifact, so there is nothing left to replay")
	case rev.Method == "":
		return note(rev.Note, "no request was sent for this entry and its inverse is empty")
	default:
		return note(rev.Note, "no inverse was recorded for this call")
	}
}

func (r *CleanupReport) bucket(partial bool, item CleanupItem) {
	if partial {
		r.Partial = append(r.Partial, item)
		return
	}
	r.Reversed = append(r.Reversed, item)
}

func resolvePlanID(runDir, planID string) (string, error) {
	if runDir == "" {
		return "", fmt.Errorf("cleanup needs a run directory: pass --path")
	}
	if planID != "" {
		if _, err := os.Stat(filepath.Join(runDir, engine.AttackPlan(planID))); err != nil {
			return "", fmt.Errorf("no plan %q in %s", planID, runDir)
		}
		return planID, nil
	}
	root := filepath.Join(runDir, engine.AttackRoot())
	dirs, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", root, err)
	}
	var found []string
	for _, d := range dirs {
		if d.IsDir() {
			found = append(found, d.Name())
		}
	}
	slices.Sort(found)
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no attack plan ran in %s", runDir)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("%s holds several plans (%s); name one", runDir, strings.Join(found, ", "))
	}
}

// cleanupClients resolves the identities the run recorded, so each inverse is
// issued by the principal that made the change.
func cleanupClients(ctx context.Context, rec PlanRecord, explicit string) map[string]*github.Client {
	out := map[string]*github.Client{}
	for _, id := range rec.Identities {
		token, _, err := resolveCredential(ctx, id.From, explicit)
		if err != nil {
			slog.Warn("cleanup identity unresolved", "identity", id.Name, "from", id.From, "err", err)
			continue
		}
		out[id.Name] = github.NewClient(token)
	}
	// A step that named no identity ran as the plan default, which the record
	// lists first.
	if len(rec.Identities) > 0 {
		if c, ok := out[rec.Identities[0].Name]; ok {
			out[""] = c
		}
	}
	return out
}
