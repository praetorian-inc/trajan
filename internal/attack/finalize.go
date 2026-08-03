package attack

import (
	"cmp"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/engine/detect"
	"github.com/praetorian-inc/trajan/internal/finding"
)

// finalize assembles the run's finding. There is no reporting step in a plan:
// the executor builds the record from every step's provenance and every handle
// the chain harvested, tags it with the detection rule the plan answers — whose
// severity and scenario it inherits rather than restating — and writes it where
// the report loader already looks.
func (x *executor) finalize(p *Plan, mode string, mutations int) error {
	f := finding.Finding{
		Producer:  "attack",
		Provider:  "github",
		Title:     cmp.Or(p.Title, p.ID),
		Subject:   finding.Subject{Kind: "chain", ID: p.ID, Display: cmp.Or(p.Title, p.ID)},
		Repo:      x.primaryTarget(p),
		Severity:  "info",
		MatchedAt: engine.IsoformatUTC(time.Now()),
	}

	ok, failed, skipped := 0, 0, 0
	var evidence []string
	for _, rec := range x.records {
		switch rec.Status {
		case statusOK:
			ok++
		case statusFailed:
			failed++
		default:
			skipped++
		}
		if s := stepSentence(rec); s != "" {
			evidence = append(evidence, s)
		}
	}
	// A call the API refused changed nothing, and a primitive is entitled to return
	// a successful step after one: a merge answered 405 as not mergeable is the
	// measurement, and the step has to return so cleanup runs. So the count that
	// decides whether the chain established anything is what landed, and a refusal
	// anywhere in it means the chain did not carry out what it set out to do.
	landed, refused := mutations, 0
	if x.sess != nil && x.sess.Ledger != nil {
		landed, refused = x.sess.Ledger.Outcomes()
	}
	established := failed == 0 && refused == 0 && landed > 0

	f.Description = fmt.Sprintf("Verification chain %q ran %d steps against %s: %d succeeded, %d failed, %d were skipped, and %d of %d mutating calls landed and were recorded for reversal.",
		p.ID, len(x.records), strings.Join(p.Scope, ", "), ok, failed, skipped, landed, mutations)
	if refused > 0 {
		f.Description += fmt.Sprintf(" %d mutating call(s) were refused by the API, so the chain did not complete what it attempted and this finding does not establish the weakness it measures.", refused)
	}
	f.Evidence = append([]string{f.Description}, evidence...)
	f.Confidence = "low"
	if established {
		f.Confidence = "high"
	}

	if p.Rule != "" {
		f.Rule = &finding.Rule{ID: p.Rule}
		if r := detectionRule(p.Rule); r != nil {
			f.Rule.ScenarioID = r.ScenarioID
			f.Severity = r.Severity
			if r.RemediationHint != "" {
				f.Remediation = &finding.Remediation{Hint: r.RemediationHint, References: []string{}}
			}
		} else {
			slog.Warn("plan names a detection rule that is not in the corpus", "plan", p.ID, "rule", p.Rule)
		}
	}
	if !established {
		f.Severity = "info"
	}

	f.Provenance = map[string]any{
		"plan":              p.ID,
		"mode":              mode,
		"scope":             p.Scope,
		"mutations":         mutations,
		"mutations_landed":  landed,
		"mutations_refused": refused,
		"steps":             provenanceSteps(x.records),
		"reversible":        "see _ledger.jsonl; attack cleanup replays the recorded inverses",
	}

	f.Fingerprint = finding.Fingerprint(f)
	return engine.WriteJSON(filepath.Join(x.runDir, engine.AttackFinding(p.ID, f.Fingerprint)), f)
}

// stepSentence is one line of the customer-facing account of what the chain did.
func stepSentence(rec StepRecord) string {
	verb := map[string]string{
		statusOK:         "succeeded",
		statusFailed:     "failed",
		statusSkipped:    "was skipped",
		statusUnresolved: "was not evaluated",
		statusPlanned:    "was rendered, not issued",
	}[rec.Status]
	if verb == "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Step %q (%s) %s", rec.ID, rec.Uses, verb)
	if rec.Target != "" {
		fmt.Fprintf(&b, " against %s", rec.Target)
	}
	if s := handleSummary(rec.Handle); s != "" {
		fmt.Fprintf(&b, ", producing %s", s)
	}
	switch {
	case rec.Error != "":
		fmt.Fprintf(&b, ": %s", rec.Error)
	case rec.Note != "":
		fmt.Fprintf(&b, " (%s)", rec.Note)
	}
	return b.String() + "."
}

func handleSummary(h Handle) string {
	switch t := h.(type) {
	case Fork:
		return fmt.Sprintf("the fork %s/%s", t.Owner, t.Repo)
	case Branch:
		return fmt.Sprintf("the branch %s at %s", t.Ref, shortSHA(t.SHA))
	case Commit:
		return fmt.Sprintf("commit %s on %s", shortSHA(t.SHA), t.Ref)
	case Ref:
		return fmt.Sprintf("%s now at %s (was %s)", t.Ref, shortSHA(t.SHA), shortSHA(t.PreviousSHA))
	case PullRequest:
		return fmt.Sprintf("pull request #%d (%s into %s)", t.Number, t.HeadLabel, t.Base)
	case Issue:
		return fmt.Sprintf("issue #%d", t.Number)
	case Comment:
		return fmt.Sprintf("comment %d on #%d", t.ID, t.Number)
	case WorkflowRun:
		return fmt.Sprintf("run %d of %s (%s)", t.ID, t.WorkflowPath, t.Conclusion)
	case Status:
		return fmt.Sprintf("the status %q reporting %s on %s", t.Context, t.State, shortSHA(t.SHA))
	case CheckRun:
		return fmt.Sprintf("the check run %q on %s (%s/%s)", t.Name, shortSHA(t.HeadSHA), t.Status, cmp.Or(t.Conclusion, "no conclusion"))
	case CacheEntry:
		return fmt.Sprintf("the cache entry %q scoped to %s", t.Key, t.Scope)
	case RunnerInventory:
		return fmt.Sprintf("%d self-hosted runner(s) on %s, %d online, labels [%s]",
			len(t.Runners), t.Target, t.Online, strings.Join(t.Labels, " "))
	case PendingDeployment:
		return fmt.Sprintf("run %d waiting on %s, approvable by this identity: %t",
			t.RunID, environmentNames(t.Environments), t.CanApprove)
	case Loot:
		return fmt.Sprintf("%d evidence item(s) from run %d, classified %s", len(t.Items), t.RunID, t.Classification)
	default:
		return ""
	}
}

func provenanceSteps(records []StepRecord) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		entry := map[string]any{"id": rec.ID, "uses": rec.Uses, "status": rec.Status, "mutating": rec.Mutating}
		for k, v := range map[string]string{"target": rec.Target, "identity": rec.Identity, "note": rec.Note, "error": rec.Error, "handle": string(rec.HandleKind)} {
			if v != "" {
				entry[k] = v
			}
		}
		out = append(out, entry)
	}
	return out
}

func (x *executor) primaryTarget(p *Plan) string {
	for _, rec := range x.records {
		if rec.Mutating && rec.Target != "" {
			return rec.Target
		}
	}
	if len(p.Scope) > 0 {
		return strings.TrimSuffix(p.Scope[0], "/*")
	}
	return ""
}

func detectionRule(id string) *detect.Rule {
	rules, err := detect.LoadRules("github")
	if err != nil {
		return nil
	}
	if i := slices.IndexFunc(rules, func(r detect.Rule) bool { return r.ID == id }); i >= 0 {
		return &rules[i]
	}
	return nil
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
