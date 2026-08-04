package attack

import (
	"cmp"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/ui"
)

// head opens the run log: what the attack is, which credential acts, and what it
// is allowed to touch — before the first request goes out, so an operator who
// mistyped a plan or a scope learns it from this block and not from the audit
// trail on the customer's system.
func head(p *Plan, s *Session, mode string) {
	repos := "repositories"
	if len(p.Scope) == 1 {
		repos = "repository"
	}
	fields := [][2]string{
		{"plan", p.ID},
		{"mode", fmt.Sprintf("%s, %d steps, %d %s", mode, len(allSteps(p)), len(p.Scope), repos)},
	}
	for _, ic := range uniqueIdentities(s.identities) {
		if ic.err != nil {
			fields = append(fields, [2]string{"identity", ic.name + ", " + ic.from + ", unresolved: " + ic.err.Error()})
			continue
		}
		fields = append(fields, [2]string{"identity", strings.Join(present(ic.login, ic.kind, ic.from), ", ")})
	}
	fields = append(fields, [2]string{"scope", strings.Join(p.Scope, ", ")})
	ui.Head(cmp.Or(p.Title, p.ID), fields...)
}

func present(vs ...string) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// maxDetail keeps the table's last column from wrapping. A real API error carries
// a URL and a JSON body and runs to hundreds of characters; the whole text is in
// the step record, and a failed step's error is reprinted in full by the degraded
// block at the end of the run.
const maxDetail = 72

// stepDetail is the object column. A step that succeeded names what it produced;
// anything else names why it did not, because the reason is then the news and the
// object it would have produced does not exist.
func stepDetail(rec StepRecord) string {
	if rec.Status == statusOK {
		return clip(objectOf(rec))
	}
	return clip(cmp.Or(rec.Error, rec.Note, objectOf(rec)))
}

func clip(s string) string {
	r := []rune(s)
	if len(r) <= maxDetail {
		return s
	}
	return string(r[:maxDetail-1]) + "\u2026"
}

// objectOf is deliberately terser than handleSummary, which writes a clause for a
// customer-facing report rather than a column of a table. Every case guards its
// identifying field: a dry run renders a mutation without issuing it, so the
// handle it produces is zero-valued and "#0" would name nothing.
func objectOf(rec StepRecord) string {
	switch t := rec.Handle.(type) {
	case Fork:
		return join(t.Owner, "/", t.Repo)
	case Branch:
		return shortRef(t.Ref)
	case Commit:
		if len(t.Files) > 0 {
			return strings.Join(t.Files, " ")
		}
		return join(shortSHA(t.SHA), " on ", shortRef(t.Ref))
	case Ref:
		return join(shortRef(t.Ref), " at ", shortSHA(t.SHA))
	case PullRequest:
		if t.Number == 0 {
			return ""
		}
		if t.Merged {
			return fmt.Sprintf("#%d merged", t.Number)
		}
		return strings.TrimSpace(fmt.Sprintf("#%d %s", t.Number, t.State))
	case Issue:
		if t.Number == 0 {
			return ""
		}
		return fmt.Sprintf("#%d", t.Number)
	case Comment:
		if t.ID == 0 {
			return ""
		}
		return fmt.Sprintf("comment %d on #%d", t.ID, t.Number)
	case WorkflowRun:
		return join(base(t.WorkflowPath), " ", cmp.Or(t.Conclusion, t.Status))
	case DispatchReceipt:
		return join(inputBase(rec, "workflow"), " on ", shortRef(t.Ref))
	case Status:
		return join(t.Context, " ", t.State)
	case CheckRun:
		return join(t.Name, " ", cmp.Or(t.Conclusion, t.Status))
	case CacheEntry:
		return t.Key
	case RunnerInventory:
		return fmt.Sprintf("%d runners, %d online", len(t.Runners), t.Online)
	case PendingDeployment:
		return environmentNames(t.Environments)
	case Loot:
		s := fmt.Sprintf("%d items, %s", len(t.Items), t.Classification)
		if t.Encrypted {
			s += ", encrypted"
		}
		return s
	}
	return ""
}

// join drops the separator and the whole pair when either side is missing, so a
// zero-valued handle yields nothing rather than a dangling "at" or a bare slash.
func join(left, sep, right string) string {
	switch {
	case left == "" && right == "":
		return ""
	case left == "":
		return right
	case right == "":
		return left
	}
	return left + sep + right
}

// actionOf falls back to the primitive name so an unregistered uses: still names
// itself on the row that reports it failing.
func actionOf(uses string) string {
	if e, ok := lookup(uses); ok && e.spec.Action != "" {
		return e.spec.Action
	}
	return uses
}

func shortRef(ref string) string { return strings.TrimPrefix(ref, "refs/heads/") }

func inputBase(rec StepRecord, key string) string {
	s, _ := rec.Inputs[key].(string)
	return base(s)
}

// base leaves an absent path absent: path.Base("") is ".", which would name a
// workflow on a handle a dry run never populated.
func base(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(p)
}

// outcomeCounts orders the closing line as what happened, then what did not, then
// the scale of it. Color is what makes a failure stand out, not position.
func outcomeCounts(res *RunResult) []ui.Count {
	return []ui.Count{
		{Label: "ok", N: res.OK},
		{Label: "planned", N: res.Planned},
		{Label: "failed", N: res.Failed},
		{Label: "skipped", N: res.Skipped},
		{Label: "resumed", N: res.Resumed},
		{Label: "mutations", N: res.Mutations},
	}
}

func elapsed(seconds float64) string {
	if seconds <= 0 {
		return ""
	}
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}
