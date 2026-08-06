package attack

import (
	"cmp"
	"fmt"
	"path"
	"strconv"
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

// resourceOf names the one object a step acted on, as its path on github.com: a row
// resolves by pasting it after the host, and one grammar covers a repository, a
// branch, a pull request, a comment and a run. Every case guards its identifying
// field, because a dry run renders a mutation without issuing it \u2014 the handle it
// produces is zero-valued, and "/pull/0" would name nothing. The repository is the
// fallback rather than an error: it is the coarsest true answer, never a wrong one.
func resourceOf(rec StepRecord) string {
	root := rec.Target
	switch t := rec.Handle.(type) {
	case Branch:
		return sub(root, "tree", shortRef(t.Ref))
	case Ref:
		return sub(root, "tree", shortRef(t.Ref))
	case Commit:
		return sub(root, "commit", realSHA(t.SHA))
	case PullRequest:
		return sub(root, "pull", number(t.Number))
	case Issue:
		return sub(root, "issues", number(t.Number))
	case Comment:
		// The one handle that already carries a URL, and the only one whose parent \u2014
		// a pull request or an issue \u2014 nothing else on it distinguishes.
		if p := urlPath(t.HTMLURL); p != "" {
			return p
		}
	case WorkflowRun:
		return sub(root, "actions/runs", number64(t.ID))
	case DispatchReceipt:
		if t.RunID != 0 {
			return sub(root, "actions/runs", number64(t.RunID))
		}
		return sub(root, "actions/workflows", inputBase(rec, "workflow"))
	case Loot:
		return sub(root, "actions/runs", number64(t.RunID))
	case PendingDeployment:
		return sub(root, "actions/runs", number64(t.RunID))
	case CheckRun:
		return sub(root, "runs", number64(t.ID))
	case Status:
		return sub(root, "commit", realSHA(t.SHA))
	case CacheEntry:
		return sub(root, "actions/caches", t.Key)
	case RunnerInventory:
		return t.Target
	case Org:
		return t.Owner
	case Identity:
		return t.Login
	}
	return root
}

// stepNote is what a row says after its resource. A step that did what it says
// carries nothing, because the resource is then the whole news; the two exceptions
// are outcomes rather than state, and dropping them would leave a row unable to say
// whether the workflow it watched went green or whether the harvest saw its marker
// at all. Anything other than ok names its reason in one clause: a failed inverse
// an operator does not see is how a run gets read as clean when it is not.
func stepNote(rec StepRecord) string {
	if rec.Status != statusOK {
		return firstClause(cmp.Or(rec.Error, rec.Note))
	}
	switch t := rec.Handle.(type) {
	case WorkflowRun:
		return cmp.Or(t.Conclusion, t.Status)
	case Loot:
		return t.Classification
	}
	return ""
}

// firstClause keeps the status a client error leads with and drops the URL and body
// that follow it. A note is left whole: "when: false" is already the clause.
func firstClause(s string) string {
	before, _, found := strings.Cut(s, " from ")
	if found {
		return before
	}
	return s
}

// sub drops the whole segment when the handle did not identify one, so a zero-valued
// handle names its repository rather than a path that resolves to nothing.
func sub(root, segment, value string) string {
	if root == "" || value == "" {
		return root
	}
	return root + "/" + segment + "/" + value
}

// A dry run fills the sha of a commit it never created with plannedSHA, which is
// not absent and not real: a path built from it names a commit nobody can fetch.
func realSHA(s string) string {
	if s == plannedSHA {
		return ""
	}
	return shortSHA(s)
}

func number(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func number64(n int64) string {
	if n == 0 {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

// urlPath reduces a URL to what follows its host, keeping any fragment: the
// #issuecomment-<id> is what makes a comment's path identify the comment rather
// than the pull request it sits on.
func urlPath(u string) string {
	_, afterScheme, found := strings.Cut(u, "://")
	if !found {
		return ""
	}
	_, p, found := strings.Cut(afterScheme, "/")
	if !found {
		return ""
	}
	return p
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
