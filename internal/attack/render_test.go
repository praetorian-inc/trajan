package attack

import (
	"testing"
)

// A dry run renders a mutation without issuing it, so the handle it produces is
// zero-valued. A path built from it would resolve to nothing, which is the one
// thing this column must never do: the repository it acted in is the coarsest true
// answer and the only safe fallback.
func TestResourceOfFallsBackToTheRepositoryForARenderedMutation(t *testing.T) {
	// plannedSHA is the one id a dry run fills in rather than leaves empty, so a
	// commit is listed twice: absent, and rendered-but-never-created.
	for _, h := range []Handle{PullRequest{}, Issue{}, Comment{}, Ref{}, Branch{}, Commit{}, Fork{}, WorkflowRun{}, DispatchReceipt{}, Loot{},
		Commit{RefLoc: RefLoc{SHA: plannedSHA}}, Status{SHA: plannedSHA}} {
		got := resourceOf(StepRecord{Target: "acme/widgets", Handle: h})
		if got != "acme/widgets" {
			t.Errorf("%T produced %q from a zero handle", h, got)
		}
	}
}

func TestResourceOfNamesThePathEachHandleResolvesAt(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  StepRecord
		want string
	}{
		{"pull request", StepRecord{Target: "acme/widgets", Handle: PullRequest{IssueLoc: IssueLoc{Number: 47}, State: "open"}}, "acme/widgets/pull/47"},
		{"branch", StepRecord{Target: "acme/widgets", Handle: Branch{RefLoc: RefLoc{Ref: "refs/heads/topic"}}}, "acme/widgets/tree/topic"},
		{"commit", StepRecord{Target: "acme/widgets", Handle: Commit{RefLoc: RefLoc{SHA: "0123456"}}}, "acme/widgets/commit/0123456"},
		{"workflow run", StepRecord{Target: "acme/widgets", Handle: WorkflowRun{ID: 3094}}, "acme/widgets/actions/runs/3094"},
		{"loot", StepRecord{Target: "acme/widgets", Handle: Loot{RunID: 3094}}, "acme/widgets/actions/runs/3094"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceOf(tc.rec); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A comment's own html_url is the only thing that says whether it sits on a pull
// request or an issue, and the fragment is what makes the path name the comment
// rather than its parent.
func TestResourceOfKeepsACommentsFragment(t *testing.T) {
	rec := StepRecord{Target: "acme/widgets", Handle: Comment{
		RepoLoc: RepoLoc{Owner: "acme", Repo: "widgets"}, Number: 29, ID: 5183452687,
		HTMLURL: "https://github.com/acme/widgets/pull/29#issuecomment-5183452687",
	}}
	if got := resourceOf(rec); got != "acme/widgets/pull/29#issuecomment-5183452687" {
		t.Errorf("got %q", got)
	}
}

// A step that did what it says spends no words on the fact. The two exceptions are
// outcomes: a watched run's conclusion, and whether the harvest saw its marker.
func TestStepNoteIsSilentOnSuccessExceptForAnOutcome(t *testing.T) {
	if got := stepNote(StepRecord{Status: statusOK, Handle: PullRequest{IssueLoc: IssueLoc{Number: 47}, State: "open"}}); got != "" {
		t.Errorf("a successful step should carry no note, got %q", got)
	}
	if got := stepNote(StepRecord{Status: statusOK, Handle: WorkflowRun{Status: "completed", Conclusion: "failure"}}); got != "failure" {
		t.Errorf("got %q, want the conclusion", got)
	}
	if got := stepNote(StepRecord{Status: statusOK, Handle: Loot{Classification: "never_ran"}}); got != "never_ran" {
		t.Errorf("got %q, want the classification", got)
	}
}

// The URL a client error carries and the body after it belong to the step record.
// The status is the whole news on a row, and a skip's own reason is already a clause.
func TestStepNoteKeepsTheStatusAndDropsTheURL(t *testing.T) {
	rec := StepRecord{
		Status: statusFailed,
		Error:  `HTTP 404 from https://api.github.com/repos/acme/widgets/git/refs/heads/topic: {"message":"Reference does not exist"}`,
	}
	if got := stepNote(rec); got != "HTTP 404" {
		t.Errorf("got %q", got)
	}
	if got := stepNote(StepRecord{Status: statusSkipped, Note: "when: false"}); got != "when: false" {
		t.Errorf("got %q", got)
	}
}
