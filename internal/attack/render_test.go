package attack

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A dry run renders a mutation without issuing it, so the handle it produces is
// zero-valued. "#0" or a dangling "at" would name a resource that does not exist,
// which is the one thing this column must never do.
func TestObjectOfNamesNothingForARenderedMutation(t *testing.T) {
	for _, h := range []Handle{PullRequest{}, Issue{}, Comment{}, Ref{}, Branch{}, Commit{}, Fork{}, WorkflowRun{}, DispatchReceipt{}} {
		if got := objectOf(StepRecord{Handle: h}); got != "" {
			t.Errorf("%T produced %q from a zero handle", h, got)
		}
	}
}

func TestObjectOfNamesAPullRequestItActuallyOpened(t *testing.T) {
	got := objectOf(StepRecord{Handle: PullRequest{IssueLoc: IssueLoc{Number: 47}, State: "open"}})
	if got != "#47 open" {
		t.Errorf("got %q", got)
	}
	if got := objectOf(StepRecord{Handle: PullRequest{IssueLoc: IssueLoc{Number: 47}, State: "closed", Merged: true}}); got != "#47 merged" {
		t.Errorf("got %q", got)
	}
}

func TestClipDoesNotSplitAMultiByteRune(t *testing.T) {
	got := clip(strings.Repeat("é", maxDetail+10))
	if !utf8.ValidString(got) {
		t.Fatalf("clip produced invalid UTF-8: %q", got)
	}
	if n := utf8.RuneCountInString(got); n != maxDetail {
		t.Errorf("want %d runes, got %d", maxDetail, n)
	}
}

// A failed step's reason is the news; the object it would have produced is not.
func TestStepDetailPrefersTheReasonOverTheObject(t *testing.T) {
	rec := StepRecord{Status: statusFailed, Error: "422 no commits", Handle: PullRequest{IssueLoc: IssueLoc{Number: 47}}}
	if got := stepDetail(rec); got != "422 no commits" {
		t.Errorf("got %q", got)
	}
	rec = StepRecord{Status: statusSkipped, Note: "when: false"}
	if got := stepDetail(rec); got != "when: false" {
		t.Errorf("got %q", got)
	}
}
