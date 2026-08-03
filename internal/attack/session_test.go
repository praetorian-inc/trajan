package attack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
)

// unknownOutcomeSession drives Session.Mutate against a test server. The mutation
// path is a full URL, which the client honours verbatim, so nothing global is
// rewired.
func unknownOutcomeSession(t *testing.T) (*Session, string) {
	t.Helper()
	runDir := t.TempDir()
	if err := engine.WriteJSON(filepath.Join(runDir, engine.AttackPlan("p")), PlanRecord{
		ID: "p", Scope: []string{"acme/lab"}, Mode: "execute",
	}); err != nil {
		t.Fatalf("plan record: %v", err)
	}
	ledgerPath := filepath.Join(runDir, engine.AttackLedger("p"))
	l, err := OpenLedger(ledgerPath)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	s := &Session{
		Plan: &Plan{ID: "p", Scope: []string{"acme/lab"}}, Ledger: l, PlanDir: runDir, Execute: true,
		identities: map[string]*identityClient{}, aliases: map[string]string{}, extraScope: map[string]string{},
	}
	s.begin(actingContext{step: "open", uses: "pr.open", id: &identityClient{name: "operator", client: github.NewClient("tok")}})
	return s, runDir
}

func readRunLedger(t *testing.T, runDir string) []LedgerEntry {
	t.Helper()
	entries, err := ReadLedger(filepath.Join(runDir, engine.AttackLedger("p")))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return entries
}

func unknownOutcomeEffects(entries []LedgerEntry) []Effect {
	var out []Effect
	for _, e := range entries {
		if e.Kind == RecordEffect && e.Effect != nil && e.Effect.Class == "unknown_outcome" {
			out = append(out, *e.Effect)
		}
	}
	return out
}

// A create that answered 5xx may have created the resource, and its write-ahead
// intent carries no inverse because the number did not exist yet. The read-back
// is the only thing that can name what is there, and its result has to reach the
// ledger — otherwise cleanup cannot close the pull request this run opened.
func TestUnknownOutcomeReadBackNamesTheArtifact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(502)
			w.Write([]byte(`<html>Server Error</html>`))
			return
		}
		w.Write([]byte(`[{"number":42,"state":"open","head":{"label":"acme:trajan-x"},"base":{"ref":"main"}}]`))
	}))
	defer srv.Close()

	s, runDir := unknownOutcomeSession(t)
	var readBacks int
	_, status, err := s.Mutate(t.Context(), Mutation{
		Method: http.MethodPost,
		Path:   srv.URL + "/repos/acme/lab/pulls",
		Body:   map[string]any{"head": "acme:trajan-x", "base": "main"},
		Target: "acme/lab",
		InverseFrom: func(json.RawMessage) []UndoStep {
			t.Error("InverseFrom must not be consulted when no response body arrived")
			return nil
		},
		ReadBack: func(ctx context.Context) ([]UndoStep, error) {
			readBacks++
			c, cerr := s.Client()
			if cerr != nil {
				return nil, cerr
			}
			raw, _, gerr := c.Get(ctx, srv.URL+"/repos/acme/lab/pulls", nil, false)
			if gerr != nil {
				return nil, gerr
			}
			var found []struct{ Number int }
			if uerr := json.Unmarshal(raw, &found); uerr != nil || len(found) == 0 {
				return nil, uerr
			}
			return []UndoStep{{
				Method:  http.MethodPatch,
				Path:    fmt.Sprintf("/repos/acme/lab/pulls/%d", found[0].Number),
				Body:    map[string]any{"state": "closed"},
				Partial: true,
			}}, nil
		},
	})

	if !errors.Is(err, github.ErrAmbiguous) {
		t.Fatalf("an unknown outcome must still fail the step, got %v", err)
	}
	if status != 502 {
		t.Fatalf("status = %d, want 502", status)
	}
	if readBacks != 1 {
		t.Fatalf("read-back ran %d times, want exactly 1", readBacks)
	}

	entries := readRunLedger(t, runDir)
	revs := Reversals(entries)
	if len(revs) != 1 {
		t.Fatalf("expected one recorded mutation, got %d", len(revs))
	}
	if len(revs[0].Steps) != 1 || revs[0].Steps[0].Path != "/repos/acme/lab/pulls/42" {
		t.Fatalf("the ledger cannot name the artifact: %+v", revs[0].Steps)
	}
	effs := unknownOutcomeEffects(entries)
	if len(effs) != 1 {
		t.Fatalf("expected one unknown_outcome effect, got %d", len(effs))
	}
	if !strings.Contains(effs[0].Summary, "502") {
		t.Errorf("effect summary does not say what happened: %q", effs[0].Summary)
	}

	// The cleanup replay is the deliverable: it has to reach the artifact.
	report, err := Cleanup(t.Context(), CleanupOptions{RunDir: runDir, PlanID: "p", DryRun: true})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !slices.ContainsFunc(report.Partial, func(it CleanupItem) bool { return it.Path == "/repos/acme/lab/pulls/42" }) {
		t.Fatalf("cleanup cannot close the pull request the run may have opened: %+v", report)
	}
}

// With no read-back the artifact cannot be named — but the report must still say
// a call went out whose outcome is unknown, and it must not invent an inverse.
func TestUnknownOutcomeWithoutReadBackIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	s, runDir := unknownOutcomeSession(t)
	if _, _, err := s.Mutate(t.Context(), Mutation{
		Method: http.MethodPost,
		Path:   srv.URL + "/repos/acme/lab/issues",
		Target: "acme/lab",
	}); !errors.Is(err, github.ErrAmbiguous) {
		t.Fatalf("expected an unknown-outcome failure, got %v", err)
	}

	entries := readRunLedger(t, runDir)
	if slices.ContainsFunc(entries, func(e LedgerEntry) bool { return e.Kind == RecordUndo }) {
		t.Fatal("no undo record may be written for an artifact nothing established the existence of")
	}
	effs := unknownOutcomeEffects(entries)
	if len(effs) != 1 {
		t.Fatalf("expected one unknown_outcome effect, got %d", len(effs))
	}
	if !strings.Contains(effs[0].Summary, "acme/lab") {
		t.Errorf("the operator is not told where to look: %q", effs[0].Summary)
	}

	report, err := Cleanup(t.Context(), CleanupOptions{RunDir: runDir, PlanID: "p", DryRun: true})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !slices.ContainsFunc(report.Irreversible, func(it CleanupItem) bool {
		return strings.Contains(it.Detail, "unknown_outcome")
	}) {
		t.Fatalf("the cleanup report is silent about a call whose outcome is unknown: %+v", report.Irreversible)
	}
}

// A read-back that could not run leaves the question open, which is a different
// answer from "nothing is there" and must not be reported as one.
func TestUnknownOutcomeFailedReadBackSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
	}))
	defer srv.Close()

	s, runDir := unknownOutcomeSession(t)
	if _, _, err := s.Mutate(t.Context(), Mutation{
		Method: http.MethodPost,
		Path:   srv.URL + "/repos/acme/lab/issues",
		Target: "acme/lab",
		ReadBack: func(context.Context) ([]UndoStep, error) {
			return nil, errors.New("list issues: HTTP 403")
		},
	}); !errors.Is(err, github.ErrAmbiguous) {
		t.Fatalf("expected an unknown-outcome failure, got %v", err)
	}

	effs := unknownOutcomeEffects(readRunLedger(t, runDir))
	if len(effs) != 1 {
		t.Fatalf("expected one unknown_outcome effect, got %d", len(effs))
	}
	if !strings.Contains(effs[0].Summary, "HTTP 403") || !strings.Contains(effs[0].Summary, "by hand") {
		t.Errorf("a failed read-back must be reported as unresolved, got %q", effs[0].Summary)
	}
}

// A refused call changed nothing, so it is neither an unknown outcome nor
// something to read back.
func TestRefusedMutationIsNotAnUnknownOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		w.Write([]byte(`{"message":"Validation Failed"}`))
	}))
	defer srv.Close()

	s, runDir := unknownOutcomeSession(t)
	_, status, err := s.Mutate(t.Context(), Mutation{
		Method: http.MethodPost,
		Path:   srv.URL + "/repos/acme/lab/pulls",
		Target: "acme/lab",
		ReadBack: func(context.Context) ([]UndoStep, error) {
			t.Error("a refused call must not be read back")
			return nil, nil
		},
	})
	if err == nil || status != 422 {
		t.Fatalf("expected a 422 failure, got status %d err %v", status, err)
	}
	if effs := unknownOutcomeEffects(readRunLedger(t, runDir)); len(effs) != 0 {
		t.Fatalf("a refused call recorded an unknown outcome: %+v", effs)
	}
}
