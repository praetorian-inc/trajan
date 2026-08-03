package attack

import (
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

// liveAPI is a Session whose acting identity answers from a local handler. A
// primitive builds its own request paths, and internal/github's base URL is
// package-private, so the transport a client from NewClient falls through to is the
// only seam that reaches a read without editing that package.
func liveAPI(t *testing.T, h http.HandlerFunc) *Session {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	orig := http.DefaultTransport
	http.DefaultTransport = toHost{srv.Listener.Addr().String(), orig}
	t.Cleanup(func() { http.DefaultTransport = orig })

	dir := t.TempDir()
	l, err := OpenLedger(filepath.Join(dir, engine.AttackLedger(bucketPlan)))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	s := &Session{
		Plan: &Plan{ID: bucketPlan, Scope: []string{"acme/lab"}}, Ledger: l, PlanDir: dir, Execute: true,
		identities: map[string]*identityClient{}, aliases: map[string]string{}, extraScope: map[string]string{},
	}
	s.begin(actingContext{step: "step", uses: "uses", id: &identityClient{name: "operator", client: github.NewClient("token")}})
	return s
}

type toHost struct {
	host string
	next http.RoundTripper
}

func (t toHost) RoundTrip(r *http.Request) (*http.Response, error) {
	u := *r.URL
	u.Scheme, u.Host = "http", t.host
	out := r.Clone(r.Context())
	out.URL, out.Host = &u, u.Host
	return t.next.RoundTrip(out)
}

func ledgerOf(s *Session) string {
	return filepath.Join(s.PlanDir, engine.AttackLedger(s.Plan.ID))
}

// gitRefAPI answers as the two documented endpoints do: GET /git/ref/{ref} is exact
// or 404, and GET /git/refs/{ref} prefix-matches like matching-refs, so a ref that is
// absent while a longer one carries its name answers 200 with an array. A DELETE of a
// ref that is not there is refused, which is what makes an unrecognised absence a
// failed request in the customer's audit trail.
func gitRefAPI(existing []string, sent *[]string) http.HandlerFunc {
	object := func(w http.ResponseWriter, ref, sha string) {
		fmt.Fprintf(w, `{"ref":%q,"object":{"sha":%q}}`, ref, sha)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		*sent = append(*sent, r.Method+" "+r.URL.Path)
		singular := strings.Contains(r.URL.Path, "/git/ref/")
		_, tail, found := strings.Cut(r.URL.Path, "/git/ref")
		want := "refs" + strings.TrimPrefix(tail, "s")
		switch {
		case r.Method == http.MethodGet && found:
			var prefixed []string
			for _, ref := range existing {
				if ref == want {
					object(w, ref, refAPISHA)
					return
				}
				if strings.HasPrefix(ref, want) {
					prefixed = append(prefixed, ref)
				}
			}
			if singular || len(prefixed) == 0 {
				http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
				return
			}
			var arr []string
			for _, ref := range prefixed {
				arr = append(arr, fmt.Sprintf(`{"ref":%q,"object":{"sha":"5111ba5eba115eba11ba5eba11ba5eba11ba5eba"}}`, ref))
			}
			fmt.Fprintf(w, "[%s]", strings.Join(arr, ","))
		case r.Method == http.MethodDelete && !slices.Contains(existing, want):
			http.Error(w, `{"message":"Reference does not exist"}`, http.StatusUnprocessableEntity)
		default:
			w.Write([]byte(`{}`))
		}
	}
}

const refAPISHA = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"

func sentAny(sent []string, method string) bool {
	return slices.ContainsFunc(sent, func(req string) bool { return strings.HasPrefix(req, method+" ") })
}

// A branch this chain created and a longer branch beside it is ordinary — trajan-x
// and trajan-x-2 from two runs of the same plan. The read has to answer that the
// first is gone, because a DELETE of an absent ref is refused, and a refusal is an
// error in the customer's audit trail that establishes nothing.
func TestRefDeleteRecognisesAnAbsentRefBehindALongerOne(t *testing.T) {
	var sent []string
	s := liveAPI(t, gitRefAPI([]string{"refs/heads/trajan-x-2"}, &sent))

	gone := Branch{RefLoc: RefLoc{Owner: "acme", Repo: "lab", Ref: "refs/heads/trajan-x"}}
	if _, err := refDelete(t.Context(), s, refDeleteParams{}, Inputs{ports: map[string]Handle{"ref": gone}}); err != nil {
		t.Fatalf("a ref that is already gone is nothing to delete, not an error: %v", err)
	}
	if sentAny(sent, http.MethodDelete) {
		t.Errorf("a DELETE was issued for a ref that is not there: %v", sent)
	}
	if s.acting.empty == "" {
		t.Error("the step record must say the ref was already absent")
	}
}

// The ref exists, which is what a resumed run finds, and a longer ref carries its
// name too. Adoption is the only thing standing between a resume and a second branch.
func TestRefCreateAdoptsTheRefAnEarlierAttemptCreated(t *testing.T) {
	var sent []string
	s := liveAPI(t, gitRefAPI([]string{"refs/heads/main", "refs/heads/trajan-x", "refs/heads/trajan-x-2"}, &sent))

	on := Branch{RefLoc: RefLoc{Owner: "acme", Repo: "lab", Ref: "refs/heads/main", SHA: "dddd4444dddd4444dddd4444dddd4444dddd4444"}}
	out, err := refCreate(t.Context(), s, refCreateParams{Name: "trajan-x"}, Inputs{ports: map[string]Handle{"on": on}})
	if err != nil {
		t.Fatalf("refCreate: %v", err)
	}
	if sentAny(sent, http.MethodPost) {
		t.Errorf("the branch was already there, so no second one may be created: %v", sent)
	}
	if out.Created || out.SHA != refAPISHA {
		t.Errorf("the adopted branch must carry the existing ref's sha and not claim it was created, got created=%v sha=%q", out.Created, out.SHA)
	}
}

// pr.merge returns a commit with no sha when GitHub refuses the merge — a 405 as
// not mergeable, a 409 from the expected-head guard — and PATCH /git/refs takes
// the sha absolutely. A chain that fed that commit on would ask for a ref pointing
// at nothing, and the refusal belongs here: a 422 in the customer's audit log
// establishes nothing and still costs them an entry.
func TestRefUpdateRefusesACommitWithNoSHA(t *testing.T) {
	// A dry-run session records what it would send instead of sending it, which is
	// the only way to read a primitive's request body without a network.
	s := newProcess(t, t.TempDir(), "update", "ref.update")
	s.Execute = false
	loc := RepoLoc{Owner: "acme", Repo: "lab"}

	refused := Commit{RefLoc: RefLoc{Owner: loc.Owner, Repo: loc.Repo}}
	if _, err := refUpdate(t.Context(), s, refUpdateParams{Ref: "refs/heads/main"},
		Inputs{ports: map[string]Handle{"to": refused}}); err == nil {
		t.Error("a commit with no sha must be refused")
	}
	if got := s.takePlanned(); len(got) != 0 {
		t.Fatalf("no request may be built from a sha that was never produced, got %+v", got)
	}

	landed := Commit{RefLoc: RefLoc{Owner: loc.Owner, Repo: loc.Repo, SHA: "ba5eba11ba5eba11ba5eba11ba5eba11ba5eba11"}}
	if _, err := refUpdate(t.Context(), s, refUpdateParams{Ref: "refs/heads/main"},
		Inputs{ports: map[string]Handle{"to": landed}}); err != nil {
		t.Fatalf("a commit that exists must still move the ref: %v", err)
	}
	planned := s.takePlanned()
	if len(planned) != 1 {
		t.Fatalf("want the one PATCH, got %+v", planned)
	}
	if body, _ := planned[0].Body.(map[string]any); body["sha"] != landed.SHA {
		t.Errorf("the ref must be pointed at the commit that was produced, got %+v", planned[0].Body)
	}
}
