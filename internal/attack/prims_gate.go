package attack

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name: "status.create",
		Summary: "Post a commit status under a chosen context. It attaches to a SHA, not to a branch or a pull request, " +
			"and it is not a check run: a required check of the same name is not satisfied by a status, nor the reverse.",
		Ports:      []Port{Accepts[Repo]("repo", true), Accepts[Commit]("commit", true)},
		Caps:       []Capability{CapContentsWrite},
		Mutating:   true,
		OriginFrom: "repo",
	}, statusCreate)

	Register(Spec{
		Name: "check.create",
		Summary: "Create a check run on a commit — the gate a required status check cannot express. Only a GitHub App " +
			"installation token with checks:write can, which is why identity: is a port; status: defaults to completed " +
			"and conclusion: to success, the outcome a merge gate reads as satisfied.",
		Ports:      []Port{Accepts[Repo]("repo", true), Accepts[Commit]("commit", true), Accepts[Identity]("identity", true)},
		Caps:       []Capability{CapChecksWrite},
		Mutating:   true,
		AppOnly:    true,
		OriginFrom: "repo",
	}, checkCreate)
}

var statusStates = []string{"error", "failure", "pending", "success"}

type statusCreateParams struct {
	Context     string `yaml:"context"`
	State       string `yaml:"state"`
	Description string `yaml:"description"`
	TargetURL   string `yaml:"target_url"`
}

// statusCreate writes no inverse, because none exists. There is no delete-status
// endpoint: posting the prior state on the same (sha, context) changes what the
// combined status reports, and GET /commits/{ref}/statuses still returns this
// entry — with its author and its timestamp — permanently. The ledger records the
// call with no undo, which is what puts it in cleanup's irreversible bucket rather
// than implying it was erased.
func statusCreate(ctx context.Context, s *Session, p statusCreateParams, in Inputs) (Status, error) {
	target := In[Repo](in, "repo").RepoRef()
	commit := In[Commit](in, "commit")
	state := strings.ToLower(strings.TrimSpace(p.State))
	switch {
	case strings.TrimSpace(p.Context) == "":
		return Status{}, errors.New("status.create needs context: the name the status reports under; an unnamed status posts as \"default\" and no gate keys on that")
	case !slices.Contains(statusStates, state):
		return Status{}, fmt.Errorf("state %q must be one of %s", p.State, strings.Join(statusStates, ", "))
	}
	sha := commit.SHA
	if sha == "" {
		if s.Execute {
			return Status{}, errors.New("the bound commit carries no sha, so there is nothing to attach a status to")
		}
		sha = plannedSHA
	}
	out := Status{RepoLoc: target, SHA: sha, Context: p.Context, State: state, Description: p.Description, TargetURL: p.TargetURL}

	client, err := s.Client()
	if err != nil && s.Execute {
		return Status{}, err
	}
	combined := ""
	switch {
	// A sha the render invented resolves to nothing. Reading a combined status or a
	// ref tip against it is a real request that can only 404, and the mark it leaves
	// says nothing about the target — so the ordering hazard is stated plainly and
	// nothing is sent.
	case sha == plannedSHA:
		s.Note(statusOrderAdvice)
	case client != nil:
		prior, current, err := readCombinedStatus(ctx, client, target, sha, p.Context)
		if err := s.SoftRead(err, "read commit status"); err != nil {
			return Status{}, err
		}
		out.PreviousState, combined = prior, current
		s.Note(statusOrderNote(ctx, client, commit, sha))
	}

	raw, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/statuses/%s", target.Owner, target.Repo, sha),
		Body: map[string]any{
			"state": state, "context": p.Context,
			"description": p.Description, "target_url": p.TargetURL,
		},
		Target: target.Owner + "/" + target.Repo,
		Note: "no inverse exists: there is no delete-status endpoint, and posting the prior state adds a third entry " +
			"to a per-sha history that keeps every one of them",
	})
	if err != nil {
		return out, err
	}
	var made struct {
		ID        int64  `json:"id"`
		State     string `json:"state"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(raw, &made); err != nil {
		return out, err
	}
	out.ID, out.CreatedAt = made.ID, made.CreatedAt
	out.State = cmp.Or(made.State, state)

	s.Note(fmt.Sprintf("a status is not a check run: a branch protection rule requiring the check run %q is not satisfied by this status, and a rule requiring the status %q is not satisfied by a check run of that name",
		p.Context, p.Context))
	if made.ID == 0 {
		return out, nil
	}
	if err := s.RecordEffect(Effect{
		Class: "commit_status",
		Summary: fmt.Sprintf("status %q reported %s on %s of %s/%s; there is no delete-status endpoint, so the entry stays in GET /commits/%s/statuses permanently, and only the combined status can be changed by posting again",
			p.Context, out.State, shortSHA(sha), target.Owner, target.Repo, shortSHA(sha)),
		Detail: map[string]any{
			"repository":      target.Owner + "/" + target.Repo,
			"sha":             sha,
			"context":         p.Context,
			"state":           out.State,
			"previous_state":  out.PreviousState,
			"combined_before": combined,
			"status_id":       made.ID,
		},
	}); err != nil {
		return out, err
	}
	return out, nil
}

type contextStatus struct {
	Context string `json:"context"`
	State   string `json:"state"`
}

// readCombinedStatus answers two things: what this context last reported, which is
// the only thing an inverse could aim at, and the combined state, which is what a
// merge gate actually consults. The combined state is the server's own verdict over
// every context, so the first page carries it whole; the contexts are paginated, and
// a prior state left blank because it sat on the second page would understate the
// record of what this step overwrote.
func readCombinedStatus(ctx context.Context, c *github.Client, loc RepoLoc, sha, context string) (prior, combined string, err error) {
	path := fmt.Sprintf("/repos/%s/%s/commits/%s/status", loc.Owner, loc.Repo, sha)
	raw, _, err := c.Get(ctx, path, url.Values{"per_page": []string{"100"}}, false)
	if err != nil {
		return "", "", err
	}
	var body struct {
		State      string          `json:"state"`
		TotalCount int             `json:"total_count"`
		Statuses   []contextStatus `json:"statuses"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", "", err
	}
	if state := contextState(body.Statuses, context); state != "" {
		return state, body.State, nil
	}
	if body.TotalCount <= len(body.Statuses) {
		return "", body.State, nil
	}
	// From the second page, since the first is already read: the page size above is
	// the one this offset is counted in.
	items, err := c.Paginate(ctx, path, url.Values{"per_page": []string{"100"}, "page": []string{"2"}}, 100)
	if err != nil {
		return "", body.State, err
	}
	rest := make([]contextStatus, 0, len(items))
	for _, item := range items {
		var st contextStatus
		if err := json.Unmarshal(item, &st); err != nil {
			continue
		}
		rest = append(rest, st)
	}
	return contextState(rest, context), body.State, nil
}

func contextState(statuses []contextStatus, context string) string {
	for _, st := range statuses {
		if st.Context == context {
			return st.State
		}
	}
	return ""
}

const statusOrderAdvice = "a status attaches to a sha, not to a branch or a pull request, so it must be posted after the final ref update or it lands on a commit the gate no longer reads"

// statusOrderNote is the ordering hazard made concrete. A status attaches to a
// sha, so one posted before the last ref update lands on a commit the gate no
// longer looks at; when the ref is readable this says whether that already
// happened rather than only warning that it can.
func statusOrderNote(ctx context.Context, c *github.Client, commit Commit, sha string) string {
	if !strings.HasPrefix(commit.Ref, "refs/") {
		return statusOrderAdvice
	}
	tip, err := getString(ctx, c, gitRefReadPath(commit.Owner, commit.Repo, commit.Ref), "object", "sha")
	if err != nil || tip == "" || tip == sha {
		return statusOrderAdvice
	}
	return fmt.Sprintf("%s — and %s is already at %s, so this status lands on %s, which is not the head the gate reads",
		statusOrderAdvice, commit.Ref, shortSHA(tip), shortSHA(sha))
}

type checkCreateParams struct {
	Name       string `yaml:"name"`
	Status     string `yaml:"status"`
	Conclusion string `yaml:"conclusion"`
	DetailsURL string `yaml:"details_url"`
	Title      string `yaml:"title"`
	Summary    string `yaml:"summary"`
}

var (
	// The whole documented enum: waiting, requested and pending are what a check run
	// parked on a gate reports, which is the measurement a merge-gate plan is written
	// for. GitHub grants those three to GitHub Actions alone, and no identity class
	// here records that distinction, so it is GitHub's refusal to make rather than
	// one to make offline against a principal this side cannot classify.
	checkStatuses    = []string{"queued", "in_progress", "completed", "waiting", "requested", "pending"}
	checkConclusions = []string{"action_required", "cancelled", "failure", "neutral", "success", "skipped", "stale", "timed_out"}
)

// checkCreate writes no inverse. A check run cannot be deleted, and patching one
// to neutral or failure leaves both states in its own history, so there is nothing
// to record that would restore the prior state.
func checkCreate(ctx context.Context, s *Session, p checkCreateParams, in Inputs) (CheckRun, error) {
	target := In[Repo](in, "repo").RepoRef()
	commit := In[Commit](in, "commit")
	bound := In[Identity](in, "identity")
	if strings.TrimSpace(p.Name) == "" {
		return CheckRun{}, errors.New("check.create needs name: the check run name a branch protection rule requires")
	}
	status := cmp.Or(strings.TrimSpace(p.Status), "completed")
	if !slices.Contains(checkStatuses, status) {
		return CheckRun{}, fmt.Errorf("status %q must be one of %s", p.Status, strings.Join(checkStatuses, ", "))
	}
	conclusion := strings.TrimSpace(p.Conclusion)
	switch {
	case status == "completed":
		conclusion = cmp.Or(conclusion, "success")
		if !slices.Contains(checkConclusions, conclusion) {
			return CheckRun{}, fmt.Errorf("conclusion %q must be one of %s", conclusion, strings.Join(checkConclusions, ", "))
		}
	case conclusion != "":
		return CheckRun{}, fmt.Errorf("conclusion %q applies only to a completed check run; this one is %s", conclusion, status)
	}
	if err := appIdentityGuard(s, bound); err != nil {
		return CheckRun{}, err
	}
	sha := commit.SHA
	if sha == "" {
		if s.Execute {
			return CheckRun{}, errors.New("the bound commit carries no sha, so there is nothing to attach a check run to")
		}
		sha = plannedSHA
	}
	out := CheckRun{RepoLoc: target, Name: p.Name, HeadSHA: sha, Status: status, Conclusion: conclusion, DetailsURL: p.DetailsURL}

	marker := checkMarker(s.Plan.ID, p.Name)
	client, err := s.Client()
	if err != nil && s.Execute {
		return CheckRun{}, err
	}
	if client != nil && sha != plannedSHA {
		runs, err := readCheckRuns(ctx, client, target, sha, p.Name)
		if err := s.SoftRead(err, "read check runs"); err != nil {
			return CheckRun{}, err
		}
		mine, foreign := classifyCheckRuns(runs, p.Name, marker)
		if mine.ID != 0 {
			s.Note(fmt.Sprintf("adopted check run %d on %s: it carries this plan's external id, so an earlier attempt of this step created it and a second run of the same name would leave the gate reading two",
				mine.ID, shortSHA(sha)))
			return mine.handle(target), nil
		}
		if len(foreign) > 0 {
			s.Note(fmt.Sprintf("%d check run(s) named %q on %s belong to %s and not to this chain, so they were left alone and this step created its own; the gate now reads more than one run of that name",
				len(foreign), p.Name, shortSHA(sha), foreignApps(foreign)))
		}
	}

	body := map[string]any{"name": p.Name, "head_sha": sha, "status": status, "external_id": marker}
	if conclusion != "" {
		body["conclusion"] = conclusion
	}
	if p.DetailsURL != "" {
		body["details_url"] = p.DetailsURL
	}
	if p.Title != "" || p.Summary != "" {
		body["output"] = map[string]any{"title": p.Title, "summary": p.Summary}
	}
	raw, httpStatus, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/repos/%s/%s/check-runs", target.Owner, target.Repo),
		Body:   body,
		Target: target.Owner + "/" + target.Repo,
		Note: "no inverse exists: a check run cannot be deleted, and patching it to neutral or failure keeps both " +
			"states in its history and leaves it on the commit",
	})
	if err != nil {
		if httpStatus == http.StatusForbidden {
			return out, fmt.Errorf("creating a check run was refused with 403: this is an identity boundary, not a missing scope — only a GitHub App installation token can create one, and %q is a %s: %w",
				s.ActingName(), cmp.Or(s.ActingKind(), "credential of unknown class"), err)
		}
		return out, err
	}
	var made checkRunBody
	if err := json.Unmarshal(raw, &made); err != nil {
		return out, err
	}
	out = made.handle(target)
	if made.ID == 0 {
		return out, nil
	}
	if err := s.RecordEffect(Effect{
		Class: "check_run",
		Summary: fmt.Sprintf("check run %q was created on %s of %s/%s as %s/%s by the App %q; a check run cannot be deleted, and patching it to failure would leave both states in its history",
			out.Name, shortSHA(sha), target.Owner, target.Repo, out.Status, cmp.Or(out.Conclusion, "no conclusion"), cmp.Or(out.AppSlug, "the acting installation")),
		Detail: map[string]any{
			"repository":   target.Owner + "/" + target.Repo,
			"sha":          sha,
			"check_run_id": out.ID,
			"name":         out.Name,
			"status":       out.Status,
			"conclusion":   out.Conclusion,
			"app":          out.AppSlug,
			"app_id":       out.AppID,
		},
	}); err != nil {
		return out, err
	}
	return out, nil
}

// appIdentityGuard refuses locally what GitHub would refuse anyway: only a GitHub
// App installation token can create a check run, and a PAT is answered 403 — an
// error in the customer's audit log that produces no evidence. It also insists the
// bound identity is the one that will act, because s.Mutate issues as the step's
// as:, so a plan naming an App under identity: and acting as something else would
// assert a capability it does not use. An unrecognised class is allowed through:
// the classes GitHub definitely refuses are named here, and a principal this list
// has not learned about is not one to refuse offline.
func appIdentityGuard(s *Session, bound Identity) error {
	if bound.Name != "" && s.ActingName() != "" && bound.Name != s.ActingName() {
		return fmt.Errorf("this step acts as %q but binds %q to identity:, and the request goes out as the identity it acts as; add `as:` naming the same identity so the App installation is the principal that creates the check run",
			s.ActingName(), bound.Name)
	}
	switch kind := cmp.Or(s.ActingKind(), bound.IDKind); kind {
	case kindPAT, kindFineGrained, kindGhCLI:
		return fmt.Errorf("identity %q is a %s, and only a GitHub App installation token with checks:write can create a check run: GitHub answers 403. An Actions GITHUB_TOKEN carries an App identity and can",
			s.ActingName(), kind)
	}
	return nil
}

type checkRunBody struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	DetailsURL string `json:"details_url"`
	ExternalID string `json:"external_id"`
	StartedAt  string `json:"started_at"`
	App        struct {
		ID   int64  `json:"id"`
		Slug string `json:"slug"`
	} `json:"app"`
}

func (b checkRunBody) handle(loc RepoLoc) CheckRun {
	return CheckRun{
		RepoLoc: loc, ID: b.ID, Name: b.Name, HeadSHA: b.HeadSHA,
		Status: b.Status, Conclusion: b.Conclusion, DetailsURL: b.DetailsURL,
		AppSlug: b.App.Slug, AppID: b.App.ID, StartedAt: b.StartedAt,
	}
}

// checkMarker is the external id this chain stamps on every check run it creates.
// It is the only thing that distinguishes one from the customer's own: a name is
// not a key, and on a live repository a run called build or ci/lint on a commit
// this chain just pushed is their CI answering the push.
func checkMarker(planID, name string) string { return "trajan:" + planID + ":" + name }

// readCheckRuns asks for the one name and follows the pages of that answer. The
// endpoint pages at 30 over every run on the commit, and a commit this chain has
// just pushed to is one the customer's CI is answering: reading a first page of
// those can miss this plan's own marker, and the step then creates a second check
// run of the name the gate reads.
func readCheckRuns(ctx context.Context, c *github.Client, loc RepoLoc, sha, name string) ([]checkRunBody, error) {
	items, err := c.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/commits/%s/check-runs", loc.Owner, loc.Repo, sha),
		url.Values{"check_name": []string{name}}, 100)
	if err != nil {
		return nil, err
	}
	runs := make([]checkRunBody, 0, len(items))
	for _, item := range items {
		var cr checkRunBody
		if err := json.Unmarshal(item, &cr); err != nil {
			continue
		}
		runs = append(runs, cr)
	}
	return runs, nil
}

// classifyCheckRuns splits the runs of one name on a sha into the one this chain
// created — a re-run or a resume adopts it rather than leaving the gate reading
// two — and the ones it did not. Adopting a foreign run would hand the step the
// customer's own check run as its product and let the finding narrate a gate this
// chain never forged.
func classifyCheckRuns(runs []checkRunBody, name, marker string) (mine checkRunBody, foreign []checkRunBody) {
	for _, cr := range runs {
		switch {
		case cr.Name != name:
		case cr.ExternalID == marker && mine.ID == 0:
			mine = cr
		default:
			foreign = append(foreign, cr)
		}
	}
	return mine, foreign
}

func foreignApps(runs []checkRunBody) string {
	var out []string
	for _, cr := range runs {
		if slug := cmp.Or(cr.App.Slug, "an app this response does not name"); !slices.Contains(out, slug) {
			out = append(out, slug)
		}
	}
	return strings.Join(out, ", ")
}
