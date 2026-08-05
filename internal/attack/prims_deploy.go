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
		Name:   "deployment.pending.list",
		Action: "read pending deployments",
		Summary: "Read which environments are blocking a waiting run, who may release each one, and whether the acting " +
			"identity may. current_user_can_approve beside the run's triggering actor is the measurement a configuration " +
			"flag cannot give: the account that caused the deployment is also allowed to release it.",
		Ports:      []Port{Accepts[WorkflowRun]("run", true)},
		OriginFrom: "run",
	}, deploymentPendingList)

	Register(Spec{
		Name:   "deployment.review",
		Action: "review deployment",
		Summary: "Approve or reject named environments of a waiting run. Observing is the default — every environment an " +
			"approval releases must be named here, never derived — because releasing one pushes a real deployment.",
		Ports: []Port{Accepts[PendingDeployment]("on", true)},
		// Reviewing a pending deployment needs deployments:write, not the actions:write
		// its sibling read suggests: a preflight asserting the wrong grant passes a plan
		// that then fails at the call, and an operator provisioning the engagement
		// credential from what this declares provisions the wrong permission.
		Caps:        []Capability{CapDeployments},
		Mutating:    true,
		Destructive: true,
		OriginFrom:  "on",
	}, deploymentReview)
}

const cleanupRejectComment = "rejected by trajan cleanup: an authorized verification chain left this deployment waiting " +
	"and did not release it"

type deploymentPendingListParams struct{}

func deploymentPendingList(ctx context.Context, s *Session, _ deploymentPendingListParams, in Inputs) (PendingDeployment, error) {
	run := In[WorkflowRun](in, "run")
	loc := run.RepoRef()
	out := PendingDeployment{
		RepoLoc: loc, RunID: run.ID, Status: run.Status, Provoked: run.Provoked,
		ActingLogin: s.Login(), Environments: []PendingEnvironment{},
	}
	if run.ID == 0 {
		s.MarkEmpty("no run id to read pending deployments from")
		return out, nil
	}

	client, err := s.Client()
	if err != nil {
		if err := s.SoftRead(err, "read pending deployments"); err != nil {
			return PendingDeployment{}, err
		}
		return out, nil
	}
	// The actor is what gives current_user_can_approve its meaning, but the waiting
	// set is the read this step exists for, so a run record that will not load is
	// noted and costs only the actor.
	status, actor, err := readRunActor(ctx, client, loc, run.ID)
	if err != nil {
		s.Note(fmt.Sprintf("the record of run %d is unreadable (%s), so its triggering actor is blank", run.ID, apiMessage(err)))
	}
	out.Status, out.TriggeringActor = cmp.Or(status, out.Status), actor

	envs, err := readPending(ctx, client, loc, run.ID)
	if err != nil {
		if softFail(s, err, fmt.Sprintf("pending deployments of run %d", run.ID)) {
			return out, nil
		}
		return PendingDeployment{}, err
	}
	out.Environments = envs
	out.CanApprove = slices.ContainsFunc(envs, func(e PendingEnvironment) bool { return e.CurrentUserCanApprove })
	out.SelfApproval = selfApproval(out)
	if why := out.SelfApproval.Reason; why != "" {
		s.Note(fmt.Sprintf("%s, so self_approval of run %d is recorded as unestablished rather than false: false is what a reviewer distinct from the actor looks like",
			why, run.ID))
	}

	if len(envs) == 0 {
		s.MarkEmpty(fmt.Sprintf("run %d is %s and no environment is waiting on a reviewer, so there is nothing to release",
			run.ID, cmp.Or(out.Status, "in an unread state")))
		return out, nil
	}
	if out.SelfApproval.Value {
		s.Note(fmt.Sprintf("%s triggered run %d and is also on the reviewer list of %s, so the same account can release its own deployment",
			out.ActingLogin, run.ID, environmentNames(envs)))
	}
	return out, declareAbandonment(s, run, out)
}

func declareAbandonment(s *Session, run WorkflowRun, pd PendingDeployment) error {
	if !run.Provoked {
		s.Note(fmt.Sprintf("this chain did not provoke run %d, so cleanup will not reject or cancel it: rejecting a deployment the customer's own run is waiting on would sabotage their release. If this chain leaves it waiting, that is the customer's own run waiting as it was",
			run.ID))
		return nil
	}
	if s.DeclaredInverse(pendingDeploymentsPath(pd.RepoRef(), run.ID)) != 0 {
		return nil
	}
	ids := make([]int64, 0, len(pd.Environments))
	for _, e := range pd.Environments {
		ids = append(ids, e.ID)
	}
	seq, err := s.Declare(Mutation{
		Target: pd.Owner + "/" + pd.Repo,
		Note: fmt.Sprintf("run %d, which this chain provoked, is waiting on %s; no request is sent from here, and the inverse is the rejection that clears the customer's approvals queue if the chain is abandoned",
			run.ID, environmentNames(pd.Environments)),
		Inverse: []UndoStep{{
			Method: http.MethodPost,
			Path:   pendingDeploymentsPath(pd.RepoRef(), run.ID),
			Body:   map[string]any{"environment_ids": ids, "state": "rejected", "comment": cleanupRejectComment},
			Note: "rejects the environments this run left waiting rather than leaving them in the approvals queue; a " +
				"rejection is a new state and not a restoration, and the review request already notified the reviewers",
			Partial: true,
		}},
	})
	if err != nil {
		return err
	}
	if seq != 0 {
		s.Note("recorded the rejection cleanup will issue if this chain is abandoned while these environments are waiting")
	}
	return nil
}

func selfApproval(pd PendingDeployment) Measurement {
	switch {
	case pd.ActingLogin == "":
		return Unmeasured("the acting credential reports no login, which is what an App installation token does, so it could not be compared with the account that triggered the run")
	case pd.TriggeringActor == "":
		return Unmeasured(fmt.Sprintf("the triggering actor of run %d could not be read, so it could not be compared with the acting login", pd.RunID))
	}
	return Measured(pd.CanApprove && strings.EqualFold(pd.ActingLogin, pd.TriggeringActor))
}

func pendingDeploymentsPath(loc RepoLoc, runID int64) string {
	return fmt.Sprintf("/repos/%s/%s/actions/runs/%d/pending_deployments", loc.Owner, loc.Repo, runID)
}

var deploymentStates = []string{"approved", "rejected"}

type deploymentReviewParams struct {
	Environments []string `yaml:"environments"`
	State        string   `yaml:"state"`
	Comment      string   `yaml:"comment"`
}

func deploymentReview(ctx context.Context, s *Session, p deploymentReviewParams, in Inputs) (WorkflowRun, error) {
	pd := In[PendingDeployment](in, "on")
	loc := pd.RepoRef()
	state := strings.ToLower(strings.TrimSpace(p.State))
	if !slices.Contains(deploymentStates, state) {
		return WorkflowRun{}, fmt.Errorf("state %q must be approved or rejected; deployment.review has no default, because releasing an environment in a customer's estate pushes a real deployment",
			p.State)
	}
	named := make([]string, 0, len(p.Environments))
	for _, name := range p.Environments {
		if n := strings.TrimSpace(name); n != "" {
			named = append(named, n)
		}
	}
	if len(named) == 0 {
		return WorkflowRun{}, fmt.Errorf("deployment.review needs environments: the environments to %s, named one by one; run %d is waiting on %s",
			state, pd.RunID, environmentNames(pd.Environments))
	}
	out := WorkflowRun{RepoLoc: loc, ID: pd.RunID, Status: pd.Status, Provoked: pd.Provoked}
	if pd.RunID == 0 {
		if s.Execute {
			return WorkflowRun{}, errors.New("no run id to review a deployment on")
		}
		s.Note("the run these environments belong to was rendered, not read, so the request renders with run id 0")
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return WorkflowRun{}, err
	}
	waiting := pd.Environments
	if client != nil && pd.RunID != 0 {
		// The bound handle can be minutes old: a human reviewer or an expiring wait
		// timer may have released the environment already, and approving what is no
		// longer waiting is a 4xx in the customer's audit log for nothing.
		fresh, err := readPending(ctx, client, loc, pd.RunID)
		if err := s.SoftRead(err, "re-read pending deployments"); err != nil {
			return WorkflowRun{}, err
		}
		if err == nil {
			waiting = fresh
		}
	}

	ids, err := environmentIDs(s, named, waiting, state)
	if err != nil {
		return WorkflowRun{}, err
	}

	body := map[string]any{
		"environment_ids": ids,
		"state":           state,
		"comment":         cmp.Or(strings.TrimSpace(p.Comment), "authorized verification chain (trajan)"),
	}
	_, httpStatus, err := s.Mutate(ctx, Mutation{
		Method: http.MethodPost,
		Path:   pendingDeploymentsPath(loc, pd.RunID),
		Body:   body,
		Target: loc.Owner + "/" + loc.Repo,
		Note: "no inverse: an approval releases the deployment and its jobs start immediately, and a rejection is a new " +
			"state rather than a restoration",
	})
	if err != nil {
		if httpStatus == http.StatusForbidden {
			return out, fmt.Errorf("the review was refused with 403: this is an identity boundary, not a scope one — the acting token must belong to a principal on the environment's reviewer list (%s), and a grant of deployments:write does not put it there: %w",
				reviewerList(named, waiting), err)
		}
		return out, err
	}
	// A dry run sent nothing, so nothing was released: an effect record is a
	// consequence, and this run must never claim one it did not cause.
	if !s.Execute {
		return out, nil
	}

	if err := recordReviewEffect(s, pd, named, state); err != nil {
		return out, err
	}
	if err := retireAbandonment(s, pd, named, waiting); err != nil {
		return out, err
	}
	if client != nil && pd.RunID != 0 {
		if current, err := readRun(ctx, client, loc, pd.RunID); err == nil && current.ID != 0 {
			current.Provoked = pd.Provoked
			return current, nil
		}
	}
	return out, nil
}

// A name that is not waiting is refused under --execute: the id would be a guess,
// and a request naming the wrong environment is a refusal in the customer's audit
// log that establishes nothing. A dry run renders it with the zero id every
// unresolved object gets.
func environmentIDs(s *Session, named []string, waiting []PendingEnvironment, state string) ([]int64, error) {
	ids := make([]int64, 0, len(named))
	for _, name := range named {
		i := slices.IndexFunc(waiting, func(e PendingEnvironment) bool { return strings.EqualFold(e.Name, name) })
		if i < 0 {
			if s.Execute {
				return nil, fmt.Errorf("environment %q is not waiting on a reviewer; the run is waiting on %s", name, environmentNames(waiting))
			}
			s.Note(fmt.Sprintf("environment %q was not read as waiting, so its id renders as 0", name))
			ids = append(ids, 0)
			continue
		}
		env := waiting[i]
		if state == "approved" && !env.CurrentUserCanApprove && s.Execute {
			return nil, fmt.Errorf("identity %q cannot approve %q: GitHub reports current_user_can_approve false. That is an identity boundary, not a missing scope — the reviewers are %s, and a token is only allowed to release the environment if the principal it acts as is one of them",
				s.ActingName(), env.Name, reviewerText(env))
		}
		ids = append(ids, env.ID)
	}
	return ids, nil
}

func recordReviewEffect(s *Session, pd PendingDeployment, named []string, state string) error {
	verb := "approved, releasing the deployment"
	detail := "an approval cannot be withdrawn: the environment's jobs start immediately, and a deployment they performed, " +
		"a page they raised or a change ticket they opened is outside anything this tool can reverse"
	if state == "rejected" {
		verb = "rejected"
		detail = "a rejection fails the run's deployment job; it is a new state rather than a restoration, and the review " +
			"request already notified the reviewers"
	}
	record := map[string]any{
		"repository":       pd.Owner + "/" + pd.Repo,
		"run_id":           pd.RunID,
		"environments":     named,
		"state":            state,
		"triggering_actor": pd.TriggeringActor,
		"acting_login":     pd.ActingLogin,
		"reviewed_by":      cmp.Or(s.Login(), s.ActingName()),
	}
	// self_approval is written only where it was measured. Recorded as false for a
	// principal whose login could not be read, it would put a finding in the ledger
	// that the same account did not release its own deployment when nobody looked.
	if pd.SelfApproval.Known {
		record["self_approval"] = pd.SelfApproval.Value
	} else {
		record["self_approval_undetermined"] = cmp.Or(pd.SelfApproval.Reason,
			"the acting login and the run's triggering actor were not both readable, so whether the account that caused this deployment also released it was not established")
	}
	return s.RecordEffect(Effect{
		Class: "deployment_review",
		Summary: fmt.Sprintf("%s of run %d in %s/%s were %s by %s; %s",
			strings.Join(named, ", "), pd.RunID, pd.Owner, pd.Repo, verb, cmp.Or(s.Login(), s.ActingName()), detail),
		Detail: record,
	})
}

// Replaying the declared rejection against a run this chain already released
// would be refused, and cleanup would report an artifact still standing that is
// not there — and say a deployment is stuck in the customer's queue that this
// chain let through.
//
// The sequence to retire comes from the ledger rather than from this process. A
// resume rehydrates the step that declared it without running its body, so
// nothing in memory knows the declaration exists, and the run that would replay
// it reads the same file.
func retireAbandonment(s *Session, pd PendingDeployment, named []string, waiting []PendingEnvironment) error {
	seq := s.DeclaredInverse(pendingDeploymentsPath(pd.RepoRef(), pd.RunID))
	if seq == 0 {
		return nil
	}
	for _, env := range waiting {
		if !slices.ContainsFunc(named, func(n string) bool { return strings.EqualFold(n, env.Name) }) {
			return nil // still waiting on an environment this step did not name
		}
	}
	return s.Retire(seq, pd.Owner+"/"+pd.Repo)
}

func readPending(ctx context.Context, c *github.Client, loc RepoLoc, runID int64) ([]PendingEnvironment, error) {
	items, err := c.Paginate(ctx,
		fmt.Sprintf("/repos/%s/%s/actions/runs/%d/pending_deployments", loc.Owner, loc.Repo, runID),
		url.Values{"per_page": []string{"100"}}, 100)
	if err != nil {
		return nil, err
	}
	out := make([]PendingEnvironment, 0, len(items))
	for _, item := range items {
		var body pendingDeploymentBody
		if err := json.Unmarshal(item, &body); err != nil {
			continue
		}
		out = append(out, body.entry())
	}
	return out, nil
}

func readRunActor(ctx context.Context, c *github.Client, loc RepoLoc, runID int64) (status, actor string, err error) {
	raw, _, err := c.Get(ctx, fmt.Sprintf("/repos/%s/%s/actions/runs/%d", loc.Owner, loc.Repo, runID), nil, false)
	if err != nil {
		return "", "", err
	}
	var body struct {
		Status          string `json:"status"`
		TriggeringActor struct {
			Login string `json:"login"`
		} `json:"triggering_actor"`
		Actor struct {
			Login string `json:"login"`
		} `json:"actor"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", "", err
	}
	return body.Status, cmp.Or(body.TriggeringActor.Login, body.Actor.Login), nil
}

type pendingDeploymentBody struct {
	Environment struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"environment"`
	WaitTimer             int    `json:"wait_timer"`
	WaitTimerStartedAt    string `json:"wait_timer_started_at"`
	CurrentUserCanApprove bool   `json:"current_user_can_approve"`
	Reviewers             []struct {
		Type     string `json:"type"`
		Reviewer struct {
			Login string `json:"login"`
			Slug  string `json:"slug"`
		} `json:"reviewer"`
	} `json:"reviewers"`
}

func (b pendingDeploymentBody) entry() PendingEnvironment {
	reviewers := make([]string, 0, len(b.Reviewers))
	for _, r := range b.Reviewers {
		switch {
		case r.Reviewer.Login != "":
			reviewers = append(reviewers, "user:"+r.Reviewer.Login)
		case r.Reviewer.Slug != "":
			reviewers = append(reviewers, "team:"+r.Reviewer.Slug)
		default:
			reviewers = append(reviewers, strings.ToLower(cmp.Or(r.Type, "unknown")))
		}
	}
	return PendingEnvironment{
		Name: b.Environment.Name, ID: b.Environment.ID,
		WaitTimer: b.WaitTimer, WaitTimerStartedAt: b.WaitTimerStartedAt,
		CurrentUserCanApprove: b.CurrentUserCanApprove, Reviewers: reviewers,
	}
}

func environmentNames(envs []PendingEnvironment) string {
	if len(envs) == 0 {
		return "no environment"
	}
	names := make([]string, 0, len(envs))
	for _, e := range envs {
		names = append(names, e.Name)
	}
	return strings.Join(names, ", ")
}

func reviewerText(env PendingEnvironment) string {
	if len(env.Reviewers) == 0 {
		return "not readable from the pending record"
	}
	return strings.Join(env.Reviewers, ", ")
}

func reviewerList(named []string, waiting []PendingEnvironment) string {
	var out []string
	for _, env := range waiting {
		if slices.ContainsFunc(named, func(n string) bool { return strings.EqualFold(n, env.Name) }) {
			out = append(out, env.Name+": "+reviewerText(env))
		}
	}
	if len(out) == 0 {
		return "not readable from the pending record"
	}
	return strings.Join(out, "; ")
}
