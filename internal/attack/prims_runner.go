package attack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name: "runner.list",
		Summary: "List the self-hosted runners a repository or an organization registers, with the labels an operator " +
			"assigned kept apart from the ones configuration applies, whether each registered as ephemeral, their " +
			"online/busy state and their runner group.",
		Ports:      []Port{Accepts[Repo]("repo", false), Accepts[Org]("org", false)},
		OneOf:      []string{"repo", "org"},
		OriginFrom: "repo",
	}, runnerList)
}

type runnerListParams struct{}

// runnerList reads the same inventory from either of two unrelated endpoints. The
// source is two optional ports rather than one union handle because the port
// lattice's floor is a repository and an organization is not one: an Org satisfies
// no port interface, so a single port could not accept both.
func runnerList(ctx context.Context, s *Session, _ runnerListParams, in Inputs) (RunnerInventory, error) {
	repo, hasRepo := InOpt[Repo](in, "repo")
	org, hasOrg := InOpt[Org](in, "org")
	if hasRepo == hasOrg {
		return RunnerInventory{}, errors.New("runner.list reads either a repository or an organization: bind exactly one of the repo: or org: ports")
	}

	out := RunnerInventory{Runners: []Runner{}, Labels: []string{}, CustomLabels: []string{}}
	base := ""
	switch {
	case hasRepo:
		out.Scope, out.Target = "repository", repo.Owner+"/"+repo.Repo
		base = fmt.Sprintf("/repos/%s/%s/actions", repo.Owner, repo.Repo)
	default:
		if err := s.OrgAllowed(org.Owner); err != nil {
			return RunnerInventory{}, err
		}
		out.Scope, out.Target = "organization", org.Owner
		base = "/orgs/" + url.PathEscape(org.Owner) + "/actions"
	}

	client, err := s.Client()
	if err != nil {
		if err := s.SoftRead(err, "list runners"); err != nil {
			return RunnerInventory{}, err
		}
		return out, nil
	}
	items, err := client.Paginate(ctx, base+"/runners", url.Values{"per_page": []string{"100"}}, 100)
	if err != nil {
		if softFail(s, err, "self-hosted runners of "+out.Target) {
			return out, nil
		}
		return RunnerInventory{}, err
	}

	groups := runnerGroups(ctx, s, client, base, out.Scope)
	untyped := 0
	for _, item := range items {
		var body runnerBody
		if err := json.Unmarshal(item, &body); err != nil {
			continue
		}
		r := body.entry()
		r.Group = groups[r.GroupID]
		untyped += body.untypedLabels()
		out.Runners = append(out.Runners, r)
		if r.Status == "online" {
			out.Online++
		}
		if r.Busy {
			out.Busy++
		}
		out.Labels = addLabels(out.Labels, r.Labels)
		out.CustomLabels = addLabels(out.CustomLabels, r.CustomLabels)
	}
	slices.Sort(out.Labels)
	slices.Sort(out.CustomLabels)
	out.AnyPersistent = anyPersistent(out.Runners)

	if len(out.Runners) == 0 {
		s.MarkEmpty(out.Target + " registers no self-hosted runners that this identity can see")
		return out, nil
	}
	if why := out.AnyPersistent.Reason; why != "" {
		s.Note(why + "; the inventory records it as unestablished rather than as a fleet that keeps nothing, because " +
			"keeping nothing is what an all-ephemeral fleet looks like")
	}
	if untyped > 0 {
		s.Note(fmt.Sprintf("%d label(s) across %s carry no type, so they are listed under labels but not under custom_labels: "+
			"a read-only label is applied automatically when the runner is configured, so only a custom one names a runner "+
			"somebody chose to make reachable by runs-on", untyped, out.Target))
	}
	return out, nil
}

func addLabels(into, names []string) []string {
	for _, name := range names {
		if !slices.Contains(into, name) {
			into = append(into, name)
		}
	}
	return into
}

func anyPersistent(runners []Runner) Measurement {
	silent := 0
	for _, r := range runners {
		switch {
		case r.Ephemeral.Known && !r.Ephemeral.Value:
			return Measured(true)
		case !r.Ephemeral.Known:
			silent++
		}
	}
	if silent > 0 {
		return Unmeasured(fmt.Sprintf("%d of %d runner(s) report no ephemeral field, so whether any of them keeps its state for the next job was not established",
			silent, len(runners)))
	}
	return Measured(false)
}

// runnerGroups names the groups the runners belong to. A group is what decides
// which repositories may reach a runner, so the name is the half of the fact worth
// reporting; the endpoint is organization-only and needs admin, and a read that
// fails leaves the ids in place rather than failing the inventory.
func runnerGroups(ctx context.Context, s *Session, c *github.Client, base, scope string) map[int64]string {
	if scope != "organization" {
		return nil
	}
	items, err := c.Paginate(ctx, base+"/runner-groups", url.Values{"per_page": []string{"100"}}, 100)
	if err != nil {
		s.MarkEmpty("runner groups are unreadable (HTTP " + fmt.Sprint(statusOf(err)) + "), so each runner carries its group id and no name")
		return nil
	}
	out := map[int64]string{}
	for _, item := range items {
		var g struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(item, &g); err == nil && g.ID != 0 {
			out[g.ID] = g.Name
		}
	}
	return out
}

type runnerBody struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	OS            string `json:"os"`
	Status        string `json:"status"`
	Busy          bool   `json:"busy"`
	RunnerGroupID int64  `json:"runner_group_id"`
	// Ephemeral is a pointer because the field is optional in the runner schema:
	// absent is a registration that reported nothing, which is a different fact
	// from a runner that reported itself persistent.
	Ephemeral *bool         `json:"ephemeral"`
	Labels    []runnerLabel `json:"labels"`
}

// runnerLabel carries type because a read-only label is applied automatically
// when the runner is configured: every self-hosted runner has self-hosted and its
// os and arch, so only a custom label names a runs-on target somebody chose.
type runnerLabel struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

const labelCustom = "custom"

func (b runnerBody) entry() Runner {
	labels := make([]string, 0, len(b.Labels))
	custom := []string{}
	for _, l := range b.Labels {
		labels = append(labels, l.Name)
		if l.Type == labelCustom {
			custom = append(custom, l.Name)
		}
	}
	return Runner{
		ID: b.ID, Name: b.Name, OS: b.OS, Status: b.Status, Busy: b.Busy,
		Labels: labels, CustomLabels: custom, Ephemeral: ephemerality(b.Ephemeral),
		GroupID: b.RunnerGroupID,
	}
}

func (b runnerBody) untypedLabels() int {
	n := 0
	for _, l := range b.Labels {
		if l.Type == "" {
			n++
		}
	}
	return n
}

func ephemerality(reported *bool) Measurement {
	if reported == nil {
		return Unmeasured("this runner's registration reports no ephemeral field, so whether it takes one job or stays for the next was not established")
	}
	return Measured(*reported)
}
