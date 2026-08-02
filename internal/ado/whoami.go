package ado

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

func WhoAmI(ctx context.Context, org, token string) error {
	org = cmp.Or(strings.TrimSpace(org), strings.TrimSpace(os.Getenv("ORG_NAME")))
	if org == "" {
		return errors.New("no Azure DevOps organization: pass --org or set ORG_NAME")
	}
	scope, err := ParseScope(org)
	if err != nil {
		return err
	}
	pat, err := ResolveToken(token)
	if err != nil {
		return err
	}
	cl := NewClient(scope.Org, pat)

	raw, _, err := cl.Get(ctx, "core", APIVersionPreview, "/_apis/connectionData", nil, false)
	if err != nil {
		return fmt.Errorf("GET /_apis/connectionData: %w", err)
	}
	var conn struct {
		AuthenticatedUser struct {
			ID                  string `json:"id"`
			SubjectDescriptor   string `json:"subjectDescriptor"`
			ProviderDisplayName string `json:"providerDisplayName"`
			Properties          struct {
				// Account is {"$type":...,"$value":...}, not a bare string.
				Account struct {
					Value string `json:"$value"`
				} `json:"Account"`
			} `json:"properties"`
		} `json:"authenticatedUser"`
		DeploymentType string `json:"deploymentType"`
	}
	if err := json.Unmarshal(raw, &conn); err != nil {
		return fmt.Errorf("parsing connectionData: %w", err)
	}

	reachable := map[string]bool{}
	// Reachability is the HTTP status, never list emptiness: an org with zero
	// variable groups is reachable, a PAT denied them is not. A hard failure
	// (transport, exhausted 5xx/429 retries) proves nothing either way, so it warns
	// rather than silently reading as a missing scope.
	mark := func(name string, status int, err error) {
		switch {
		case err != nil:
			slog.Warn("surface probe failed", "surface", name, "error", err)
		case status == 0:
			reachable[name] = true
		}
	}
	// Only the status is wanted, so ask for one item and don't page the list.
	probe := func(name, host, api, p string) {
		_, status, err := softGet(ctx, cl, host, api, p, url.Values{"$top": {"1"}})
		mark(name, status, err)
	}

	projects, status, err := softList(ctx, cl, "core", APIVersion, "/_apis/projects", nil)
	mark("Projects", status, err)
	probe("Agent pools", "core", APIVersion, "/_apis/distributedtask/pools")
	probe("Artifact feeds", "feeds", APIVersionPreview, "/_apis/packaging/feeds")

	if len(projects) > 0 {
		pe := url.PathEscape(strField(projects[0], "name"))
		probe("Repositories", "core", APIVersion, "/"+pe+"/_apis/git/repositories")
		probe("Pipelines", "core", APIVersion, "/"+pe+"/_apis/pipelines")
		probe("Variable groups", "core", APIVersion, "/"+pe+"/_apis/distributedtask/variablegroups")
		probe("Service connections", "core", APIVersionSEP, "/"+pe+"/_apis/serviceendpoint/endpoints")
	}

	u := conn.AuthenticatedUser
	identity := u.ProviderDisplayName
	if email := u.Properties.Account.Value; email != "" {
		identity += " <" + email + ">"
	}
	fmt.Printf("identity: %s\n", identity)
	if provider, _, found := strings.Cut(u.SubjectDescriptor, "."); found {
		fmt.Printf("id: %s (%s)\n", u.ID, provider)
	} else {
		fmt.Printf("id: %s\n", u.ID)
	}
	if conn.DeploymentType != "" {
		fmt.Printf("organization: %s (%s)\n", scope.Org, conn.DeploymentType)
	} else {
		fmt.Printf("organization: %s\n", scope.Org)
	}
	if reachable["Projects"] {
		fmt.Printf("projects: %d\n", len(projects))
	}

	var ok []string
	for _, name := range []string{
		"Projects", "Repositories", "Pipelines", "Agent pools",
		"Variable groups", "Service connections", "Artifact feeds",
	} {
		if reachable[name] {
			ok = append(ok, name)
		}
	}
	if len(ok) == 0 {
		fmt.Println("reachable: none")
	} else {
		fmt.Printf("reachable: %s\n", strings.Join(ok, ", "))
	}
	return nil
}
