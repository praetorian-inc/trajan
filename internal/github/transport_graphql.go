package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// graphqlTransport serves the graphql-mappable surfaces (repo metadata, repo
// topics, org members) by synthesizing the exact REST `data` shape each collector
// expects. Any unmapped surface or graphql error yields errUnservable so the
// router falls through to REST — graphql is a pure optimization that drains the
// separate GraphQL budget instead of the binding REST core budget.
type graphqlTransport struct {
	gql *gqlClient
}

func (*graphqlTransport) kind() transportKind { return transportGraphQL }

var _ transport = (*graphqlTransport)(nil)

func newGraphQLTransport(c *Client) *graphqlTransport {
	return &graphqlTransport{gql: &gqlClient{c: c}}
}

// errNotMapped wraps errUnservable so the router falls through to REST.
var errNotMapped = fmt.Errorf("%w: graphql surface not mapped", errUnservable)

func (g *graphqlTransport) Get(ctx context.Context, p string, _ url.Values, _ bool) (json.RawMessage, http.Header, error) {
	switch {
	case strings.HasSuffix(stripQuery(p), "/topics"):
		raw, err := g.repoTopics(ctx, p)
		return raw, http.Header{}, gqlFallthrough(err)
	case isBareRepo(p):
		raw, err := g.repoMeta(ctx, p)
		return raw, http.Header{}, gqlFallthrough(err)
	}
	return nil, nil, errNotMapped
}

func (g *graphqlTransport) Paginate(ctx context.Context, p string, _ url.Values, _ int) ([]json.RawMessage, error) {
	if orgSubResource(stripQuery(p), "members") {
		items, err := g.orgMembers(ctx, p)
		if err != nil {
			return nil, gqlFallthrough(err)
		}
		return items, nil
	}
	return nil, errNotMapped
}

func (g *graphqlTransport) GetRaw(context.Context, string, url.Values, string) ([]byte, http.Header, error) {
	return nil, nil, errNotMapped
}

func (g *graphqlTransport) GetContentWithSHA(context.Context, string, string, bool) ([]byte, string, bool, error) {
	return nil, "", false, errNotMapped
}

func (g *graphqlTransport) ResolveRefCommitSHA(context.Context, string, string, string) (string, error) {
	return "", errNotMapped
}

// gqlFallthrough marks any graphql failure as unservable so the router falls
// through to REST; allow404 and permission divergence are handled there.
func gqlFallthrough(err error) error {
	if err == nil || errors.Is(err, errUnservable) {
		return err
	}
	return fmt.Errorf("%w: %v", errUnservable, err)
}

func orgSubResource(p, sub string) bool {
	i := strings.Index(p, "/orgs/")
	if i < 0 {
		return false
	}
	tail := p[i+len("/orgs/"):]
	j := strings.IndexByte(tail, '/')
	if j < 0 {
		return false
	}
	return strings.HasPrefix(tail[j+1:], sub)
}

// repoMeta maps a repo to the fields normalizeRepos reads. visibility is
// lowercased to match REST; default_branch is null on an empty repo.
func (g *graphqlTransport) repoMeta(ctx context.Context, p string) (json.RawMessage, error) {
	owner, repo, err := parseRepoPath(p)
	if err != nil {
		return nil, errNotMapped
	}
	var out struct {
		Repository *struct {
			DatabaseID    *int64 `json:"databaseId"`
			Name          string `json:"name"`
			NameWithOwner string `json:"nameWithOwner"`
			IsPrivate     bool   `json:"isPrivate"`
			IsArchived    bool   `json:"isArchived"`
			IsFork        bool   `json:"isFork"`
			Visibility    string `json:"visibility"`
			Owner         struct {
				Login string `json:"login"`
			} `json:"owner"`
			DefaultBranchRef *struct {
				Name string `json:"name"`
			} `json:"defaultBranchRef"`
		} `json:"repository"`
	}
	const q = `query($owner:String!,$name:String!){repository(owner:$owner,name:$name){databaseId name nameWithOwner isPrivate isArchived isFork visibility owner{login} defaultBranchRef{name}}}`
	if err := g.gql.query(ctx, q, map[string]any{"owner": owner, "name": repo}, &out); err != nil {
		return nil, err
	}
	if out.Repository == nil {
		return nil, &GhError{Status: 404, URL: "graphql:" + p, Body: "repository not found"}
	}
	r := out.Repository
	defaultBranch := json.RawMessage("null")
	if r.DefaultBranchRef != nil {
		defaultBranch = jsonStr(r.DefaultBranchRef.Name)
	}
	obj := map[string]json.RawMessage{
		"id":             jsonNum(r.DatabaseID),
		"name":           jsonStr(r.Name),
		"full_name":      jsonStr(r.NameWithOwner),
		"private":        jsonBool(r.IsPrivate),
		"archived":       jsonBool(r.IsArchived),
		"fork":           jsonBool(r.IsFork),
		"visibility":     jsonStr(strings.ToLower(r.Visibility)),
		"owner":          json.RawMessage(`{"login":` + jsonString(r.Owner.Login) + `}`),
		"default_branch": defaultBranch,
	}
	return marshalRaw(obj)
}

func (g *graphqlTransport) repoTopics(ctx context.Context, p string) (json.RawMessage, error) {
	owner, repo, err := parseRepoPath(p)
	if err != nil {
		return nil, errNotMapped
	}
	var out struct {
		Repository *struct {
			RepositoryTopics struct {
				Nodes []struct {
					Topic struct {
						Name string `json:"name"`
					} `json:"topic"`
				} `json:"nodes"`
			} `json:"repositoryTopics"`
		} `json:"repository"`
	}
	const q = `query($owner:String!,$name:String!){repository(owner:$owner,name:$name){repositoryTopics(first:100){nodes{topic{name}}}}}`
	if err := g.gql.query(ctx, q, map[string]any{"owner": owner, "name": repo}, &out); err != nil {
		return nil, err
	}
	if out.Repository == nil {
		return nil, &GhError{Status: 404, URL: "graphql:" + p, Body: "repository not found"}
	}
	names := make([]string, 0, len(out.Repository.RepositoryTopics.Nodes))
	for _, n := range out.Repository.RepositoryTopics.Nodes {
		names = append(names, n.Topic.Name)
	}
	return marshalRaw(map[string]any{"names": names})
}

// orgMembers maps /orgs/{org}/members to {login, id, type}, paginating the
// connection fully; type is always "User" for org membership.
func (g *graphqlTransport) orgMembers(ctx context.Context, p string) ([]json.RawMessage, error) {
	org, err := parseOrgPath(p)
	if err != nil {
		return nil, errNotMapped
	}
	const q = `query($login:String!,$cursor:String){organization(login:$login){membersWithRole(first:100,after:$cursor){pageInfo{hasNextPage endCursor} nodes{login databaseId}}}}`
	var users []json.RawMessage
	var cursor *string
	for {
		var out struct {
			Organization *struct {
				MembersWithRole struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						Login      string `json:"login"`
						DatabaseID *int64 `json:"databaseId"`
					} `json:"nodes"`
				} `json:"membersWithRole"`
			} `json:"organization"`
		}
		vars := map[string]any{"login": org}
		if cursor != nil {
			vars["cursor"] = *cursor
		}
		if err := g.gql.query(ctx, q, vars, &out); err != nil {
			return nil, err
		}
		if out.Organization == nil {
			return nil, &GhError{Status: 404, URL: "graphql:" + p, Body: "organization not found"}
		}
		for _, n := range out.Organization.MembersWithRole.Nodes {
			raw, err := marshalRaw(map[string]json.RawMessage{
				"login": jsonStr(n.Login),
				"id":    jsonNum(n.DatabaseID),
				"type":  jsonStr("User"),
			})
			if err != nil {
				return nil, err
			}
			users = append(users, raw)
		}
		if !out.Organization.MembersWithRole.PageInfo.HasNextPage {
			break
		}
		c := out.Organization.MembersWithRole.PageInfo.EndCursor
		cursor = &c
	}
	if users == nil {
		users = []json.RawMessage{}
	}
	return users, nil
}

func parseOrgPath(p string) (string, error) {
	p = stripQuery(p)
	i := strings.Index(p, "/orgs/")
	if i < 0 {
		return "", errors.New("not an org path: " + p)
	}
	tail := p[i+len("/orgs/"):]
	if j := strings.IndexByte(tail, '/'); j >= 0 {
		tail = tail[:j]
	}
	if tail == "" {
		return "", errors.New("not an org path: " + p)
	}
	return tail, nil
}

func jsonStr(s string) json.RawMessage { return json.RawMessage(jsonString(s)) }

func jsonBool(b bool) json.RawMessage {
	if b {
		return json.RawMessage("true")
	}
	return json.RawMessage("false")
}

func marshalRaw(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
