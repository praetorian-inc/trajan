package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// gqlFixtureServer serves a canned GraphQL `data` payload (the shape GitHub
// returns) so a mapper can be driven against a captured response and asserted to
// equal the REST `data` shape the collectors expect. responses are consumed in
// order, one per POST, so paginated mappers can be exercised across pages.
func gqlFixtureServer(t *testing.T, responses ...string) *graphqlTransport {
	t.Helper()
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("graphql server got %s, want POST", r.Method)
		}
		body := `{"data":` + responses[min(i, len(responses)-1)] + `}`
		i++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	old := graphqlEndpoint
	graphqlEndpoint = srv.URL
	t.Cleanup(func() { graphqlEndpoint = old })

	return newGraphQLTransport(NewClient("tok"))
}

// asMap parses a json.RawMessage to map[string]any for shape comparison (numbers
// land as float64, matching what the normalizer's json decode would produce).
func asMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not an object: %v (%s)", err, raw)
	}
	return m
}

func TestGraphQLRepoMetaMapsToRESTShape(t *testing.T) {
	// captured GraphQL response for a private, non-archived repo with a default
	// branch — uppercase visibility enum, databaseId numeric.
	g := gqlFixtureServer(t, `{
      "repository": {
        "databaseId": 123456,
        "name": "fr-02-02",
        "nameWithOwner": "ghektestorg/fr-02-02",
        "isPrivate": true,
        "isArchived": false,
        "isFork": false,
        "visibility": "PRIVATE",
        "owner": {"login": "ghektestorg"},
        "defaultBranchRef": {"name": "main"}
      }
    }`)

	raw, _, err := g.Get(context.Background(), "/repos/ghektestorg/fr-02-02", nil, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got := asMap(t, raw)
	want := map[string]any{
		"id":             float64(123456),
		"name":           "fr-02-02",
		"full_name":      "ghektestorg/fr-02-02",
		"private":        true,
		"archived":       false,
		"fork":           false,
		"visibility":     "private", // lowercased to match REST
		"owner":          map[string]any{"login": "ghektestorg"},
		"default_branch": "main",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("repo meta shape mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestGraphQLRepoMetaEmptyRepoNullDefaultBranch(t *testing.T) {
	g := gqlFixtureServer(t, `{
      "repository": {
        "databaseId": 9,
        "name": "empty",
        "nameWithOwner": "o/empty",
        "isPrivate": false,
        "isArchived": false,
        "isFork": false,
        "visibility": "PUBLIC",
        "owner": {"login": "o"},
        "defaultBranchRef": null
      }
    }`)
	raw, _, err := g.Get(context.Background(), "/repos/o/empty", nil, false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got := asMap(t, raw)
	if got["default_branch"] != nil {
		t.Fatalf("empty repo default_branch = %#v, want null", got["default_branch"])
	}
	if got["visibility"] != "public" {
		t.Fatalf("visibility = %#v, want public", got["visibility"])
	}
}

func TestGraphQLRepoTopicsMapsToRESTShape(t *testing.T) {
	g := gqlFixtureServer(t, `{
      "repository": {
        "repositoryTopics": {
          "nodes": [
            {"topic": {"name": "security"}},
            {"topic": {"name": "ci"}}
          ]
        }
      }
    }`)
	raw, _, err := g.Get(context.Background(), "/repos/o/r/topics", nil, true)
	if err != nil {
		t.Fatalf("Get topics: %v", err)
	}
	got := asMap(t, raw)
	names, ok := got["names"].([]any)
	if !ok {
		t.Fatalf("topics has no names array: %#v", got)
	}
	if len(names) != 2 || names[0] != "security" || names[1] != "ci" {
		t.Fatalf("topics names = %#v, want [security ci]", names)
	}
}

func TestGraphQLRepoTopicsEmptyIsArrayNotNull(t *testing.T) {
	g := gqlFixtureServer(t, `{"repository":{"repositoryTopics":{"nodes":[]}}}`)
	raw, _, err := g.Get(context.Background(), "/repos/o/r/topics", nil, true)
	if err != nil {
		t.Fatalf("Get topics: %v", err)
	}
	// REST {"names":[]} — names must serialize as [] (rules key on presence).
	if string(raw) != `{"names":[]}` {
		t.Fatalf("empty topics = %s, want {\"names\":[]}", raw)
	}
}

func TestGraphQLOrgMembersMapsToRESTShapeAndPaginates(t *testing.T) {
	// two pages: page 1 hasNextPage true with an endCursor, page 2 terminal.
	page1 := `{
      "organization": {
        "membersWithRole": {
          "pageInfo": {"hasNextPage": true, "endCursor": "C1"},
          "nodes": [{"login":"alice","databaseId":1},{"login":"bob","databaseId":2}]
        }
      }
    }`
	page2 := `{
      "organization": {
        "membersWithRole": {
          "pageInfo": {"hasNextPage": false, "endCursor": ""},
          "nodes": [{"login":"carol","databaseId":3}]
        }
      }
    }`
	g := gqlFixtureServer(t, page1, page2)

	items, err := g.Paginate(context.Background(), "/orgs/ghektestorg/members", nil, 100)
	if err != nil {
		t.Fatalf("Paginate members: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("members count = %d, want 3 (paginated)", len(items))
	}
	// each must carry login/id/type exactly as loginIDType reads them.
	first := asMap(t, items[0])
	want := map[string]any{"login": "alice", "id": float64(1), "type": "User"}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("member shape mismatch\n got: %#v\nwant: %#v", first, want)
	}
	if asMap(t, items[2])["login"] != "carol" {
		t.Fatalf("pagination dropped page 2: %s", items[2])
	}
}

// Any graphql error (NOT_FOUND, FORBIDDEN/scopes) must be unservable so the
// router falls through to REST rather than aborting a surface REST can serve.
func TestGraphQLErrorsAreUnservable(t *testing.T) {
	for _, typ := range []string{"NOT_FOUND", "FORBIDDEN", "INSUFFICIENT_SCOPES"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data":null,"errors":[{"type":"` + typ + `","message":"x"}]}`))
		}))
		old := graphqlEndpoint
		graphqlEndpoint = srv.URL
		g := newGraphQLTransport(NewClient("tok"))

		_, _, err := g.Get(context.Background(), "/repos/o/r", nil, false)
		if !errors.Is(err, errUnservable) {
			t.Fatalf("%s err = %v, want errUnservable (fall through to REST)", typ, err)
		}
		var ghErr *GhError
		if errors.As(err, &ghErr) {
			t.Fatalf("%s must not surface as a GhError (router would not fall through)", typ)
		}
		srv.Close()
		graphqlEndpoint = old
	}
}

func TestGraphQLUnmappedSurfaceFallsThrough(t *testing.T) {
	g := newGraphQLTransport(NewClient("tok"))
	_, _, err := g.Get(context.Background(), "/orgs/o/rulesets", nil, false)
	if !errors.Is(err, errUnservable) {
		t.Fatalf("unmapped Get err = %v, want unservable", err)
	}
}
