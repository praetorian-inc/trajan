package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestPlatform_EnumerateToken_GitHubApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" || r.URL.Path == "/user/orgs" {
			t.Errorf("app token must not call %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"total_count":2,"repository_selection":"all","repositories":[
			{"name":"a","owner":{"login":"acme","type":"Organization"}},
			{"name":"b","owner":{"login":"acme","type":"Organization"}}]}`)
	}))
	defer server.Close()

	p := NewPlatform()
	if err := p.Init(context.Background(), platforms.Config{BaseURL: server.URL, Token: "ghs_test"}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	result, err := p.EnumerateToken(context.Background())
	if err != nil {
		t.Fatalf("EnumerateToken() error = %v", err)
	}
	if result.TokenInfo == nil || result.TokenInfo.Type != TokenTypeGitHubApp {
		t.Fatalf("token type not github_app: %+v", result.TokenInfo)
	}
	if result.AccessibleRepos != 2 {
		t.Errorf("AccessibleRepos = %d, want 2", result.AccessibleRepos)
	}
	if result.RepositorySelection != "all" {
		t.Errorf("RepositorySelection = %q, want all", result.RepositorySelection)
	}
	if len(result.Organizations) != 1 || result.Organizations[0].Name != "acme" {
		t.Errorf("Organizations = %+v, want [acme]", result.Organizations)
	}
}

func TestPlatform_EnumerateRepos_GitHubAppSelf(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user/orgs" || r.URL.Path == "/user/repos" {
			t.Errorf("app token must not call %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"total_count":1,"repository_selection":"selected","repositories":[
			{"name":"a","owner":{"login":"acme","type":"Organization"},"private":true}]}`)
	}))
	defer server.Close()

	p := NewPlatform()
	if err := p.Init(context.Background(), platforms.Config{BaseURL: server.URL, Token: "ghs_test"}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	result, err := p.EnumerateRepos(context.Background(), platforms.Target{Type: platforms.TargetUser, Value: ""})
	if err != nil {
		t.Fatalf("EnumerateRepos() error = %v", err)
	}
	if len(result.Repositories) != 1 || result.Repositories[0].Name != "a" {
		t.Errorf("Repositories = %+v, want [a]", result.Repositories)
	}
}
