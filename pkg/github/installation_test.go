package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ListInstallationRepos_Pagination(t *testing.T) {
	// total_count=3, per_page=2 => two pages; terminate on total_count.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/repositories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch page {
		case "1":
			fmt.Fprint(w, `{"total_count":3,"repository_selection":"selected","repositories":[
				{"name":"a","owner":{"login":"acme","type":"Organization"}},
				{"name":"b","owner":{"login":"acme","type":"Organization"}}]}`)
		default:
			fmt.Fprint(w, `{"total_count":3,"repository_selection":"selected","repositories":[
				{"name":"c","owner":{"login":"acme","type":"Organization"}}]}`)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "ghs_test")
	repos, selection, err := client.ListInstallationRepos(context.Background())
	if err != nil {
		t.Fatalf("ListInstallationRepos() error = %v", err)
	}
	if len(repos) != 3 {
		t.Errorf("got %d repos, want 3", len(repos))
	}
	if selection != "selected" {
		t.Errorf("selection = %q, want selected", selection)
	}
}

func TestClient_IsGitHubAppToken(t *testing.T) {
	if !NewClient("", "ghs_x").IsGitHubAppToken() {
		t.Error("ghs_ token should be app token")
	}
	if NewClient("", "ghp_x").IsGitHubAppToken() {
		t.Error("ghp_ token should not be app token")
	}
}
