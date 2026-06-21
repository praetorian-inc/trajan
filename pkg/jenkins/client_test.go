package jenkins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_BasicAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"jobs":[]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "mytoken", WithUsername("admin"))
	var resp JobsResponse
	err := c.getJSON(context.Background(), "/api/json", &resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Basic auth for "admin:mytoken" = "YWRtaW46bXl0b2tlbg=="
	want := "Basic YWRtaW46bXl0b2tlbg=="
	if gotAuth != want {
		t.Errorf("auth header = %q, want %q", gotAuth, want)
	}
}

func TestClient_AnonymousAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"jobs":[]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "") // No token, no username = anonymous
	var resp JobsResponse
	err := c.getJSON(context.Background(), "/api/json", &resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "" {
		t.Errorf("anonymous request should have no auth header, got %q", gotAuth)
	}
}

func TestClient_PostFormWithCrumb(t *testing.T) {
	var gotCrumb string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crumbIssuer/api/json":
			w.Write([]byte(`{"crumb":"test-crumb-123","crumbRequestField":"Jenkins-Crumb"}`))
		case "/script":
			gotCrumb = r.Header.Get("Jenkins-Crumb")
			w.Write([]byte(`Result: OK`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))
	body, err := c.postForm(context.Background(), "/script", map[string]string{"script": "println 'hi'"})
	if err != nil {
		t.Fatalf("postForm failed: %v", err)
	}
	if gotCrumb != "test-crumb-123" {
		t.Errorf("crumb header = %q, want %q", gotCrumb, "test-crumb-123")
	}
	if string(body) != "Result: OK" {
		t.Errorf("body = %q, want %q", string(body), "Result: OK")
	}
}

func TestClient_PostFormCSRFDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound) // CSRF disabled
		case "/script":
			w.Write([]byte(`Result: OK`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))
	body, err := c.postForm(context.Background(), "/script", map[string]string{"script": "println 'hi'"})
	if err != nil {
		t.Fatalf("postForm should succeed when CSRF disabled: %v", err)
	}
	if string(body) != "Result: OK" {
		t.Errorf("body = %q", string(body))
	}
}

func TestClient_GetServerInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jenkins", "2.426.3")
		w.Write([]byte(`{"mode":"NORMAL","useSecurity":true,"useCrumbs":true,"numExecutors":2}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	info, err := c.GetServerInfo(context.Background())
	if err != nil {
		t.Fatalf("GetServerInfo: %v", err)
	}
	if info.Version != "2.426.3" {
		t.Errorf("version = %q, want %q", info.Version, "2.426.3")
	}
	if !info.UseSecurity {
		t.Error("expected useSecurity=true")
	}
}

func TestClient_GetWhoAmI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"admin","anonymous":false,"authorities":["authenticated","admin"]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))
	who, err := c.GetWhoAmI(context.Background())
	if err != nil {
		t.Fatalf("GetWhoAmI: %v", err)
	}
	if who.Name != "admin" {
		t.Errorf("name = %q, want %q", who.Name, "admin")
	}
}

func TestClient_PostScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crumbIssuer/api/json":
			w.Write([]byte(`{"crumb":"c","crumbRequestField":"Jenkins-Crumb"}`))
		case "/scriptText":
			r.ParseForm()
			w.Write([]byte("Result: " + r.FormValue("script")))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))
	out, err := c.PostScript(context.Background(), "println 'hello'")
	if err != nil {
		t.Fatalf("PostScript: %v", err)
	}
	if out != "Result: println 'hello'" {
		t.Errorf("output = %q", out)
	}
}

func TestFlattenJobs_Empty(t *testing.T) {
	result := flattenJobs(nil, "")
	if result != nil {
		t.Errorf("flattenJobs(nil, \"\") = %v, want nil", result)
	}
}

func TestFlattenJobs_FlatList(t *testing.T) {
	jobs := []Job{
		{Name: "job1", URL: "http://jenkins/job/job1"},
		{Name: "job2", URL: "http://jenkins/job/job2"},
	}
	result := flattenJobs(jobs, "")
	if len(result) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(result))
	}
	for _, j := range result {
		if j.InFolder {
			t.Errorf("job %q should not be InFolder", j.Name)
		}
	}
}

func TestFlattenJobs_NestedFolders(t *testing.T) {
	jobs := []Job{
		{
			Name: "folder1",
			Jobs: []Job{
				{Name: "nested-job-a", URL: "http://jenkins/job/folder1/job/nested-job-a"},
				{Name: "nested-job-b", URL: "http://jenkins/job/folder1/job/nested-job-b"},
			},
		},
		{Name: "top-level-job"},
	}

	result := flattenJobs(jobs, "")
	if len(result) != 3 {
		t.Fatalf("expected 3 jobs, got %d", len(result))
	}

	// Check that nested jobs have FullName set and InFolder=true
	nestedCount := 0
	for _, j := range result {
		if j.InFolder {
			nestedCount++
			if !strings.HasPrefix(j.FullName, "folder1/") {
				t.Errorf("nested job FullName = %q, expected prefix 'folder1/'", j.FullName)
			}
		}
	}
	if nestedCount != 2 {
		t.Errorf("expected 2 nested (InFolder) jobs, got %d", nestedCount)
	}
}

func TestClient_StringRedactsToken(t *testing.T) {
	c := NewClient("http://jenkins.example.com", "super-secret-token", WithUsername("admin"))

	str := c.String()
	if strings.Contains(str, "super-secret-token") {
		t.Error("String() should not contain the actual token")
	}
	if !strings.Contains(str, "REDACTED") {
		t.Error("String() should contain REDACTED")
	}

	goStr := c.GoString()
	if strings.Contains(goStr, "super-secret-token") {
		t.Error("GoString() should not contain the actual token")
	}
	if !strings.Contains(goStr, "REDACTED") {
		t.Error("GoString() should contain REDACTED")
	}

	// Also test through fmt to ensure the interface works
	formatted := fmt.Sprintf("client=%v", c)
	if strings.Contains(formatted, "super-secret-token") {
		t.Error("fmt.Sprintf with percent-v should not contain the actual token")
	}
}

func TestClient_CheckScriptConsole_Accessible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/script" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html>Script Console</html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))
	accessible, statusCode, err := c.CheckScriptConsole(context.Background())
	if err != nil {
		t.Fatalf("CheckScriptConsole() error: %v", err)
	}
	if !accessible {
		t.Error("expected accessible=true for 200 response")
	}
	if statusCode != 200 {
		t.Errorf("statusCode = %d, want 200", statusCode)
	}
}

func TestClient_CheckScriptConsole_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/script" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))
	accessible, statusCode, err := c.CheckScriptConsole(context.Background())
	if err != nil {
		t.Fatalf("CheckScriptConsole() error: %v", err)
	}
	if accessible {
		t.Error("expected accessible=false for 403 response")
	}
	if statusCode != 403 {
		t.Errorf("statusCode = %d, want 403", statusCode)
	}
}

func TestClient_FetchCrumbRetriesAfterTransientError(t *testing.T) {
	crumbCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crumbIssuer/api/json":
			crumbCalls++
			if crumbCalls == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write([]byte(`{"crumb":"retry-crumb","crumbRequestField":"Jenkins-Crumb"}`))
		case "/script":
			w.Write([]byte("OK"))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))

	// First postForm call should fail because fetchCrumb gets a 500.
	_, err := c.postForm(context.Background(), "/script", map[string]string{"script": "x"})
	if err == nil {
		t.Fatal("expected error on first postForm when crumb returns 500")
	}

	// Second postForm should succeed because fetchCrumb retries (crumbFetched
	// was not set on the transient error).
	_, err = c.postForm(context.Background(), "/script", map[string]string{"script": "x"})
	if err != nil {
		t.Fatalf("second postForm should succeed after crumb retry: %v", err)
	}

	if crumbCalls != 2 {
		t.Errorf("crumb issuer called %d times, want 2", crumbCalls)
	}
}

func TestClient_CSRFDisabled(t *testing.T) {
	t.Run("false before any fetch", func(t *testing.T) {
		c := NewClient("http://localhost:9999", "tok", WithUsername("admin"))
		if c.CSRFDisabled() {
			t.Error("CSRFDisabled() should be false before any crumb fetch")
		}
	})

	t.Run("true after 404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/crumbIssuer/api/json":
				w.WriteHeader(http.StatusNotFound)
			case "/script":
				w.Write([]byte("OK"))
			}
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "tok", WithUsername("admin"))

		// Trigger crumb fetch via postForm.
		_, err := c.postForm(context.Background(), "/script", map[string]string{"script": "x"})
		if err != nil {
			t.Fatalf("postForm error: %v", err)
		}
		if !c.CSRFDisabled() {
			t.Error("CSRFDisabled() should be true after 404 from crumb issuer")
		}
	})

	t.Run("false after successful crumb fetch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/crumbIssuer/api/json":
				w.Write([]byte(`{"crumb":"c","crumbRequestField":"Jenkins-Crumb"}`))
			case "/script":
				w.Write([]byte("OK"))
			}
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "tok", WithUsername("admin"))

		_, err := c.postForm(context.Background(), "/script", map[string]string{"script": "x"})
		if err != nil {
			t.Fatalf("postForm error: %v", err)
		}
		if c.CSRFDisabled() {
			t.Error("CSRFDisabled() should be false after successful crumb fetch")
		}
	})
}

func TestClient_ListJobsRecursive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/json") {
			w.Write([]byte(`{
				"jobs": [
					{"name": "top-level-job", "url": "http://jenkins/job/top-level-job", "color": "blue"},
					{
						"name": "folder1",
						"url": "http://jenkins/job/folder1",
						"_class": "com.cloudbees.hudson.plugins.folder.Folder",
						"jobs": [
							{"name": "nested-job", "url": "http://jenkins/job/folder1/job/nested-job", "color": "blue"}
						]
					}
				]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", WithUsername("admin"))
	jobs, err := c.ListJobsRecursive(context.Background())
	if err != nil {
		t.Fatalf("ListJobsRecursive: %v", err)
	}

	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(jobs))
	}

	// Find the nested job and verify its properties.
	var nested *Job
	for i := range jobs {
		if jobs[i].Name == "nested-job" {
			nested = &jobs[i]
			break
		}
	}
	if nested == nil {
		t.Fatal("nested-job not found in flattened results")
	}
	if !nested.InFolder {
		t.Error("nested job should have InFolder=true")
	}
	if nested.FullName != "folder1/nested-job" {
		t.Errorf("nested job FullName = %q, want %q", nested.FullName, "folder1/nested-job")
	}
}
