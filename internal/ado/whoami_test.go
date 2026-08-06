package ado

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
)

const stubConnectionData = `{
  "authenticatedUser": {
    "id": "11111111-2222-3333-4444-555555555555",
    "subjectDescriptor": "aad.QWRhTG92ZWxhY2U",
    "providerDisplayName": "Ada Lovelace",
    "properties": {
      "Account": {"$type": "System.String", "$value": "ada@example.test"}
    }
  },
  "deploymentType": "hosted"
}`

func repointHosts(t *testing.T, base string) {
	t.Helper()
	for k := range hostBase {
		prev := hostBase[k]
		hostBase[k] = base
		t.Cleanup(func() { hostBase[k] = prev })
	}
}

// Serves connectionData plus every probe surface as a non-empty 2xx list, with
// individual path suffixes overridden. An override that never matches fails the test,
// so a renamed probe path cannot silently disarm the case that relies on it.
func whoamiStub(t *testing.T, status map[string]int, body map[string]string) func() []string {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	hit := map[string]bool{}
	match := func(suffix, p string) bool {
		if !strings.HasSuffix(p, suffix) {
			return false
		}
		mu.Lock()
		hit[suffix] = true
		mu.Unlock()
		return true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		for suffix, code := range status {
			if match(suffix, r.URL.Path) {
				w.WriteHeader(code)
				return
			}
		}
		for suffix, b := range body {
			if match(suffix, r.URL.Path) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, b)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_apis/connectionData"):
			io.WriteString(w, stubConnectionData)
		case strings.HasSuffix(r.URL.Path, "/_apis/projects"):
			io.WriteString(w, `{"count":2,"value":[{"name":"Alpha#Proj"},{"name":"Beta"}]}`)
		default:
			io.WriteString(w, `{"count":1,"value":[{"id":1}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	repointHosts(t, srv.URL)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for suffix := range status {
			if !hit[suffix] {
				t.Errorf("status override %q never matched a request: %v", suffix, paths)
			}
		}
		for suffix := range body {
			if !hit[suffix] {
				t.Errorf("body override %q never matched a request: %v", suffix, paths)
			}
		}
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(paths)
	}
}

func runWhoAmI(t *testing.T) (string, error) {
	t.Helper()
	for _, k := range []string{
		"TRAJAN_ADO_TOKEN", "AZURE_DEVOPS_PAT", "AZDO_PAT", "AZURE_DEVOPS_EXT_PAT",
		"AZURE_BEARER_TOKEN", "SYSTEM_ACCESSTOKEN",
	} {
		t.Setenv(k, "")
	}
	prev := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = prev
		r.Close()
	}()
	callErr := WhoAmI(t.Context(), "Contoso", "", "")
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), callErr
}

func TestWhoAmI_Identity(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	whoamiStub(t, nil, nil)

	out, err := runWhoAmI(t)
	if err != nil {
		t.Fatal(err)
	}
	want := "identity: Ada Lovelace <ada@example.test>\n" +
		"id: 11111111-2222-3333-4444-555555555555 (aad)\n" +
		"organization: Contoso (hosted)\n" +
		"projects: 2\n" +
		"reachable: Projects, Repositories, Pipelines, Agent pools, Variable groups, Service connections, Artifact feeds\n"
	if out != want {
		t.Fatalf("output mismatch\n got: %q\nwant: %q", out, want)
	}
}

func TestWhoAmI_InvalidPATHTML(t *testing.T) {
	t.Setenv("ADO_PAT", "bad")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html>sign in</html>")
	}))
	t.Cleanup(srv.Close)
	repointHosts(t, srv.URL)

	out, err := runWhoAmI(t)
	if err == nil {
		t.Fatalf("want error for HTML response, got output %q", out)
	}
	if !strings.Contains(err.Error(), "invalid or expired PAT") {
		t.Fatalf("want an invalid-PAT error, got %v", err)
	}
	if out != "" {
		t.Fatalf("want no output on auth failure, got %q", out)
	}
}

func TestWhoAmI_ForbiddenSurface(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	whoamiStub(t, map[string]int{"/_apis/distributedtask/variablegroups": http.StatusForbidden}, nil)

	out, err := runWhoAmI(t)
	if err != nil {
		t.Fatal(err)
	}
	line := "reachable: Projects, Repositories, Pipelines, Agent pools, Service connections, Artifact feeds\n"
	if !strings.Contains(out, line) {
		t.Fatalf("want %q in output, got %q", line, out)
	}
}

func TestWhoAmI_HardFailureDoesNotAbort(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	prev := sleepFn
	sleepFn = func(context.Context, float64) {}
	t.Cleanup(func() { sleepFn = prev })
	whoamiStub(t, map[string]int{"/_apis/distributedtask/pools": http.StatusInternalServerError}, nil)

	out, err := runWhoAmI(t)
	if err != nil {
		t.Fatal(err)
	}
	line := "reachable: Projects, Repositories, Pipelines, Variable groups, Service connections, Artifact feeds\n"
	if !strings.Contains(out, line) {
		t.Fatalf("want %q in output, got %q", line, out)
	}
}

// Empty-but-2xx is reachable: status decides, not list length.
func TestWhoAmI_EmptySurfaceStillReachable(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	whoamiStub(t, nil, map[string]string{
		"/_apis/distributedtask/variablegroups": `{"count":0,"value":[]}`,
	})

	out, err := runWhoAmI(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Variable groups") {
		t.Fatalf("empty 2xx surface must still be reachable, got %q", out)
	}
}

func TestWhoAmI_NoProjectsSkipsPerProjectProbes(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	paths := whoamiStub(t, nil, map[string]string{"/_apis/projects": `{"count":0,"value":[]}`})

	out, err := runWhoAmI(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "projects: 0\n") {
		t.Fatalf("want projects: 0, got %q", out)
	}
	if !strings.Contains(out, "reachable: Projects, Agent pools, Artifact feeds\n") {
		t.Fatalf("per-project surfaces must be absent, got %q", out)
	}
	if got := paths(); len(got) != 4 {
		t.Fatalf("want 4 requests with zero projects, got %d: %v", len(got), got)
	}
}

// An org past ADO's project page size answers /_apis/projects across pages, so the
// printed count is only right if the continuation token is followed to the end.
func TestWhoAmI_PagedProjectsCountsEveryPage(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_apis/connectionData"):
			io.WriteString(w, stubConnectionData)
		case strings.HasSuffix(r.URL.Path, "/_apis/projects"):
			if r.URL.Query().Get("continuationToken") == "" {
				w.Header().Set("x-ms-continuationtoken", "page2")
				io.WriteString(w, `{"count":2,"value":[{"name":"First"},{"name":"Second"}]}`)
				return
			}
			io.WriteString(w, `{"count":1,"value":[{"name":"Third"}]}`)
		default:
			io.WriteString(w, `{"count":1,"value":[{"id":1}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	repointHosts(t, srv.URL)

	out, err := runWhoAmI(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "projects: 3\n") {
		t.Fatalf("want the total across both pages, got %q", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(paths, " "), "/First/_apis/git/repositories") {
		t.Fatalf("per-project probes must use the first page's first project: %v", paths)
	}
	if got := len(paths); got != 9 {
		t.Fatalf("want 9 requests (8 + one extra project page), got %d: %v", got, paths)
	}
}

// A project with no name would build "//_apis/...", which real ADO answers 400/404
// on three of the four surfaces — reporting them denied when they are not.
func TestWhoAmI_SkipsNamelessProject(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	paths := whoamiStub(t, nil, map[string]string{
		"/_apis/projects": `{"count":2,"value":[{"id":"no-name"},{"name":"Named"}]}`,
	})

	out, err := runWhoAmI(t)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(paths(), " ")
	if strings.Contains(joined, "//_apis/git/repositories") {
		t.Fatalf("probed an empty project segment: %v", paths())
	}
	if !strings.Contains(joined, "/Named/_apis/git/repositories") {
		t.Fatalf("want probes against the first named project, got %v", paths())
	}
	if !strings.Contains(out, "reachable: Projects, Repositories, Pipelines, Agent pools, Variable groups, Service connections, Artifact feeds\n") {
		t.Fatalf("every surface must still read reachable, got %q", out)
	}
}

func TestWhoAmI_HappyPathRequestCount(t *testing.T) {
	t.Setenv("ADO_PAT", "pat")
	paths := whoamiStub(t, nil, nil)

	if _, err := runWhoAmI(t); err != nil {
		t.Fatal(err)
	}
	got := paths()
	if len(got) != 8 {
		t.Fatalf("want 8 requests (1 identity + 3 org + 4 project), got %d: %v", len(got), got)
	}
	if !strings.Contains(strings.Join(got, " "), "/Alpha%23Proj/_apis/git/repositories") {
		t.Fatalf("per-project probes must target the first project's escaped name: %v", got)
	}
}
