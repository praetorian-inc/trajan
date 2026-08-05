//go:build integration

package jenkins

import (
	"context"
	"os"
	"testing"
)

func getTestClient(t *testing.T) *Client {
	t.Helper()
	url := os.Getenv("JENKINS_TEST_URL")
	user := os.Getenv("JENKINS_TEST_USER")
	token := os.Getenv("JENKINS_TEST_TOKEN")
	if url == "" {
		t.Skip("JENKINS_TEST_URL not set")
	}
	return NewClient(url, token, WithUsername(user))
}

func TestIntegration_GetServerInfo(t *testing.T) {
	c := getTestClient(t)
	info, err := c.GetServerInfo(context.Background())
	if err != nil {
		t.Fatalf("GetServerInfo: %v", err)
	}
	if info.Version == "" {
		t.Error("expected non-empty version")
	}
	t.Logf("Jenkins version: %s", info.Version)
}

func TestIntegration_GetWhoAmI(t *testing.T) {
	c := getTestClient(t)
	who, err := c.GetWhoAmI(context.Background())
	if err != nil {
		t.Fatalf("GetWhoAmI: %v", err)
	}
	if who.Name == "" {
		t.Error("expected non-empty name")
	}
	t.Logf("Authenticated as: %s", who.Name)
}

func TestIntegration_ListNodes(t *testing.T) {
	c := getTestClient(t)
	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) == 0 {
		t.Error("expected at least one node (built-in)")
	}
	for _, n := range nodes {
		t.Logf("Node: %s (offline=%v, executors=%d)", n.DisplayName, n.Offline, n.NumExecutors)
	}
}

func TestIntegration_ListPlugins(t *testing.T) {
	c := getTestClient(t)
	plugins, err := c.ListPlugins(context.Background())
	if err != nil {
		t.Fatalf("ListPlugins: %v", err)
	}
	if len(plugins) == 0 {
		t.Error("expected at least one plugin")
	}
	t.Logf("Found %d plugins", len(plugins))
}

func TestIntegration_ListJobsRecursive(t *testing.T) {
	c := getTestClient(t)
	jobs, err := c.ListJobsRecursive(context.Background())
	if err != nil {
		t.Fatalf("ListJobsRecursive: %v", err)
	}
	if len(jobs) == 0 {
		t.Error("expected at least one job")
	}
	for _, j := range jobs {
		t.Logf("Job: %s (class=%s, inFolder=%v)", j.Name, j.Class, j.InFolder)
	}
}

func TestIntegration_CheckScriptConsole(t *testing.T) {
	c := getTestClient(t)
	accessible, statusCode, err := c.CheckScriptConsole(context.Background())
	if err != nil {
		t.Fatalf("CheckScriptConsole: %v", err)
	}
	t.Logf("Script console accessible=%v (status=%d)", accessible, statusCode)
}

func TestIntegration_PostScript(t *testing.T) {
	c := getTestClient(t)
	out, err := c.PostScript(context.Background(), "println 'integration-test'")
	if err != nil {
		t.Fatalf("PostScript: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty script output")
	}
	t.Logf("Script output: %s", out)
}

func TestIntegration_FetchCrumb(t *testing.T) {
	c := getTestClient(t)
	crumb, err := c.fetchCrumb(context.Background())
	if err != nil {
		t.Fatalf("fetchCrumb: %v", err)
	}
	if crumb != nil {
		t.Logf("Crumb field=%s, value=%s", crumb.CrumbRequestField, crumb.Crumb)
	} else {
		t.Log("CSRF disabled (no crumb)")
	}
}
