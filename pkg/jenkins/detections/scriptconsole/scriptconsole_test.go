package scriptconsole

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
	"github.com/stretchr/testify/require"
)

func TestRequiresAPI(t *testing.T) {
	require.True(t, New().RequiresAPI(), "this detection must declare RequiresAPI=true; without it, --local mode will run it and it will return nil")
}

func TestNew(t *testing.T) {
	d := New()
	if d.Name() != "script-console" {
		t.Errorf("Name() = %q, want %q", d.Name(), "script-console")
	}
	if d.Platform() != "jenkins" {
		t.Errorf("Platform() = %q, want %q", d.Platform(), "jenkins")
	}
	if d.Severity() != detections.SeverityCritical {
		t.Errorf("Severity() = %q, want %q", d.Severity(), detections.SeverityCritical)
	}
}

func TestDetect_NoMetadata(t *testing.T) {
	d := New()
	g := graph.NewGraph()
	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings without metadata, got %d", len(findings))
	}
}

func TestDetect_ConsoleAccessible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/script" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html>Script Console</html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := jenkins.NewClient(srv.URL, "tok", jenkins.WithUsername("admin"))
	g := graph.NewGraph()
	g.SetMetadata("jenkins_client", client)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != detections.VulnJenkinsScriptConsole {
		t.Errorf("finding type = %q, want %q", f.Type, detections.VulnJenkinsScriptConsole)
	}
	if f.Severity != detections.SeverityCritical {
		t.Errorf("severity = %q, want %q", f.Severity, detections.SeverityCritical)
	}
	if f.Workflow != "/script" {
		t.Errorf("workflow = %q, want %q", f.Workflow, "/script")
	}
}

func TestDetect_ConsoleNotAccessible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/script" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := jenkins.NewClient(srv.URL, "tok", jenkins.WithUsername("admin"))
	g := graph.NewGraph()
	g.SetMetadata("jenkins_client", client)

	d := New()
	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when console is forbidden, got %d", len(findings))
	}
}
