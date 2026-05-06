package csrf

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
	if d.Name() != "csrf-disabled" {
		t.Errorf("Name() = %q, want %q", d.Name(), "csrf-disabled")
	}
	if d.Platform() != "jenkins" {
		t.Errorf("Platform() = %q, want %q", d.Platform(), "jenkins")
	}
	if d.Severity() != detections.SeverityMedium {
		t.Errorf("Severity() = %q, want %q", d.Severity(), detections.SeverityMedium)
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

func TestDetect_CSRFDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/json" {
			w.Header().Set("X-Jenkins", "2.426.3")
			w.Write([]byte(`{"mode":"NORMAL","useSecurity":true,"useCrumbs":false,"numExecutors":2}`))
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
		t.Fatalf("expected 1 finding for CSRF disabled, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != detections.VulnJenkinsCSRFDisabled {
		t.Errorf("finding type = %q, want %q", f.Type, detections.VulnJenkinsCSRFDisabled)
	}
	if f.Severity != detections.SeverityMedium {
		t.Errorf("severity = %q, want %q", f.Severity, detections.SeverityMedium)
	}
}

func TestDetect_CSRFEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/json" {
			w.Header().Set("X-Jenkins", "2.426.3")
			w.Write([]byte(`{"mode":"NORMAL","useSecurity":true,"useCrumbs":true,"numExecutors":2}`))
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
		t.Errorf("expected 0 findings when CSRF is enabled, got %d", len(findings))
	}
}
