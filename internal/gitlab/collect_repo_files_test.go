package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func rawFilePath(base, repoPath string) string {
	return base + "/repository/files/" + url.PathEscape(repoPath) + "/raw"
}

// collectCodeowners fetches CODEOWNERS from each of GitLab's three valid
// locations; whichever exists is written raw under repo-files (cat-06/cat-04).
func TestCollectCodeownersWritesPresentFile(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.get[rawFilePath(base, ".gitlab/CODEOWNERS")] = json.RawMessage("* @team\n^[Optional]\n/.gitlab-ci.yml @ci\n")
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectCodeowners(context.Background(), cl, cp, "g/p", base, json.RawMessage(`{"default_branch":"main"}`)); err != nil {
		t.Fatalf("collectCodeowners: %v", err)
	}
	b, err := readRaw(cp.RunDir, engine.CollectGLRepoFile("g/p", ".gitlab/CODEOWNERS"))
	if err != nil {
		t.Fatalf("CODEOWNERS not written: %v", err)
	}
	if !strings.Contains(string(b), "Optional") {
		t.Errorf("CODEOWNERS = %q, want the raw file contents", b)
	}
	// The two absent locations must not produce files.
	if _, err := readRaw(cp.RunDir, engine.CollectGLRepoFile("g/p", "CODEOWNERS")); err == nil {
		t.Error("wrote a file for an absent root CODEOWNERS")
	}
}

// An entirely absent CODEOWNERS (every location 404/empty) is non-fatal and
// writes nothing — normalize reads that as "no CODEOWNERS control".
func TestCollectCodeownersAbsent(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectCodeowners(context.Background(), cl, cp, "g/p", base, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("absent CODEOWNERS must be non-fatal: %v", err)
	}
	for _, rp := range codeownersPaths {
		if _, err := readRaw(cp.RunDir, engine.CollectGLRepoFile("g/p", rp)); err == nil {
			t.Errorf("wrote a file for absent %s", rp)
		}
	}
}

// A soft 403 on a CODEOWNERS location is skipped, not aborted.
func TestCollectCodeownersSoftForbidden(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.softPath[rawFilePath(base, "CODEOWNERS")] = http.StatusForbidden
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectCodeowners(context.Background(), cl, cp, "g/p", base, json.RawMessage(`{"default_branch":"main"}`)); err != nil {
		t.Fatalf("soft-forbidden CODEOWNERS must not abort: %v", err)
	}
}

// collectDuoFiles fetches agent-config.yml and mcp.json, then lists the flows dir
// and fetches each .yaml/.yml blob (cat-13).
func TestCollectDuoFilesFetchesAllWiring(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.get[rawFilePath(base, ".gitlab/duo/agent-config.yml")] = json.RawMessage("flows:\n  - review\n")
	cl.get[rawFilePath(base, ".gitlab/duo/mcp.json")] = json.RawMessage(`{"servers":[{"url":"https://evil.example"}]}`)
	cl.list[base+"/repository/tree"] = []json.RawMessage{
		json.RawMessage(`{"type":"blob","path":".gitlab/duo/flows/review.yaml"}`),
		json.RawMessage(`{"type":"tree","path":".gitlab/duo/flows/sub"}`),
		json.RawMessage(`{"type":"blob","path":".gitlab/duo/flows/notes.txt"}`),
	}
	cl.get[rawFilePath(base, ".gitlab/duo/flows/review.yaml")] = json.RawMessage("agent:\n  provider: external\n")
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectDuoFiles(context.Background(), cl, cp, "g/p", base, json.RawMessage(`{"default_branch":"main"}`)); err != nil {
		t.Fatalf("collectDuoFiles: %v", err)
	}
	for _, rp := range []string{".gitlab/duo/agent-config.yml", ".gitlab/duo/mcp.json", ".gitlab/duo/flows/review.yaml"} {
		if _, err := readRaw(cp.RunDir, engine.CollectGLRepoFile("g/p", rp)); err != nil {
			t.Errorf("%s not written: %v", rp, err)
		}
	}
	// A non-yaml blob in the flows dir is skipped.
	if _, err := readRaw(cp.RunDir, engine.CollectGLRepoFile("g/p", ".gitlab/duo/flows/notes.txt")); err == nil {
		t.Error("wrote a non-yaml flows file")
	}
}

// When the flows dir listing soft-fails (absent dir → 404), the two fixed duo
// files are still collected and the pass is non-fatal.
func TestCollectDuoFilesFlowsDirAbsent(t *testing.T) {
	cl := newFake()
	base := "/projects/7"
	cl.softPath[base+"/repository/tree"] = http.StatusNotFound
	cl.get[rawFilePath(base, ".gitlab/duo/mcp.json")] = json.RawMessage(`{"servers":[]}`)
	cp := engine.CurrentPhase{RunDir: t.TempDir()}

	if err := collectDuoFiles(context.Background(), cl, cp, "g/p", base, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("absent flows dir must be non-fatal: %v", err)
	}
	if _, err := readRaw(cp.RunDir, engine.CollectGLRepoFile("g/p", ".gitlab/duo/mcp.json")); err != nil {
		t.Errorf("mcp.json not written when flows dir absent: %v", err)
	}
}
