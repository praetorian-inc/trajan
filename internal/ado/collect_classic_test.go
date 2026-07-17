package ado

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func raws(ss ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(ss))
	for i, s := range ss {
		out[i] = json.RawMessage(s)
	}
	return out
}

// Union of /build/definitions and /pipelines: dedup by id (first name wins),
// sorted output.
func TestPipelineIDUnion(t *testing.T) {
	m := map[int64]string{}
	addPipelineIDs(m, raws(`{"id":3,"name":"c"}`, `{"id":1,"name":"a"}`, `{"id":0}`))
	addPipelineIDs(m, raws(`{"id":1,"name":"dup"}`, `{"id":2,"name":"b"}`))
	got := sortedIDs(m)
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("union ids = %v, want [1 2 3]", got)
	}
	if m[1] != "a" {
		t.Errorf("first name should win: id 1 = %q, want a", m[1])
	}
	if ids := collectIDs(raws(`{"id":7}`, `{"id":0}`, `{"name":"x"}`)); len(ids) != 1 || ids[0] != 7 {
		t.Errorf("collectIDs = %v, want [7] (id 0 and absent dropped)", ids)
	}
}

// panicADO fails the test if the collector makes any HTTP call.
type panicADO struct{ t *testing.T }

func (p panicADO) Get(context.Context, string, string, string, url.Values, bool) (json.RawMessage, http.Header, error) {
	p.t.Fatal("classic pipeline must not trigger a git-items fetch")
	return nil, nil, nil
}
func (p panicADO) GetRaw(context.Context, string, string, string, url.Values) ([]byte, http.Header, error) {
	p.t.Fatal("unexpected GetRaw")
	return nil, nil, nil
}
func (p panicADO) Post(context.Context, string, string, string, url.Values, any) (json.RawMessage, error) {
	p.t.Fatal("unexpected Post")
	return nil, nil
}
func (p panicADO) Paginate(context.Context, string, string, string, url.Values) ([]json.RawMessage, error) {
	p.t.Fatal("unexpected Paginate")
	return nil, nil
}

// A classic/designer definition (no yamlFilename) must be skipped for YAML
// collection — its steps live in the full definition's process.phases.
func TestCollectPipelineYAML_SkipsClassic(t *testing.T) {
	cp := engineCP(t.TempDir())
	full := json.RawMessage(`{"repository":{"id":"r","type":"TfsGit","defaultBranch":"refs/heads/main"},"process":{"type":1}}`)
	if err := collectPipelineYAML(context.Background(), panicADO{t}, cp, "Proj", nil, 5, full); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cp.RunDir, "00-collect", "pipeline-yaml")); !os.IsNotExist(err) {
		t.Fatal("classic pipeline should write no pipeline-yaml files")
	}
}

// getADO serves a single canned body for any Get.
type getADO struct{ body json.RawMessage }

func (g getADO) Get(context.Context, string, string, string, url.Values, bool) (json.RawMessage, http.Header, error) {
	return g.body, http.Header{}, nil
}
func (g getADO) GetRaw(context.Context, string, string, string, url.Values) ([]byte, http.Header, error) {
	return nil, nil, nil
}
func (g getADO) Post(context.Context, string, string, string, url.Values, any) (json.RawMessage, error) {
	return nil, nil
}
func (g getADO) Paginate(context.Context, string, string, string, url.Values) ([]json.RawMessage, error) {
	return nil, nil
}

// collectReleaseFull stores the full classic-release definition (approvals/gates).
func TestCollectReleaseFull(t *testing.T) {
	cp := engineCP(t.TempDir())
	rel := `{"id":9,"name":"prod","environments":[{"name":"prod","preDeployApprovals":{"approvals":[{"approver":{"id":"u"}}]}}]}`
	if err := collectReleaseFull(context.Background(), getADO{json.RawMessage(rel)}, cp, "Proj", 9); err != nil {
		t.Fatal(err)
	}
	data := readData(t, cp.RunDir, engine.CollectADOReleaseFull("Proj", 9))
	if data["name"] != "prod" {
		t.Fatalf("release full not stored: %v", data)
	}
	envs, ok := data["environments"].([]any)
	if !ok || len(envs) != 1 {
		t.Fatalf("environments not preserved: %v", data["environments"])
	}
}
