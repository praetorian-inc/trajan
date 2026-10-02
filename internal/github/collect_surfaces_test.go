package github

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func TestCollectEnvironmentsConfinesAHostileName(t *testing.T) {
	const hostile = "../../../../escaped"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/environments") {
			json.NewEncoder(w).Encode(map[string]any{
				"total_count":  1,
				"environments": []map[string]any{{"name": hostile}},
			})
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	root := t.TempDir()
	run := filepath.Join(root, "run1")
	collectErr := collectEnvironments(context.Background(), newTestClient(srv), engine.CurrentPhase{RunDir: run}, "acme", "r")

	var written []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(run, p)
		if rerr != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("collect wrote %q, outside the run directory", p)
			return nil
		}
		written = append(written, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	wantDir := path.Dir(engine.CollectEnvironment("r", "e")) + "/"
	if len(written) != 1 || !strings.HasPrefix(written[0], wantDir) {
		t.Fatalf("wrote %v (err %v), want one record under %s", written, collectErr, wantDir)
	}
}
