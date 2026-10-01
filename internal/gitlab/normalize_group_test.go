package gitlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func TestNormalizeGroupEmitsNoRecordForAnUnobservedGroup(t *testing.T) {
	runDir := t.TempDir()
	p := filepath.Join(runDir, engine.CollectGLGroup("grp"))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{"data": map[string]any{"_unobserved": 403}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}

	timer := engine.StartPhaseTimer(engine.PhaseNormalize, "normalize")
	if err := normalizeGroup(engine.PriorPhase{RunDir: runDir}, engine.CurrentPhase{RunDir: runDir}, "grp", nil, timer); err != nil {
		t.Fatalf("normalizeGroup: %v", err)
	}

	if _, err := os.Stat(filepath.Join(runDir, engine.NormalizeGLGroup("grp"))); !os.IsNotExist(err) {
		t.Error("an unobserved group was normalized into a record with default settings")
	}
	if len(timer.Errors) != 1 {
		t.Errorf("timer.Errors = %v, want one entry naming the unobserved group", timer.Errors)
	}
}
