package ado

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/trajan/internal/engine"
)

type projectMeta struct {
	ID   string
	Name string
}

// Normalize turns the raw collected JSON (00-collect) into structural node/edge
// records (10-normalize) per the ADO security-graph ontology. This is the
// structural pass: nodes, collected edges, and the three settings-resolution
// joins. Derived/attack (taint) edges are a later pass.
func Normalize(ctx context.Context, runDir string) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhaseNormalize); err != nil {
		return err
	}
	for _, d := range state.StaleDirs(engine.PhaseNormalize) {
		if err := os.RemoveAll(filepath.Join(runDir, d)); err != nil {
			return err
		}
	}
	// Clear this phase's own output so a re-run against shrunk input leaves no
	// orphan records for correlate to read back.
	if err := os.RemoveAll(filepath.Join(runDir, "10-normalize")); err != nil {
		return err
	}
	org := state.Org
	if org == "" {
		return fmt.Errorf("org not set in %s; run collect first", engine.RunMeta())
	}

	timer := engine.StartPhaseTimer(engine.PhaseNormalize, "normalize")
	prior := engine.PriorPhase{RunDir: runDir}
	cp := engine.CurrentPhase{RunDir: runDir}

	normErr := normalizeEntities(ctx, prior, cp, org, timer)
	if normErr == nil {
		normErr = normalizePipelines(ctx, prior, cp, timer)
	}
	if normErr == nil {
		normErr = correlate(ctx, prior, cp, org, timer)
	}

	rec := timer.Stop(normErr)
	state.RecordPhase(rec)
	if err := state.Save(runDir); err != nil {
		return err
	}
	return normErr
}

// emit writes one normalized record and counts it. Normalize is sequential, so
// no locking is needed on the timer.
func emit(cp engine.CurrentPhase, timer *engine.PhaseTimer, rel string, rec any) error {
	if err := cp.Write(rel, rec); err != nil {
		return err
	}
	timer.OutputFiles++
	return nil
}

// projects reads the collected project roster (id + true name; per-project
// surface files are keyed by the sanitized name).
func projects(prior engine.PriorPhase, org string) []projectMeta {
	var out []projectMeta
	for _, raw := range entLoadList(prior, engine.CollectADOProjects(org)) {
		m := entMap(raw)
		if id, name := entStr(m["id"]), entStr(m["name"]); id != "" && name != "" {
			out = append(out, projectMeta{ID: id, Name: name})
		}
	}
	return out
}
