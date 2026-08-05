package ado

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

type projectMeta struct {
	ID   string
	Name string
}

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

	scope, err := ParseScope(state.Scope)
	if err != nil {
		return fmt.Errorf("scope %q in %s: %w", state.Scope, engine.RunMeta(), err)
	}

	timer := engine.StartPhaseTimer(engine.PhaseNormalize, "normalize")
	prior := engine.PriorPhase{RunDir: runDir}
	cp := engine.CurrentPhase{RunDir: runDir}

	normErr := normalizeEntities(ctx, prior, cp, org, scope.Project, timer)
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
	if normErr != nil {
		return normErr
	}
	engine.PhaseDone(rec)
	return nil
}

// Normalize is sequential, so the timer needs no locking.
func emit(cp engine.CurrentPhase, timer *engine.PhaseTimer, rel string, rec any) error {
	if err := cp.Write(rel, rec); err != nil {
		return err
	}
	timer.OutputFiles++
	return nil
}

// collect writes the whole org roster but fans out only to the scoped project, so a
// scoped run must re-apply that filter or it emits project subjects whose detail was
// never collected.
func projects(prior engine.PriorPhase, org, only string) []projectMeta {
	var out []projectMeta
	for _, raw := range entLoadList(prior, engine.CollectADOProjects(org)) {
		m := entMap(raw)
		id, name := entStr(m["id"]), entStr(m["name"])
		if id == "" || name == "" {
			continue
		}
		if only != "" && !strings.EqualFold(name, only) {
			continue
		}
		out = append(out, projectMeta{ID: id, Name: name})
	}
	return out
}
