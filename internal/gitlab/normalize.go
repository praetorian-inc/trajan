package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// projectMeta is the per-project roster GitLab lacks as a single surface: it is
// rebuilt by scanning 00-collect/project/ (each project = one CollectGLProject
// file) and reading path_with_namespace / id / default_branch off the detail.
type projectMeta struct {
	FullPath      string
	ID            int64
	DefaultBranch string
}

// Normalize turns the raw collected JSON (00-collect) into per-subject fact
// records and cross-entity chain joins (10-normalize) per the GitLab normalized
// field contract (docs/gitlab/gitlab-normalized-fields.md). Structural entity
// records first, then the resolved-job records, then the correlation joins the
// chain rules read. Per-item failures accumulate in timer.Errors and are skipped;
// only IO / contract violations abort the phase.
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
	projs := projects(prior)

	normErr := normalizeEntities(ctx, prior, cp, org, projs, timer)
	if normErr == nil {
		_, normErr = normalizeJobs(ctx, prior, cp, org, projs, timer)
	}
	if normErr == nil {
		normErr = correlate(ctx, prior, cp, org, timer)
	}

	state.RecordPhase(timer.Stop(normErr))
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

// itemErr records a per-item failure without aborting the phase.
func itemErr(timer *engine.PhaseTimer, subject string, err error) {
	timer.Errors = append(timer.Errors, fmt.Sprintf("%s: %v", subject, err))
}

// projects rebuilds the project roster from 00-collect/project/. Order is stable
// (directory iteration) so re-runs produce identical output.
func projects(prior engine.PriorPhase) []projectMeta {
	files, err := prior.IterJSON("00-collect/project")
	if err != nil {
		return nil
	}
	out := make([]projectMeta, 0, len(files))
	for _, f := range files {
		var env map[string]any
		if err := json.Unmarshal(f.Data, &env); err != nil {
			continue
		}
		d := entMap(env["data"])
		fp := entStr(d["path_with_namespace"])
		if fp == "" || entUnobserved(d) {
			continue
		}
		out = append(out, projectMeta{
			FullPath:      fp,
			ID:            entInt64(d["id"]),
			DefaultBranch: entStr(d["default_branch"]),
		})
	}
	return out
}
