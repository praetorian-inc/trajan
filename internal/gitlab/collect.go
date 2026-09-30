package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func Collect(ctx context.Context, cfg *engine.Config, locator string) (string, error) {
	scope, err := ParseScope(locator)
	if err != nil {
		return "", err
	}
	if cfg.Token == "" {
		return "", fmt.Errorf("%w for GitLab", engine.ErrNoCredential)
	}
	cl := NewClient(cfg.BaseURL, cfg.Token, cfg.Insecure, cfg.Concurrency)

	runDir, err := engine.MintRunDir(cfg, "gl", scope.Slug)
	if err != nil {
		return "", err
	}
	state, err := engine.LoadState(runDir)
	if err != nil {
		return "", err
	}
	if err := state.CheckPhase(engine.PhaseCollect); err != nil {
		return "", err
	}
	for _, d := range state.StaleDirs(engine.PhaseCollect) {
		if err := os.RemoveAll(filepath.Join(runDir, d)); err != nil {
			return "", err
		}
	}
	state.Platform = "gl"
	state.Scope = scopeString(scope)
	state.Org = scope.Group
	state.SetInvocation(cfg.Invocation)
	if state.StartedAt == "" {
		state.StartedAt = engine.IsoformatUTC(timeNow())
	}

	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")
	cp := engine.CurrentPhase{RunDir: runDir}

	collectErr := runCollect(ctx, cfg, cl, cp, &scope, state, timer)

	timer.OutputFiles = countJSON(runDir)
	rec := timer.Stop(collectErr)
	state.RecordPhase(rec)
	if err := state.Save(runDir); err != nil {
		return runDir, err
	}
	if collectErr != nil {
		return runDir, collectErr
	}
	engine.PhaseDone(rec, cfg.Sink())
	return runDir, nil
}

type projectRef struct {
	ID       int64
	FullPath string
}

func runCollect(ctx context.Context, cfg *engine.Config, cl GitLab, cp engine.CurrentPhase, scope *Scope, state *engine.State, timer *engine.PhaseTimer) error {
	// The scope depth is undecided until probed: try the whole path as a group, and on
	// 404 treat it as a project whose owning group is its namespace full_path.
	groupPath := scope.Group
	var projRaw json.RawMessage
	groupRaw, gstatus, err := softGet(ctx, cl, "/groups/"+url.PathEscape(scope.path), nil)
	if err != nil {
		return err
	}
	if gstatus != 0 {
		var pstatus int
		var perr error
		projRaw, pstatus, perr = softGet(ctx, cl, "/projects/"+url.PathEscape(scope.path), nil)
		if perr != nil {
			return perr
		}
		if pstatus != 0 {
			return fmt.Errorf("scope %q resolves as neither a group (%d) nor a project (%d)", scope.path, gstatus, pstatus)
		}
		scope.Kind = ScopeProject
		scope.Project = scope.path
		groupPath = namespaceFullPath(projRaw)
		scope.Group = groupPath
		if groupPath != "" {
			groupRaw, _, _ = softGet(ctx, cl, "/groups/"+url.PathEscape(groupPath), nil)
		}
	}
	state.Scope = scopeString(*scope)
	state.Org = groupPath

	var gid int64
	if groupPath != "" {
		gid = numField(groupRaw, "id")
		collectGroupSurfaces(ctx, cl, cp, groupPath, gid, groupRaw, timer)
	}

	projects, err := scopedProjects(ctx, cl, timer, scope, projRaw, groupPath, gid)
	if err != nil {
		return err
	}
	timer.InputFiles = len(projects)

	engine.RunPartial(ctx, cfg.Concurrency, projects,
		func(ctx context.Context, p projectRef) (int, error) {
			return 0, collectOneProject(ctx, cl, cp, p, timer)
		},
		func(p projectRef, e error) {
			appendErr(timer, fmt.Sprintf("project %s: %v", p.FullPath, e))
		},
	)

	collectInstanceSurfaces(ctx, cl, cp, timer)
	return nil
}

func scopedProjects(ctx context.Context, cl GitLab, timer *engine.PhaseTimer, scope *Scope,
	projRaw json.RawMessage, groupPath string, gid int64) ([]projectRef, error) {
	if scope.Project != "" {
		id, fullPath := numField(projRaw, "id"), strField(projRaw, "path_with_namespace")
		if id == 0 || fullPath == "" {
			return nil, fmt.Errorf("project %q: response carries no id or path_with_namespace", scope.Project)
		}
		return []projectRef{{ID: id, FullPath: fullPath}}, nil
	}
	if groupPath == "" {
		return nil, nil
	}
	return enumerateProjects(ctx, cl, timer, groupPath, gid)
}

func namespaceFullPath(projRaw json.RawMessage) string {
	ns := objField(projRaw, "namespace")
	if ns == nil {
		return ""
	}
	return strField(ns, "full_path")
}

// An unreadable group degrades rather than aborts: the group and instance rules need no project list.
func enumerateProjects(ctx context.Context, cl GitLab, timer *engine.PhaseTimer, groupPath string, gid int64) ([]projectRef, error) {
	gref := groupRef(groupPath, gid)
	items, status, err := softList(ctx, cl, "/groups/"+gref+"/projects", url.Values{"include_subgroups": []string{"true"}})
	if err != nil {
		return nil, err
	}
	if status != 0 {
		msg := fmt.Sprintf("list projects for group %s: HTTP %d", groupPath, status)
		appendErr(timer, msg)
		timer.AddSurface("group/projects", "degraded", msg)
		return nil, nil
	}
	timer.AddSurface("group/projects", "ok", "")
	out := make([]projectRef, 0, len(items))
	for _, raw := range items {
		id := numField(raw, "id")
		fp := strField(raw, "path_with_namespace")
		if id != 0 && fp != "" {
			out = append(out, projectRef{ID: id, FullPath: fp})
		}
	}
	return out, nil
}

// The numeric id needs no escaping, so it is preferred over a nested group path.
func groupRef(groupPath string, gid int64) string {
	if gid != 0 {
		return fmt.Sprintf("%d", gid)
	}
	return url.PathEscape(groupPath)
}

func softSurface(ctx context.Context, timer *engine.PhaseTimer, surface, label string, fn func(context.Context) error) {
	sctx, tally := engine.WithSoftTally(ctx)
	if err := fn(sctx); err != nil {
		appendErr(timer, fmt.Sprintf("%s: %v", label, err))
		timer.AddSurface(surface, "degraded", err.Error())
		return
	}
	status, reason := tally.Surface()
	timer.AddSurface(surface, status, reason)
}

func appendErr(timer *engine.PhaseTimer, msg string) {
	timer.AddError(msg)
	// Debug, not Warn: PhaseDone reports these as one aggregate at the end.
	slog.Debug("collect surface degraded", "detail", msg)
}

func countJSON(runDir string) int {
	n := 0
	_ = filepath.WalkDir(filepath.Join(runDir, "00-collect"), func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
			n++
		}
		return nil
	})
	return n
}
