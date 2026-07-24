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
	"sync"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func Collect(ctx context.Context, cfg *engine.Config, locator string) (string, error) {
	scope, err := ParseScope(locator)
	if err != nil {
		return "", err
	}
	token, err := ResolveToken(cfg.Token)
	if err != nil {
		return "", err
	}
	cl := NewClient(ResolveBaseURL(FlagURL), token, FlagInsecure, cfg.Concurrency)

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
	state.Invocation = os.Args[1:]
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
	return runDir, collectErr
}

type projectRef struct {
	ID       int64
	FullPath string
}

func runCollect(ctx context.Context, cfg *engine.Config, cl GitLab, cp engine.CurrentPhase, scope *Scope, state *engine.State, timer *engine.PhaseTimer) error {
	// Depth resolution: try the full path as a group; on 404 treat the last segment
	// as a project whose owning group is its namespace full_path.
	groupPath := scope.Group
	groupRaw, gstatus, err := softGet(ctx, cl, "/groups/"+url.PathEscape(scope.path), nil)
	if err != nil {
		return err
	}
	if gstatus != 0 {
		projRaw, pstatus, perr := softGet(ctx, cl, "/projects/"+url.PathEscape(scope.path), nil)
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

	if groupPath != "" {
		gid := numField(groupRaw, "id")
		collectGroupSurfaces(ctx, cl, cp, groupPath, gid, groupRaw, timer)

		projects, perr := enumerateProjects(ctx, cl, cp, groupPath, gid)
		if perr != nil {
			return perr
		}
		if scope.Project != "" {
			projects = filterProjects(projects, scope.Project)
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
	}

	collectInstanceSurfaces(ctx, cl, cp, timer)
	return nil
}

func namespaceFullPath(projRaw json.RawMessage) string {
	ns := objField(projRaw, "namespace")
	if ns == nil {
		return ""
	}
	return strField(ns, "full_path")
}

// enumerateProjects lists all projects under the group (including subgroups) — the
// seed list for the fan-out. This is the one fatal list: a genuine transport error
// sinks the run, but a soft 403/404 yields an empty (marked) list and continues.
func enumerateProjects(ctx context.Context, cl GitLab, cp engine.CurrentPhase, groupPath string, gid int64) ([]projectRef, error) {
	gref := groupRef(groupPath, gid)
	items, status, err := softList(ctx, cl, "/groups/"+gref+"/projects", url.Values{"include_subgroups": []string{"true"}})
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, nil
	}
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

func filterProjects(projects []projectRef, fullPath string) []projectRef {
	for _, p := range projects {
		if strings.EqualFold(p.FullPath, fullPath) {
			return []projectRef{p}
		}
	}
	return nil
}

// groupRef prefers the numeric id (URL-safe) when known, else the escaped path.
func groupRef(groupPath string, gid int64) string {
	if gid != 0 {
		return fmt.Sprintf("%d", gid)
	}
	return url.PathEscape(groupPath)
}

var errMu sync.Mutex

func softSurface(timer *engine.PhaseTimer, label string, fn func() error) {
	if err := fn(); err != nil {
		appendErr(timer, fmt.Sprintf("%s: %v", label, err))
	}
}

func appendErr(timer *engine.PhaseTimer, msg string) {
	errMu.Lock()
	timer.Errors = append(timer.Errors, msg)
	errMu.Unlock()
	slog.Warn("collect surface degraded", "detail", msg)
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
