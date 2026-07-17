package ado

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func Collect(ctx context.Context, cfg *engine.Config, locator string) (string, error) {
	if strings.TrimSpace(locator) == "" {
		locator = strings.TrimSpace(os.Getenv("ORG_NAME"))
	}
	scope, err := ParseScope(locator)
	if err != nil {
		return "", err
	}
	token, err := ResolveToken()
	if err != nil {
		return "", err
	}
	cl := NewClient(scope.Org, token)

	runDir, err := engine.MintRunDir(cfg, "ado", scope.Slug)
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
	state.Platform = "ado"
	state.Scope = scopeString(scope)
	state.Org = scope.Org
	state.Invocation = os.Args[1:]
	if state.StartedAt == "" {
		state.StartedAt = engine.IsoformatUTC(timeNow())
	}

	timer := engine.StartPhaseTimer(engine.PhaseCollect, "collect")
	cp := engine.CurrentPhase{RunDir: runDir}

	collectErr := runCollect(ctx, cfg, cl, cp, scope, timer)

	timer.OutputFiles = countJSON(runDir)
	rec := timer.Stop(collectErr)
	state.RecordPhase(rec)
	if err := state.Save(runDir); err != nil {
		return runDir, err
	}
	return runDir, collectErr
}

func runCollect(ctx context.Context, cfg *engine.Config, cl ADO, cp engine.CurrentPhase, scope Scope, timer *engine.PhaseTimer) error {
	org := scope.Org

	softSurface(timer, "connection-data", func() error { return collectConnectionData(ctx, cl, cp, org) })
	softSurface(timer, "security-namespaces", func() error { return collectSecurityNamespaces(ctx, cl, cp, org) })
	softSurface(timer, "graph", func() error { return collectGraph(ctx, cl, cp, org) })
	softSurface(timer, "extensions", func() error { return collectExtensions(ctx, cl, cp, org) })
	softSurface(timer, "service-hooks", func() error { return collectServiceHooks(ctx, cl, cp, org) })
	softSurface(timer, "feeds", func() error { return collectFeeds(ctx, cl, cp, org) })
	softSurface(timer, "agent-pools", func() error { return collectAgentPools(ctx, cl, cp) })

	projects, err := collectProjects(ctx, cl, cp, org)
	if err != nil {
		return err
	}
	if scope.Project != "" {
		projects = filterProjects(projects, scope.Project)
	}
	timer.InputFiles = len(projects)

	engine.RunPartial(ctx, cfg.Concurrency, projects,
		func(ctx context.Context, p projectRef) (int, error) {
			return 0, collectOneProject(ctx, cl, cp, scope, p, timer)
		},
		func(p projectRef, e error) {
			appendErr(timer, fmt.Sprintf("project %s: %v", p.Name, e))
		},
	)
	return nil
}

func collectOneProject(ctx context.Context, cl ADO, cp engine.CurrentPhase, scope Scope, pt projectRef, timer *engine.PhaseTimer) error {
	project, pid := pt.Name, pt.ID
	lbl := func(s string) string { return project + "/" + s }

	softSurface(timer, lbl("detail"), func() error { return collectProjectDetail(ctx, cl, cp, project) })
	softSurface(timer, lbl("general-settings"), func() error { return collectGeneralSettings(ctx, cl, cp, project) })
	softSurface(timer, lbl("project-properties"), func() error { return collectProjectProperties(ctx, cl, cp, pid, project) })
	softSurface(timer, lbl("policies"), func() error { return collectPolicies(ctx, cl, cp, project) })
	softSurface(timer, lbl("build-acl"), func() error { return collectBuildACL(ctx, cl, cp, project, pid) })

	pe := url.PathEscape(project)

	var repos []repoRef
	softSurface(timer, lbl("repos"), func() error {
		r, e := collectRepos(ctx, cl, cp, project)
		repos = r
		return e
	})

	var resources []resourceRef
	collectList := func(label, host, api, apiPath, rel, collector, rtype string) {
		softSurface(timer, lbl(label), func() error {
			refs, e := listSurface(ctx, cl, cp, project, host, api, apiPath, rel, collector, rtype)
			resources = append(resources, refs...)
			return e
		})
	}
	collectList("service-connections", "core", APIVersionSEP, "/"+pe+"/_apis/serviceendpoint/endpoints",
		engine.CollectADOServiceConnections(project), "service-connections", "endpoint")
	collectList("variable-groups", "core", APIVersion, "/"+pe+"/_apis/distributedtask/variablegroups",
		engine.CollectADOVariableGroups(project), "variable-groups", "variablegroup")
	collectList("secure-files", "core", APIVersion, "/"+pe+"/_apis/distributedtask/securefiles",
		engine.CollectADOSecureFiles(project), "secure-files", "securefile")
	collectList("environments", "core", APIVersion, "/"+pe+"/_apis/distributedtask/environments",
		engine.CollectADOEnvironments(project), "environments", "environment")
	collectList("agent-queues", "core", APIVersion, "/"+pe+"/_apis/distributedtask/queues",
		engine.CollectADOAgentQueues(project), "agent-queues", "queue")

	// deployment groups: the preview api-version is required (GA 400s); the
	// $expand=machines option is no longer supported, so per-machine detail would
	// need per-group queries (deferred — none exist in the target estate).
	softSurface(timer, lbl("deployment-groups"), func() error {
		items, _, e := softList(ctx, cl, "core", APIVersionPreview,
			"/"+pe+"/_apis/distributedtask/deploymentgroups", nil)
		if e != nil {
			return e
		}
		return envelope(cp, engine.CollectADODeploymentGroups(project), "deployment-groups",
			"/"+project+"/_apis/distributedtask/deploymentgroups", rawArray(items))
	})
	softSurface(timer, lbl("task-groups"), func() error {
		_, e := listSurface(ctx, cl, cp, project, "core", APIVersionPreview,
			"/"+pe+"/_apis/distributedtask/taskgroups", engine.CollectADOTaskGroups(project), "task-groups", "")
		return e
	})
	// classic release definitions: list (summary) then fan out full detail —
	// approvals/gates/artifacts live only on the per-definition GET (cat-14).
	var releaseIDs []int64
	softSurface(timer, lbl("releases"), func() error {
		items, status, e := softList(ctx, cl, "vsrm", APIVersion, "/"+pe+"/_apis/release/definitions", nil)
		if e != nil {
			return e
		}
		if e := envelope(cp, engine.CollectADOReleases(project), "release-definitions",
			"/"+project+"/_apis/release/definitions", rawArray(items)); e != nil {
			return e
		}
		if status == 0 {
			releaseIDs = collectIDs(items)
		}
		return nil
	})

	// Pipeline id set = /build/definitions (YAML type-2 AND classic/designer type-1
	// builds) UNION /pipelines (newer abstraction), so a pipeline surfaced by only
	// one endpoint is still collected.
	pipelineNames := map[int64]string{}
	softSurface(timer, lbl("build-definitions"), func() error {
		items, _, e := softList(ctx, cl, "core", APIVersion, "/"+pe+"/_apis/build/definitions", nil)
		if e != nil {
			return e
		}
		if e := envelope(cp, engine.CollectADOBuildDefs(project), "build-definitions",
			"/"+project+"/_apis/build/definitions", rawArray(items)); e != nil {
			return e
		}
		addPipelineIDs(pipelineNames, items)
		return nil
	})
	softSurface(timer, lbl("pipelines"), func() error {
		items, _, e := softList(ctx, cl, "core", APIVersion, "/"+pe+"/_apis/pipelines", nil)
		if e != nil {
			return e
		}
		if e := envelope(cp, engine.CollectADOPipelines(project), "pipelines",
			"/"+project+"/_apis/pipelines", rawArray(items)); e != nil {
			return e
		}
		addPipelineIDs(pipelineNames, items)
		return nil
	})

	// per pipeline: full definition; YAML pipelines (process.type==2) additionally
	// get preview + template closure; classic/designer pipelines (type 1) carry
	// their steps in the full definition's process.phases, so nothing more is fetched.
	for _, id := range sortedIDs(pipelineNames) {
		softSurface(timer, lbl(fmt.Sprintf("pipeline/%d", id)), func() error {
			full, e := collectBuildDefFull(ctx, cl, cp, project, id)
			if e != nil || full == nil {
				return e
			}
			if numField(objField(full, "process"), "type") != 2 {
				return nil // classic/designer: steps already captured in the full definition
			}
			if e := collectPipelinePreview(ctx, cl, cp, project, id); e != nil {
				return e
			}
			return collectPipelineYAML(ctx, cl, cp, project, repos, id, full)
		})
	}
	for _, id := range releaseIDs {
		softSurface(timer, lbl(fmt.Sprintf("release/%d", id)), func() error {
			return collectReleaseFull(ctx, cl, cp, project, id)
		})
	}

	// per resource: pipeline permissions + checks
	for _, r := range resources {
		softSurface(timer, lbl("perms/"+r.Type+"/"+r.ID), func() error { return collectPipelinePermissions(ctx, cl, cp, project, r) })
		softSurface(timer, lbl("checks/"+r.Type+"/"+r.ID), func() error { return collectChecks(ctx, cl, cp, project, r) })
		switch r.Type {
		case "environment":
			if envID, err := strconv.ParseInt(r.ID, 10, 64); err == nil {
				softSurface(timer, lbl("env-detail/"+r.ID), func() error { return collectEnvironmentDetail(ctx, cl, cp, project, envID) })
			}
		case "endpoint":
			softSurface(timer, lbl("endpoint-acl/"+r.ID), func() error { return collectEndpointACL(ctx, cl, cp, project, pid, r.ID) })
		}
	}

	// per repo: git ACL (skip others if a repo scope was requested)
	for _, repo := range repos {
		if scope.Repo != "" && !strings.EqualFold(repo.Name, scope.Repo) {
			continue
		}
		softSurface(timer, lbl("repo-acl/"+repo.Name), func() error { return collectRepoACL(ctx, cl, cp, project, pid, repo) })
	}
	return nil
}

func filterProjects(projects []projectRef, name string) []projectRef {
	for _, p := range projects {
		if strings.EqualFold(p.Name, name) {
			return []projectRef{p}
		}
	}
	return nil
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
