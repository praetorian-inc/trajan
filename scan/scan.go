// Package scan runs the trajan pipeline in-process and returns its findings,
// coverage and graph resources.
package scan

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/trajan/finding"
	"github.com/praetorian-inc/trajan/internal/ado"
	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
	"github.com/praetorian-inc/trajan/internal/gitlab"
	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/internal/ui"
	"github.com/praetorian-inc/trajan/resource"
)

type Config struct {
	Token       string
	BearerToken string
	BaseURL     string
	Insecure    bool
	WorkDir     string
	Concurrency int
	Scope       string

	HierarchyOnly     bool
	BuildGraph        bool
	DefaultBranchOnly bool
	ForceREST         bool
}

type SurfaceStatus struct{ Name, Status, Reason string }

type Coverage struct {
	Surfaces       []SurfaceStatus
	RulesEvaluated int
	RulesTotal     int
	Degraded       bool
}

type Result struct {
	Findings      []finding.Finding
	Coverage      Coverage
	Resources     []resource.Resource
	Relationships []resource.Relationship
}

func GitHub(ctx context.Context, cfg Config) (Result, error) {
	opts := github.ScanOptions{HierarchyOnly: cfg.HierarchyOnly}
	return run(ctx, cfg, phases{
		collect:   github.Collect,
		normalize: github.Normalize,
		scan: func(ctx context.Context, ec *engine.Config, runDir string) error {
			return github.Scan(ctx, ec, runDir, opts)
		},
		graph: buildGraph,
	})
}

func GitLab(ctx context.Context, cfg Config) (Result, error) {
	opts := gitlab.ScanOptions{HierarchyOnly: cfg.HierarchyOnly}
	return run(ctx, cfg, phases{
		collect:   gitlab.Collect,
		normalize: gitlab.Normalize,
		scan: func(ctx context.Context, ec *engine.Config, runDir string) error {
			return gitlab.Scan(ctx, ec, runDir, opts)
		},
	})
}

func ADO(ctx context.Context, cfg Config) (Result, error) {
	opts := ado.ScanOptions{HierarchyOnly: cfg.HierarchyOnly}
	return run(ctx, cfg, phases{
		collect:   ado.Collect,
		normalize: ado.Normalize,
		scan: func(ctx context.Context, ec *engine.Config, runDir string) error {
			return ado.Scan(ctx, ec, runDir, opts)
		},
	})
}

// graph is nil on a platform with no graph builder, which makes BuildGraph a no-op.
type phases struct {
	collect   func(context.Context, *engine.Config, string) (string, error)
	normalize func(context.Context, *engine.Config, string) error
	scan      func(context.Context, *engine.Config, string) error
	graph     func(context.Context, *engine.Config, string) error
}

const defaultConcurrency = 8

func run(ctx context.Context, cfg Config, p phases) (Result, error) {
	if strings.TrimSpace(cfg.WorkDir) == "" {
		return Result{}, errors.New("scan: WorkDir is required")
	}
	ec := &engine.Config{
		Concurrency:       cmp.Or(cfg.Concurrency, defaultConcurrency),
		OutputDir:         cfg.WorkDir,
		Token:             cfg.Token,
		BearerToken:       cfg.BearerToken,
		BaseURL:           cfg.BaseURL,
		Insecure:          cfg.Insecure,
		UI:                ui.Discard,
		DefaultBranchOnly: cfg.DefaultBranchOnly,
		ForceREST:         cfg.ForceREST,
	}

	runDir, err := p.collect(ctx, ec, cfg.Scope)
	if err != nil {
		return Result{}, err
	}
	if err := p.normalize(ctx, ec, runDir); err != nil {
		return Result{}, err
	}
	if err := p.scan(ctx, ec, runDir); err != nil {
		return Result{}, err
	}

	var res Result
	var extra []SurfaceStatus

	built := false
	if cfg.BuildGraph && p.graph != nil {
		st := runGraph(ctx, ec, runDir, p.graph)
		extra = append(extra, st)
		built = st.Status == "ok"
	}

	var seen int
	res.Findings, seen, err = engine.LoadFindings(ctx, ec, runDir,
		func(e error) { slog.Warn("unreadable finding record", "err", e) })
	if err != nil {
		return Result{}, err
	}
	if seen > len(res.Findings) {
		extra = append(extra, SurfaceStatus{Name: "findings", Status: "degraded",
			Reason: "unreadable finding records were dropped"})
	}

	if built {
		res.Resources, res.Relationships, err = readGraph(runDir)
		if err != nil {
			return Result{}, err
		}
	}

	res.Coverage, err = coverage(runDir, extra)
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// A graph failure is a coverage fact, never a lost scan: the findings already ran.
func runGraph(ctx context.Context, ec *engine.Config, runDir string,
	build func(context.Context, *engine.Config, string) error) SurfaceStatus {
	err := build(ctx, ec, runDir)
	switch {
	case err == nil:
		return SurfaceStatus{Name: "graph", Status: "ok"}
	case errors.Is(err, graph.ErrNoOrgRecord):
		return SurfaceStatus{Name: "graph", Status: "skipped", Reason: err.Error()}
	default:
		return SurfaceStatus{Name: "graph", Status: "degraded", Reason: err.Error()}
	}
}

func buildGraph(ctx context.Context, ec *engine.Config, runDir string) error {
	targets, err := graph.RuleTargets(func(e error) { slog.Warn("rule skipped", "err", e) })
	if err != nil {
		return err
	}
	return graph.Build(ctx, ec, runDir, targets)
}

func readGraph(runDir string) ([]resource.Resource, []resource.Relationship, error) {
	var rf struct {
		Resources []resource.Resource `json:"resources"`
	}
	var lf struct {
		Relationships []resource.Relationship `json:"relationships"`
	}
	if err := engine.ReadJSON(filepath.Join(runDir, engine.GraphResources()), &rf); err != nil {
		return nil, nil, err
	}
	if err := engine.ReadJSON(filepath.Join(runDir, engine.GraphRelationships()), &lf); err != nil {
		return nil, nil, err
	}
	return rf.Resources, lf.Relationships, nil
}

func coverage(runDir string, extra []SurfaceStatus) (Coverage, error) {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return Coverage{}, err
	}
	var cov Coverage
	for _, ph := range state.Phases {
		for _, s := range ph.Surfaces {
			cov.Surfaces = append(cov.Surfaces, SurfaceStatus{Name: s.Name, Status: s.Status, Reason: s.Reason})
		}
		if len(ph.Errors) > 0 {
			cov.Degraded = true
		}
	}
	cov.Surfaces = append(cov.Surfaces, extra...)
	// A skipped surface is an absent one, so only an unreadable surface degrades.
	for _, s := range cov.Surfaces {
		if s.Status == "degraded" {
			cov.Degraded = true
		}
	}

	var sum struct {
		RulesLoaded int `json:"rules_loaded"`
		RulesTotal  int `json:"rules_total"`
	}
	if err := engine.ReadJSON(filepath.Join(runDir, engine.ScanSummary()), &sum); err != nil {
		return cov, err
	}
	cov.RulesEvaluated, cov.RulesTotal = sum.RulesLoaded, sum.RulesTotal
	return cov, nil
}
