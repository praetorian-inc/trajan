package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// RuleFires includes rules that fired zero times.
type scanSummary struct {
	RulesLoaded   int            `json:"rules_loaded"`
	TotalFindings int            `json:"total_findings"`
	RuleFires     map[string]int `json:"rule_fires"`
}

type ScanOptions struct {
	OrgOnly bool
}

// Scan runs the shared detection engine for a platform: it loads that provider's
// rule subtree, evaluates each rule against the matching 10-normalize records,
// and writes findings to 20-scan.
func Scan(ctx context.Context, runDir string, p Provider, opts ScanOptions) error {
	state, err := engine.LoadState(runDir)
	if err != nil {
		return err
	}
	if err := state.CheckPhase(engine.PhaseScan); err != nil {
		return err
	}

	timer := engine.StartPhaseTimer(engine.PhaseScan, "scan")
	scanErr := runScan(ctx, runDir, state.Org, p, opts, timer)

	rec := timer.Stop(scanErr)
	state.RecordPhase(rec)
	if err := state.Save(runDir); err != nil {
		return err
	}
	return scanErr
}

// OrgOnlyRules filters on SubjectKind, not folder, so it holds even though
// cat-13-org rules keep their original cat-NN IDs.
func OrgOnlyRules(rules []Rule) []Rule {
	return slices.DeleteFunc(rules, func(r Rule) bool { return r.SubjectKind() != "org" })
}

func runScan(ctx context.Context, runDir, org string, p Provider, opts ScanOptions, timer *engine.PhaseTimer) error {
	prior := engine.PriorPhase{RunDir: runDir}
	cp := engine.CurrentPhase{RunDir: runDir}

	if err := os.RemoveAll(filepath.Join(runDir, "20-scan")); err != nil {
		return fmt.Errorf("clear 20-scan: %w", err)
	}

	rules, err := LoadRules(p.RuleSubtree)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	if opts.OrgOnly {
		rules = OrgOnlyRules(rules)
	}
	timer.InputFiles = len(rules)

	subjectsByKind := map[string][]map[string]any{}
	for i := range rules {
		if rules[i].SubjectKind() == "chain" {
			continue
		}
		kind := rules[i].SubjectKind()
		if _, done := subjectsByKind[kind]; done {
			continue
		}
		subs, err := loadSubjects(prior, p, kind)
		if err != nil {
			return fmt.Errorf("load %s subjects: %w", kind, err)
		}
		subjectsByKind[kind] = subs
	}

	onError := func(e error) { timer.Errors = append(timer.Errors, e.Error()) }

	ruleFires := make(map[string]int, len(rules))
	total := 0
	for i := range rules {
		rule := &rules[i]
		kind := rule.SubjectKind()

		var matched []map[string]any
		if kind == "chain" {
			chainData, err := loadChain(prior, rule.ChainOf)
			if err != nil {
				onError(fmt.Errorf("%s: %w", rule.ID, err))
			}
			matched = EvaluateChainRule(rule, chainData, onError)
		} else {
			matched = EvaluateRule(rule, subjectsByKind[kind], onError)
		}

		fires := 0
		for _, subj := range matched {
			if err := emitFinding(cp, p, rule, subj, kind, org, runDir); err != nil {
				onError(fmt.Errorf("%s: write finding: %w", rule.ID, err))
				continue
			}
			fires++
		}
		ruleFires[rule.ID] = fires
		total += fires
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	if err := cp.Write(engine.ScanSummary(), scanSummary{
		RulesLoaded:   len(rules),
		TotalFindings: total,
		RuleFires:     ruleFires,
	}); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	timer.OutputFiles = total

	slog.Info("scan complete", "rules", len(rules), "findings", total, "errors", len(timer.Errors))
	return nil
}

// A malformed record is a normalize contract violation and aborts the phase.
func loadSubjects(prior engine.PriorPhase, p Provider, kind string) ([]map[string]any, error) {
	dir, ok := p.SubjectDirs[kind]
	if !ok {
		return nil, nil
	}
	return loadRecords(prior, filepath.Join("10-normalize", dir))
}

// A missing file yields (nil,nil) so the rule fires zero times; a missing join
// is left for EvaluateChainRule to report.
func loadChain(prior engine.PriorPhase, chain *ChainOf) (map[string]any, error) {
	if chain == nil || chain.Join == "" {
		return nil, nil
	}
	p := prior.Abs(filepath.Join("10-normalize", "chains", chain.Join+".json"))
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("chain %s: %w", chain.Join, err)
	}
	return data, nil
}

func emitFinding(cp engine.CurrentPhase, p Provider, rule *Rule, subject map[string]any, kind, org, runDir string) error {
	f := BuildFinding(p, rule, subject, kind, org, runDir)
	return cp.Write(engine.Finding(rule.ID, p.subjectHash(subject)), f)
}
