package ado

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	adopkg "github.com/praetorian-inc/trajan/internal/ado"
	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/engine/detect"
	"github.com/praetorian-inc/trajan/internal/report"
)

var AdoCmd = newAdoCmd()

func ruleTargets() (map[string]adopkg.Target, error) {
	onError := func(e error) { slog.Warn("rule skipped", "err", e) }
	rules, err := detect.LoadRules("ado", onError)
	if err != nil {
		return nil, err
	}
	targets := make(map[string]adopkg.Target, len(rules))
	for _, r := range rules {
		t, err := adopkg.ParseTarget(r.Graph)
		if err != nil {
			onError(fmt.Errorf("%s: %w", r.ID, err))
			continue
		}
		targets[r.ID] = t
	}
	return targets, nil
}

const (
	tokenHelp     = "PAT (prefer TRAJAN_ADO_TOKEN/ADO_PAT/AZURE_DEVOPS_PAT/AZDO_PAT/AZURE_DEVOPS_EXT_PAT env; this flag is an escape hatch)"
	bearerHelp    = "bearer token (prefer AZURE_BEARER_TOKEN/SYSTEM_ACCESSTOKEN env; this flag is an escape hatch)"
	neo4jPassHelp = "Neo4j password (prefer TRAJAN_NEO4J_PASSWORD/NEO4J_PASSWORD env; this flag is an escape hatch)"
)

func newAdoCmd() *cobra.Command {
	cfg := &engine.Config{}

	ado := &cobra.Command{
		Use:   "ado",
		Short: "Trajan - Azure DevOps",
		Long:  "Trajan - Azure DevOps",
	}

	ado.PersistentFlags().SortFlags = false
	ado.PersistentFlags().IntVar(&cfg.Concurrency, "concurrency", 8, "max concurrent API workers")
	ado.PersistentFlags().StringVar(&cfg.OutputDir, "output-dir", "./trajan-out", "run output directory")

	var path string
	var orgDetectionsOnly bool
	var reportFormat, reportMinSev, reportMinConf, reportOut string
	var neo4jURL, neo4jUser, neo4jPass string
	var neo4jReset bool

	collectRun := func(cmd *cobra.Command, args []string) (string, error) {
		locator := ""
		if len(args) > 0 {
			locator = args[0]
		}
		return adopkg.Collect(cmd.Context(), cfg, locator)
	}

	var whoamiOrg string
	whoami := &cobra.Command{
		Use:   "whoami",
		Short: "Resolve the token and print the authenticated identity and reachable surfaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return adopkg.WhoAmI(cmd.Context(), whoamiOrg, cfg.Token, cfg.BearerToken)
		},
	}
	whoami.Flags().StringVar(&whoamiOrg, "org", "", "Azure DevOps organization (default: ORG_NAME)")

	collect := &cobra.Command{
		Use:   "collect [locator]",
		Short: "Collect raw Azure DevOps configuration for an org/project",
		Long: `Collect raw Azure DevOps configuration into a new run directory.

Locator is "<org>", "<org>/<project>" or "<org>/<project>/<repo>", either bare or
as a full URL (https://dev.azure.com/<org>/<project>, <org>.visualstudio.com/...).
Omitted, it falls back to the ORG_NAME environment variable.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := collectRun(cmd, args)
			return err
		},
	}
	normalize := &cobra.Command{
		Use:   "normalize",
		Short: "Normalize collected Azure DevOps data into structural node/edge records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "ado", path)
			if err != nil {
				return err
			}
			return adopkg.Normalize(cmd.Context(), runDir)
		},
	}
	scan := &cobra.Command{
		Use:   "scan",
		Short: "Evaluate ADO detection rules over a normalized run",
		Long: `Run the phased detection engine over a normalized run directory.

Reads the 10-normalize records produced by 'ado normalize', evaluates the
embedded ADO detection-rule corpus, and writes findings to 20-scan.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "ado", path)
			if err != nil {
				return err
			}
			return adopkg.Scan(cmd.Context(), runDir, adopkg.ScanOptions{OrgOnly: orgDetectionsOnly})
		},
	}
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Render findings (json|jsonl|md|html|all) from a scanned run",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "ado", path)
			if err != nil {
				return err
			}
			return report.Run(cmd.Context(), runDir, report.Options{
				Format:        reportFormat,
				MinSeverity:   reportMinSev,
				MinConfidence: reportMinConf,
				Out:           reportOut,
			})
		},
	}
	graph := &cobra.Command{
		Use:   "graph",
		Short: "Build the property graph from a normalized, scanned run",
		Long: `Build nodes and edges from a normalized run directory.

Reads the 10-normalize records and 20-scan findings, resolves every edge record to
typed endpoints, and writes nodes, edges and a summary to 30-graph.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "ado", path)
			if err != nil {
				return err
			}
			targets, err := ruleTargets()
			if err != nil {
				return err
			}
			return adopkg.BuildGraph(cmd.Context(), cfg, runDir, targets)
		},
	}
	push := &cobra.Command{
		Use:   "push",
		Short: "Push a built graph into Neo4j",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "ado", path)
			if err != nil {
				return err
			}
			return adopkg.PushGraph(cmd.Context(), cfg, runDir, neo4jURL, neo4jUser,
				engine.ResolveNeo4j(neo4jPass), neo4jReset)
		},
	}
	run := &cobra.Command{
		Use:   "run [locator]",
		Short: "Wrapper: collect, normalize, scan, graph in one process",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runDir, err := collectRun(cmd, args)
			if err != nil {
				return err
			}
			if err := adopkg.Normalize(cmd.Context(), runDir); err != nil {
				return err
			}
			if err := adopkg.Scan(cmd.Context(), runDir, adopkg.ScanOptions{}); err != nil {
				return err
			}
			targets, err := ruleTargets()
			if err != nil {
				return err
			}
			return adopkg.BuildGraph(cmd.Context(), cfg, runDir, targets)
		},
	}

	scan.Flags().BoolVar(&orgDetectionsOnly, "org-detections-only", false, "evaluate only org-subject (org-level) rules")
	push.Flags().StringVar(&neo4jURL, "neo4j-url", "bolt://localhost:7687", "Neo4j bolt URL")
	push.Flags().StringVar(&neo4jUser, "neo4j-user", "neo4j", "Neo4j user")
	push.Flags().StringVar(&neo4jPass, "neo4j-pass", "", neo4jPassHelp)
	push.Flags().BoolVar(&neo4jReset, "reset", false, "delete every node in the database before writing")

	for _, c := range []*cobra.Command{normalize, scan, reportCmd, graph, push} {
		c.Flags().StringVarP(&path, "path", "p", "", "run directory (default: latest)")
	}
	reportCmd.Flags().StringVar(&reportFormat, "format", "jsonl", "output format: json|jsonl|md|html|all")
	reportCmd.Flags().StringVar(&reportMinSev, "min-severity", "info", "drop findings below this severity")
	reportCmd.Flags().StringVar(&reportMinConf, "min-confidence", "low", "drop findings below this confidence")
	reportCmd.Flags().StringVar(&reportOut, "out", "", "destination dir, or '-' for stdout (default: the run dir)")

	for _, c := range []*cobra.Command{whoami, collect, run} {
		c.Flags().StringVar(&cfg.Token, "token", "", tokenHelp)
		c.Flags().StringVar(&cfg.BearerToken, "azure-bearer-token", "", bearerHelp)
	}

	ado.AddCommand(whoami, collect, normalize, scan, reportCmd, graph, push, run)
	return ado
}
