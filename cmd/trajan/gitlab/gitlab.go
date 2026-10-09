package gitlab

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/gitlab"
	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/internal/report"
	"github.com/praetorian-inc/trajan/internal/ui"
)

var GitLabCmd = newGitLabCmd(&engine.Config{})

func buildGraph(cmd *cobra.Command, cfg *engine.Config, runDir string) error {
	provider := gitlab.GraphProvider()
	targets, err := graph.RuleTargets(provider, func(e error) { slog.Warn("rule skipped", "err", e) })
	if err != nil {
		return err
	}
	return graph.Build(cmd.Context(), cfg, runDir, provider, targets)
}

func newGitLabCmd(cfg *engine.Config) *cobra.Command {
	gl := &cobra.Command{
		Use:     "gitlab",
		Aliases: []string{"gl"},
		Short:   "GitLab platform",
		Long:    "GitLab platform",
	}

	// --concurrency / --output-dir are local to the GitLab subtree (not root
	// globals) and feed engine.Config. GitLab ignores trajan's root --output.
	gl.PersistentFlags().SortFlags = false
	gl.PersistentFlags().IntVar(&cfg.Concurrency, "concurrency", 8, "max concurrent API workers")
	gl.PersistentFlags().StringVar(&cfg.OutputDir, "output-dir", "./trajan-out", "run output directory")
	gl.PersistentFlags().StringVar(&cfg.BaseURL, "url", "https://gitlab.com", "GitLab base URL (self-hosted)")
	gl.PersistentFlags().BoolVar(&cfg.Insecure, "insecure", false, "skip TLS verify (self-signed self-hosted)")
	gl.PersistentPreRunE = func(*cobra.Command, []string) error {
		cfg.UI = ui.Std()
		cfg.Invocation = os.Args[1:]
		return nil
	}

	var path string
	var tokenFlag string
	var writeBack, noGraph, detailed bool
	var groupDetectionsOnly bool
	var reportFormat, reportMinSev, reportMinConf, reportOut string
	var neo4jURL, neo4jUser, neo4jPass string
	var neo4jReset bool

	whoami := &cobra.Command{
		Use:   "whoami",
		Short: "Resolve the token and print the authenticated identity and scopes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return gitlab.WhoAmI(cmd.Context(), cfg)
		},
	}
	collect := &cobra.Command{
		Use:   "collect <locator>",
		Short: "Collect raw GitLab CI configuration for a group, subgroup, or project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := gitlab.Collect(cmd.Context(), cfg, args[0])
			return err
		},
	}
	normalize := &cobra.Command{
		Use:   "normalize",
		Short: "Normalize collected data into fact records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gl", path)
			if err != nil {
				return err
			}
			return gitlab.Normalize(cmd.Context(), cfg, runDir)
		},
	}
	scan := &cobra.Command{
		Use:   "scan [locator]",
		Short: "Evaluate category rules over normalized facts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gl", path)
			if err != nil {
				return err
			}
			return gitlab.Scan(cmd.Context(), cfg, runDir, gitlab.ScanOptions{HierarchyOnly: groupDetectionsOnly})
		},
	}
	reportCmd := &cobra.Command{
		Use:   "report [locator]",
		Short: "Render findings (json|jsonl|md|html|all) from a scanned run",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gl", path)
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
	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "Build the property graph from a normalized, scanned run",
		Long: `Build nodes and containment edges from a normalized run directory.

Reads the 10-normalize records and 20-scan findings, emits one node per record so
every finding has somewhere to land, and writes nodes, edges and a summary to
30-graph. GitLab carries no relationship vocabulary beyond containment.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gl", path)
			if err != nil {
				return err
			}
			return buildGraph(cmd, cfg, runDir)
		},
	}
	push := &cobra.Command{
		Use:   "push",
		Short: "Push a built graph into Neo4j",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gl", path)
			if err != nil {
				return err
			}
			return gitlab.PushGraph(cmd.Context(), cfg, runDir, neo4jURL, neo4jUser,
				engine.ResolveNeo4j(neo4jPass), neo4jReset)
		},
	}
	analyze := &cobra.Command{
		Use:   "analyze",
		Short: "Run deeper analysis over the graph",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gl", path)
			if err != nil {
				return err
			}
			return graph.Analyze(cmd.Context(), cfg, runDir, writeBack, noGraph, detailed)
		},
	}
	attack := &cobra.Command{
		Use:   "attack",
		Short: "Active exploitation (reserved)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return engine.ErrNotImplemented
		},
	}
	run := &cobra.Command{
		Use:   "run <locator>",
		Short: "Wrapper: collect, normalize, scan, graph in one process",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runDir, err := gitlab.Collect(cmd.Context(), cfg, args[0])
			if err != nil {
				return err
			}
			if err := gitlab.Normalize(cmd.Context(), cfg, runDir); err != nil {
				return err
			}
			if err := gitlab.Scan(cmd.Context(), cfg, runDir, gitlab.ScanOptions{}); err != nil {
				return err
			}
			return buildGraph(cmd, cfg, runDir)
		},
	}

	scan.Flags().BoolVar(&groupDetectionsOnly, "group-detections-only", false, "evaluate only rules above the project (group and instance subjects)")

	push.Flags().StringVar(&neo4jURL, "neo4j-url", "bolt://localhost:7687", "Neo4j bolt URL")
	push.Flags().StringVar(&neo4jUser, "neo4j-user", "neo4j", "Neo4j user")
	push.Flags().StringVar(&neo4jPass, "neo4j-pass", "",
		"Neo4j password (prefer TRAJAN_NEO4J_PASSWORD/NEO4J_PASSWORD env; this flag is an escape hatch)")
	push.Flags().BoolVar(&neo4jReset, "reset", false, "delete every node in the database before writing")

	for _, c := range []*cobra.Command{normalize, scan, reportCmd, graphCmd, push, analyze, attack} {
		c.Flags().StringVarP(&path, "path", "p", "", "run directory (default: latest)")
	}
	reportCmd.Flags().StringVar(&reportFormat, "format", "jsonl", "output format: json|jsonl|md|html|all")
	reportCmd.Flags().StringVar(&reportMinSev, "min-severity", "info", "drop findings below this severity")
	reportCmd.Flags().StringVar(&reportMinConf, "min-confidence", "low", "drop findings below this confidence")
	reportCmd.Flags().StringVar(&reportOut, "out", "", "destination dir, or '-' for stdout (default: the run dir)")
	analyze.Flags().BoolVarP(&writeBack, "write-back", "w", false, "persist analysis results")
	analyze.Flags().BoolVarP(&noGraph, "no-graph", "G", false, "analyze in-memory (no Neo4j)")
	analyze.Flags().BoolVarP(&detailed, "detailed", "d", false, "expand output")

	resolveToken := func(*cobra.Command, []string) error {
		tok, err := gitlab.ResolveToken(tokenFlag)
		if err != nil {
			return err
		}
		cfg.Token = tok
		return nil
	}
	for _, c := range []*cobra.Command{whoami, collect, run} {
		c.Flags().StringVar(&tokenFlag, "token", "", "API token (prefer TRAJAN_GL_TOKEN/GITLAB_TOKEN/GL_TOKEN/CI_JOB_TOKEN env; this flag is an escape hatch)")
		c.PreRunE = resolveToken
	}

	gl.AddCommand(whoami, collect, normalize, scan, reportCmd, graphCmd, push, analyze, attack, run)
	return gl
}
