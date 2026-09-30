package github

import (
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/internal/report"
	"github.com/praetorian-inc/trajan/internal/ui"
)

func envTrue(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	return v != "" && v != "0" && v != "false"
}

var GitHubCmd = newGitHubCmd()

func newGitHubCmd() *cobra.Command {
	cfg := &engine.Config{}

	gh := &cobra.Command{
		Use:     "github",
		Aliases: []string{"gh"},
		Short:   "GitHub platform",
		Long:    "GitHub platform",
	}

	// --concurrency / --output-dir are local to the GitHub subtree (not root
	// globals) and feed engine.Config. GitHub ignores trajan's root --output.
	gh.PersistentFlags().SortFlags = false
	gh.PersistentFlags().IntVar(&cfg.Concurrency, "concurrency", 8, "max concurrent API workers")
	gh.PersistentFlags().StringVar(&cfg.OutputDir, "output-dir", "./trajan-out", "run output directory")
	gh.PersistentFlags().StringVar(&cfg.BaseURL, "url", "", "GitHub Enterprise Server base URL (default github.com)")
	gh.PersistentFlags().BoolVar(&cfg.Insecure, "insecure", false, "skip TLS verify (self-signed GitHub Enterprise Server)")
	gh.PersistentPreRunE = func(*cobra.Command, []string) error {
		cfg.UI = ui.Std()
		cfg.Invocation = os.Args[1:]
		cfg.DefaultBranchOnly = envTrue("TRAJAN_DEFAULT_BRANCH_ONLY")
		cfg.ForceREST = os.Getenv("TRAJAN_FORCE_REST") != ""
		return nil
	}

	var path string
	var tokenFlag string
	var neo4jURL, neo4jUser, neo4jPass string
	var neo4jReset bool
	var writeBack, noGraph, detailed bool
	var orgDetectionsOnly bool
	var reportFormat, reportMinSev, reportMinConf, reportOut string

	whoami := &cobra.Command{
		Use:   "whoami",
		Short: "Resolve the token and print the authenticated identity and scopes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return github.WhoAmI(cmd.Context(), cfg)
		},
	}
	collect := &cobra.Command{
		Use:   "collect <locator>",
		Short: "Collect raw GitHub Actions configuration for an org or repo",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := github.Collect(cmd.Context(), cfg, args[0])
			return err
		},
	}
	normalize := &cobra.Command{
		Use:   "normalize",
		Short: "Normalize collected data into fact records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", path)
			if err != nil {
				return err
			}
			return github.Normalize(cmd.Context(), cfg, runDir)
		},
	}
	scan := &cobra.Command{
		Use:   "scan [locator]",
		Short: "Evaluate category rules over normalized facts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", path)
			if err != nil {
				return err
			}
			return github.Scan(cmd.Context(), cfg, runDir, github.ScanOptions{HierarchyOnly: orgDetectionsOnly})
		},
	}
	reportCmd := &cobra.Command{
		Use:   "report [locator]",
		Short: "Render findings (json|jsonl|md|html|all) from a scanned run",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", path)
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
		Short: "Build importable graph nodes/edges from normalized facts and findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", path)
			if err != nil {
				return err
			}
			targets, err := graph.RuleTargets(func(e error) { slog.Warn("rule skipped", "err", e) })
			if err != nil {
				return err
			}
			return graph.Build(cmd.Context(), cfg, runDir, targets)
		},
	}
	push := &cobra.Command{
		Use:   "push",
		Short: "Push facts + findings into the graph",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", path)
			if err != nil {
				return err
			}
			return graph.Push(cmd.Context(), cfg, runDir, neo4jURL, neo4jUser, neo4jPass, neo4jReset)
		},
	}
	analyze := &cobra.Command{
		Use:   "analyze",
		Short: "Run deeper analysis over the graph",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runDir, err := engine.ResolveRunDir(cfg, "gh", path)
			if err != nil {
				return err
			}
			return graph.Analyze(cmd.Context(), cfg, runDir, writeBack, noGraph, detailed)
		},
	}
	attack := newAttackCmd(cfg)
	run := &cobra.Command{
		Use:   "run <locator>",
		Short: "Wrapper: collect, normalize, scan in one process",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runDir, err := github.Collect(cmd.Context(), cfg, args[0])
			if err != nil {
				return err
			}
			if err := github.Normalize(cmd.Context(), cfg, runDir); err != nil {
				return err
			}
			return github.Scan(cmd.Context(), cfg, runDir, github.ScanOptions{})
		},
	}

	scan.Flags().BoolVar(&orgDetectionsOnly, "org-detections-only", false, "evaluate only rules above the repository (org subjects)")

	// attack is deliberately absent: its subcommands each bind their own --path, so a
	// flag on the parent would read a variable none of them consult.
	for _, c := range []*cobra.Command{normalize, scan, reportCmd, graphCmd, push, analyze} {
		c.Flags().StringVarP(&path, "path", "p", "", "run directory (default: latest)")
	}
	reportCmd.Flags().StringVar(&reportFormat, "format", "jsonl", "output format: json|jsonl|md|html|all")
	reportCmd.Flags().StringVar(&reportMinSev, "min-severity", "info", "drop findings below this severity")
	reportCmd.Flags().StringVar(&reportMinConf, "min-confidence", "low", "drop findings below this confidence")
	// No "o" shorthand: the root command already owns -o for --output, and cobra
	// panics when a subcommand's local flag redefines an inherited shorthand.
	reportCmd.Flags().StringVar(&reportOut, "out", "", "destination dir, or '-' for stdout (default: stdout for json/jsonl, run dir for md/html)")
	push.Flags().StringVar(&neo4jURL, "neo4j-url", "bolt://localhost:7687", "Neo4j Bolt URL")
	push.Flags().StringVar(&neo4jUser, "neo4j-user", "neo4j", "Neo4j user")
	push.Flags().StringVar(&neo4jPass, "neo4j-pass", "", "Neo4j password")
	push.Flags().BoolVar(&neo4jReset, "reset", false, "delete every node in the database before pushing")
	analyze.Flags().BoolVarP(&writeBack, "write-back", "w", false, "persist analysis results")
	analyze.Flags().BoolVarP(&noGraph, "no-graph", "G", false, "analyze in-memory (no Neo4j)")
	analyze.Flags().BoolVarP(&detailed, "detailed", "d", false, "expand output")

	resolveToken := func(cmd *cobra.Command, _ []string) error {
		tok, err := github.ResolveToken(cmd.Context(), tokenFlag)
		if err != nil {
			return err
		}
		cfg.Token = tok
		return nil
	}
	for _, c := range []*cobra.Command{whoami, collect, run} {
		c.Flags().StringVar(&tokenFlag, "token", "", "API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch)")
		c.PreRunE = resolveToken
	}

	gh.AddCommand(whoami, collect, normalize, scan, reportCmd, graphCmd, push, analyze, attack, run)
	return gh
}
