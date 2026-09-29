package github

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/engine/detect"
	"github.com/praetorian-inc/trajan/internal/github"
	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/internal/report"
)

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
	// globals) and feed engine.Config. The root command carries no output flag
	// of its own for them to shadow.
	gh.PersistentFlags().SortFlags = false
	gh.PersistentFlags().IntVar(&cfg.Concurrency, "concurrency", 8, "max concurrent API workers")
	gh.PersistentFlags().StringVar(&cfg.OutputDir, "output-dir", "./trajan-out", "run output directory")

	var path string
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
			return github.WhoAmI(cmd.Context(), cfg.Token)
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
			return github.Normalize(cmd.Context(), runDir)
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
			return github.Scan(cmd.Context(), runDir, github.ScanOptions{OrgOnly: orgDetectionsOnly})
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
			// detect carries rule.Graph as an unparsed string so it stays
			// provider-generic; the target vocabulary is this platform's, so the
			// rule -> target index is built here rather than inside graph.Build.
			onError := func(e error) { slog.Warn("rule skipped", "err", e) }
			rules, err := detect.LoadRules("github", onError)
			if err != nil {
				return err
			}
			targets := make(map[string]graph.Target, len(rules))
			for _, r := range rules {
				t, err := graph.ParseTarget(r.Graph)
				if err != nil {
					onError(fmt.Errorf("%s: %w", r.ID, err))
					continue
				}
				targets[r.ID] = t
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
			if err := github.Normalize(cmd.Context(), runDir); err != nil {
				return err
			}
			return github.Scan(cmd.Context(), runDir, github.ScanOptions{})
		},
	}

	scan.Flags().BoolVar(&orgDetectionsOnly, "org-detections-only", false, "evaluate only org-subject (org-level) rules")

	// attack is deliberately absent: its subcommands each bind their own --path, so a
	// flag on the parent would read a variable none of them consult.
	for _, c := range []*cobra.Command{normalize, scan, reportCmd, graphCmd, push, analyze} {
		c.Flags().StringVarP(&path, "path", "p", "", "run directory (default: latest)")
	}
	reportCmd.Flags().StringVar(&reportFormat, "format", "jsonl", "output format: json|jsonl|md|html|all")
	reportCmd.Flags().StringVar(&reportMinSev, "min-severity", "info", "drop findings below this severity")
	reportCmd.Flags().StringVar(&reportMinConf, "min-confidence", "low", "drop findings below this confidence")
	// No "o" shorthand, here or on the gitlab and ado report commands: -o is
	// unclaimed across the whole tree, and leaving it so keeps it available to a
	// future root-level flag without a local shorthand shadowing it.
	reportCmd.Flags().StringVar(&reportOut, "out", "", "destination dir, or '-' for stdout (default: stdout for json/jsonl, run dir for md/html)")
	push.Flags().StringVar(&neo4jURL, "neo4j-url", "bolt://localhost:7687", "Neo4j Bolt URL")
	push.Flags().StringVar(&neo4jUser, "neo4j-user", "neo4j", "Neo4j user")
	push.Flags().StringVar(&neo4jPass, "neo4j-pass", "", "Neo4j password")
	push.Flags().BoolVar(&neo4jReset, "reset", false, "delete every node in the database before pushing")
	analyze.Flags().BoolVarP(&writeBack, "write-back", "w", false, "persist analysis results")
	analyze.Flags().BoolVarP(&noGraph, "no-graph", "G", false, "analyze in-memory (no Neo4j)")
	analyze.Flags().BoolVarP(&detailed, "detailed", "d", false, "expand output")

	for _, c := range []*cobra.Command{whoami, collect, run} {
		c.Flags().StringVar(&cfg.Token, "token", "", "API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch)")
	}

	gh.AddCommand(whoami, collect, normalize, scan, reportCmd, graphCmd, push, analyze, attack, run)
	return gh
}
