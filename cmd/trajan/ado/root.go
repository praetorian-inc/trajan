package ado

import (
	"os"

	"github.com/spf13/cobra"

	adopkg "github.com/praetorian-inc/trajan/internal/ado"
	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/report"
)

var AdoCmd = newAdoCmd()

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

	collectRun := func(cmd *cobra.Command, args []string) (string, error) {
		cfg.Token, _ = cmd.Flags().GetString("token") // honor the global --token (persistent flag)
		cfg.BearerToken = getBearerToken(cmd)
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
			token, _ := cmd.Flags().GetString("token")
			return adopkg.WhoAmI(cmd.Context(), whoamiOrg, token)
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
	run := &cobra.Command{
		Use:   "run [locator]",
		Short: "Wrapper: collect, normalize, scan in one process",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runDir, err := collectRun(cmd, args)
			if err != nil {
				return err
			}
			if err := adopkg.Normalize(cmd.Context(), runDir); err != nil {
				return err
			}
			return adopkg.Scan(cmd.Context(), runDir, adopkg.ScanOptions{})
		},
	}

	scan.Flags().BoolVar(&orgDetectionsOnly, "org-detections-only", false, "evaluate only org-subject (org-level) rules")

	for _, c := range []*cobra.Command{normalize, scan, reportCmd} {
		c.Flags().StringVarP(&path, "path", "p", "", "run directory (default: latest)")
	}
	reportCmd.Flags().StringVar(&reportFormat, "format", "jsonl", "output format: json|jsonl|md|html|all")
	reportCmd.Flags().StringVar(&reportMinSev, "min-severity", "info", "drop findings below this severity")
	reportCmd.Flags().StringVar(&reportMinConf, "min-confidence", "low", "drop findings below this confidence")
	reportCmd.Flags().StringVar(&reportOut, "out", "", "destination dir, or '-' for stdout (default: the run dir)")

	for _, c := range []*cobra.Command{scanCmd, attackCmd, retrieveCmd, collect, run} {
		c.Flags().String("azure-bearer-token", "", "Azure Entra ID bearer token (or set AZURE_BEARER_TOKEN)")
	}

	// The phased scan takes over "ado scan"; the legacy scanner stays reachable here.
	scanCmd.Use = "scan-legacy"

	ado.AddCommand(whoami, enumerateCmd, collect, normalize, scan, reportCmd, run, attackCmd, retrieveCmd, scanCmd)
	return ado
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "azuredevops")
}

func getBearerToken(cmd *cobra.Command) string {
	if t, err := cmd.Flags().GetString("azure-bearer-token"); err == nil && t != "" {
		return t
	}
	return os.Getenv("AZURE_BEARER_TOKEN")
}
