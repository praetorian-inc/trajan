package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/ui"

	ado "github.com/praetorian-inc/trajan/cmd/trajan/ado"
	ghcmd "github.com/praetorian-inc/trajan/cmd/trajan/github"
	gitlab "github.com/praetorian-inc/trajan/cmd/trajan/gitlab"
)

var (
	verbose bool
	debug   bool
	noColor bool

	httpProxy  string
	socksProxy string
)

var rootCmd = &cobra.Command{
	Use:   "trajan",
	Short: "Trajan - CI/CD Security Scanner",
	Long:  `Trajan - CI/CD Security Scanner`,
}

func Execute(ctx context.Context) {
	err := rootCmd.ExecuteContext(ctx)
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		slog.Warn("interrupted")
		os.Exit(130)
	}
	ui.Error(err.Error(), remedyFor(err))
	os.Exit(1)
}

func remedyFor(err error) string {
	switch {
	case errors.Is(err, engine.ErrNoRunDir):
		return "run the collect phase first, or pass --path to an existing run directory"
	case errors.Is(err, engine.ErrPhaseBackStep):
		return "run the missing phase first, or start over with collect"
	}
	return ""
}

func init() {
	cobra.EnableCommandSorting = false
	cobra.OnInitialize(initUI)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	// Cobra otherwise finds the subcommand by skipping args it takes for flag
	// values, so an unknown flag ahead of it swallows the command name.
	rootCmd.TraverseChildren = true
	rootCmd.PersistentFlags().SortFlags = false
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "raw slog records instead of humanized output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable color (also honors NO_COLOR)")
	// Superseded by --debug, but the pkg/ platforms still read it.
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	_ = rootCmd.PersistentFlags().MarkHidden("verbose")
	rootCmd.PersistentFlags().StringVar(&httpProxy, "proxy", "", "HTTP proxy URL (e.g., http://proxy:8080)")
	rootCmd.PersistentFlags().StringVar(&socksProxy, "socks-proxy", "", "SOCKS5 proxy URL (e.g., socks5://proxy:1080)")

	rootCmd.AddGroup(
		&cobra.Group{ID: "platforms", Title: "Platforms:"},
		&cobra.Group{ID: "utilities", Title: "Utilities:"},
	)

	// Registration order is the help order: command sorting is disabled above.
	ghcmd.GitHubCmd.GroupID = "platforms"
	gitlab.GitLabCmd.GroupID = "platforms"
	ado.AdoCmd.GroupID = "platforms"

	rootCmd.AddCommand(ghcmd.GitHubCmd)
	rootCmd.AddCommand(gitlab.GitLabCmd)
	rootCmd.AddCommand(ado.AdoCmd)

	searchCmd.Hidden = true
	versionCmd.GroupID = "utilities"

	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(versionCmd)

	rootCmd.SetHelpCommandGroupID("utilities")
	rootCmd.SetCompletionCommandGroupID("utilities")
}

func initUI() {
	tier := ui.Human
	if debug || verbose {
		tier = ui.Debug
		_ = rootCmd.PersistentFlags().Set("verbose", "true")
	}
	ui.Init(tier, !noColor && ui.ColorEnabled())
}
