package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	ado "github.com/praetorian-inc/trajan/cmd/trajan/ado"
	ghcmd "github.com/praetorian-inc/trajan/cmd/trajan/github"
	gitlab "github.com/praetorian-inc/trajan/cmd/trajan/gitlab"
	jenkins "github.com/praetorian-inc/trajan/cmd/trajan/jenkins"
	jfrog "github.com/praetorian-inc/trajan/cmd/trajan/jfrog"
	local "github.com/praetorian-inc/trajan/cmd/trajan/local"
)

var (
	// Global flags
	verbose bool
	output  string
	token   string

	// Proxy flags
	httpProxy  string
	socksProxy string
)

var rootCmd = &cobra.Command{
	Use:   "trajan",
	Short: "Trajan - CI/CD Security Scanner",
	Long:  `Trajan - CI/CD Security Scanner`,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.EnableCommandSorting = false
	cobra.OnInitialize(initLogging)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.PersistentFlags().SortFlags = false
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "console", "output format (console, json, sarif, html)")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "API token (or set GH_TOKEN/GITHUB_TOKEN env var)")
	rootCmd.PersistentFlags().StringVar(&httpProxy, "proxy", "", "HTTP proxy URL (e.g., http://proxy:8080)")
	rootCmd.PersistentFlags().StringVar(&socksProxy, "socks-proxy", "", "SOCKS5 proxy URL (e.g., socks5://proxy:1080)")

	// Command groups
	rootCmd.AddGroup(
		&cobra.Group{ID: "platforms", Title: "Platforms:"},
		&cobra.Group{ID: "utilities", Title: "Utilities:"},
	)

	// Platform commands (ordered)
	ghcmd.GitHubCmd.GroupID = "platforms"
	gitlab.GitLabCmd.GroupID = "platforms"
	ado.AdoCmd.GroupID = "platforms"
	jenkins.JenkinsCmd.GroupID = "platforms"
	jfrog.JFrogCmd.GroupID = "platforms"
	local.LocalCmd.GroupID = "platforms"

	rootCmd.AddCommand(ghcmd.GitHubCmd)
	rootCmd.AddCommand(gitlab.GitLabCmd)
	rootCmd.AddCommand(ado.AdoCmd)
	rootCmd.AddCommand(jenkins.JenkinsCmd)
	rootCmd.AddCommand(jfrog.JFrogCmd)
	rootCmd.AddCommand(local.LocalCmd)

	// Utility commands
	searchCmd.Hidden = true
	versionCmd.GroupID = "utilities"

	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(versionCmd)

	// Move built-in help and completion into utilities group
	rootCmd.SetHelpCommandGroupID("utilities")
	rootCmd.SetCompletionCommandGroupID("utilities")
}

func initLogging() {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
