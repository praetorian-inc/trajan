package gitlab

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	_ "github.com/praetorian-inc/trajan/pkg/gitlab/attacks/ror"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/attacks/runnerexec"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/attacks/secretsdump"
)

var (
	attackProject    string
	attackPlugins    []string
	attackTimeout    time.Duration
	attackOutputFile string
	attackList       bool
	attackDryRun     bool
	attackConfirm    bool
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Execute attacks against GitLab CI/CD vulnerabilities",
	Long: `Trajan - GitLab CI - Attack

SAFETY WARNING: This command executes real attacks that modify resources.
Always use --dry-run first to preview changes.

Available Plugins:
  secrets-dump        Exfiltrate CI/CD secrets via PPE (Poisoned Pipeline Execution)
  runner-exec         Execute commands on self-hosted runners
  ror                 Deploy a rogue runner via snippet payload (Runner-on-Runner)`,
	RunE: runAttack,
}

func init() {
	attackCmd.Flags().SortFlags = false

	// List plugins
	attackCmd.Flags().BoolVar(&attackList, "list", false, "list available attack plugins")

	// Target flags
	attackCmd.Flags().StringVar(&attackProject, "project", "", "project to attack (namespace/project)")

	// Attack selection
	attackCmd.Flags().StringSliceVar(&attackPlugins, "plugin", nil, "attack plugins to run")

	// Execution control
	attackCmd.Flags().BoolVar(&attackDryRun, "dry-run", false, "preview attack without executing")
	attackCmd.Flags().BoolVar(&attackConfirm, "confirm", false, "confirm live execution (required without --dry-run)")
	attackCmd.Flags().DurationVar(&attackTimeout, "timeout", 5*time.Minute, "timeout for pipeline execution")
	attackCmd.Flags().StringVar(&attackOutputFile, "output-file", "", "save command output to file")

	// runner-exec plugin flags
	attackCmd.Flags().String("runner-tags", "", "comma-separated runner tags for targeting specific runners")
	attackCmd.Flags().String("command", "", "command to execute for runner-exec")
	attackCmd.Flags().Bool("no-cleanup", false, "preserve artifacts after attack (branch, pipeline, logs)")

	// ror plugin flags
	attackCmd.Flags().String("snippet-url", "", "URL to GitLab snippet containing base64-encoded RoR payload")
	attackCmd.Flags().Bool("stealth", false, "use benign-looking job/stage/branch names")
	attackCmd.Flags().String("job-name", "", "custom job name for the injected CI job")
	attackCmd.Flags().String("stage-name", "", "custom stage name for the injected CI job")
	attackCmd.Flags().String("commit-message", "Update CI configuration", "commit message for the injected .gitlab-ci.yml")
	attackCmd.Flags().String("branch", "", "branch name for the attack (default: auto-generated)")
	attackCmd.Flags().Int("persist", 0, "keep the job alive for N minutes after payload execution")
}

func runAttack(cmd *cobra.Command, args []string) error {
	// Handle --list flag
	if attackList {
		plugins := registry.GetAttackPlugins("gitlab")
		if len(plugins) == 0 {
			fmt.Println("No attack plugins available for gitlab")
			return nil
		}

		fmt.Println("Available GitLab attack plugins:")
		for _, plugin := range plugins {
			fmt.Printf("  %-20s %s\n", plugin.Name(), plugin.Description())
		}
		return nil
	}

	if attackProject == "" {
		return fmt.Errorf("--project is required")
	}

	if len(attackPlugins) == 0 {
		return fmt.Errorf("--plugin is required")
	}

	// Safety gate: require --confirm for live execution
	if !attackDryRun && !attackConfirm {
		return fmt.Errorf("SAFETY: Live attack execution requires --confirm flag.\n" +
			"Use --dry-run to preview, or --confirm to execute.\n" +
			"Example: trajan gitlab attack --project namespace/project --plugin secrets-dump --confirm")
	}

	// Show what will happen (stderr so structured output stays clean)
	if attackDryRun {
		fmt.Fprintf(os.Stderr, "[DRY RUN] Previewing attack against %s\n\n", attackProject)
	} else {
		fmt.Fprintf(os.Stderr, "Executing live attack against %s\n\n", attackProject)
	}

	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("GITLAB_TOKEN is required")
	}

	sessionID := uuid.New().String()[:8]

	ctx, cancel := context.WithTimeout(context.Background(), attackTimeout)
	defer cancel()

	platform, err := registry.GetPlatform("gitlab")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	gitlabURL, _ := cmd.Flags().GetString("url")
	if gitlabURL == "" {
		gitlabURL = "https://gitlab.com"
	}

	initConfig := platforms.Config{
		Token:       token,
		BaseURL:     gitlabURL,
		Concurrency: 10,
	}
	cmdutil.ApplyProxyFlags(cmd, &initConfig)

	if err := platform.Init(ctx, initConfig); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	target := platforms.Target{Type: platforms.TargetRepo, Value: attackProject}
	session := attacks.NewSession(sessionID, target, "gitlab", "")

	// Build extra options shared across all plugins
	extraOpts := make(map[string]string)
	if runnerTags, _ := cmd.Flags().GetString("runner-tags"); runnerTags != "" {
		extraOpts["runner-tags"] = runnerTags
	}
	if command, _ := cmd.Flags().GetString("command"); command != "" {
		extraOpts["command"] = command
	}
	noCleanup, _ := cmd.Flags().GetBool("no-cleanup")
	if noCleanup {
		extraOpts["cleanup"] = "false"
	}

	// RoR plugin flags
	if snippetURL, _ := cmd.Flags().GetString("snippet-url"); snippetURL != "" {
		extraOpts["snippet-url"] = snippetURL
	}
	if stealthFlag, _ := cmd.Flags().GetBool("stealth"); stealthFlag {
		extraOpts["stealth"] = "true"
	}
	if jn, _ := cmd.Flags().GetString("job-name"); jn != "" {
		extraOpts["job-name"] = jn
	}
	if sn, _ := cmd.Flags().GetString("stage-name"); sn != "" {
		extraOpts["stage-name"] = sn
	}
	if cm, _ := cmd.Flags().GetString("commit-message"); cm != "" {
		extraOpts["commit-message"] = cm
	}
	if persist, _ := cmd.Flags().GetInt("persist"); persist > 0 {
		extraOpts["persist"] = fmt.Sprintf("%d", persist)
	}

	// Execute plugins and collect results
	var results []*attacks.AttackResult
	for _, pluginName := range attackPlugins {
		plugin, err := registry.GetAttackPluginByName(registry.PluginKey(platforms.PlatformGitLab, pluginName))
		if err != nil {
			return fmt.Errorf("unknown plugin: %s", pluginName)
		}

		attackBranch, _ := cmd.Flags().GetString("branch")
		opts := attacks.AttackOptions{
			Platform:  platform,
			Target:    target,
			SessionID: sessionID,
			DryRun:    attackDryRun,
			Timeout:   attackTimeout,
			Branch:    attackBranch,
			ExtraOpts: extraOpts,
		}

		result, err := plugin.Execute(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Attack %s failed: %v\n", pluginName, err)
			continue
		}

		results = append(results, result)
		session.AddResult(result)
	}

	if err := session.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
	}

	// Write extracted data to file if requested
	if attackOutputFile != "" {
		if err := cmdutil.WriteExtractedDataToFile(attackOutputFile, results); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write output file: %v\n", err)
		}
	}

	return cmdutil.OutputAttackResults(cmdutil.GetOutput(cmd), results, sessionID, "trajan gitlab attack cleanup")
}
