package github

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/chain"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"

	// Import to trigger init() registration
	_ "github.com/praetorian-inc/trajan/pkg/attacks/all"
)

var (
	// Attack target flags
	attackRepo string
	attackOrg  string

	// Attack selection flags
	attackPlugins  []string // Specific plugins to run
	attackCategory string   // Category filter
	attackAll      bool     // Run all applicable attacks

	// Execution flags
	attackDryRun    bool
	attackConfirm   bool // Confirmation for live execution
	attackForce     bool // Bypass vulnerability check for attack plugins
	attackTimeout   time.Duration
	attackSessionID string // For resuming/cleanup

	// Attack-specific flags
	attackPayload           string
	attackBranch            string
	attackC2Repo            string // C2 repository for runner-on-runner and interactive-shell
	attackTargetOS          string // Target OS for runner-on-runner (linux|win|macos)
	attackTargetArch        string // Target architecture for runner-on-runner (x64|arm64)
	attackRunnerLabels      string // Runner labels for runner-on-runner
	attackPersistenceMethod string // Persistence method (deploy_key|malicious_workflow|scheduled_backdoor)

	// Chain execution flags
	attackChain        string   // Named chain to execute
	attackChainPlugins []string // Custom chain (ordered plugin list)
	attackChainList    bool     // List available chains
	attackChainDeps    bool     // Show chain dependencies
	attackC2Org        string   // C2 organization for GitHub App installation tokens
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Execute attacks against GitHub CI/CD vulnerabilities",
	Long: `Trajan - GitHub - Attack

Execute offensive operations against detected GitHub CI/CD vulnerabilities.

SAFETY WARNING: This command executes real attacks that modify resources.
Always use --dry-run first to preview changes.

Available Plugins:
  secrets-dump        Exfiltrate repository secrets via encrypted workflow
  workflow-injection  Inject malicious workflow into repository
  pr-attack           Pull request based attack (pwn request exploitation)
  runner-on-runner    Pivot from self-hosted runner to C2
  interactive-shell   Get interactive shell on self-hosted runner
  c2-setup            Set up C2 infrastructure using GitHub repos
  persistence         Establish persistent access (deploy key, backdoor workflow)

Attack Chains (pre-built sequences):
  ror            Runner-on-Runner: C2 setup, deploy implant, connect shell
  secrets        Secrets Exfiltration: Dump pipeline secrets (no C2 needed)
  persistence    Establish Persistence: C2 setup, deploy persistent backdoor
  full           Full Attack: C2, RoR, shell, secrets dump, persistence
  ai-takeover    AI-powered CI/CD takeover chain
  supply-chain   Supply chain poisoning via artifacts
  toctou-exploit TOCTOU race condition exploitation
  stealth        Stealthy persistence via review bypass

Categories: secrets, cicd, runners, persistence, c2`,
	RunE: runAttack,
}

var attackCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up resources created by attacks",
	Long: `Trajan - GitHub - Attack - Cleanup

Remove or revert resources created during attack execution.`,
	RunE: runAttackCleanup,
}

func init() {
	attackCmd.AddCommand(attackCleanupCmd)

	attackCmd.Flags().SortFlags = false

	// Target flags
	attackCmd.Flags().StringVar(&attackRepo, "repo", "", "repository to attack (owner/repo)")
	attackCmd.Flags().StringVar(&attackOrg, "org", "", "organization to attack")

	// Attack selection
	attackCmd.Flags().StringSliceVar(&attackPlugins, "plugin", nil, "attack plugins to run (comma-separated)")
	attackCmd.Flags().StringVar(&attackCategory, "category", "", "attack category filter (secrets, cicd, runners, persistence, c2)")
	attackCmd.Flags().BoolVar(&attackAll, "all", false, "run all applicable attacks")

	// Execution control
	attackCmd.Flags().BoolVar(&attackDryRun, "dry-run", false, "preview attack without executing")
	attackCmd.Flags().BoolVar(&attackConfirm, "confirm", false, "confirm live execution (required without --dry-run)")
	attackCmd.Flags().BoolVar(&attackForce, "force", false, "bypass vulnerability check for attack plugins (force execution)")
	attackCmd.Flags().DurationVar(&attackTimeout, "timeout", 5*time.Minute, "attack timeout")
	attackCmd.Flags().StringVar(&attackSessionID, "session", "", "session ID for tracking/cleanup")

	// Attack-specific
	attackCmd.Flags().StringVar(&attackPayload, "payload", "", "custom payload file or inline script")
	attackCmd.Flags().StringVar(&attackBranch, "branch", "", "branch name for PR-based attacks")
	attackCmd.Flags().StringVar(&attackC2Repo, "c2-repo", "", "C2 repository for runner-on-runner and interactive-shell (owner/repo)")
	attackCmd.Flags().StringVar(&attackC2Org, "c2-org", "", "C2 organization for GitHub App installation tokens (creates C2 repo in this org)")
	attackCmd.Flags().StringVar(&attackTargetOS, "target-os", "linux", "target OS for runner-on-runner (linux|win|macos)")
	attackCmd.Flags().StringVar(&attackTargetArch, "target-arch", "x64", "target architecture for runner-on-runner (x64|arm64)")
	attackCmd.Flags().StringVar(&attackRunnerLabels, "runner-labels", "self-hosted", "runner labels for runner-on-runner (comma-separated)")
	attackCmd.Flags().StringVar(&attackPersistenceMethod, "persistence-method", "malicious_workflow", "persistence method (deploy_key|malicious_workflow|scheduled_backdoor)")

	// Chain execution
	attackCmd.Flags().StringVar(&attackChain, "chain", "", "execute named attack chain (ror, secrets, persistence, full)")
	attackCmd.Flags().StringSliceVar(&attackChainPlugins, "chain-plugins", nil, "execute custom chain with specified plugins in order")
	attackCmd.Flags().BoolVar(&attackChainList, "chain-list", false, "list available attack chains")
	attackCmd.Flags().BoolVar(&attackChainDeps, "chain-deps", false, "show dependency graph for specified chain")

	// Cleanup flags
	attackCleanupCmd.Flags().SortFlags = false
	attackCleanupCmd.Flags().StringVar(&attackSessionID, "session", "", "session ID to cleanup")
	attackCleanupCmd.Flags().Bool("list", false, "list available sessions")
	attackCleanupCmd.Flags().StringVar(&attackOrg, "org", "", "organization (auto-detected from session if not specified)")
}

func runAttack(cmd *cobra.Command, args []string) error {
	// Handle chain listing (early exit, read-only operation)
	if attackChainList {
		fmt.Println("Available attack chains:")
		for _, name := range chain.ListChains() {
			chainDef, ok := chain.GetChain(name)
			if !ok {
				slog.Warn("failed to get chain definition", "chain", name)
				continue
			}
			fmt.Printf("  %-12s %s\n", name, chainDef.Description)
			fmt.Printf("               Plugins: %s\n", strings.Join(chainDef.Plugins, " → "))
		}
		return nil
	}

	// Safety gate: require --confirm for live execution
	if !attackDryRun && !attackConfirm {
		return fmt.Errorf("SAFETY: Live attack execution requires --confirm flag.\n" +
			"Use --dry-run to preview, or --confirm to execute.\n" +
			"Example: trajan github attack --repo owner/repo --plugin secrets-dump --confirm")
	}

	// Validate token
	t := getToken(cmd)
	if t == "" {
		return fmt.Errorf("no token provided (use --token or set GH_TOKEN/GITHUB_TOKEN env var)")
	}

	// Validate target
	var target platforms.Target
	switch {
	case attackRepo != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: attackRepo}
	case attackOrg != "":
		target = platforms.Target{Type: platforms.TargetOrg, Value: attackOrg}
	default:
		if !attackChainDeps {
			return fmt.Errorf("must specify --repo or --org")
		}
	}

	// Handle chain dependencies (early exit)
	if attackChainDeps {
		if attackChain == "" {
			return fmt.Errorf("--chain-deps requires --chain")
		}
		chainDef, ok := chain.GetChain(attackChain)
		if !ok {
			return fmt.Errorf("unknown chain: %s", attackChain)
		}
		fmt.Printf("Chain: %s (%s)\n", chainDef.Name, chainDef.Description)
		for i, pluginName := range chainDef.Plugins {
			fmt.Printf("  %d. %s\n", i+1, pluginName)
			plugin, err := registry.GetAttackPluginByName(registry.PluginKey(platforms.PlatformGitHub, pluginName))
			if err != nil {
				fmt.Printf("     ERROR: %v\n", err)
				continue
			}
			if chainable, ok := plugin.(attacks.ChainableAttackPlugin); ok {
				provides := chainable.Provides()
				requires := chainable.Requires()
				if len(provides) > 0 {
					fmt.Printf("     Provides: %v\n", provides)
				}
				if len(requires) > 0 {
					fmt.Printf("     Requires: %v\n", requires)
				}
			}
		}
		return nil
	}

	// Validate attack selection (skip if chain specified)
	if attackChain == "" && len(attackChainPlugins) == 0 {
		if len(attackPlugins) == 0 && attackCategory == "" && !attackAll {
			return fmt.Errorf("must specify --plugin, --category, --all, --chain, or --chain-plugins")
		}
	}

	// Generate session ID if not provided
	sessionID := attackSessionID
	if sessionID == "" {
		sessionID = uuid.New().String()[:8]
	}

	ctx, cancel := context.WithTimeout(context.Background(), attackTimeout)
	defer cancel()

	// Initialize platform
	platform, err := registry.GetPlatform("github")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	initConfig := platforms.Config{
		Token:       t,
		Concurrency: 10,
	}
	if url := getURL(cmd); url != "" {
		initConfig.BaseURL = url
	}
	cmdutil.ApplyProxyFlags(cmd, &initConfig)

	if err := platform.Init(ctx, initConfig); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	// Verify write access before proceeding (skip for org targets, verified per-repo later)
	if target.Type == platforms.TargetRepo {
		if err := verifyWriteAccess(ctx, platform, target); err != nil {
			return fmt.Errorf("insufficient permissions: %w", err)
		}
	}

	// Phase 1: Detection (to get findings for attack targeting)
	if cmdutil.GetVerbose(cmd) {
		fmt.Fprintf(os.Stderr, "Phase 1: Scanning for vulnerabilities...\n")
	}

	scanResult, err := platform.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	allPlugins := registry.GetDetections("github")
	executor := scanner.NewDetectionExecutor(allPlugins, 10)
	execResult, err := executor.Execute(ctx, scanResult.Workflows)
	if err != nil {
		return fmt.Errorf("detecting vulnerabilities: %w", err)
	}

	if len(execResult.Findings) == 0 && !attackForce && len(attackPlugins) == 0 {
		fmt.Println("No vulnerabilities detected. No attacks applicable.")
		return nil
	}

	if cmdutil.GetVerbose(cmd) {
		fmt.Fprintf(os.Stderr, "Found %d vulnerabilities\n", len(execResult.Findings))
	}

	// Create session for tracking
	session := attacks.NewSession(sessionID, target, "github", attackOrg)

	// Build ExtraOpts from attack-specific flags
	extraOpts := make(map[string]string)
	if attackC2Repo != "" {
		extraOpts["c2_repo"] = attackC2Repo
	}
	if attackC2Org != "" {
		extraOpts["c2_org"] = attackC2Org
	}
	if attackTargetOS != "" {
		extraOpts["target_os"] = attackTargetOS
	}
	if attackTargetArch != "" {
		extraOpts["target_arch"] = attackTargetArch
	}
	if attackRunnerLabels != "" {
		extraOpts["runner_labels"] = attackRunnerLabels
	}
	if attackPersistenceMethod != "" {
		extraOpts["method"] = attackPersistenceMethod
	}

	// If the target is an org (not a specific repo), iterate over discovered repos
	if target.Type == platforms.TargetOrg && attackRepo == "" {
		return runOrgWideAttack(ctx, cmd, platform, scanResult, execResult, extraOpts, sessionID)
	}

	opts := attacks.AttackOptions{
		Target:    target,
		Platform:  platform,
		Findings:  execResult.Findings,
		DryRun:    attackDryRun,
		Verbose:   cmdutil.GetVerbose(cmd),
		Timeout:   attackTimeout,
		SessionID: sessionID,
		Payload:   attackPayload,
		Branch:    attackBranch,
		ExtraOpts: extraOpts,
	}

	// Handle chain execution
	if attackChain != "" || len(attackChainPlugins) > 0 {
		if cmdutil.GetVerbose(cmd) {
			fmt.Fprintf(os.Stderr, "Phase 2: Executing attack chain...\n")
		}

		chainExecutor := chain.NewChainExecutor(session, cmdutil.GetVerbose(cmd))
		results, err := chainExecutor.ExecuteChain(ctx, opts, attackChain, attackChainPlugins)
		if err != nil {
			return fmt.Errorf("chain execution failed: %w", err)
		}

		if err := session.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
		}

		return cmdutil.OutputAttackResults(cmdutil.GetOutput(cmd), results, sessionID, "trajan github attack cleanup")
	}

	// Phase 2: Select attack plugins
	attacksToRun := cmdutil.SelectAttackPlugins("github", execResult.Findings, cmdutil.AttackSelectionCriteria{
		PluginNames: attackPlugins,
		Category:    attackCategory,
		Force:       attackForce,
	})
	if len(attacksToRun) == 0 {
		fmt.Println("No applicable attacks found for detected vulnerabilities.")
		return nil
	}

	// Phase 3: Execute attacks
	if cmdutil.GetVerbose(cmd) {
		fmt.Fprintf(os.Stderr, "Phase 2: Executing %d attacks (session: %s)...\n", len(attacksToRun), sessionID)
	}

	var results []*attacks.AttackResult
	for _, plugin := range attacksToRun {
		if cmdutil.GetVerbose(cmd) {
			fmt.Fprintf(os.Stderr, "Executing: %s\n", plugin.Name())
		}

		result, err := plugin.Execute(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Attack %s failed: %v\n", plugin.Name(), err)
			continue
		}

		results = append(results, result)
		session.AddResult(result)
	}

	if err := session.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
	}

	return cmdutil.OutputAttackResults(cmdutil.GetOutput(cmd), results, sessionID, "trajan github attack cleanup")
}

// runOrgWideAttack iterates over all repositories discovered in the org scan
// and runs the selected attack plugins against each repo.
func runOrgWideAttack(
	ctx context.Context,
	cmd *cobra.Command,
	platform platforms.Platform,
	scanResult *platforms.ScanResult,
	execResult *scanner.ExecutionResult,
	extraOpts map[string]string,
	sessionID string,
) error {
	if len(scanResult.Repositories) == 0 {
		fmt.Println("No repositories found in organization.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories in organization\n", len(scanResult.Repositories))

	var allResults []*attacks.AttackResult
	session := attacks.NewSession(sessionID, platforms.Target{Type: platforms.TargetOrg, Value: attackOrg}, "github", attackOrg)

	for _, repo := range scanResult.Repositories {
		repoSlug := repo.FullName()
		repoTarget := platforms.Target{Type: platforms.TargetRepo, Value: repoSlug}

		// Collect findings for this specific repo
		var repoFindings []detections.Finding
		for _, f := range execResult.Findings {
			if f.Repository == repoSlug {
				repoFindings = append(repoFindings, f)
			}
		}

		// Skip repos with no findings unless --force or explicit --plugin
		if len(repoFindings) == 0 && !attackForce && len(attackPlugins) == 0 {
			if cmdutil.GetVerbose(cmd) {
				fmt.Fprintf(os.Stderr, "Skipping %s (no findings)\n", repoSlug)
			}
			continue
		}

		// Select attack plugins for this repo's findings
		attacksToRun := cmdutil.SelectAttackPlugins("github", repoFindings, cmdutil.AttackSelectionCriteria{
			PluginNames: attackPlugins,
			Category:    attackCategory,
			Force:       attackForce,
		})
		if len(attacksToRun) == 0 {
			if cmdutil.GetVerbose(cmd) {
				fmt.Fprintf(os.Stderr, "Skipping %s (no applicable attacks)\n", repoSlug)
			}
			continue
		}

		fmt.Fprintf(os.Stderr, "Attacking %s (%d plugins)...\n", repoSlug, len(attacksToRun))

		opts := attacks.AttackOptions{
			Target:    repoTarget,
			Platform:  platform,
			Findings:  repoFindings,
			DryRun:    attackDryRun,
			Verbose:   cmdutil.GetVerbose(cmd),
			Timeout:   attackTimeout,
			SessionID: sessionID,
			Payload:   attackPayload,
			Branch:    attackBranch,
			ExtraOpts: extraOpts,
		}

		for _, plugin := range attacksToRun {
			if cmdutil.GetVerbose(cmd) {
				fmt.Fprintf(os.Stderr, "  Executing: %s against %s\n", plugin.Name(), repoSlug)
			}

			result, err := plugin.Execute(ctx, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Attack %s failed on %s: %v\n", plugin.Name(), repoSlug, err)
				continue
			}

			allResults = append(allResults, result)
			session.AddResult(result)
		}
	}

	if err := session.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
	}

	return cmdutil.OutputAttackResults(cmdutil.GetOutput(cmd), allResults, sessionID, "trajan github attack cleanup")
}

func runAttackCleanup(cmd *cobra.Command, args []string) error {
	list, err := cmd.Flags().GetBool("list")
	if err != nil {
		return fmt.Errorf("getting list flag: %w", err)
	}

	if list {
		sessions, err := attacks.ListSessions()
		if err != nil {
			return fmt.Errorf("listing sessions: %w", err)
		}
		fmt.Println("=== Available Sessions ===")
		for _, s := range sessions {
			platformInfo := ""
			if s.PlatformName != "" {
				platformInfo = fmt.Sprintf(" [%s]", s.PlatformName)
			}
			fmt.Printf("  %s - %s%s (%d artifacts)\n", s.ID, s.Target.Value, platformInfo, s.ArtifactCount)
		}
		return nil
	}

	if attackSessionID == "" {
		return fmt.Errorf("must specify --session or --list")
	}

	session, err := attacks.LoadSession(attackSessionID)
	if err != nil {
		return fmt.Errorf("loading session: %w", err)
	}

	ctx := context.Background()

	t := getToken(cmd)
	if t == "" {
		return fmt.Errorf("no token provided (use --token or set GH_TOKEN/GITHUB_TOKEN env var)")
	}

	platform, err := registry.GetPlatform("github")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	initConfig := platforms.Config{
		Token:       t,
		Concurrency: 10,
	}
	if url := getURL(cmd); url != "" {
		initConfig.BaseURL = url
	}
	cmdutil.ApplyProxyFlags(cmd, &initConfig)

	if err := platform.Init(ctx, initConfig); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	// Set platform on session for cleanup
	session.Platform = platform

	// Execute cleanup for each unique plugin
	fmt.Printf("=== Cleaning up session %s ===\n", attackSessionID)
	cleanedPlugins := make(map[string]bool)
	for _, result := range session.Results {
		if cleanedPlugins[result.Plugin] {
			continue
		}
		cleanedPlugins[result.Plugin] = true

		plugin, err := registry.GetAttackPluginByName(registry.PluginKey(session.PlatformName, result.Plugin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unknown plugin %s\n", result.Plugin)
			continue
		}

		fmt.Printf("Cleaning up %s...\n", result.Plugin)
		if err := plugin.Cleanup(ctx, session); err != nil {
			fmt.Fprintf(os.Stderr, "  Cleanup failed: %v\n", err)
		} else {
			fmt.Printf("  Cleaned up successfully\n")
		}
	}

	if err := session.Delete(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to delete session file: %v\n", err)
	}

	return nil
}

// verifyWriteAccess checks if the token has write access to the target repository.
func verifyWriteAccess(ctx context.Context, platform platforms.Platform, target platforms.Target) error {
	p, ok := platform.(*github.Platform)
	if !ok {
		return fmt.Errorf("unsupported platform for attack verification")
	}

	client := p.Client()
	parts := strings.Split(target.Value, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid target format")
	}

	owner, repo := parts[0], parts[1]
	repository, err := client.GetRepository(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("getting repository permissions: %w", err)
	}

	if !repository.Permissions.Push {
		return fmt.Errorf("token does not have write access to %s", target.Value)
	}

	return nil
}
