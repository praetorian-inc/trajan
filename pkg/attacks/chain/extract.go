package chain

import (
	"strings"

	"github.com/praetorian-inc/trajan/pkg/attacks"
)

// ExtractArtifacts pulls chain-relevant data from an AttackResult
// Maps known fields to artifact keys for downstream consumption
func ExtractArtifacts(result *attacks.AttackResult) map[attacks.ContextKey]interface{} {
	artifacts := make(map[attacks.ContextKey]interface{})

	// Extract from Data field (plugin-specific)
	if data, ok := result.Data.(map[string]interface{}); ok {
		// c2-setup provides repo_full_name
		if repoName, ok := data["repo_full_name"].(string); ok {
			artifacts[attacks.C2RepoKey] = repoName
		}
		if repoURL, ok := data["repo_url"].(string); ok {
			artifacts[attacks.C2URLKey] = repoURL
		}

		// runner-on-runner provides runners list
		if runners, ok := data["runners"]; ok {
			artifacts[attacks.RunnersKey] = runners
		}

		// gist_id from runner-on-runner
		if gistID, ok := data["gist_id"].(string); ok {
			artifacts[attacks.GistIDKey] = gistID
		}

		// fork_repo from runner-on-runner
		if forkRepo, ok := data["fork_repo"].(string); ok {
			artifacts[attacks.ForkRepoKey] = forkRepo
		}

		// pr_number from runner-on-runner
		if prNumber, ok := data["pr_number"].(int); ok {
			artifacts[attacks.PRNumberKey] = prNumber
		}
	}

	// Extract from Artifacts field (fallback)
	for _, artifact := range result.Artifacts {
		if artifact.Type == attacks.ArtifactRepository {
			if strings.Contains(artifact.Description, "C2") ||
				strings.Contains(artifact.Description, "c2") {
				artifacts[attacks.C2RepoKey] = artifact.Identifier
			}
		}
	}

	return artifacts
}
