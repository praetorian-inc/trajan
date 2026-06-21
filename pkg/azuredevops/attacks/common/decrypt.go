package common

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/crypto"
)

// RetrieveAndDecryptSecrets downloads the encrypted artifact from a pipeline run,
// extracts the encrypted payload and key from the zip, and decrypts using the private key.
// Returns the decrypted plaintext (typically JSON).
func RetrieveAndDecryptSecrets(ctx context.Context, client *azuredevops.Client, project string, pipelineID, runID int, artifactName, privateKeyPEM string) ([]byte, error) {
	// Get pipeline artifact with signed download URL
	artifact, err := client.GetPipelineArtifact(ctx, project, pipelineID, runID, artifactName)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline artifact: %w", err)
	}

	if artifact.SignedContent == nil || artifact.SignedContent.URL == "" {
		return nil, fmt.Errorf("artifact has no signed download URL")
	}

	// Download from signed URL
	zipData, err := DownloadFromSignedURL(artifact.SignedContent.URL)
	if err != nil {
		return nil, fmt.Errorf("downloading artifact: %w", err)
	}

	// Extract files from zip
	files, err := ExtractFilesFromZip(zipData)
	if err != nil {
		return nil, fmt.Errorf("extracting artifact zip: %w", err)
	}

	// Find encrypted payload and key
	encryptedSecrets, ok := files["output_updated.json"]
	if !ok {
		return nil, fmt.Errorf("output_updated.json not found in artifact")
	}

	encryptedKey, ok := files["lookup.txt"]
	if !ok {
		return nil, fmt.Errorf("lookup.txt not found in artifact")
	}

	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	// Decrypt
	plaintext, err := crypto.DecryptSecrets(privateKey, encryptedKey, encryptedSecrets)
	if err != nil {
		return nil, fmt.Errorf("decrypting secrets: %w", err)
	}

	return plaintext, nil
}

// FormatDecryptedSecrets returns a human-readable string representation of the decrypted secrets.
// The input is expected to be JSON but this handles non-JSON gracefully.
func FormatDecryptedSecrets(decrypted []byte) string {
	s := strings.TrimSpace(string(decrypted))
	if s == "" || s == "{}" || s == "null" {
		return "(no secrets found)"
	}
	return s
}

// FormatStructuredSecrets parses structured JSON output from the pipeline and formats it
// into human-readable sectioned text. The JSON is expected to have group names as keys
// mapping to key-value dicts. The special key "__environment_variables__" is rendered
// as "Environment Variables".
func FormatStructuredSecrets(decrypted []byte) (string, error) {
	s := strings.TrimSpace(string(decrypted))
	if s == "" || s == "{}" || s == "null" {
		return "(no secrets found)", nil
	}

	var structured map[string]map[string]string
	if err := json.Unmarshal(decrypted, &structured); err != nil {
		// Fall back to raw output if not structured JSON
		return s, nil
	}

	// Check if there are any actual variables across all sections
	totalVars := 0
	for _, vars := range structured {
		totalVars += len(vars)
	}
	if totalVars == 0 {
		return "(no secrets found)", nil
	}

	// Sort section names: __environment_variables__ first, then groups alphabetically
	var envSection string
	var groupNames []string
	for name := range structured {
		if name == "__environment_variables__" {
			envSection = name
		} else {
			groupNames = append(groupNames, name)
		}
	}
	sort.Strings(groupNames)

	var sb strings.Builder

	// Environment variables section first
	if envSection != "" && len(structured[envSection]) > 0 {
		sb.WriteString("=== Environment Variables ===\n")
		writeKeyValues(&sb, structured[envSection])
		sb.WriteString("\n")
	}

	// Variable group sections
	for _, name := range groupNames {
		vars := structured[name]
		if len(vars) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "=== Variable Group: %s ===\n", name)
		writeKeyValues(&sb, vars)
		sb.WriteString("\n")
	}

	return strings.TrimRight(sb.String(), "\n"), nil
}

// SecretsSummary returns a human-readable summary of the structured secrets
// (e.g. "5 environment variables, 2 variable groups (8 secrets)").
func SecretsSummary(decrypted []byte) string {
	var structured map[string]map[string]string
	if err := json.Unmarshal(decrypted, &structured); err != nil {
		return "secrets retrieved"
	}

	var envCount int
	var groupCount int
	var groupSecretCount int

	for name, vars := range structured {
		if name == "__environment_variables__" {
			envCount = len(vars)
		} else {
			groupCount++
			groupSecretCount += len(vars)
		}
	}

	var parts []string
	if envCount > 0 {
		parts = append(parts, fmt.Sprintf("%d environment variables", envCount))
	}
	if groupCount > 0 {
		parts = append(parts, fmt.Sprintf("%d variable groups (%d secrets)", groupCount, groupSecretCount))
	}

	if len(parts) == 0 {
		return "no secrets found"
	}
	return strings.Join(parts, ", ")
}

// WriteSecretsToFile writes the formatted secrets text to a file with restricted permissions.
func WriteSecretsToFile(formatted string, outputPath string) error {
	return os.WriteFile(outputPath, []byte(formatted+"\n"), 0o600)
}

// writeKeyValues writes sorted key=value pairs to a string builder.
func writeKeyValues(sb *strings.Builder, vars map[string]string) {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Fprintf(sb, "%s=%s\n", k, vars[k])
	}
}
