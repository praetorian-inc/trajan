package cmdutil

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// AttackSelectionCriteria configures attack plugin selection.
type AttackSelectionCriteria struct {
	PluginNames []string
	Category    string
	Force       bool
}

// SelectAttackPlugins returns applicable attack plugins based on findings and criteria.
func SelectAttackPlugins(platformName string, findings []detections.Finding, criteria AttackSelectionCriteria) []attacks.AttackPlugin {
	var selected []attacks.AttackPlugin
	allAttacks := registry.GetAttackPlugins(platformName)

	for _, attack := range allAttacks {
		// Filter by plugin name if specified
		if len(criteria.PluginNames) > 0 {
			found := false
			for _, name := range criteria.PluginNames {
				if attack.Name() == name {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter by category if specified
		if criteria.Category != "" {
			if string(attack.Category()) != criteria.Category {
				continue
			}
		}

		// When --plugin is explicitly specified or --force is used, skip CanAttack check
		if len(criteria.PluginNames) > 0 || criteria.Force {
			selected = append(selected, attack)
		} else if attack.CanAttack(findings) {
			selected = append(selected, attack)
		}
	}

	return selected
}

// OutputAttackResults outputs attack results in the specified format.
func OutputAttackResults(outputFormat string, results []*attacks.AttackResult, sessionID, cleanupCmd string) error {
	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"session_id": sessionID,
			"results":    results,
		})
	default:
		fmt.Printf("=== Attack Results (Session: %s) ===\n", sessionID)
		for _, r := range results {
			status := "FAILED"
			if r.Success {
				status = "SUCCESS"
			}
			fmt.Printf("\n[%s] %s\n", status, r.Plugin)
			fmt.Printf("  Message: %s\n", r.Message)
			if len(r.Artifacts) > 0 {
				fmt.Printf("  Artifacts:\n")
				for _, a := range r.Artifacts {
					fmt.Printf("    - %s: %s\n", a.Type, a.Identifier)
				}
			}
			printExtractedData(r.Data)
		}
		fmt.Printf("\nTo cleanup: %s --session %s\n", cleanupCmd, sessionID)

		return nil
	}
}

// toStringSlice converts an interface{} to []string.
// Handles both []string (from in-process plugin data) and []interface{} (from JSON deserialization).
func toStringSlice(v interface{}) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			result = append(result, fmt.Sprintf("%v", item))
		}
		return result
	default:
		return nil
	}
}

// printExtractedData prints extracted secrets, command output, and file paths
// from an attack result's Data field.
func printExtractedData(data interface{}) {
	if data == nil {
		return
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	// Print extracted secrets
	if secrets := toStringSlice(dataMap["secrets"]); len(secrets) > 0 {
		fmt.Printf("  Extracted Credentials:\n")
		for i, s := range secrets {
			fmt.Printf("    [%d] %s\n", i+1, s)
		}
	}

	// Print command output
	if output := toStringSlice(dataMap["output"]); len(output) > 0 {
		fmt.Printf("  Command Output:\n")
		for _, line := range output {
			fmt.Printf("    %s\n", line)
		}
	}

	// Print extracted files
	if outputDir, ok := dataMap["output_dir"]; ok {
		fmt.Printf("  Extracted Files: %v\n", outputDir)
		if fileNames := toStringSlice(dataMap["file_names"]); len(fileNames) > 0 {
			for _, f := range fileNames {
				fmt.Printf("    - %s\n", f)
			}
		}
	}
}

// WriteExtractedDataToFile writes extracted secrets and output lines from all
// results to the specified file, one item per line.
func WriteExtractedDataToFile(path string, results []*attacks.AttackResult) error {
	var lines []string

	for _, r := range results {
		if r.Data == nil {
			continue
		}
		dataMap, ok := r.Data.(map[string]interface{})
		if !ok {
			continue
		}

		lines = append(lines, toStringSlice(dataMap["secrets"])...)

		lines = append(lines, toStringSlice(dataMap["output"])...)
	}

	if len(lines) == 0 {
		return nil
	}

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o600)
}
