package enumerate

import (
	"encoding/json"
	"fmt"
	"os"

	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
)

const (
	// GitLab access levels
	gitLabDeveloperAccess = 30 // Developer access level
)

func outputBranchProtectionsConsole(results []*gitlabplatform.BranchProtectionsEnumerateResult, showWeakOnly bool) error {
	fmt.Printf("=== Branch Protection Enumeration ===\n\n")

	totalProjects := len(results)
	totalProtections := 0
	weakProtections := 0

	for _, result := range results {
		totalProtections += len(result.Protections)
		for _, prot := range result.Protections {
			if isWeakProtection(prot) {
				weakProtections++
			}
		}
	}

	if totalProjects == 0 {
		fmt.Println("No projects found")
		return nil
	}

	fmt.Printf("Total: %d projects, %d protected branches\n", totalProjects, totalProtections)
	if weakProtections > 0 {
		fmt.Printf("Weak protections: %d\n", weakProtections)
	}

	// Print results for each project
	for _, result := range results {
		if len(result.Errors) > 0 {
			fmt.Printf("\n%s:\n", result.Project)
			fmt.Printf("  Errors:\n")
			for _, err := range result.Errors {
				fmt.Printf("    * %s\n", err)
			}
			continue
		}

		if len(result.Protections) == 0 {
			if !showWeakOnly {
				fmt.Printf("\n%s:\n", result.Project)
				fmt.Printf("  No protected branches\n")
			}
			continue
		}

		// Filter weak protections if flag is set
		protections := result.Protections
		if showWeakOnly {
			weak := []gitlabplatform.BranchProtection{}
			for _, prot := range protections {
				if isWeakProtection(prot) {
					weak = append(weak, prot)
				}
			}
			if len(weak) == 0 {
				continue
			}
			protections = weak
		}

		fmt.Printf("\n%s (default: %s):\n", result.Project, result.DefaultBranch)
		for _, prot := range protections {
			fmt.Printf("  * %s\n", prot.Name)

			// Push access
			if len(prot.PushAccessLevels) > 0 {
				fmt.Printf("    - Push: %s\n", formatAccessLevels(prot.PushAccessLevels))
			} else {
				fmt.Printf("    - Push: No one\n")
			}

			// Merge access
			if len(prot.MergeAccessLevels) > 0 {
				fmt.Printf("    - Merge: %s\n", formatAccessLevels(prot.MergeAccessLevels))
			} else {
				fmt.Printf("    - Merge: No one\n")
			}

			// Force push
			if prot.AllowForcePush {
				fmt.Printf("    - Force push: ALLOWED\n")
			}

			// Code owner approval
			if prot.CodeOwnerApprovalRequired {
				fmt.Printf("    - Code owner approval: Required\n")
			}

			// Weakness indicators
			if isWeakProtection(prot) {
				fmt.Printf("    - WARNING: Weak protection detected\n")
				printWeaknessReasons(prot)
			}
		}
	}

	// Print warnings section if there are any weak protections
	if weakProtections > 0 && !showWeakOnly {
		fmt.Printf("\nWarnings:\n")
		fmt.Printf("  * %d branches have weak protections\n", weakProtections)
		fmt.Printf("  * Use --show-weak-only to filter results\n")
	}

	return nil
}

func outputBranchProtectionsJSON(results []*gitlabplatform.BranchProtectionsEnumerateResult, outputFile string) error {
	enc := json.NewEncoder(os.Stdout)
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		enc = json.NewEncoder(f)
	}

	enc.SetIndent("", "  ")

	// For single project, output the single result directly
	// For multiple projects, output as array
	if len(results) == 1 {
		return enc.Encode(results[0])
	}
	return enc.Encode(results)
}

// formatAccessLevels formats access levels for console output
func formatAccessLevels(levels []gitlabplatform.AccessLevel) string {
	if len(levels) == 0 {
		return "No one"
	}
	descriptions := make([]string, 0, len(levels))
	for _, level := range levels {
		descriptions = append(descriptions, level.AccessLevelDescription)
	}
	// Join with commas
	result := ""
	for i, desc := range descriptions {
		if i > 0 {
			result += ", "
		}
		result += desc
	}
	return result
}

// isWeakProtection determines if a branch protection is weak
func isWeakProtection(prot gitlabplatform.BranchProtection) bool {
	// Allow force push is always weak
	if prot.AllowForcePush {
		return true
	}

	// No push restrictions is weak (anyone can push)
	if len(prot.PushAccessLevels) == 0 {
		return true
	}

	// Developers can push to protected branch is considered weak
	for _, level := range prot.PushAccessLevels {
		if level.AccessLevel <= gitLabDeveloperAccess { // Developer or lower
			return true
		}
	}

	// No merge restrictions is weak
	if len(prot.MergeAccessLevels) == 0 {
		return true
	}

	return false
}

// printWeaknessReasons prints specific reasons why a protection is weak
func printWeaknessReasons(prot gitlabplatform.BranchProtection) {
	if prot.AllowForcePush {
		fmt.Printf("      - Force push is allowed\n")
	}
	if len(prot.PushAccessLevels) == 0 {
		fmt.Printf("      - No push restrictions (anyone can push)\n")
	} else {
		for _, level := range prot.PushAccessLevels {
			if level.AccessLevel <= 30 {
				fmt.Printf("      - %s can push directly\n", level.AccessLevelDescription)
			}
		}
	}
	if len(prot.MergeAccessLevels) == 0 {
		fmt.Printf("      - No merge restrictions\n")
	}
}
