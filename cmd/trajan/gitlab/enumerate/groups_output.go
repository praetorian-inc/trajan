package enumerate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
)

func outputGroupsConsole(result *gitlabplatform.GroupsEnumerateResult) error {
	fmt.Printf("=== Group Enumeration ===\n\n")

	if len(result.Groups) == 0 {
		fmt.Println("No groups found")
		return nil
	}

	fmt.Printf("Total: %d groups\n", len(result.Groups))

	// Separate direct groups and shared groups
	groupsByLevel := map[string][]gitlabplatform.GroupWithAccess{
		"Owner":      {},
		"Maintainer": {},
		"Developer":  {},
		"Reporter":   {},
		"Guest":      {},
	}
	var sharedGroups []gitlabplatform.GroupWithAccess

	for _, g := range result.Groups {
		if g.Shared {
			sharedGroups = append(sharedGroups, g)
			continue
		}
		switch {
		case g.AccessLevel >= 50:
			groupsByLevel["Owner"] = append(groupsByLevel["Owner"], g)
		case g.AccessLevel >= 40:
			groupsByLevel["Maintainer"] = append(groupsByLevel["Maintainer"], g)
		case g.AccessLevel >= 30:
			groupsByLevel["Developer"] = append(groupsByLevel["Developer"], g)
		case g.AccessLevel >= 20:
			groupsByLevel["Reporter"] = append(groupsByLevel["Reporter"], g)
		default:
			groupsByLevel["Guest"] = append(groupsByLevel["Guest"], g)
		}
	}

	for _, label := range []string{"Owner", "Maintainer", "Developer", "Reporter", "Guest"} {
		groups := groupsByLevel[label]
		if len(groups) == 0 {
			continue
		}
		fmt.Printf("\n%s (%d):\n", label, len(groups))
		for _, g := range groups {
			// Calculate indentation based on nesting (count slashes in path)
			indent := "  "
			if g.ParentID != nil {
				// Count path depth for indentation
				depth := strings.Count(g.FullPath, "/")
				indent = strings.Repeat("  ", depth+1)
			}
			parentInfo := ""
			if g.ParentID != nil {
				parentInfo = fmt.Sprintf(" (parent: %d)", *g.ParentID)
			}
			fmt.Printf("%s* %s [%s] (ID: %d)%s\n", indent, g.FullPath, g.Visibility, g.ID, parentInfo)
		}
	}

	if len(sharedGroups) > 0 {
		fmt.Printf("\nShared Access (%d):\n", len(sharedGroups))
		for _, g := range sharedGroups {
			fmt.Printf("  * %s [%s] (ID: %d)\n", g.FullPath, g.Visibility, g.ID)
			fmt.Printf("    via: %s (effective: %s)\n", g.SharedVia, accessLevelName(g.AccessLevel))
		}
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Printf("\nWarnings:\n")
		for _, err := range result.Errors {
			fmt.Printf("  * %s\n", err)
		}
	}

	return nil
}

func outputGroupsJSON(result *gitlabplatform.GroupsEnumerateResult, outputFile string) error {
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
	return enc.Encode(result)
}

func accessLevelName(level int) string {
	switch {
	case level >= 50:
		return "Owner"
	case level >= 40:
		return "Maintainer"
	case level >= 30:
		return "Developer"
	case level >= 20:
		return "Reporter"
	case level >= 10:
		return "Guest"
	default:
		return "None"
	}
}
