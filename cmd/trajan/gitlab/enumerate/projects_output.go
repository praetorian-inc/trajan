package enumerate

import (
	"encoding/json"
	"fmt"
	"os"

	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
)

func outputProjectsConsole(result *gitlabplatform.ProjectsEnumerateResult) error {
	fmt.Printf("=== Project Enumeration ===\n\n")

	if len(result.Projects) == 0 {
		fmt.Println("No projects found")
		return nil
	}

	fmt.Printf("Total: %d projects (%d private, %d internal, %d public)\n",
		result.Summary.Total,
		result.Summary.Private,
		result.Summary.Internal,
		result.Summary.Public)

	// Group by access level, descending
	groups := map[string][]gitlabplatform.ProjectWithPermissions{
		"Owner":          {},
		"Maintainer":     {},
		"Developer":      {},
		"Reporter/Guest": {},
	}

	for _, p := range result.Projects {
		switch {
		case p.AccessLevel >= 50:
			groups["Owner"] = append(groups["Owner"], p)
		case p.AccessLevel >= 40:
			groups["Maintainer"] = append(groups["Maintainer"], p)
		case p.AccessLevel >= 30:
			groups["Developer"] = append(groups["Developer"], p)
		default:
			groups["Reporter/Guest"] = append(groups["Reporter/Guest"], p)
		}
	}

	// Print in order
	for _, label := range []string{"Owner", "Maintainer", "Developer", "Reporter/Guest"} {
		projects := groups[label]
		if len(projects) == 0 {
			continue
		}

		fmt.Printf("\n%s Access (%d projects):\n", label, len(projects))
		for _, p := range projects {
			fmt.Printf("  * %s/%s [%s, %s]\n",
				p.Owner, p.Name, p.Visibility, p.DefaultBranch)
		}
	}

	return nil
}

func outputProjectsJSON(result *gitlabplatform.ProjectsEnumerateResult, outputFile string) error {
	enc := json.NewEncoder(os.Stdout)
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		enc = json.NewEncoder(f)
	}

	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
