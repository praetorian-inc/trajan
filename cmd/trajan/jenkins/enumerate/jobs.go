package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var (
	jobsURL    string
	jobsFolder string
)

var jobsCmd = &cobra.Command{
	Use:   "jobs",
	Short: "List all accessible jobs and folders",
	Long: `Trajan - Jenkins - Enumerate

List all accessible Jenkins jobs and folders, including nested items.
Displays job type (pipeline, freestyle, multibranch) and last build status.
Use --folder to scope enumeration to a specific folder path.`,
	RunE: runJobsEnumerate,
}

func init() {
	jobsCmd.Flags().SortFlags = false
	jobsCmd.Flags().StringVar(&jobsURL, "url", "", "Jenkins instance URL")
	jobsCmd.Flags().StringVar(&jobsFolder, "folder", "", "Scope enumeration to a specific folder")
}

func runJobsEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	username := getUsername(cmd)
	output := cmdutil.GetOutput(cmd)

	if jobsURL == "" {
		return fmt.Errorf("must specify --url")
	}

	ctx := context.Background()

	platform, err := registry.GetPlatform("jenkins")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:   token,
		BaseURL: jobsURL,
		Jenkins: &platforms.JenkinsAuth{Username: username},
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	jPlatform, ok := platform.(*jenkins.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type %T", platform)
	}
	client := jPlatform.Client()

	if output == "console" || output == "" {
		fmt.Fprintf(os.Stderr, "Enumerating jobs at %s...\n", jobsURL)
	}

	jobs, err := client.ListJobsRecursive(ctx)
	if err != nil {
		return fmt.Errorf("listing jobs: %w", err)
	}

	// Filter by folder if specified
	if jobsFolder != "" {
		var filtered []jenkins.Job
		for _, j := range jobs {
			if j.InFolder && len(j.FullName) > 0 {
				// Check if job is in the specified folder
				if len(j.FullName) > len(jobsFolder) && j.FullName[:len(jobsFolder)] == jobsFolder {
					filtered = append(filtered, j)
				}
			}
		}
		jobs = filtered
	}

	switch output {
	case "json":
		return outputJobsJSON(jobs)
	default:
		return outputJobsConsole(jobs)
	}
}

func outputJobsConsole(jobs []jenkins.Job) error {
	fmt.Printf("=== Jenkins Jobs (%d) ===\n\n", len(jobs))

	for _, j := range jobs {
		name := j.Name
		if j.FullName != "" {
			name = j.FullName
		}
		status := jobStatusSymbol(j.Color)
		jobType := classifyJobType(j.Class)
		fmt.Printf("  %s %-50s [%s]\n", status, name, jobType)
	}

	return nil
}

func outputJobsJSON(jobs []jenkins.Job) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(jobs)
}

func jobStatusSymbol(color string) string {
	switch color {
	case "blue":
		return "●" // success
	case "red":
		return "✗" // failure
	case "yellow":
		return "◐" // unstable
	case "notbuilt", "disabled":
		return "○" // not built
	default:
		return "?" // unknown
	}
}

func classifyJobType(class string) string {
	switch {
	case strings.Contains(class, "WorkflowJob"):
		return "pipeline"
	case strings.Contains(class, "FreeStyleProject"):
		return "freestyle"
	case strings.Contains(class, "WorkflowMultiBranchProject"):
		return "multibranch"
	case strings.Contains(class, "Folder"):
		return "folder"
	default:
		return "unknown"
	}
}
