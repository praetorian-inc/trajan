package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/output"
)

var listGroupsDescriptor string

func newGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "List groups in the organization",
		Long: `Trajan - Azure DevOps - Enumerate

List all security groups in the Azure DevOps organization.
Use --project to scope to groups within a specific project.
Use --group <descriptor> to list the members of a specific group.`,
		RunE: runListGroups,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().StringVar(&listGroupsDescriptor, "group", "", "Group descriptor to list members")

	return cmd
}

func runListGroups(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListGroupsAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListGroupsAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	if listGroupsDescriptor != "" {
		members, err := client.ListGroupMembers(ctx, listGroupsDescriptor)
		if err != nil {
			return err
		}

		switch enumOutput {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(members)

		case "csv":
			headers := []string{"Container Descriptor", "Member Descriptor"}
			rows := make([][]string, len(members))
			for i, member := range members {
				rows[i] = []string{member.ContainerDescriptor, member.MemberDescriptor}
			}
			return output.RenderCSV(os.Stdout, headers, rows)

		default: // console
			if len(members) == 0 {
				fmt.Println("No members found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "CONTAINER\tMEMBER")
			for _, member := range members {
				fmt.Fprintf(w, "%s\t%s\n", member.ContainerDescriptor, member.MemberDescriptor)
			}
			w.Flush()

			fmt.Printf("\nTotal: %d members\n", len(members))
			return nil
		}
	}

	var scopeDesc string
	if enumProject != "" {
		proj, err := client.GetProject(ctx, enumProject)
		if err != nil {
			return fmt.Errorf("getting project %s: %w", enumProject, err)
		}
		desc, err := client.GetDescriptor(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("getting project descriptor: %w", err)
		}
		scopeDesc = desc
	}
	groups, err := client.ListGroups(ctx, scopeDesc)
	if err != nil {
		return err
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(groups)

	case "csv":
		headers := []string{"Display Name", "Principal Name", "Origin", "Descriptor"}
		rows := make([][]string, len(groups))
		for i, group := range groups {
			rows[i] = []string{group.DisplayName, group.PrincipalName, group.Origin, group.Descriptor}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(groups) == 0 {
			fmt.Println("No groups found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DISPLAY NAME\tPRINCIPAL NAME\tORIGIN")
		for _, group := range groups {
			fmt.Fprintf(w, "%s\t%s\t%s\n", group.DisplayName, group.PrincipalName, group.Origin)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d groups\n", len(groups))
		return nil
	}
}
