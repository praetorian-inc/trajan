package gitlab

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func (p *Platform) EnumerateBranchProtections(ctx context.Context, target platforms.Target) (*BranchProtectionsEnumerateResult, error) {
	result := &BranchProtectionsEnumerateResult{}

	if target.Type != platforms.TargetRepo {
		result.Errors = append(result.Errors, "must specify --project for branch protection enumeration")
		return result, nil
	}

	project, err := p.client.GetProject(ctx, target.Value)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("getting project: %s", err.Error()))
		return result, nil
	}

	result.Project = project.PathWithNamespace
	result.ProjectID = project.ID
	result.DefaultBranch = project.DefaultBranch

	protections, err := p.client.ListProtectedBranches(ctx, project.ID)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("listing protected branches: %s", err.Error()))
		return result, nil
	}

	result.Protections = protections

	return result, nil
}
