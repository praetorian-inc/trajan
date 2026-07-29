package gitlab

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// The security policy project holds scan-execution and approval policies (cat-06
// approval_policy, cat-02 pipeline_execution_policy). It is a linked project whose
// .gitlab/security-policies/policy.yml drives enforcement; the GraphQL
// scanExecutionPolicies/approvalPolicies edges surface the parsed policies plus the
// source-project link, which is what the rules key on.
const securityPolicyQuery = `query($fullPath: ID!) {
  project(fullPath: $fullPath) {
    securityPolicyProject { id fullPath }
    scanExecutionPolicies { nodes { name enabled yaml source { __typename ... on ProjectSecurityPolicySource { project { fullPath } } ... on GroupSecurityPolicySource { namespace { fullPath } } } } }
    approvalPolicies { nodes { name enabled yaml source { __typename ... on ProjectSecurityPolicySource { project { fullPath } } ... on GroupSecurityPolicySource { namespace { fullPath } } } } }
  }
}`

func collectSecurityPolicies(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp string) error {
	data, status, err := graphQLSoft(ctx, cl, securityPolicyQuery, map[string]any{"fullPath": fp})
	if err != nil {
		return err
	}
	rel := engine.CollectGLSecurityPolicies(fp)
	const src = "graphql:project.{securityPolicyProject,scanExecutionPolicies,approvalPolicies}"
	if status != 0 {
		return envelopeSrc(cp, rel, "security-policies", sourceGQL, src, map[string]any{"_unobserved": status})
	}
	return envelopeSrc(cp, rel, "security-policies", sourceGQL, src, data)
}
