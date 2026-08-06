package gitlab

import (
	"context"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Policies live in a separate linked project's .gitlab/security-policies/policy.yml.
// These GraphQL edges surface them already parsed, plus the source-project link, which
// is what tells a rule whether a policy is inherited or local.
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
