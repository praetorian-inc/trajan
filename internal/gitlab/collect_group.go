package gitlab

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func collectGroupSurfaces(ctx context.Context, cl GitLab, cp engine.CurrentPhase, groupPath string, gid int64, groupRaw json.RawMessage, timer *engine.PhaseTimer) {
	ref := groupRef(groupPath, gid)

	softSurface(timer, "group/"+groupPath+"/detail", func() error {
		return envelope(cp, engine.CollectGLGroup(groupPath), "group", "/groups/"+ref, groupRaw)
	})

	listSurface := func(label, apiPath, rel, collector string, params url.Values) {
		softSurface(timer, "group/"+groupPath+"/"+label, func() error {
			items, status, err := softList(ctx, cl, apiPath, params)
			if err != nil {
				return err
			}
			return writeListOrMark(cp, rel, collector, apiPath, items, status)
		})
	}
	getSurface := func(label, apiPath, rel, collector string, params url.Values) {
		softSurface(timer, "group/"+groupPath+"/"+label, func() error {
			raw, status, err := softGet(ctx, cl, apiPath, params)
			if err != nil {
				return err
			}
			return writeOrMark(cp, rel, collector, apiPath, raw, status)
		})
	}

	base := "/groups/" + ref
	listSurface("subgroups", base+"/subgroups", engine.CollectGLSubgroups(groupPath), "group-subgroups", nil)
	listSurface("shared-groups", base+"/groups/shared", engine.CollectGLSharedGroups(groupPath), "group-shared-groups", nil)
	listSurface("members", base+"/members/all", engine.CollectGLGroupMembers(groupPath), "group-members", nil)
	listSurface("variables", base+"/variables", engine.CollectGLGroupVariables(groupPath), "group-variables", nil)
	softSurface(timer, "group/"+groupPath+"/runners", func() error {
		apiPath := base + "/runners"
		items, status, err := softList(ctx, cl, apiPath, nil)
		if err != nil {
			return err
		}
		items = enrichRunners(ctx, cl, items, timer, "group/"+groupPath)
		return writeListOrMark(cp, engine.CollectGLGroupRunners(groupPath), "group-runners", apiPath, items, status)
	})
	listSurface("protected-environments", base+"/protected_environments", engine.CollectGLGroupProtectedEnvironments(groupPath), "group-protected-environments", nil)
	listSurface("deploy-tokens", base+"/deploy_tokens", engine.CollectGLGroupDeployTokens(groupPath), "group-deploy-tokens", nil)
	listSurface("access-tokens", base+"/access_tokens", engine.CollectGLGroupAccessTokens(groupPath), "group-access-tokens", nil)
	// /groups/:id/saml is not tenant-readable in practice — it 404s or 401s on both
	// firing-range instances even to an Owner. Collected anyway so it is marked
	// _unobserved rather than silently absent.
	getSurface("saml", base+"/saml", engine.CollectGLGroupSAML(groupPath), "group-saml", nil)

	// The billing plan gates the Premium/Ultimate-only agent controls. A group is a
	// namespace, so /namespaces/:id carries its plan: the instance license on
	// self-managed, the subscription tier on gitlab.com.
	getSurface("namespace", "/namespaces/"+ref, engine.CollectGLNamespace(groupPath), "namespace", nil)

	// GitLab has no group CI/CD settings endpoint: project_creation_role,
	// subgroup_creation_level, default_membership_role and shared_runners_setting all
	// come off the group detail, refetched here without the project list.
	getSurface("ci-settings", base, engine.CollectGLGroupCISettings(groupPath), "group-ci-settings", url.Values{"with_projects": []string{"false"}})

	softSurface(timer, "group/"+groupPath+"/duo", func() error {
		return collectGroupDuo(ctx, cl, cp, groupPath)
	})
}

const groupDuoQuery = `query($fullPath: ID!) {
  group(fullPath: $fullPath) {
    aiSettings { duoFeaturesEnabled promptInjectionProtectionLevel duoWorkflowMcpEnabled }
  }
}`

func collectGroupDuo(ctx context.Context, cl GitLab, cp engine.CurrentPhase, groupPath string) error {
	data, status, err := graphQLSoft(ctx, cl, groupDuoQuery, map[string]any{"fullPath": groupPath})
	if err != nil {
		return err
	}
	rel := engine.CollectGLGroupDuo(groupPath)
	if status != 0 {
		return envelopeSrc(cp, rel, "group-duo", sourceGQL, "graphql:group.aiSettings", map[string]any{"_unobserved": status})
	}
	return envelopeSrc(cp, rel, "group-duo", sourceGQL, "graphql:group.aiSettings", data)
}
