package gitlab

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Every surface here is admin-scoped, so on gitlab.com or with a non-admin token they
// all 403 and mark _unobserved rather than aborting.
func collectInstanceSurfaces(ctx context.Context, cl GitLab, cp engine.CurrentPhase, timer *engine.PhaseTimer) {
	softSurface(timer, "instance/variables", func() error {
		items, status, err := softList(ctx, cl, "/admin/ci/variables", nil)
		if err != nil {
			return err
		}
		return writeListOrMark(cp, engine.CollectGLInstanceVariables(), "instance-variables", "/admin/ci/variables", items, status)
	})
	softSurface(timer, "instance/runners", func() error {
		items, status, err := softList(ctx, cl, "/runners/all", nil)
		if err != nil {
			return err
		}
		items = enrichRunners(ctx, cl, items, timer, "instance")
		return writeListOrMark(cp, engine.CollectGLInstanceRunners(), "instance-runners", "/runners/all", items, status)
	})
	softSurface(timer, "instance/service-accounts", func() error {
		items, status, err := softList(ctx, cl, "/service_accounts", nil)
		if err != nil {
			return err
		}
		return writeListOrMark(cp, engine.CollectGLServiceAccounts(), "service-accounts", "/service_accounts", items, status)
	})
	softSurface(timer, "instance/settings", func() error {
		raw, status, err := softGet(ctx, cl, "/application/settings", nil)
		if err != nil {
			return err
		}
		return writeOrMark(cp, engine.CollectGLInstanceSettings(), "instance-settings", "/application/settings", raw, status)
	})
	// The projects and groups the token's own backing identity belongs to.
	// /users/:id/memberships is admin-only, so a tenant token 403s here; the id it needs
	// comes from /user.
	softSurface(timer, "self/memberships", func() error {
		userRaw, ustatus, err := softGet(ctx, cl, "/user", nil)
		if err != nil {
			return err
		}
		if ustatus != 0 {
			return nil
		}
		uid := numField(userRaw, "id")
		if uid == 0 {
			return nil
		}
		p := fmt.Sprintf("/users/%d/memberships", uid)
		items, status, err := softList(ctx, cl, p, nil)
		if err != nil {
			return err
		}
		return writeListOrMark(cp, engine.CollectGLUserMemberships(uid), "user-memberships", p, items, status)
	})
	softSurface(timer, "instance/duo", func() error {
		data, status, err := graphQLSoft(ctx, cl, instanceDuoQuery, nil)
		if err != nil {
			return err
		}
		if status != 0 {
			return envelopeSrc(cp, engine.CollectGLInstanceDuo(), "instance-duo", sourceGQL, "graphql:duoSettings", map[string]any{"_unobserved": status})
		}
		return envelopeSrc(cp, engine.CollectGLInstanceDuo(), "instance-duo", sourceGQL, "graphql:duoSettings", data)
	})
}

const instanceDuoQuery = `query {
  duoSettings { duoFeaturesEnabled promptInjectionProtectionLevel duoWorkflowMcpEnabled }
}`
