package gitlab

import (
	"context"
	"net/url"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// defaultBranch reads the project's default_branch, falling back to "main" when
// the detail surface was unobservable.
func defaultBranch(projRaw []byte) string {
	if ref := strField(projRaw, "default_branch"); ref != "" {
		return ref
	}
	return "main"
}

// fetchRepoFile GETs a raw repository file on ref and writes it under repo-files
// if present. A soft 404 (file absent) or 401/403 (blocked) skips silently — the
// downstream rules treat an absent CODEOWNERS/duo file as "control not present".
func fetchRepoFile(ctx context.Context, cl GitLab, cp engine.CurrentPhase, base, fp, ref, repoPath string) error {
	p := base + "/repository/files/" + url.PathEscape(repoPath) + "/raw"
	b, _, err := cl.GetRaw(ctx, p, url.Values{"ref": {ref}})
	if err != nil {
		if isSoft(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return cp.WriteRaw(engine.CollectGLRepoFile(fp, repoPath), b)
}

var codeownersPaths = []string{"CODEOWNERS", ".gitlab/CODEOWNERS", "docs/CODEOWNERS"}

// collectCodeowners fetches the CODEOWNERS file from each of GitLab's three valid
// locations on the default branch (cat-06 codeowners.* and cat-04
// source_ci_writable_by_lower_trust). At most one normally exists; whichever is
// present is written raw.
func collectCodeowners(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string, projRaw []byte) error {
	ref := defaultBranch(projRaw)
	for _, rp := range codeownersPaths {
		if err := fetchRepoFile(ctx, cl, cp, base, fp, ref, rp); err != nil {
			return err
		}
	}
	return nil
}

// collectDuoFiles fetches the Duo-flow wiring files (cat-13): the agent config,
// the MCP server manifest, and every flow definition under .gitlab/duo/flows/.
// These feed job.is_duo_flow, duo_flow_context_sources, duo_flow_autonomous_write,
// duo_mcp_endpoint_untrusted_host, duo_external_agent_untrusted_host, and
// project.duo.{config_present,flows,mcp_endpoint}.
func collectDuoFiles(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string, projRaw []byte) error {
	ref := defaultBranch(projRaw)
	for _, rp := range []string{".gitlab/duo/agent-config.yml", ".gitlab/duo/mcp.json"} {
		if err := fetchRepoFile(ctx, cl, cp, base, fp, ref, rp); err != nil {
			return err
		}
	}
	flows, status, err := softList(ctx, cl, base+"/repository/tree",
		url.Values{"path": {".gitlab/duo/flows"}, "ref": {ref}, "recursive": {"true"}})
	if err != nil {
		return err
	}
	if status != 0 {
		return nil
	}
	for _, node := range flows {
		if strField(node, "type") != "blob" {
			continue
		}
		rp := strField(node, "path")
		if !strings.HasSuffix(rp, ".yaml") && !strings.HasSuffix(rp, ".yml") {
			continue
		}
		if err := fetchRepoFile(ctx, cl, cp, base, fp, ref, rp); err != nil {
			return err
		}
	}
	return nil
}
