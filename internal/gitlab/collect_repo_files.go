package gitlab

import (
	"context"
	"net/url"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Falls back to "main" when the project detail surface was unobservable.
func defaultBranch(projRaw []byte) string {
	if ref := strField(projRaw, "default_branch"); ref != "" {
		return ref
	}
	return "main"
}

// A soft 404 or 403 skips silently, because the rules downstream already read an
// absent CODEOWNERS or Duo file as "control not present".
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

// GitLab honors CODEOWNERS in three locations and normally only one exists, so all
// three are tried and whichever answers is written raw.
func collectCodeowners(ctx context.Context, cl GitLab, cp engine.CurrentPhase, fp, base string, projRaw []byte) error {
	ref := defaultBranch(projRaw)
	for _, rp := range codeownersPaths {
		if err := fetchRepoFile(ctx, cl, cp, base, fp, ref, rp); err != nil {
			return err
		}
	}
	return nil
}

// The Duo agent config, the MCP server manifest, and every flow definition under
// .gitlab/duo/flows/ — together the whole wiring the Duo job and project folds read.
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
