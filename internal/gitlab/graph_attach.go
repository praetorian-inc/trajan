package gitlab

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/graph"
	"github.com/praetorian-inc/trajan/pkg/finding"
)

var unattachedReasons = []string{
	graph.ReasonLabelMismatch, graph.ReasonNoSubjectDir,
	graph.ReasonNoTarget, graph.ReasonSubjectUnresolved,
}

type anchorRef struct {
	label NodeLabel
	id    string
}

var chainAnchors = []struct {
	file, key string
	fn        func(map[string]any) []anchorRef
}{
	{"agent-ci-access", "grants", anchorAgentGrant},
	{"cache-keyspace", "prefix_overlaps", anchorProjectField},
	{"cross-project-artifact", "edges", anchorCrossArtifact},
	{"deploy-key-reuse", "reused_keys", anchorDeployKeyReuse},
	{"dotenv-flow", "edges", anchorDotenvFlow},
	{"group-runner-reachability", "reachable_runners", anchorGroupRunner},
	{"job-token-allowlist", "edges", anchorJobToken},
	{"protected-var-reachability", "reachable_vars", anchorProjectField},
	{"runner-reachability", "reachable_runners", anchorRunner},
}

type attacher struct {
	n       *nodeSet
	targets map[string]graph.Target
	chain   map[string][]anchorRef
	res     *graph.AttachResult
}

func newAttacher(c *glCorpus, n *nodeSet, targets map[string]graph.Target) *attacher {
	a := &attacher{
		n: n, targets: targets,
		chain: map[string][]anchorRef{},
		res:   graph.NewAttachResult(unattachedReasons),
	}
	for _, ca := range chainAnchors {
		for _, item := range graph.Objects(c.chains[ca.file][ca.key]) {
			id := graph.Str(item["_id"])
			if _, dup := a.chain[id]; id == "" || dup {
				continue
			}
			a.chain[id] = ca.fn(item)
		}
	}
	return a
}

func (a *attacher) run(ctx context.Context, findings []finding.Finding) error {
	for i := range findings {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.one(&findings[i])
	}
	slices.SortFunc(a.res.Unattached, func(x, y graph.UnattachedFinding) int {
		return cmp.Or(cmp.Compare(x.RuleID, y.RuleID), cmp.Compare(x.Fingerprint, y.Fingerprint))
	})
	return nil
}

func ruleID(f *finding.Finding) string {
	if f.Rule == nil {
		return ""
	}
	return f.Rule.ID
}

func (a *attacher) one(f *finding.Finding) {
	a.res.Total++
	t, ok := a.targets[ruleID(f)]
	if !ok {
		a.fail(f, t, graph.ReasonNoTarget, "rule id is absent from the loaded rule set; rules and findings are out of sync")
		return
	}

	var anchors []anchorRef
	if f.Subject.Kind == "chain" {
		anchors, ok = a.chain[f.Subject.ID]
		if !ok {
			a.fail(f, t, graph.ReasonSubjectUnresolved, "no chain tuple carries this _id")
			return
		}
	} else {
		dir, known := gitlabScanProvider.SubjectDirs[f.Subject.Kind]
		if !known {
			a.fail(f, t, graph.ReasonNoSubjectDir, "subject kind "+f.Subject.Kind+" names no 10-normalize directory")
			return
		}
		id, found := a.n.Subject(dir, f.Subject.ID)
		if !found {
			a.fail(f, t, graph.ReasonSubjectUnresolved, "no record in "+dir+" carries this _id")
			return
		}
		anchors = []anchorRef{{a.n.Get(id).Labels[0], id}}
	}

	ref := graph.FindingRef{
		RuleID: ruleID(f), Fingerprint: f.Fingerprint, Severity: f.Severity,
		Confidence: f.Confidence, Target: graph.RenderTarget(t),
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID, Title: f.Title,
	}
	for _, an := range anchors {
		if an.label != NodeLabel(t.Label) {
			continue
		}
		n := a.n.Get(an.id)
		if n == nil {
			continue
		}
		graph.AppendFinding(&n.Findings, ref)
		a.res.Attached++
		a.res.ToNodes++
		return
	}
	a.fail(f, t, graph.ReasonLabelMismatch, "the subject resolves to no "+t.Label+" node")
}

func (a *attacher) fail(f *finding.Finding, t graph.Target, reason, detail string) {
	target := graph.RenderTarget(t)
	a.res.ByReason[reason]++
	a.res.ByRule[ruleID(f)]++
	a.res.ByTarget[target]++
	a.res.Unattached = append(a.res.Unattached, graph.UnattachedFinding{
		Fingerprint: f.Fingerprint, RuleID: ruleID(f), Target: target,
		SubjectKind: f.Subject.Kind, SubjectID: f.Subject.ID,
		Reason: reason, Detail: detail,
	})
}

func anchorAt(l NodeLabel, key string) anchorRef {
	if key == "" {
		return anchorRef{}
	}
	return anchorRef{l, graph.NodeID(glSchema{}, l, map[string]string{"_id": key})}
}

func anchorsOf(in ...anchorRef) []anchorRef {
	out := make([]anchorRef, 0, len(in))
	for _, a := range in {
		if a.id != "" {
			out = append(out, a)
		}
	}
	return out
}

func roleID(item map[string]any, role string) string {
	m, _ := item[role].(map[string]any)
	return graph.Str(m["_id"])
}

// A GitLab job id is "<project full path>:<job name>"; the path may contain slashes.
func jobIDProject(id string) string {
	if i := strings.LastIndex(id, ":"); i >= 0 {
		return id[:i]
	}
	return ""
}

func anchorProjectField(item map[string]any) []anchorRef {
	return anchorsOf(anchorAt(LabelProject, graph.Str(item["project"])))
}

func anchorJobToken(item map[string]any) []anchorRef {
	return anchorsOf(
		anchorAt(LabelProject, roleID(item, "source")),
		anchorAt(LabelProject, roleID(item, "target")),
	)
}

func anchorDotenvFlow(item map[string]any) []anchorRef {
	producer, consumer := roleID(item, "producer"), roleID(item, "consumer")
	return anchorsOf(
		anchorAt(LabelJob, producer),
		anchorAt(LabelJob, consumer),
		anchorAt(LabelProject, jobIDProject(producer)),
		anchorAt(LabelProject, jobIDProject(consumer)),
	)
}

func anchorCrossArtifact(item map[string]any) []anchorRef {
	consumer := roleID(item, "consumer")
	return anchorsOf(
		anchorAt(LabelJob, consumer),
		anchorAt(LabelProject, jobIDProject(consumer)),
		anchorAt(LabelProject, roleID(item, "producer")),
	)
}

func anchorDeployKeyReuse(item map[string]any) []anchorRef {
	paths, _ := item["projects"].([]any)
	refs := make([]anchorRef, 0, len(paths))
	for _, p := range paths {
		refs = append(refs, anchorAt(LabelProject, graph.Str(p)))
	}
	return anchorsOf(refs...)
}

func anchorAgentGrant(item map[string]any) []anchorRef {
	return anchorsOf(
		anchorAt(LabelAgent, roleID(item, "agent")),
		anchorAt(LabelProject, roleID(item, "project")),
	)
}

func anchorRunner(item map[string]any) []anchorRef {
	return anchorsOf(anchorAt(LabelRunner, roleID(item, "runner")))
}

func anchorGroupRunner(item map[string]any) []anchorRef {
	return anchorsOf(
		anchorAt(LabelRunner, roleID(item, "runner")),
		anchorAt(LabelGroup, roleID(item, "group")),
	)
}
