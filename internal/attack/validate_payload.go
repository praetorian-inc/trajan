package attack

import (
	"fmt"
	"slices"
	"strings"

	yaml "go.yaml.in/yaml/v4"

	"github.com/praetorian-inc/trajan/internal/attack/payload"
)

// payloadFlavors fixes the rendering context by primitive, never by the author.
// Actions evaluates ${{ secrets.X }} only inside workflow YAML, so a fragment
// written for the workflow flavor is inert text in a checked-out shell file —
// which is precisely the vector a pwn-request chain is forced to use. The author
// cannot attach the inert variant because the primitive decides.
var payloadFlavors = map[string]payload.Flavor{
	"commit.code":     payload.Shell,
	"comment.create":  payload.Shell,
	"issue.open":      payload.Shell,
	"workflow.commit": payload.WorkflowSteps,
}

const (
	encryptionNone = "none"
	encryptionSeal = "rsa-oaep-hybrid"
)

// encryptionCheck holds a plan's encryption: declaration to what the seal can
// reach. The seal is a pair of steps bracketing the job envelope composed around
// a workflow-flavor fragment, so only a chain that authors its own job can carry
// it. A shell fragment is committed as a file the target's own workflow runs:
// there is no envelope to bracket, and the marker stream reaches the customer's
// Actions log in the clear however the plan is spelled.
func encryptionCheck(p *Plan) []error {
	enc := strings.TrimSpace(p.Encryption)
	switch enc {
	case "", encryptionNone:
		return nil
	case encryptionSeal:
	default:
		return []error{fmt.Errorf("encryption %q must be %s or %s", enc, encryptionNone, encryptionSeal)}
	}
	if slices.ContainsFunc(allSteps(p), composesJob) {
		return nil
	}
	return []error{fmt.Errorf("plan declares encryption: %s but composes no job to seal: the seal is applied to the job envelope, bracketing the steps of a workflow this chain authors, and every fragment this plan attaches is shell-flavor — committed as a file the target's own workflow runs, where the marker stream reaches the run log in the clear. A chain that does not author its job cannot be sealed: drop encryption:, or attach the payload through workflow.commit", enc)}
}

// composesJob reports whether a step renders a fragment into a workflow document
// of its own — the one place the seal steps can be inserted.
func composesJob(st Step) bool {
	if payloadFlavors[st.Uses] != payload.WorkflowSteps {
		return false
	}
	if _, ok := literalTemplate(st.Keys["template"]); ok {
		return true
	}
	files, _ := st.Keys["files"].(map[string]any)
	for _, raw := range files {
		entry, isMapping := raw.(map[string]any)
		if !isMapping {
			continue
		}
		if _, ok := literalTemplate(entry["template"]); ok {
			return true
		}
	}
	return false
}

// validatePayloads checks every fragment a step attaches: it exists, its flavor
// matches the attaching primitive, its include graph is within depth, its required
// params are supplied, and every param value the plan can resolve offline survives
// the coercion and the quoting it will render through. A value only the run can
// produce is checked for presence, not content.
func validatePayloads(st *Step, p *Plan, prior map[string]bool) []error {
	want, attaches := payloadFlavors[st.Uses]
	if !attaches {
		return nil
	}
	var errs []error
	label := stepLabel(st)

	if id, ok := literalTemplate(st.Keys["template"]); ok {
		params, refErrs := staticParams(st.Keys["params"], p, prior, label, "params")
		errs = append(errs, refErrs...)
		for _, e := range payload.Validate(id, want, params) {
			errs = append(errs, fmt.Errorf("%s: %w", label, e))
		}
	}
	files, _ := st.Keys["files"].(map[string]any)
	for _, path := range sortedKeys(files) {
		entry, isMapping := files[path].(map[string]any)
		if !isMapping {
			continue
		}
		id, ok := literalTemplate(entry["template"])
		if !ok {
			errs = append(errs, fmt.Errorf("%s: files[%q] must name a template", label, path))
			continue
		}
		params, refErrs := staticParams(entry["params"], p, prior, label, fmt.Sprintf("files[%q].params", path))
		errs = append(errs, refErrs...)
		for _, e := range payload.Validate(id, want, params) {
			errs = append(errs, fmt.Errorf("%s: files[%q]: %w", label, path, e))
		}
	}
	return errs
}

// staticParams resolves a params mapping as far as the plan can offline, by the
// same rules the executor binds a field with: a bare word naming an input is that
// input's value, a bare <step>.<field> is a handle read, and anything else is a
// literal. Resolving rather than passing the reference text through is what lets
// the renderer's screens run against the value that will actually be interpolated
// — including one that arrived from collected data through --set-file — without
// reporting a reference as a malformed value.
func staticParams(raw any, p *Plan, prior map[string]bool, label, key string) (map[string]any, []error) {
	given, _ := raw.(map[string]any)
	if given == nil {
		return nil, nil
	}
	out := make(map[string]any, len(given))
	var errs []error
	for _, k := range sortedKeys(given) {
		v, refErrs := staticValue(given[k], p, prior, label, key+"."+k)
		out[k] = v
		errs = append(errs, refErrs...)
	}
	return out, errs
}

func staticValue(raw any, p *Plan, prior map[string]bool, label, key string) (any, []error) {
	switch v := raw.(type) {
	case string:
		if strings.Contains(v, "${{") {
			var errs []error
			for _, ref := range interpolations(v) {
				root := id0(ref)
				if _, declared := p.Inputs[root]; !declared && !prior[root] {
					errs = append(errs, fmt.Errorf("%s: %s interpolates %q, which names neither a prior step nor an input; the run cannot resolve it and the fragment would receive the reference text itself", label, key, ref))
				}
			}
			return payload.Unresolved{}, errs
		}
		if id, _, ok := splitDotRef(v); ok && prior[id] {
			return payload.Unresolved{}, nil
		}
		if _, declared := p.Inputs[v]; declared {
			if val, resolved := p.resolvedInputs[v]; resolved {
				return val, nil
			}
			return payload.Unresolved{}, nil
		}
		return v, nil
	case []any:
		out := make([]any, len(v))
		var errs []error
		for i, e := range v {
			r, refErrs := staticValue(e, p, prior, label, key)
			out[i] = r
			errs = append(errs, refErrs...)
		}
		return out, errs
	default:
		return raw, nil
	}
}

// literalTemplate accepts only a spelled-out fragment id. A value built from an
// input or a prior step is unknown offline and is left to render time.
func literalTemplate(raw any) (string, bool) {
	id, ok := raw.(string)
	if !ok || id == "" || strings.Contains(id, "${{") {
		return "", false
	}
	return id, true
}

// workflowPathCheck keeps commit.code out of .github/workflows/** and keeps the
// run watchers on a workflow file path. Writing under .github/workflows needs
// the workflow capability on top of contents:write — a boundary the in-workflow
// token can never cross by any route. Naming a workflow by its YAML name: is the
// other half: GitHub does not require that name to be unique, so a watcher given
// one polls for a run that never arrives. Both are told offline rather than by a
// 403 or a silent timeout against the target.
func workflowPathCheck(st *Step) []error {
	var errs []error
	switch st.Uses {
	case "commit.code":
		report := func(p string) {
			if strings.HasPrefix(p, workflowDir) {
				errs = append(errs, fmt.Errorf("%s writes %s, which needs the workflow capability: use workflow.commit", stepLabel(st), p))
			}
		}
		if p, ok := st.Keys["path"].(string); ok {
			report(p)
		}
		files, _ := st.Keys["files"].(map[string]any)
		for _, p := range sortedKeys(files) {
			report(p)
		}
	case "run.await", "run.observe", "workflow.dispatch":
		p, ok := st.Keys["workflow"].(string)
		if !ok || strings.Contains(p, "${{") {
			return nil
		}
		if !strings.HasSuffix(p, ".yml") && !strings.HasSuffix(p, ".yaml") {
			errs = append(errs, fmt.Errorf("%s: workflow %q is not a workflow file path; name the file (.github/workflows/ci.yml), never the YAML name:, which GitHub does not require to be unique", stepLabel(st), p))
		}
	}
	return errs
}

// workflowEnvelopeCheck screens the job envelope a workflow.commit composes
// before anything is committed: an event GitHub would refuse to parse, a
// workflow_run trigger broad enough to fire on every run in the repository, a
// permission value that fails the job at startup, and an envelope naming secrets
// no declared trigger can deliver. A key built from an input is unknown offline;
// the primitive body screens the resolved value through the same function.
func workflowEnvelopeCheck(st *Step) []error {
	if st.Uses != "workflow.commit" {
		return nil
	}
	b, err := yaml.Marshal(st.Keys)
	if err != nil {
		return nil
	}
	var p workflowCommitParams
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil // a key of the wrong YAML type; validateField reports that
	}
	var errs []error
	for _, e := range p.envelopeErrors() {
		errs = append(errs, fmt.Errorf("%s: %w", stepLabel(st), e))
	}
	return errs
}

// delimiterWarning catches an author who has the two interpolation syntaxes
// backwards. << >> belongs to the payload renderer and is never resolved in plan
// YAML; ${{ }} is the plan's own and is never resolved inside a fragment body.
func delimiterWarning(st *Step) []error {
	var errs []error
	for _, k := range sortedKeys(st.Keys) {
		walkStrings(st.Keys[k], func(s string) {
			if strings.Contains(s, "<<") {
				errs = append(errs, ValidationWarning{fmt.Sprintf(
					"%s: %q contains <<, which only a payload fragment body resolves; a plan interpolates with ${{ }}", stepLabel(st), k)})
			}
		})
	}
	return errs
}
