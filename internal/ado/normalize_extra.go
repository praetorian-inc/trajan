package ado

import (
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// pipelineDecoratorContribution is the contribution type an extension declares to
// inject steps into every pipeline run — the org-wide code-injection surface.
const pipelineDecoratorContribution = "ms.azure-pipelines.pipeline-decorator"

// normalizeExtensions emits an :Extension node per installed extension and, when
// an extension contributes a pipeline decorator, a :PipelineDecorator node + an
// INSTALLS edge (schema §; cat-07/03, cat-12/04).
func normalizeExtensions(prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) error {
	// The installedextensions surface stores the raw {count,value} envelope.
	data := entLoadData(prior, engine.CollectADOExtensions(org))
	for _, raw := range entListOrEmpty(data["value"]) {
		e := entMap(raw)
		pub, ext := entStr(e["publisherId"]), entStr(e["extensionId"])
		if pub == "" || ext == "" {
			continue
		}
		id := pub + "." + ext
		flags := entStr(entGetIn(e, "installState", "flags"))
		var decorator bool
		contribs := []any{}
		for _, c := range entListOrEmpty(e["contributions"]) {
			ctype := entStr(entMap(c)["type"])
			contribs = append(contribs, map[string]any{"id": entStr(entMap(c)["id"]), "type": ctype})
			if ctype == pipelineDecoratorContribution {
				decorator = true
			}
		}
		rec := map[string]any{
			"_id": id, "kind": "Extension", "org": org,
			"publisher_id": pub, "publisher_name": entStr(e["publisherName"]),
			"extension_id": ext, "extension_name": entStr(e["extensionName"]),
			"version":                             entStr(e["version"]),
			"scopes":                              entListOrEmpty(e["scopes"]),
			"is_builtin":                          strings.Contains(flags, "builtIn"),
			"is_trusted":                          strings.Contains(flags, "trusted"),
			"auto_update":                         strings.Contains(flags, "autoUpdate"),
			"org_installed":                       true,
			"has_pipeline_decorator_contribution": decorator,
			"contributions":                       contribs,
			"_provenance":                         prov(engine.CollectADOExtensions(org)),
		}
		if err := emit(cp, timer, engine.NormalizeADOExtension(id), rec); err != nil {
			return err
		}
		if decorator {
			deco := map[string]any{
				"_id": id + "/decorator", "kind": "PipelineDecorator", "org": org,
				"extension_id": id, "publisher_id": pub, "scopes": entListOrEmpty(e["scopes"]),
			}
			if err := emit(cp, timer, engine.NormalizeADOEdges("installs", adoSafe(id)), map[string]any{
				"kind": "INSTALLS", "org": org, "extension_id": id, "decorator_id": id + "/decorator",
			}); err != nil {
				return err
			}
			if err := emit(cp, timer, engine.NormalizeADOExtension(id+"__decorator"), deco); err != nil {
				return err
			}
		}
	}
	return nil
}

// normalizeSecureFiles emits a :SecureFile node per collected secure file with its
// folded checks + pipeline permissions (schema §; cat-03/05). Empty in estates
// with no secure files.
func normalizeSecureFiles(prior engine.PriorPhase, cp engine.CurrentPhase, org string, p projectMeta, timer *engine.PhaseTimer) error {
	for _, raw := range entLoadList(prior, engine.CollectADOSecureFiles(p.Name)) {
		f := entMap(raw)
		id := entStr(f["id"])
		if id == "" {
			continue
		}
		rec := map[string]any{
			"_id": p.Name + "/" + id, "kind": "SecureFile", "project": p.Name,
			"id": id, "name": entStr(f["name"]),
			"checks":               foldChecks(prior, p.Name, "securefile", id),
			"pipeline_permissions": foldAuthorization(prior, p.Name, "securefile", id),
			"_provenance":          prov(engine.CollectADOSecureFiles(p.Name)),
		}
		if err := emit(cp, timer, engine.NormalizeADOSecureFile(p.Name, id), rec); err != nil {
			return err
		}
	}
	return nil
}

// normalizeServiceHooks emits a :ServiceHookSubscription node per subscription
// (schema §; cat-07/10). Empty in estates with no hooks.
func normalizeServiceHooks(prior engine.PriorPhase, cp engine.CurrentPhase, org string, timer *engine.PhaseTimer) error {
	for _, raw := range entLoadList(prior, engine.CollectADOServiceHooks(org)) {
		s := entMap(raw)
		id := entStr(s["id"])
		if id == "" {
			continue
		}
		cons := entObj(s, "consumerInputs")
		rec := map[string]any{
			"_id": id, "kind": "ServiceHookSubscription", "org": org,
			"id": id, "consumer_id": entStr(s["consumerId"]), "consumer_action_id": entStr(s["consumerActionId"]),
			"event_type": entStr(s["eventType"]), "publisher_id": entStr(s["publisherId"]),
			"status":      entStr(s["status"]),
			"url":         entStr(cons["url"]),
			"project":     entStr(entGetIn(s, "publisherInputs", "projectId")),
			"_provenance": prov(engine.CollectADOServiceHooks(org)),
		}
		if err := emit(cp, timer, engine.NormalizeADOServiceHook(id), rec); err != nil {
			return err
		}
	}
	return nil
}
