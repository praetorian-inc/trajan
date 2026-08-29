package ado

import "strconv"

type endpoint struct {
	Label NodeLabel
	Key   map[string]string
}

type resolved struct {
	Type EdgeType
	From endpoint
	To   endpoint
}

type endpointResolver func(org string, rec map[string]any) (resolved, bool)

func num(m map[string]any, k string) string {
	if v := mInt64(m, k); v != 0 {
		return strconv.FormatInt(v, 10)
	}
	return ""
}

func complete(e endpoint) bool {
	for _, k := range IdentityKey(e.Label) {
		if e.Key[k] == "" {
			return false
		}
	}
	return len(IdentityKey(e.Label)) > 0
}

func pair(t EdgeType, from, to endpoint) (resolved, bool) {
	if !complete(from) || !complete(to) || !ValidEdge(t, from.Label, to.Label) {
		return resolved{}, false
	}
	return resolved{Type: t, From: from, To: to}, true
}

func branchOf(org string, rec map[string]any) endpoint {
	return endpoint{Branch, map[string]string{
		"org": org, "project": mStr(rec, "project"),
		"repo": mStr(rec, "repo"), "name": mStr(rec, "branch"),
	}}
}

func pipelineOf(org, project, id string) endpoint {
	return endpoint{Pipeline, map[string]string{"org": org, "project": project, "pipeline_id": id}}
}

func groupOf(org, owner, id string) endpoint {
	return endpoint{VariableGroup, map[string]string{"org": org, "owner_project": owner, "group_id": id}}
}

func policyOf(org string, rec map[string]any) endpoint {
	return endpoint{BranchPolicy, map[string]string{
		"org": org, "project": mStr(rec, "project"), "config_id": num(rec, "config_id"),
	}}
}

func jobOf(org string, rec map[string]any) endpoint {
	return endpoint{Job, map[string]string{
		"org": org, "project": mStr(rec, "project"),
		"pipeline_id": num(rec, "pipeline_id"),
		"stage":       mStr(rec, "stage"), "job": mStr(rec, "job"),
	}}
}

var endpointResolvers = map[EdgeType]endpointResolver{
	DefinedBy: func(org string, rec map[string]any) (resolved, bool) {
		return pair(DefinedBy,
			pipelineOf(org, mStr(rec, "project"), num(rec, "pipeline_id")),
			branchOf(org, rec))
	},

	Defines: func(org string, rec map[string]any) (resolved, bool) {
		owner, gid := mStr(rec, "project"), num(rec, "group_id")
		return pair(Defines,
			groupOf(org, owner, gid),
			endpoint{SecretVariable, map[string]string{
				"org": org, "owner_project": owner, "group_id": gid, "name": mStr(rec, "secret_name"),
			}})
	},

	HasPolicy: func(org string, rec map[string]any) (resolved, bool) {
		return pair(HasPolicy, policyOf(org, rec), branchOf(org, rec))
	},

	BuildValidates: func(org string, rec map[string]any) (resolved, bool) {
		return pair(BuildValidates,
			policyOf(org, rec),
			pipelineOf(org, mStr(rec, "project"), num(rec, "build_definition_id")))
	},

	ReferencesPool: func(org string, rec map[string]any) (resolved, bool) {
		return pair(ReferencesPool,
			endpoint{ProjectAgentPool, map[string]string{
				"org": org, "project": mStr(rec, "project"), "queue_id": num(rec, "queue_id"),
			}},
			endpoint{OrgAgentPool, map[string]string{"org": org, "pool_id": num(rec, "org_pool_id")}})
	},

	LinksTo: func(org string, rec map[string]any) (resolved, bool) {
		return pair(LinksTo,
			groupOf(org, mStr(rec, "project"), num(rec, "variable_group_id")),
			endpoint{KeyVault, map[string]string{"name": mStr(rec, "keyvault_name")}})
	},

	FederatesTo: func(org string, rec map[string]any) (resolved, bool) {
		owner, conn := mStr(rec, "project"), mStr(rec, "connection_id")
		return pair(FederatesTo,
			endpoint{ServiceConnection, map[string]string{
				"org": org, "owner_project": owner, "connection_id": conn,
			}},
			endpoint{WIFCredential, map[string]string{
				"org": org, "owner_project": owner, "connection_id": conn, "subject": mStr(rec, "subject"),
			}})
	},

	Installs: func(org string, rec map[string]any) (resolved, bool) {
		ext := mStr(rec, "extension_id")
		return pair(Installs,
			endpoint{Extension, map[string]string{"org": org, "extension_id": ext}},
			endpoint{PipelineDecorator, map[string]string{"org": org, "extension_id": ext}})
	},

	Reads: func(org string, rec map[string]any) (resolved, bool) {
		return pair(Reads, jobOf(org, rec),
			endpoint{SecretVariable, map[string]string{
				"org": org, "owner_project": mStr(rec, "owner_project"),
				"group_id": num(rec, "variable_group_id"), "name": mStr(rec, "secret_name"),
			}})
	},

	ConsumesGroup: func(org string, rec map[string]any) (resolved, bool) {
		var from endpoint
		switch mStr(rec, "level") {
		case "pipeline":
			from = pipelineOf(org, mStr(rec, "project"), num(rec, "pipeline_id"))
		case "stage":
			from = endpoint{Stage, map[string]string{
				"org": org, "project": mStr(rec, "project"),
				"pipeline_id": num(rec, "pipeline_id"), "stage": mStr(rec, "stage"),
			}}
		case "job":
			from = jobOf(org, rec)
		default:
			return resolved{}, false
		}
		return pair(ConsumesGroup, from,
			groupOf(org, mStr(rec, "owner_project"), num(rec, "variable_group_id")))
	},

	UsesConnection: func(org string, rec map[string]any) (resolved, bool) {
		return pair(UsesConnection, jobOf(org, rec),
			endpoint{ServiceConnection, map[string]string{
				"org": org, "owner_project": mStr(rec, "owner_project"),
				"connection_id": mStr(rec, "service_connection_id"),
			}})
	},

	RunsOn: func(org string, rec map[string]any) (resolved, bool) {
		return pair(RunsOn, jobOf(org, rec),
			endpoint{ProjectAgentPool, map[string]string{
				"org": org, "project": mStr(rec, "project"),
				"queue_id": num(rec, "project_agent_pool_id"),
			}})
	},

	Targets: func(org string, rec map[string]any) (resolved, bool) {
		return pair(Targets, jobOf(org, rec),
			endpoint{Environment, map[string]string{
				"org": org, "project": mStr(rec, "project"), "name": mStr(rec, "environment"),
			}})
	},
}

func resolveEndpoints(org string, rec map[string]any) (resolved, bool) {
	r, ok := endpointResolvers[EdgeType(mStr(rec, "kind"))]
	if !ok {
		return resolved{}, false
	}
	return r(org, rec)
}
