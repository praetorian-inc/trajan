package ado

import (
	"strconv"
	"strings"
)

type endpoint struct {
	Label NodeLabel
	Key   map[string]string
}

type resolved struct {
	Type EdgeType
	From endpoint
	To   endpoint
}

type graphCtx struct {
	Org       string
	Principal func(descriptor string) (NodeLabel, bool)
}

type endpointResolver func(c graphCtx, rec map[string]any) []resolved

func num(m map[string]any, k string) string {
	if v := mInt64(m, k); v != 0 {
		return strconv.FormatInt(v, 10)
	}
	return ""
}

func complete(e endpoint) bool {
	if len(IdentityKey(e.Label)) == 0 {
		return false
	}
	for _, k := range IdentityKey(e.Label) {
		if e.Key[k] == "" {
			return false
		}
	}
	return true
}

func one(t EdgeType, from, to endpoint) []resolved {
	if !complete(from) || !complete(to) || !ValidEdge(t, from.Label, to.Label) {
		return nil
	}
	return []resolved{{Type: t, From: from, To: to}}
}

func (c graphCtx) principalOf(descriptor string) (endpoint, bool) {
	label, ok := c.Principal(descriptor)
	if !ok {
		return endpoint{}, false
	}
	return endpoint{label, map[string]string{"descriptor": descriptor}}, true
}

func (c graphCtx) fanOut(t EdgeType, descriptors []string, to endpoint) []resolved {
	var out []resolved
	for _, d := range descriptors {
		from, ok := c.principalOf(d)
		if !ok {
			continue
		}
		out = append(out, one(t, from, to)...)
	}
	return out
}

func sourcePrincipals(rec map[string]any) []string {
	var out []string
	for _, raw := range mList(rec, "source_principals") {
		if d := entStr(entMap(raw)["descriptor"]); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func (c graphCtx) branchOf(rec map[string]any) endpoint {
	return endpoint{Branch, map[string]string{
		"org": c.Org, "project": mStr(rec, "project"),
		"repo": mStr(rec, "repo"), "name": mStr(rec, "branch"),
	}}
}

func (c graphCtx) pipelineOf(project, id string) endpoint {
	return endpoint{Pipeline, map[string]string{"org": c.Org, "project": project, "pipeline_id": id}}
}

func (c graphCtx) groupOf(owner, id string) endpoint {
	return endpoint{VariableGroup, map[string]string{"org": c.Org, "owner_project": owner, "group_id": id}}
}

func (c graphCtx) policyOf(rec map[string]any) endpoint {
	return endpoint{BranchPolicy, map[string]string{
		"org": c.Org, "project": mStr(rec, "project"), "config_id": num(rec, "config_id"),
	}}
}

func (c graphCtx) jobOf(rec map[string]any) endpoint {
	return endpoint{Job, map[string]string{
		"org": c.Org, "project": mStr(rec, "project"),
		"pipeline_id": num(rec, "pipeline_id"),
		"stage":       mStr(rec, "stage"), "job": mStr(rec, "job"),
	}}
}

var roleResourceLabels = map[string]NodeLabel{
	"Project":           Project,
	"Repository":        Repository,
	"Pipeline":          Pipeline,
	"ServiceConnection": ServiceConnection,
}

var endpointResolvers = map[EdgeType]endpointResolver{
	DefinedBy: func(c graphCtx, rec map[string]any) []resolved {
		return one(DefinedBy,
			c.pipelineOf(mStr(rec, "project"), num(rec, "pipeline_id")),
			c.branchOf(rec))
	},

	Defines: func(c graphCtx, rec map[string]any) []resolved {
		owner, gid := mStr(rec, "project"), num(rec, "group_id")
		return one(Defines,
			c.groupOf(owner, gid),
			endpoint{SecretVariable, map[string]string{
				"org": c.Org, "owner_project": owner, "group_id": gid, "name": mStr(rec, "secret_name"),
			}})
	},

	HasPolicy: func(c graphCtx, rec map[string]any) []resolved {
		return one(HasPolicy, c.policyOf(rec), c.branchOf(rec))
	},

	BuildValidates: func(c graphCtx, rec map[string]any) []resolved {
		return one(BuildValidates, c.policyOf(rec),
			c.pipelineOf(mStr(rec, "project"), num(rec, "build_definition_id")))
	},

	ReferencesPool: func(c graphCtx, rec map[string]any) []resolved {
		return one(ReferencesPool,
			endpoint{ProjectAgentPool, map[string]string{
				"org": c.Org, "project": mStr(rec, "project"), "queue_id": num(rec, "queue_id"),
			}},
			endpoint{OrgAgentPool, map[string]string{"org": c.Org, "pool_id": num(rec, "org_pool_id")}})
	},

	LinksTo: func(c graphCtx, rec map[string]any) []resolved {
		return one(LinksTo,
			c.groupOf(mStr(rec, "project"), num(rec, "variable_group_id")),
			endpoint{KeyVault, map[string]string{"name": mStr(rec, "keyvault_name")}})
	},

	FederatesTo: func(c graphCtx, rec map[string]any) []resolved {
		owner, conn := mStr(rec, "project"), mStr(rec, "connection_id")
		return one(FederatesTo,
			endpoint{ServiceConnection, map[string]string{
				"org": c.Org, "owner_project": owner, "connection_id": conn,
			}},
			endpoint{WIFCredential, map[string]string{
				"org": c.Org, "owner_project": owner, "connection_id": conn, "subject": mStr(rec, "subject"),
			}})
	},

	Installs: func(c graphCtx, rec map[string]any) []resolved {
		ext := mStr(rec, "extension_id")
		return one(Installs,
			endpoint{Extension, map[string]string{"org": c.Org, "extension_id": ext}},
			endpoint{PipelineDecorator, map[string]string{"org": c.Org, "extension_id": ext}})
	},

	Reads: func(c graphCtx, rec map[string]any) []resolved {
		return one(Reads, c.jobOf(rec),
			endpoint{SecretVariable, map[string]string{
				"org": c.Org, "owner_project": mStr(rec, "owner_project"),
				"group_id": num(rec, "variable_group_id"), "name": mStr(rec, "secret_name"),
			}})
	},

	ConsumesGroup: func(c graphCtx, rec map[string]any) []resolved {
		var from endpoint
		switch mStr(rec, "level") {
		case "pipeline":
			from = c.pipelineOf(mStr(rec, "project"), num(rec, "pipeline_id"))
		case "stage":
			from = endpoint{Stage, map[string]string{
				"org": c.Org, "project": mStr(rec, "project"),
				"pipeline_id": num(rec, "pipeline_id"), "stage": mStr(rec, "stage"),
			}}
		case "job":
			from = c.jobOf(rec)
		default:
			return nil
		}
		return one(ConsumesGroup, from,
			c.groupOf(mStr(rec, "owner_project"), num(rec, "variable_group_id")))
	},

	UsesConnection: func(c graphCtx, rec map[string]any) []resolved {
		return one(UsesConnection, c.jobOf(rec),
			endpoint{ServiceConnection, map[string]string{
				"org": c.Org, "owner_project": mStr(rec, "owner_project"),
				"connection_id": mStr(rec, "service_connection_id"),
			}})
	},

	RunsOn: func(c graphCtx, rec map[string]any) []resolved {
		return one(RunsOn, c.jobOf(rec),
			endpoint{ProjectAgentPool, map[string]string{
				"org": c.Org, "project": mStr(rec, "project"),
				"queue_id": num(rec, "project_agent_pool_id"),
			}})
	},

	Targets: func(c graphCtx, rec map[string]any) []resolved {
		return one(Targets, c.jobOf(rec),
			endpoint{Environment, map[string]string{
				"org": c.Org, "project": mStr(rec, "project"), "name": mStr(rec, "environment"),
			}})
	},

	MemberOf: func(c graphCtx, rec map[string]any) []resolved {
		group, ok := c.principalOf(mStr(rec, "group"))
		if !ok {
			return nil
		}
		return c.fanOut(MemberOf, []string{mStr(rec, "member")}, group)
	},

	HasRole: func(c graphCtx, rec map[string]any) []resolved {
		label, ok := roleResourceLabels[mStr(rec, "resource_kind")]
		if !ok || !mBool(rec, "resource_resolved") {
			return nil
		}
		to, ok := roleResourceEndpoint(c.Org, label, mStr(rec, "resource_id"))
		if !ok {
			return nil
		}
		return c.fanOut(HasRole, []string{mStr(rec, "graph_descriptor")}, to)
	},

	CanPushTo: func(c graphCtx, rec map[string]any) []resolved {
		return c.fanOut(CanPushTo, []string{mStr(rec, "principal")}, c.branchOf(rec))
	},

	CanMergeViaPR: func(c graphCtx, rec map[string]any) []resolved {
		return c.fanOut(CanMergeViaPR, []string{mStr(rec, "principal")}, c.branchOf(rec))
	},

	CanBypass: func(c graphCtx, rec map[string]any) []resolved {
		return c.fanOut(CanBypass, []string{mStr(rec, "principal")}, c.policyOf(rec))
	},

	PipelinePoisoning: func(c graphCtx, rec map[string]any) []resolved {
		return c.fanOut(PipelinePoisoning, sourcePrincipals(rec), c.jobOf(rec))
	},

	QueueTimeInjection: func(c graphCtx, rec map[string]any) []resolved {
		return c.fanOut(QueueTimeInjection, sourcePrincipals(rec), c.jobOf(rec))
	},

	LoggingCommandInjection: func(c graphCtx, rec map[string]any) []resolved {
		return c.fanOut(LoggingCommandInjection, sourcePrincipals(rec), c.jobOf(rec))
	},

	AgentInjection: func(c graphCtx, rec map[string]any) []resolved {
		return c.fanOut(AgentInjection, sourcePrincipals(rec), c.jobOf(rec))
	},
}

func roleResourceEndpoint(org string, label NodeLabel, resourceID string) (endpoint, bool) {
	parts := strings.SplitN(resourceID, "/", 3)
	switch label {
	case Project:
		if len(parts) != 2 {
			return endpoint{}, false
		}
		return endpoint{Project, map[string]string{"org": org, "project": parts[1]}}, true
	case Repository:
		if len(parts) != 3 {
			return endpoint{}, false
		}
		return endpoint{Repository, map[string]string{"org": org, "project": parts[1], "repo": parts[2]}}, true
	case Pipeline:
		if len(parts) != 3 {
			return endpoint{}, false
		}
		return endpoint{Pipeline, map[string]string{"org": org, "project": parts[1], "pipeline_id": parts[2]}}, true
	case ServiceConnection:
		if len(parts) != 3 {
			return endpoint{}, false
		}
		return endpoint{ServiceConnection, map[string]string{
			"org": org, "owner_project": parts[1], "connection_id": parts[2],
		}}, true
	}
	return endpoint{}, false
}

func resolveEndpoints(c graphCtx, rec map[string]any) []resolved {
	r, ok := endpointResolvers[EdgeType(mStr(rec, "kind"))]
	if !ok {
		return nil
	}
	return r(c, rec)
}
