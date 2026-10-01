package ado

import "github.com/praetorian-inc/trajan/internal/graph"

var gapRegister = []graph.GapEntry{{
	Subject:     "RUNS_AS{Pipeline,BuildServiceIdentity}",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "the runs-as record carries identity_scope (project or collection) and no descriptor, so there is no build service identity to point at. The principals are collected — principals/build-service holds them — but nothing joins a scope to one.",
	UpstreamFix: "index BuildServiceIdentity by scope and project in the builder, then resolve the pair; the descriptor is already on the principal record.",
}, {
	Subject:     "TRIGGERS_ON_COMPLETION{Pipeline,Pipeline}",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "source_pipeline is a pipeline name and Pipeline identity needs the definition id, so the endpoint cannot be named from the record alone.",
	UpstreamFix: "build a (project, name) -> pipeline_id index in the builder. Names are not unique across projects, so source_project must qualify it.",
}, {
	Subject:     "SecureFile / KeyVault / WIFCredential / PipelineDecorator / ServiceHookSubscription",
	Kind:        "node",
	Status:      "empty",
	Reason:      "declared with normalizers in place and no instance in any corpus: the APIs return empty arrays because no test org provisions them. Fixture gaps, not code gaps, and distinct from a label whose writer is missing.",
	UpstreamFix: "provision a secure file, a key-vault-linked variable group, a WIF service connection, a decorator extension and a service hook in the firing range.",
	Targets:     []string{"node(SecureFile)"},
}, {
	Subject:     "extends: template stages",
	Kind:        "node",
	Status:      "partial",
	Reason:      "a pipeline that emits no jobs falls back to ADO's server-resolved preview, so extends: pipelines now yield stages and jobs. A pipeline mixing inline stages with a template stage reference still emits only the inline ones — jobs > 0, so the fallback does not fire, and widening the trigger would double-emit and erase the ${{ }} parameter sinks the inline stages carry.",
	UpstreamFix: "none wanted. The preview substitutes every ${{ }} before returning, so it can only ever be a fallback.",
}, {
	Subject:     "HAS_ROLE for uncollected principals",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "an ACE whose identity the Graph API does not enumerate — built-in server SIDs — has no principal record, so there is no label to point at and the grant is counted rather than pointed at an invented node. 14 of 45 rows in the richest corpus.",
	UpstreamFix: "none available: the descriptor is kept on the record, but User and SecurityGroup cannot be told apart without the Graph API returning the subject.",
}, {
	Subject:     "RUNS_ON for Microsoft-hosted jobs",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "a job whose pool is a vmImage names no project queue, so project_agent_pool_id is 0 and no ProjectAgentPool exists to point at. Every unbuilt RUNS_ON in every corpus is this case; the self-hosted jobs all resolve.",
	UpstreamFix: "none wanted. Pointing hosted jobs at a stand-in pool would assert a shared machine, which is the claim the agent rules exist to test.",
	Targets:     []string{"edge(RUNS_ON)"},
}, {
	Subject:     "attack edge step_index",
	Kind:        "edge",
	Status:      "identity_defect",
	Reason:      "parallel edges of one type between one pair do not exist in this model, so two sinks in different steps of the same job merge onto one edge and the second step_index is discarded.",
	UpstreamFix: "carry the step indices as an array property rather than a scalar, once a rule needs to name the step.",
}, {
	Subject:     "ACL namespace coverage",
	Kind:        "edge",
	Status:      "partial",
	Reason:      "3 of roughly 90 security namespaces are read (Git, Build, ServiceEndpoints), and the Build ACL is read at the project token only, so QUEUE_TIME_INJECTION source_principals is a project-wide approximation rather than a per-pipeline grant.",
	UpstreamFix: "read the Build namespace at the definition token, and add the namespaces governing variable groups, secure files and environments.",
}, {
	Subject:     "ArtifactsFeed scope",
	Kind:        "node",
	Status:      "partial",
	Reason:      "normalizeFeeds collects only the org-level feed list and hardcodes scope: \"org\", which is asserted rather than observed. Project-scoped feeds are invisible.",
	UpstreamFix: "collect per-project feeds; scope is already in the identity key, so they slot in without rekeying.",
}, {
	Subject:     "task groups, classic releases, deployment groups",
	Kind:        "node",
	Status:      "not_collected",
	Reason:      "no NormalizeADO path helper exists for any of them. Task groups are the ADO composite-action analog and the reusable-code supply chain; cat-14's five rules are self-described posture proxies standing in for classic releases.",
	UpstreamFix: "normalize the already-collected release-definition and build-definition surfaces, then add node writers.",
}, {
	Subject:     "synthetic positional names",
	Kind:        "node",
	Status:      "identity_defect",
	Reason:      "an unnamed stage or job becomes stage_<i> / job_<i>, so inserting a stage re-keys every downstream job and every taint edge that hangs off it. step_index is likewise array position and the only step identity.",
	UpstreamFix: "none available: the YAML supplies no other identity, and a content hash would churn on every edit.",
}}
