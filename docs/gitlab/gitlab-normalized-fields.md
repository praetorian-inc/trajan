# GitLab normalized field contract

## Purpose

This document is the **interface** between two pieces of GitLab work that are being built in parallel:

- the **detection rules** (`internal/detection-rules/gitlab/`, the catalog PRs) — declarative YAML whose `where` / `chain_of` predicates key on field names, and
- the **normalize phase** (LAB-4288) — the Go that turns collected GitLab facts into the per-subject records those predicates evaluate against.

A rule predicate is a runtime string lookup against a `map[string]any` (`internal/github/getpath.go`); nothing validates the field name at compile time. If a rule reads `merge_request.approvals_required` but normalize emits `mr.required_approvals`, the rule silently matches nothing — no error, just a dead rule. This doc fixes the names **once, up front**, so both sides converge instead of guessing. When authoring a rule, use only field paths listed here; when implementing normalize, emit exactly these paths. Add or rename a field here first, in a PR, before either side depends on it.

This is a contract, not an implementation. It says nothing about *how* facts are collected (LAB-4287) or *how* the engine loads GitLab rules (the loader/subject-dispatch generalization, LAB-4987). Severity and confidence are carried per-variant from the corpus, not produced by normalize.

## Status & consolidation follow-up (do during LAB-4288 / LAB-4987, before normalize is implemented against this)

This doc grew to ~286 field roots while all 141 rules were authored, one field-vocabulary per family. It is a **draft** to be hardened as the first step of normalize/engine work — deferred on purpose, and safe to defer because these fields are not in any PR (this file is local/gitignored) and the rules are inert until the engine + normalize land, so any rename is a mechanical sweep across the rule YAML with zero behavioral regression. Consolidation checklist:

- **Dedup / normalize naming** — collapse near-duplicate fields and align naming conventions across families (authoring produced some overlap).
- **Fold out deferred state** — a few computed booleans risk encoding deferred/uncollectable state (e.g. `dotenv_content_attacker_influenced`, `cache_paths_executable`). Per the corpus, deferred state justifies the *confidence tier*, not a predicate; move these out of `where` where that's the case.
- **Fidelity spot-check** — re-read predicates against the corpus for the families that initially failed workflow review: cat-03, 04, 07, 09, 11, 12.
- **Reconcile with real normalize output** — as LAB-4288 emits records, rename fields here to match and sweep the rule YAML; decide whether this file becomes a tracked repo artifact (e.g. `internal/detection-rules/gitlab/FIELDS.md`) rather than a local doc.

### Fix-pass follow-ups (2026-07-18 — rule-side engine-mechanics bugs corrected in the open PRs; normalizer must honor the contracts below)

A pass over the DSL-mechanics review corrected six categories in the PR branches (cat-03 field-refs folded into the `protected-var-reachability` join; cat-04 `>= "developer"` → `>= 30`; cat-12 guest existential → `has_guest_member`; cat-13 guardrail enum → uppercase; explicit `for_each` on all cat-03/09/11/12 chain rules). The normalizer must honor these to keep the rules correct-by-construction:

- **Emit `[]`, never null/omitted, for every list field (C1).** Several rules gate on `field != []` / `field == []` and `valuesEqual(nil, []any{})` is false, so an absent list makes `!= []` fire on nothing and `== []` never fire. Un-fixed rule-side (kept as-is, relying on this contract): cat-06 `external_status_checks`, cat-08 `projects`, cat-09 `consumer.cross_project_needs`, cat-11 `backing_identity_breadth`, cat-12 `artifact_paths`/`agent.ci_access_targets`, cat-14 `custom_headers`, cat-15 `environments_filter` (the dangerous direction — `== []` silently never fires if omitted).
- **`for_each` item-list keys are a hard contract** — see the Chain-joins table; each join must emit tuples under exactly the named key (unset → engine defaults to `links` → iterates nothing).
- **Guardrail enum verbatim, uppercase** — `duo_guardrail_level`/`duo_instance_guardrail_level` carry the GraphQL `promptInjectionProtectionLevel` value as-is (`LOG_ONLY`/`NO_CHECKS`/`INTERRUPT`); do not lowercase.
- **Role representation pinned numeric (C3)** — access levels are numeric (`>= 30` developer, `>= 40` maintainer), matching the corpus and cat-04's fix; reconcile the remaining string-enum uses (cat-12 `default_membership_role`) at normalize.
- **Still open, not rule-fixes:** protected-ref vocabulary split (`runs_on_protected_ref` bool vs `protected_ref_gate == "strong"` — pick the boolean; 7 cat-09 + cat-10 refs), token-freshness field (`revoked` vs `active`), runner `ref_protected != true` vs `== false`, and the missing `tier`/`namespace_plan` gate (C6, Premium/Ultimate rules false-positive on Free). These are precision items, not "cannot fire" bugs — defer to the normalize pass.

### Collectability finding — SAML SSO default membership role is UI-only, no API path (2026-07-18)

Verified against GitLab official docs + both live firing-range instances (self-hosted 19.2.0-ee groups 280/287/291/293; SaaS gitlab.com group 137657479), across REST, GraphQL, SCIM, and instance application-settings, with `read_api` (Owner) **and** admin (self-hosted root + `sudo` + `admin_mode`; SaaS group-owner full-`api`) tokens. **No route on any credential exposes the group SAML SSO "Default membership role."** It is a UI-only setting (group Settings → SAML SSO). Routes tried, all field-absent: `GET /groups/:id` (`?with_saml`), `/groups/:id/saml` (404), `/groups/:id/saml_group_links` (401), `/groups/:id/scim/identities` (no role field), `/application/settings` (has `lock_memberships_to_saml`, not the default role), GraphQL full-schema introspection (no `SamlProvider` type, no `defaultMembershipRole` field). The gating precondition `saml_provisioning_active` is likewise not tenant-readable. The custom-role variant is doubly blind — it derives from this blind field, and `member_roles` is 400/403 even to root on self-managed.

- **Affected rules (3, cat-12):** `saml-scim-default-membership-role-developer`, `saml-scim-default-membership-role-maintainer`, `saml-scim-default-custom-cicd-role`. These cannot fire under any credential we would use.
- **Status: flagged, NOT removed** (pending decision). Candidate disposition: pull from the active catalog into a manual-gap list — "verify manually in group Settings → SAML SSO."
- **Do NOT** wire these to `saml_group_links.access_level` / `member_role_id` as a proxy: that is the per-linked-group role mapping, a *different* setting from the SSO default.

## Conventions (mirrored from the GitHub rule set)

- **snake_case** field names; dot-paths for nesting (`approval.author_approval_allowed`, `oidc.sub_claim_components`).
- **Semantic names, not raw API attributes.** The normalized field is a concise meaning (`fork_pipelines_run_in_parent`); the raw GitLab attribute it derives from lives in the *Source* column (`ci_allow_fork_pipelines_to_run_in_parent_project`). This keeps predicates readable and insulates rules from GitLab's attribute churn.
- **Booleans are always present**, defaulting `false` — never omitted. A rule writes `x == true` / `x != true`.
- **Enums are lowercase strings** (`visibility == "public"`, `runner_type == "instance_type"`).
- **Sets** use `∋` membership (`triggers ∋ {merge_request_event}`); **lists** compare against `[]` (`cross_project_needs != []`).
- **Empty collections serialize as `[]`, absent scalars as `null`** — predicates key on both, so normalize must not drop them (per project CLAUDE.md).
- **`_provenance`** rides on every record for evidence templating: `{config_file, yaml_line_range, project_path}` (mirrors GitHub's `_provenance.workflow_file`).
- **Chain participants** are addressed by role prefix inside a `chain_of.where` (`producer.`, `consumer.`, `source.`, `target.`), matching GitHub's `caller.`/`callee.` style.

## Subject kinds

Each kind is one normalized record type, written to its own directory under `10-normalize/` and loaded by the scan phase. GitLab needs the `subjectDirs` map (`internal/github/scan.go:15`) extended to these — that is Go work, tracked under the engine-generalization ticket, not a rules PR.

| `subject:` | normalize dir | GitLab entity | nearest GitHub analog |
|---|---|---|---|
| `job` | `jobs` | resolved `.gitlab-ci.yml` job | `job` |
| `project` | `projects` | project settings, protected refs, variables | `repo` |
| `group` | `groups` | group settings + inheritance tree | — |
| `instance` | `instance` | instance/admin settings | `org` |
| `merge_request` | `merge-requests` | MR & approval configuration | — |
| `environment` | `environments` | environment + protected-env + deployment approval | `environment` |
| `runner` | `runners` | instance/group/project runner | (self-hosted) |
| `agent` | `agents` | Kubernetes agent `ci_access` | — |
| `credential` | `credentials` | access/deploy token, PAT, deploy key, static cloud cred | `deploy_key` |
| `integration` | `integrations` | webhook, integration, pull-mirror, Pages | — |
| `chain` | (produced by `correlate`) | cross-entity join | `chain` |

## `job`

The core subject — one record per resolved job in a project's `.gitlab-ci.yml` (includes expanded, `rules:`/`workflow:` evaluated). Most of cat-01/02/09/10 key here.

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `triggers` | set | pipeline sources the job runs on: `merge_request_event`, `push`, `schedule`, `web`, `api`, `trigger`, `pipeline`, `external_pull_request_event` | `rules:` / `workflow:` / `$CI_PIPELINE_SOURCE` | 01,02,03,09 |
| `runs_on_untrusted_ref` | bool | reachable on an attacker-nameable / unprotected ref (fork MR, feature branch, attacker tag) | ref + `rules:` resolution | 01,03,09 |
| `runs_fork_mr_in_parent` | bool | eligible to execute a fork MR pipeline in the parent project | job × project `fork_pipelines_run_in_parent` | 01 |
| `reads_cicd_variable` | bool | job exposes ≥1 CI/CD variable to its script/env | variable scope × job | 01,03 |
| `reads_protected_variable` | bool | a `protected` variable is reachable by this job | variable metadata × ref | 01,03 |
| `mints_id_token` | bool | job declares `id_tokens:` | `id_tokens:` | 01,10 |
| `id_token_aud` | list | OIDC audience(s) requested | `id_tokens:*:aud` | 10 |
| `deploys_environment` | bool | job binds an `environment:` | `environment:` | 01,03,07 |
| `environment_name` | string | bound environment name (may be ref-templated) | `environment:name` | 01,07 |
| `attacker_input_fields` | set | categories of untrusted input reaching an exec context: `mr_metadata`, `ref_name`, `commit_message`, `component_input` | `script:` + `$[[ inputs ]]` | 01 |
| `script_uses_untrusted_input` | bool | ≥1 `attacker_input_fields` reaches an exec context | `script:` analysis | 01 |
| `includes` | list | resolved includes: `{type: local\|remote\|project\|component\|template, ref, pinned: bool, source_host, cross_trust: bool}` | `include:` | 02 |
| `remote_include_untrusted_host` | bool | `include:remote` from a non-instance / non-first-party host with no `integrity:` pin | `include:remote` | 02 |
| `remote_include_cleartext` | bool | `include:remote` over `http://` with no `integrity:` pin | `include:remote` URL scheme | 02 |
| `mutable_cross_trust_project_include` | bool | `include:project` at a mutable/unprotected ref in a different trust scope | `include:project` + referenced `/protected_branches` | 02 |
| `mutable_component_version` | bool | `include:component` at a mutable `@version` from a third-party publisher | `include:component` | 02 |
| `include_ref_interpolated` | bool | an `include:` `ref`/`file`/`remote` interpolates a user-controllable predefined variable | `include:` | 02 |
| `child_pipeline_from_cross_project_artifact` | bool | `trigger:include:` sourced from a generator fed a cross-project artifact on a lower-trust ref | `trigger:include:` + `needs:project:` | 02 |
| `remote_step_untrusted_ref` | bool | a `run:` `step`/`func` from a remote git ref that is mutable, lower-trust-writable, or third-party | `run:` | 02 |
| `include_bare_ref_shadowable` | bool | a bare `ref:` in `include`/`trigger` matches a protected branch but not a protected tag in a referenced project with Developer members | `include`/`trigger` + `/protected_branches` + `/protected_tags` | 02 |
| `runs_on_protected_ref` | bool | job executes in a protected-ref context (poisoned config reaches a protected surface) | ref + `/protected_branches` | 02 |
| `outbound_job_token_broad` | bool | the job's `CI_JOB_TOKEN` outbound reach is broad | `ci_job_token_scope` posture | 02 |
| `cross_project_needs` | list | `needs:project:`/`needs:pipeline:` pulling artifacts across projects: `{project, artifacts: bool}` | `needs:project:` | 02,09 |
| `produces_dotenv` | bool | emits a dotenv report artifact | `artifacts:reports:dotenv` | 09 |
| `consumes_dotenv` | bool | inherits dotenv variables from a `needs:` producer | `needs:` + dotenv | 09 |
| `cache` | list | cache entries: `{key, key_files: [], policy}` | `cache:` | 09 |
| `artifact_paths` | list | published artifact paths | `artifacts:paths` | 12,14 |
| `publishes_pages` | bool | this is a `pages:` job | `pages:` | 14 |
| `image_ref` | string | container image reference | `image:` | 09 |
| `image_from_variable` | bool | image tag comes from a variable | `image: $VAR` | 09 |
| `image_pinned_digest` | bool | image pinned by `@sha256:` | `image:` | 09 |
| `job_token_cross_project_use` | enum | `none` \| `read` \| `terraform_state` \| `git_push` — how the job wields `CI_JOB_TOKEN` off-project | `script:` + `$CI_JOB_TOKEN` | 04 |
| `runner_tags` | set | tags selecting a runner | `tags:` | 08,13 |
| `protected_ref_gate` | enum | `none` \| `weak` \| `strong` — strength of `$CI_COMMIT_REF_PROTECTED` gating on the job | `rules:if` | 09 |
| `is_duo_flow` | bool | job runs a GitLab Duo flow/agent in CI | `.gitlab/duo/flows/*` wiring | 13 |
| `targets_self_managed_runner` | bool | job lands on a self-managed runner (not the gitlab.com shared fleet) | `/runners` runner_type × `tags:` | 01 |
| `targets_protected_runner` | bool | job can land on a `ref_protected` runner | `/runners` `access_level` × `tags:` | 01 |
| `mr_pipelines_unprotected` | bool | effective: this job's project has `protect_merge_request_pipelines == false` | `protect_merge_request_pipelines` | 01 |
| `runs_on_merged_result` | bool | job runs against a merged-results / merge-train commit | `merge_pipelines_enabled` / `merge_trains_enabled` | 01 |
| `developer_controls_mr_branches` | bool | effective: a Developer-role actor can push/create refs matching the protected pattern for both a candidate MR source and target (loose / over-broad protected-branch scheme) | `/protected_branches` + role model | 01 |
| `env_scoped_secret_reachable` | bool | an unprotected variable whose `environment_scope` matches this job's `environment:` reaches it | `cicd_variables` × `environment:` | 01 |
| `environment_name_interpolated` | bool | the job's `environment:name:` value contains a variable interpolation (`$VAR`, `${VAR}`, `review/$CI_COMMIT_REF_SLUG`) whose input a Developer can control, so the environment (and the scope it selects) is chosen at run time and no exact-match protected entry can cover it | `environment:name` (interpolation syntax) | 07 |
| `dotenv_content_attacker_influenced` | bool | producer's `script:` writes non-constant / attacker-influenceable content into the dotenv file (redirection of a variable, fetched value, printf/echo of derived data) rather than a fixed literal set | `script:` analysis of the dotenv-producing job | 09 |
| `dotenv_content_from_untrusted_source` | bool | a trusted-ref producer builds its dotenv content from untrusted input fetched at runtime from a lower-trust source (a Developer-pushable artifact/ref/submodule) with no review gate | `script:` fetch analysis of the dotenv-producing job | 09 |
| `dotenv_inheritance_unnarrowed` | bool | consumer does not narrow dotenv inheritance: no `dependencies: []` and no `inherit: {variables: false}` / restricted list | job `dependencies:`/`inherit:` analysis | 09 |
| `inherited_var_in_exec_sink` | bool | consumer references an inherited-only (or job/global-scope-declared) variable in an execution-sensitive position: `image: $VAR`, `$VAR` in a script command, or a deploy target/URL | `script:`/`image:` analysis of the consumer job | 09 |
| `dotenv_key_collides_declared_var` | bool | a reachable producer emits a dotenv `KEY=value` whose key matches a variable the consumer declares at job-level or global `variables:` scope (name collision) | producer dotenv keys × consumer `variables:` | 09 |
| `colliding_var_in_exec_sink` | bool | the colliding job/global-declared variable is used by the consumer in an execution-sensitive position (`image:`, script interpolation, deploy target/URL) | `script:`/`image:` analysis of the consumer job | 09 |
| `cache_separation_enabled` | bool | project's protected/unprotected cache separation setting (contract lists `cache_separation_enabled` on project); false collapses both classes into one cache namespace | `ci_separated_caches` (project setting joined onto the job) | 09 |
| `cache_key_static_cross_boundary` | bool | the job's `cache:key` is static/global or built only from values shared by protected and unprotected pipelines (no `$CI_COMMIT_REF_SLUG` / protection component), so it collides across the protection boundary | `cache:key` analysis | 09 |
| `cache_key_files_attacker_writable` | bool | the job uses `cache:key:files:` over files writable by lower-trust actors on an unprotected branch, enabling a content-addressed collision into a protected pipeline's bucket | `cache:key:files` + repo file writability | 09 |
| `cache_policy_writes` | bool | the job's cache policy writes the cache (`policy: pull-push` or `push`) | `cache:policy` | 09 |
| `cache_paths_executable` | bool | the cached `paths:` are executable/loaded (dependency dirs like `node_modules/`, `vendor/`, `.venv/`, `.m2/`, toolchains, or a path the consumer sources/executes) rather than inert data | `cache:paths` + `script:` usage | 09 |
| `artifact_source_ref_mutable` | bool | the `needs:project` source is referenced by a mutable branch ref, not a pinned tag or commit SHA | `needs:project` `ref:` analysis | 09 |
| `executes_fetched_artifact` | bool | the consumer extracts/executes the fetched artifact (`tar x` / `unzip` / `source` / `./` / install / copy-into-runtime-path) | `script:` analysis of the consumer job | 09 |
| `artifact_integrity_checked` | bool | the consumer verifies artifact integrity before use (`sha256sum -c` / `cosign verify` / `gpg --verify` / pinned digest); false when no such step exists | `script:` analysis of the consumer job | 09 |
| `on_consumer_job_token_allowlist` | bool | the private source project is on the consumer's job-token inbound allowlist, so the cross-project artifact fetch succeeds | inbound job-token allowlist metadata | 09 |
| `source_ref_developer_pushable` | bool | the source project's referenced ref is an unprotected branch or one a Developer of the source project can push | source project `/protected_branches` | 09 |
| `consumes_cross_pipeline_artifact` | bool | job uses `needs:pipeline:job:` (or `needs:pipeline` with `artifacts: true`) to fetch an artifact from a different pipeline in the same project | `needs:pipeline:` analysis | 09 |
| `upstream_pipeline_untrusted_ref_reachable` | bool | the referenced upstream pipeline is not constrained to protected refs by `rules:`/`workflow:`, so a Developer's unprotected-branch pipeline can be the source | referenced upstream job `rules:`/`workflow:` resolution | 09 |
| `fetches_cross_project_artifact` | bool | job fetches an artifact from a different project via a bare `CI_JOB_TOKEN` job-artifacts API call (`JOB-TOKEN: $CI_JOB_TOKEN` against `/projects/.../jobs/artifacts/...`) or `needs:project:...:artifacts:true` | `script:` + `needs:project:` analysis | 09 |
| `artifact_source_visibility` | enum | visibility of the source project the artifact is fetched from: `public` \| `internal` \| `private` (public/internal means the job-token allowlist never gates the fetch) | source project visibility metadata | 09 |
| `image_from_registry_mutable_tag` | bool | job references a registry image by a mutable tag (`latest`, `staging`, an environment name) rather than an immutable digest or self-built commit-SHA tag | `image:` analysis | 09 |
| `registry_tag_protection_covers_consumed_tag` | bool | a protected container tag rule exists whose pattern covers the consumed tag (any covering rule restricts push/delete to Maintainer+); false is the vulnerable absent-rule state | `/registry/protection/tag/rules` API × consumed tag | 09 |
| `registry_push_reachable_by_developer` | bool | registry push/overwrite of the consumed tag is reachable by a lower-trust actor via default project registry permissions (Developer+ can push) | default project registry permissions × member roles | 09 |
| `installs_gitlab_registry_package` | bool | job installs a package from the GitLab package registry | `script:` package-install analysis | 09 |
| `package_version_mutable_range` | bool | the installed package is resolved at a mutable range (floating version, `latest`/`*`/caret/tilde, otherwise unpinned) | manifest / install command version spec | 09 |
| `package_version_checksum_verified` | bool | the install pins an exact version and verifies a checksum; false when neither is present | manifest lockfile / `script:` analysis | 09 |
| `package_protection_covers_consumed_name` | bool | a package protection rule exists limiting the consumed package name/pattern to a minimum push role of Maintainer+; false is the vulnerable absent/Developer-role state | package protection rules API × consumed name | 09 |
| `package_publish_reachable_by_developer` | bool | package publish/overwrite of the consumed name is reachable by a lower-trust actor via default package-registry permissions (Developer+ can publish) | default package-registry permissions × member roles | 09 |
| `write_registry_token_reachable_low_trust` | bool | a `write_registry` deploy token (group-level usable across the group, or the auto-exposed `gitlab-deploy-token` as `CI_DEPLOY_USER`/`CI_DEPLOY_PASSWORD`) is reachable from a low-trust pipeline the attacker can influence | deploy-token metadata (scope `write_registry`, group vs project) × variable exposure to non-protected branches | 09 |
| `reuses_ondisk_checkout` | bool | job depends on reused on-disk state across jobs: `GIT_STRATEGY` in {`fetch`,`none`}, or a persisted cache/build path or `GIT_SUBMODULE_STRATEGY` reuse, rather than a clean clone into a wiped directory | `variables.GIT_STRATEGY` / `cache:` / `GIT_SUBMODULE_STRATEGY` in pipeline config | 08 |
| `runs_on_cross_trust_shared_runner` | bool | effective: this job lands on a self-managed shared (or multi-project) runner, not restricted to protected refs, that also services higher-trust jobs (protected branch / deploy / other trust level) — so reused state crosses a trust boundary | job tags/ref resolution against `/runners` metadata (self_managed, is_shared, ref_protected) and the runner's cross-trust job set | 08 |
| `sub_claim_omits_ref` | bool | effective: this job's project narrowed `ci_id_token_sub_claim_components` so the id_token sub omits both ref and ref_type (every branch mints an identical sub). Folds the project-level `oidc.sub_claim_components` setting onto the minting job as a computed effective-property boolean | `project.oidc.sub_claim_components` evaluated against the default `["project_path","ref_type","ref"]` | 10 |
| `artifacts_access_unrestricted` | bool | a saving job leaves its artifacts at default-public: no `artifacts:public: false` and no `artifacts:access developer\|maintainer\|none` | `artifacts:public` / `artifacts:access` | 12 |
| `non_member_readable_pipelines` | bool | effective: this job's project is non-member-readable (visibility public or internal AND `public_pipelines == true`), so its pipeline artifacts/logs are downloadable by non-members | `project.visibility` × `project.public_pipelines` | 12 |
| `duo_flow_context_sources` | set | categories of untrusted content the Duo flow ingests as context: `fork_mr` (fork-MR description/diff/comments), `issue_comment` (issue or comment text) | `.gitlab/duo/agent-config.yml` flow wiring + project visibility/MR/issue-access settings | 13 |
| `duo_flow_secrets_in_scope` | bool | effective: the flow's CI job carries secrets an injection could steer it to read — at least one `protected=false` CI/CD variable reachable and/or a broad `CI_JOB_TOKEN` inbound allowlist | `cicd_variables` (protected) × job scope + inbound `job_token_allowlist` | 13 |
| `duo_flow_autonomous_write` | bool | effective: the flow's agent has write-capable actions (post comments, push, open MRs, call the API) and no per-action human-approval gate | `.gitlab/duo/agent-config.yml` / flow config (tool set + approval settings) | 13 |
| `duo_group_features_enabled` | bool | effective on the job: the group governing this flow has Duo/Agent-Platform enabled (folds `group.duo_features_enabled` onto the job subject) | GraphQL `Group.duoFeaturesEnabled` for the job's owning group | 13 |
| `duo_guardrail_level` | enum | effective on the job: the group prompt-injection protection level governing this flow — `NO_CHECKS` \| `LOG_ONLY` \| `INTERRUPT`, the GraphQL enum verbatim (do **not** lowercase; rules compare against the uppercase form) (folds group `aiSettings` onto the job subject) | GraphQL `group(fullPath).aiSettings.promptInjectionProtectionLevel` | 13 |
| `duo_instance_features_enabled` | bool | effective on the job: instance-level Duo/Agent-Platform enabled (self-managed; folds `instance.duo_features_enabled` onto the job subject) | admin-scoped instance Duo/AI settings (DuoSettings) | 13 |
| `duo_instance_guardrail_level` | enum | effective on the job: instance-level prompt-injection protection level (self-managed) — `NO_CHECKS` \| `LOG_ONLY` \| `INTERRUPT`, the GraphQL enum verbatim (do **not** lowercase) (folds `instance.prompt_injection_protection_level` onto the job subject) | admin-scoped instance Duo settings `promptInjectionProtectionLevel` | 13 |
| `duo_workflow_mcp_enabled` | bool | effective on the job: MCP integration enabled for the group's agents governing this flow (default false; folds instance/group `duo_workflow_mcp_enabled` onto the job subject) | GraphQL `group(fullPath).aiSettings.duoWorkflowMcpEnabled` | 13 |
| `duo_mcp_endpoint_untrusted_host` | bool | the flow is wired via `.gitlab/duo/mcp.json` to an MCP server whose endpoint host is not org-internal/allowlisted (third-party/community/public FQDN) | `.gitlab/duo/mcp.json` server url/host (cf. `project.duo.mcp_endpoint`) | 13 |
| `duo_external_agent_untrusted_host` | bool | the flow is wired via `.gitlab/duo/flows/*.yaml` to an external agent (third-party model provider) whose endpoint host is not org-internal/allowlisted; GitLab does not scan external-agent output | `.gitlab/duo/flows/*.yaml` agent provider/endpoint | 13 |
| `pages_references_secret_variable` | bool | the Pages producer job explicitly references (`variables:`/`secrets:`) a CI/CD variable whose metadata is protected or masked | job variables/secrets refs × `cicd_variables` metadata | 14 |
| `pages_public` | bool | effective: the job's project serves Pages public (`pages_access_level == public`) with no instance-level public-Pages disable | `project.pages_access_level` folded onto job | 14 |
| `downloads_secure_file` | bool | the job downloads a project secure file (download-secure-files tool or `.secure_files/` path) and the project has secure-file metadata | job `script` + secure-files API | 14 |
| `artifact_paths_broad` | bool | the Pages job's `artifacts:paths` publishes the whole workspace (`.`), the repo root, or a non-dedicated site output directory | `artifacts:paths` analysis | 14 |
| `source_ci_writable_by_lower_trust` | bool | the executed source CI (this job's `.gitlab-ci.yml`, includes resolved) or the ref it runs on is writable by a lower-trust member: the ref is unprotected, or protected without CODEOWNERS gating on `.gitlab-ci.yml`, or an `include:` resolves a mutable/attacker-writable location | resolved `.gitlab-ci.yml` includes × `/protected_branches` × CODEOWNERS coverage of the CI config | 04 |
| `_provenance` | object | `{config_file, yaml_line_range, project_path}` | — | all |

## `project`

Project settings, protected refs, and the project's CI/CD variable inventory.

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `visibility` | enum | `public` \| `internal` \| `private` | `visibility` | 01,12 |
| `forking_enabled` | bool | forks permitted | `forking_access_level` | 01 |
| `fork_pipelines_run_in_parent` | bool | fork MR pipelines may run in the parent | `ci_allow_fork_pipelines_to_run_in_parent_project` | 01 |
| `mr_pipelines_protected` | bool | MR pipeline protection on | `protect_merge_request_pipelines` | 01 |
| `merged_results_pipelines` | bool | merged-results / merge trains on | `merge_pipelines_enabled` | 01 |
| `inbound_job_token_scope_enabled` | bool | inbound `CI_JOB_TOKEN` allowlist enforced | `ci_job_token_scope_enabled` | 01,04 |
| `job_token_allowlist` | object | `{mode: disabled\|open\|group_scoped\|project_scoped, entries: [], fine_grained: bool}` | inbound allowlist API | 04 |
| `job_token_push_allowed` | bool | git push via job token permitted | `ci_push_repository_for_job_token_allowed` | 04,14 |
| `job_token_cross_project_push_allowed` | bool | an allowlisted *other* project's job token may git push into this repo (the second, distinct toggle; both this and `job_token_push_allowed` must be on for a cross-project push) | GraphQL `crossProjectPushForJobTokenAllowed` (`project.ciCdSettings`) | 04 |
| `uses_managed_terraform_state` | bool | project uses GitLab's managed Terraform/OpenTofu state backend (state objects present at `terraform/state/:name`) | `/projects/:id/terraform/state` objects present | 04 |
| `cache_separation_enabled` | bool | protected/unprotected cache separation on | `ci_separated_caches` | 09 |
| `oidc.sub_claim_components` | list | components composing the id_token `sub` | `ci_id_token_sub_claim_components` | 10 |
| `pages_access_level` | enum | `public` \| `internal` \| `private` | `pages_access_level` | 14 |
| `auto_devops_enabled` | bool | Auto DevOps on (project override) | `auto_devops_enabled` | 12 |
| `pipeline_execution_policy_from_mutable_project` | bool | a `pipeline_execution_policy` sources CI content from a mutable / lower-trust-writable policy project | `.gitlab/security-policies` + referenced `/protected_branches` | 02 |
| `has_cicd_config` | bool | `.gitlab-ci.yml` present | repo tree | many |
| `protected_branches` | list | `{pattern, push_access_levels: [], merge_access_levels: [], allow_force_push: bool, code_owner_approval_required: bool}` | `/protected_branches` | 01,02,03,05 |
| `protected_tags` | list | `{pattern, create_access_levels: []}` | `/protected_tags` | 03,05 |
| `default_branch_protected` | enum | protection level of the default branch | `/protected_branches` | 03,05 |
| `push_rules` | object | server-side push rule metadata | `/push_rule` | 06 |
| `cicd_variables` | list | `{key, protected: bool, masked: bool, environment_scope, scope_level: project\|group\|instance}` — **values never collected** | `/variables` | 01,03,05,07,11,13,14 |
| `has_developer_reachable_secret` | bool | derived: ≥1 `cicd_variables` entry reachable by a Developer-pushable ref | `cicd_variables` × `protected_branches` | 01,03 |
| `members` | list | `{access_level, is_bot}` | `/members/all` | 03,11 |
| `has_reachable_runner` | bool | project has ≥1 runner its pipelines can land on (project/group/instance) | `/runners` (+ inherited/instance) | 01 |
| `has_self_managed_runner` | bool | ≥1 reachable runner is self-managed (not the gitlab.com shared fleet) | `/runners` runner_type | 01 |
| `holds_protected_resources` | bool | project holds protected CI/CD variables or a protected runner a reused credential could reach | `cicd_variables` / `/runners` | 11 |
| `registry_protection_rules` | list | container/package registry tag protection | `/registry/protection/...` | 11 |
| `duo` | object | `{config_present: bool, flows: [], mcp_endpoint}` from `.gitlab/duo/*` | repo tree | 13 |
| `has_masked_unprotected_secret_var` | bool | derived: ≥1 `cicd_variables` entry has `masked==true` AND `protected==false` AND a secret-shaped key (secret-name heuristic). Folds the masked-not-protected tri-state combo plus the value-is-a-secret heuristic into one collectable boolean | `cicd_variables` (key/masked/protected) | 03 |
| `has_plain_unprotected_secret_var` | bool | derived: ≥1 `cicd_variables` entry has `protected==false` AND `masked==false` AND a secret-shaped key. The precision rests entirely on the secret-name heuristic; must never fire on unprotected variables alone | `cicd_variables` (key/masked/protected) | 03 |
| `has_scoped_unprotected_secret_var` | bool | derived: ≥1 `cicd_variables` entry has `environment_scope != "*"` AND `protected==false` AND a secret-shaped key. Scope is not a ref boundary (the job names the environment), so this scoped-not-protected combo is reachable from any ref | `cicd_variables` (key/environment_scope/protected) | 03 |
| `has_developer_pushable_unprotected_ref` | bool | derived: ≥1 pushable ref not restricted to a trusted set — no covering `protected_branches` rule, or a wildcard rule whose `push_access_levels` includes Developer (30) — so a Developer can create/push a feature branch and run its pipeline. Complements `has_developer_reachable_secret` by capturing same-scope untrusted-ref reachability | `protected_branches` × default push role | 03 |
| `developer_pushable_protected_branch` | bool | effective: a protected-branch rule on a CI-trusted ref lists Developer (access level 30) or a group/user entry under push access (Allowed to push and merge) | `/protected_branches` `push_access_levels` × role model | 05 |
| `developer_mergeable_protected_branch` | bool | effective: a protected-branch rule on a CI-trusted ref lists Developer (30) or a group/user entry under merge access (Allowed to merge) | `/protected_branches` `merge_access_levels` × role model | 05 |
| `developer_writable_protected_branch` | bool | effective: a protected-branch rule on a CI-trusted ref grants push OR merge to Developer (30) or a group/user entry (either write path) | `/protected_branches` `push`+`merge_access_levels` × role model | 05 |
| `developer_creatable_wildcard_branch` | bool | effective: a WILDCARD protected-branch rule (pattern contains a glob) grants push or merge to Developer (30) or a group/user entry, so a Developer can create a matching protected branch | `/protected_branches` name pattern × `push`/`merge_access_levels` | 05 |
| `protected_var_scoped_to_writable_ref` | bool | effective join: a `protected:true` CI/CD variable (project-defined or group-inherited) is scoped to the ref/pattern the low-trust actor can write | `cicd_variables` (protected, environment_scope) × `protected_branches` ref | 05 |
| `protected_var_scoped_to_tag_pipeline` | bool | effective join: a `protected:true` CI/CD variable is in scope for a tag pipeline (protected variables apply to protected tags) and `.gitlab-ci.yml` has `$CI_COMMIT_TAG` / `only:tags` jobs consuming it | `cicd_variables` × `protected_tags` × `.gitlab-ci.yml` tag jobs | 05 |
| `author_can_self_merge` | bool | effective: no required-approval rule blocks the MR author from merging alone (approvals_required 0 or author-satisfiable, author-approval not prevented) | `/approvals` + `/approval_rules` | 05 |
| `has_protected_self_managed_runner` | bool | effective: a runner with `access_level ref_protected` that is self-managed (not gitlab.com shared fleet) is reachable by the project's pipelines via matching tags or run_untagged | `/runners` `access_level` × `runner_type` × tags/run_untagged | 05 |
| `inherited_default_branch_developer_pushable` | bool | effective: the project's default branch has an inherited protected-branch rule whose push access includes Developer (30) with `allow_force_push false` (still a protected ref) and no stricter project override | `/projects/:id` default_branch × `/protected_branches` vs instance/group defaults | 05 |
| `inherited_protection_source` | enum | origin of the lowered default-branch protection the project inherited: `instance` \| `group` \| `project` | `/application/settings` default_branch_protection_defaults vs `/groups/:id` default_branch_protection_defaults | 05 |
| `force_push_by_low_trust_pusher` | bool | effective: a protected-branch rule on a CI-trusted ref has `allow_force_push true` and its push list includes a non-Maintainer (Developer 30 or broad group/user) | `/protected_branches` `allow_force_push` × `push_access_levels` | 05 |
| `ref_is_ci_trusted` | bool | the ref is CI-trusted: a protected variable is scoped to it or it feeds a deploy pipeline (default branch or a ref used by pipeline jobs) | `cicd_variables` × `protected_branches` × `.gitlab-ci.yml` | 05 |
| `push_access_shadowed_by_permissive_rule` | bool | effective: ≥2 protected-branch rules match one CI-trusted branch and the unioned (most-permissive) push access includes a lower-trust actor than the narrowest matching rule intended | `/protected_branches` per-branch glob resolution of `push_access_levels` | 05 |
| `no_one_push_creatable_via_merge` | bool | effective: a protected pattern has push access = No one (empty `push_access_levels`) but a matching rule grants merge access to Developer (30) or a group/user entry, permitting branch creation | `/protected_branches` `push_access_levels` empty × matching `merge_access_levels` | 05 |
| `force_push_shadowed_by_permissive_rule` | bool | effective: ≥2 rules match one CI-trusted branch, the narrowest has `allow_force_push false` but a broader matching rule has `allow_force_push true` (most-permissive grants force push), and a non-Maintainer is in the effective push list | `/protected_branches` per-branch resolution of `allow_force_push` × `push_access_levels` | 05 |
| `developer_creatable_protected_tag` | bool | effective: a protected-tag rule's `create_access_levels` includes Developer (30) or a group/user entry, for a pattern matching the tag scheme used by privileged tag jobs | `/protected_tags` `create_access_levels` × `.gitlab-ci.yml` tag jobs | 05 |
| `create_access_shadowed_by_permissive_tag_rule` | bool | effective: ≥2 protected-tag rules match a release tag pattern used by tag jobs and the unioned (most-permissive) create access includes a lower-trust actor than the narrowest matching rule intended | `/protected_tags` per-pattern glob resolution of `create_access_levels` | 05 |
| `ref_has_deferred_deploy_identity` | bool | a job on the ref carries a deploy indicator whose credential is minted/scoped outside GitLab: an `id_tokens:` OIDC block and/or an `environment:` naming a protected/production environment | `.gitlab-ci.yml` `id_tokens:` / `environment:` | 05 |
| `public_pipelines` | bool | project-based pipeline visibility on: job logs/artifacts/CI menu readable at the project's visibility scope (default enabled) | `public_jobs` / `public_pipelines` | 12 |
| `has_guest_member` | bool | effective: the project has ≥1 direct member at the Guest access level (10) — precomputed because the engine's `∋` set-membership cannot express an existential over member maps | `/projects/:id/members` `access_level == 10` | 12 |
| `ci_debug_trace_enabled` | bool | `CI_DEBUG_TRACE` set truthy as a global/job variable or a project/group CI/CD variable, forcing every non-masked variable into the job trace | `variables:` `CI_DEBUG_TRACE` / `cicd_variables` key | 12 |
| `auto_devops_deploy_creds_wired` | bool | instance/group Auto DevOps deploy plumbing is present in scope: `AUTO_DEVOPS_*`/`KUBE_*` CI/CD variables, a configured container registry, or a bound Kubernetes agent the deploy stage targets | `cicd_variables` (`AUTO_DEVOPS_*`/`KUBE_*`) / registry / agent | 12 |
| `group_inherited_deploy_vars` | bool | effective: the project inherits group-level Auto DevOps deploy variables (`KUBE_*`/`AUTO_DEVOPS_*` or a group-wired registry) into its Auto DevOps pipeline | `group.cicd_variables` (inherited) key heuristic | 12 |
| `_provenance` | object | `{project_path}` | — | all |

## `group`

Group-level settings and the inheritance tree descendants inherit from. Drives the inheritance chain joins.

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `default_membership_role` | enum | role auto-granted via SAML/SCIM: `guest` \| `reporter` \| `developer` \| `maintainer` \| `owner` | `default_membership_role` | 12 |
| `default_branch_protection` | enum | group default-branch protection default | `default_branch_protection_defaults` | 03 |
| `project_creation_role` | enum | minimum role that can create projects | `default_project_creation` | 08,12 |
| `project_access_token_creation_allowed` | bool | descendants may mint project access tokens | `project_access_token_creation_allowed` | 11 |
| `shared_runners_enabled` | bool | group runners reachable by descendants | group runner settings | 08,12 |
| `duo_features_enabled` | bool | Duo enabled at group scope | `duoFeaturesEnabled` | 13 |
| `domain_allowlist` | list | egress allowlist (SSRF surface) | `domain_allowlist` | 12 |
| `cicd_variables` | list | group variables (same shape as `project.cicd_variables`) | `/groups/:id/variables` | 03,11 |
| `descendants` | list | project/subgroup paths inheriting from this group | `/groups/:id/projects` (+ subgroups) | 03,11,12 |
| `group_open_project_creation` | bool | effective: the group permits non-Owner project/subgroup creation so any Developer+ (or open self-service) user can self-create a descendant project reaching the group runner | `project_creation_role` / `subgroup_creation_level` | 12 |
| `saml_provisioning_active` | bool | group has SAML SSO and/or SCIM provisioning configured (identities auto-provisioned via the IdP) | `/groups/:id/saml` + SCIM token issued | 12 |
| `default_role_custom_cicd_ability` | bool | effective: the group's `default_membership_role` references a custom member role whose enabled abilities include a CI/CD-admin permission (`admin_cicd_variables`, `manage_project_access_tokens`, `manage_group_access_tokens`, runner management) on a low base role | `default_membership_role` × custom-role ability set | 12 |
| `_provenance` | object | `{group_path}` | — | all |

## `instance`

Self-managed instance / admin settings. On gitlab.com most are fixed defaults; instance-scope collection needs an admin token.

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `allow_local_requests_from_webhooks` | bool | webhooks/services may reach local network | `allow_local_requests_from_web_hooks_and_services` | 12,14 |
| `runner_registration_token_allowed` | bool | legacy reusable registration tokens permitted | `allow_runner_registration_token` | 08 |
| `valid_runner_registrars` | list | who may register runners | `valid_runner_registrars` | 08 |
| `auto_devops_enabled` | bool | Auto DevOps default on | `auto_devops_enabled` | 12 |
| `signup_enabled` | bool | open self-registration | `signup_enabled` | 12 |
| `service_token_expiration_enforced` | bool | service-account tokens must expire | `service_access_tokens_expiration_enforced` | 11 |
| `duo_features_enabled` | bool | Duo enabled instance-wide | `duoFeaturesEnabled` | 13 |
| `duo_workflow_mcp_enabled` | bool | external MCP tool calls permitted | `duoWorkflowMcpEnabled` | 13 |
| `prompt_injection_protection_level` | enum | `no_checks` \| `log_only` \| `interrupt` | `aiSettings.promptInjectionProtectionLevel` | 13 |
| `project_creation_unrestricted` | bool | project creation is not restricted to admins/specific roles — any authenticated user can create projects | `default_project_creation` application setting | 08 |
| `can_create_group` | bool | users may create top-level groups (lets an attacker host a fresh project escaping group-level restrictions) | `can_create_group` application setting | 08 |
| `shared_runners_enabled` | bool | instance runners are enabled at instance level and default-enabled for new projects, so a freshly created project is auto-entitled to the shared instance runner pool | `shared_runners_enabled` application setting (+ new-project default) | 08 |
| `self_managed_shared_runner_serves_higher_trust` | bool | effective: at least one self-managed instance-shared runner (not GitLab-hosted SaaS) reachable by a new project's default pipeline also services a higher-trust project (protected variables / deploy tokens / protected environments in scope) | `/runners` metadata (runner_type=instance_type, self-managed, ref_protected, run_untagged) cross-referenced with higher-trust project entitlement | 08 |
| `reusable_token_scope_serves_secrets` | bool | effective: the scope (instance/group/project) reachable via the reusable registration token services pipelines carrying protected variables or deploy credentials — so a rogue runner racing for those jobs steals something of value | runner scope cross-referenced with co-located protected variables / deploy tokens | 08 |
| `open_project_creation` | bool | effective: any authenticated user can create a project reaching instance runners (instance runners available to new projects AND permissive project/top-level-group creation AND, self-managed, sign-up enabled) | instance runner-for-new-projects × `default_project_creation` × `signup_enabled` | 12 |
| `outbound_local_requests_allowlist_effective` | bool | a tight local-address allowlist confining which internal hosts webhooks/integrations may reach is in effect (false = empty or overly broad) | `outbound_local_requests_whitelist` | 12 |
| `require_admin_approval_after_signup` | bool | new self-registered accounts are held for admin approval before becoming active (default false = active immediately) | `require_admin_approval_after_user_signup` | 12 |
| `closed_audience_instance` | bool | effective: this self-managed instance is not intended to be public (hosts internal/private organisational projects, or open project creation onto shared runners), so open unapproved sign-up is a misconfiguration rather than a community-server norm; not applicable to GitLab.com | instance visibility content + domain_allowlist heuristic | 12 |
| `_provenance` | object | `{}` | — | all |

## `merge_request`

The project's MR/approval posture (cat-06). Modeled per-project; predicates read the effective configuration.

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `author_approval_allowed` | bool | MR author may approve their own MR | `merge_requests_author_approval` | 06 |
| `committer_approval_disabled` | bool | committers barred from approving (false = they may) | `merge_requests_disable_committers_approval` | 06 |
| `approvals_required` | int | minimum approvals to merge | `/approvals` | 06 |
| `author_controls_approver_count` | bool | author can lower required approvers in-MR | approval rule scope | 06 |
| `reset_approvals_on_push` | bool | approvals reset after a post-approval commit | `reset_approvals_on_push` | 06 |
| `code_owner_approval_required` | bool | CODEOWNERS approval enforced | protected-branch rule | 06 |
| `selective_code_owner_removal` | bool | code-owner requirement resettable selectively | approval config | 06 |
| `codeowners.optional_sections` | bool | CODEOWNERS has `^[optional]` sections | `CODEOWNERS` | 06 |
| `codeowners.covers_cicd_config` | bool | CODEOWNERS covers `/.gitlab-ci.yml` | `CODEOWNERS` | 06 |
| `only_merge_if_pipeline_succeeds` | bool | merge gated on green pipeline | `only_allow_merge_if_pipeline_succeeds` | 06 |
| `only_merge_if_status_checks_pass` | bool | merge gated on external checks | `only_allow_merge_if_all_status_checks_passed` | 06 |
| `allow_merge_on_skipped_pipeline` | bool | skipped pipeline counts as success | `allow_merge_on_skipped_pipeline` | 06 |
| `external_status_checks` | list | configured external status checks | `/external_status_checks` | 06 |
| `approval_policy` | object | `{enforcement_type: warn\|..., fallback_behavior: fail_open\|fail_closed, scanners: [], bypass_settings, scope_broad: bool}` | security policy project | 06 |
| `approver_set_broad` | bool | effective: the applicable approval rule's eligible-approver set is broad (a broad group, the Developer role, or "all eligible users"), so a likely author/committer is themselves an eligible approver | approval rule eligible-approver membership × project role model | 06 |
| `independent_approver_count` | int | count of distinct eligible approvers who are neither the MR author nor a committer on the MR (the enforceable independent-review capacity of the rule) | approval rule eligible-approver set minus author + committer identities | 06 |
| `trust_relevant_path_optional_only` | bool | effective: at least one trust-relevant path (`.gitlab-ci.yml`, CI include, deploy, `/CODEOWNERS`) is owned in CODEOWNERS only under a `^`-prefixed Optional section, so its owner approval is structurally never required | CODEOWNERS section-header parsing × path trust-relevance | 06 |
| `approval_policy.enabled` | bool | the merge-request approval policy is present and enabled (relied on as the security-approval gate) | security policy project / policies API (enabled) | 06 |
| `approval_policy.fallback_behavior` | enum | policy fallback when a rule cannot evaluate: `fail_open` \| `fail_closed` | `approval_policy` `fallback_behavior` (fail: open\|closed) | 06 |
| `approval_policy.named_scanner_absent` | bool | effective: a scanner named in the policy's `scan_finding` rule has no corresponding job/include in the target project's resolved `.gitlab-ci.yml`, so the rule cannot evaluate | policy `scanners:` × target resolved pipeline jobs | 06 |
| `approval_policy.enforcement_type` | enum | policy enforcement mode: `warn` (dismissable) vs the blocking mode | `approval_policy` `enforcement_type` | 06 |
| `approval_policy.binds_trusted_target` | bool | effective: the policy's effective scope actually binds the CI-trusted target branch (false when the target is unprotected, out of `policy_scope`, or the policy is disabled) | policy branches/`policy_scope`/enabled × protected-branches list × CI-trust of branch | 06 |
| `approval_policy.scope_excludes_target` | bool | the policy's `policy_scope` / `branches` list excludes the target project or branch | `approval_policy` `policy_scope` / `branches:` | 06 |
| `target_branch_ci_trusted_unprotected` | bool | effective: a CI-trusted target branch (protected variables/runners/deploy-on-merge) is not in the project's protected-branches list, so approval policies (which bind only protected branches) do not enforce there | protected-branches list × CI-trust metadata for the branch | 06 |
| `approval_policy.bypass_actor_broad` | bool | effective: the policy's `bypass_settings` exempts a broadly-held or lower-trust actor (Developer role, large group, shared token/service account, or permissive branch pattern) rather than a single break-glass identity | `approval_policy` `bypass_settings` × group/role membership breadth | 06 |
| `required_jobs_evadable` | bool | effective: the project's required security/test jobs are gated behind author-controllable `rules:`/`workflow:` conditions (or `[skip ci]`) so an MR can legitimately produce a skipped/empty pipeline | resolved `.gitlab-ci.yml` `rules:`/`workflow:` analysis | 06 |
| `codeowners.self_owned_required` | bool | CODEOWNERS contains a required (non-Optional) entry owning its own path (`/CODEOWNERS`, `CODEOWNERS`, `/.gitlab/CODEOWNERS`), so editing the reviewer-defining file itself demands owner approval | CODEOWNERS self-referential path coverage × section requiredness | 06 |
| `_provenance` | object | `{project_path}` | — | 06 |

## `environment`

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `name` | string | environment name | environments API | 07 |
| `tier` | enum | `production` \| `staging` \| … (self-declared) | `deployment_tier` | 07 |
| `protected` | bool | environment is a protected environment | `/protected_environments` | 07 |
| `self_declared_scope` | bool | name/scope treated as a boundary but not backed by protection | derived | 07 |
| `deploy_approvals_required` | int | required deployment approvals | `required_approval_count` | 07 |
| `approval_rules` | list | `{access_level, is_bot, self_approval_allowed}` | `approval_rules[]` | 07 |
| `allow_pipeline_trigger_approve_deployment` | bool | protected environment permits the pipeline triggerer to approve their own pending deployment (the per-env 'Allow pipeline triggerer to approve deployment' toggle) | `/protected_environments` `allow_pipeline_trigger_approve_deployment` | 07 |
| `carries_deploy_context` | bool | effective: the environment carries real deploy context worth gating (an environment-scoped deploy credential whose `environment_scope` matches its name, an `id_tokens`/OIDC deploy identity, or a production/staging `deployment_tier`) rather than being a throwaway review env | `cicd_variables.environment_scope` × environment name / `id_tokens:` / `deployment_tier` | 07 |
| `near_miss_protected_name` | bool | effective: this environment name has no exact-match Protected Environments entry but is a near-neighbor of a protected name (case-insensitive equal, differs only by a `/<suffix>`, or a common alias such as prod↔production), so project-level exact-match protection does not cover it | environment name set (`environment:name` across jobs) diffed against `/projects/:id/protected_environments` exact names | 07 |
| `group_tier_protection_escaped` | bool | effective: a top-level group protects a `deployment_tier` set, but this environment's self-declared `deployment_tier` (or the guessed default) falls outside that set and no project-level Protected Environments entry covers it, so the group's tier-scoped deploy-access/approval rules do not apply | `/groups/:id/protected_environments` protected tiers × environment `deployment_tier` × `/projects/:id/protected_environments` | 07 |
| `approval_rule_bot_approver` | bool | effective: at least one `approval_rules[]` member is a non-human principal (a service account or a group/project access-token bot user, `is_bot == true`) that is an eligible approver — so an automatable identity can supply a required deployment approval | `approval_rules[]` `is_bot` member classification | 07 |
| `_provenance` | object | `{project_path}` | — | 07 |

## `runner`

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `runner_type` | enum | `instance_type` \| `group_type` \| `project_type` | `runner_type` | 08 |
| `is_shared` | bool | shared across projects | `is_shared` | 08,12 |
| `ref_protected` | bool | only runs protected-ref jobs | `access_level == ref_protected` | 08 |
| `run_untagged` | bool | picks up untagged jobs | `run_untagged` | 01,12 |
| `locked` | bool | locked to its project | `locked` | 12 |
| `tags` | set | runner tags | `tags` | 08,13 |
| `projects` | list | projects sharing this runner (co-residency) | `/runners/:id/projects` | 08 |
| `registration_token_reusable` | bool | registered via a reusable token | instance setting × runner | 08 |
| `self_managed` | bool | runner is self-managed (operator-controlled host lifecycle), not a GitLab-hosted ephemeral SaaS runner. Load-bearing classifier that separates a finding from safe ephemeral SaaS runners | runner platform/description metadata / runner_type classification | 08 |
| `spans_trust_boundary` | bool | effective: this runner is entitled to (or its projects list contains) both a low-trust/broad-membership project and at least one higher-trust project (protected variables / deploy tokens / protected environments) — i.e. its scope straddles a trust boundary | `/runners/:id/projects` (or instance/group entitlement) cross-referenced with per-project protected variables / protected environments / membership breadth | 08 |
| `serves_protected_ref_only_jobs` | bool | effective: the runner (by id/tag) is targeted by jobs that run only on protected refs (`rules:if $CI_COMMIT_REF_PROTECTED` or `only:[main,tags]`) — marking it a trusted/deploy runner | jobs' `rules:`/`only:` resolution cross-referenced with runner tags/id | 08 |
| `serves_untrusted_ref_jobs` | bool | effective: the same runner also picks up jobs reachable from arbitrary/non-protected branches — no protected-ref separation between trusted and untrusted workloads on the runner | jobs' ref/rules resolution cross-referenced with runner tags/id | 08 |
| `untrusted_ref_job_matches_tags` | bool | effective: an attacker-writable `.gitlab-ci.yml` on a non-protected ref carries `tags:` matching this runner (no CODEOWNERS/required-review gate on `.gitlab-ci.yml`), so a job can be deliberately steered onto it | jobs' `tags:` (from attacker-writable `.gitlab-ci.yml`) cross-referenced with runner tags | 08 |
| `bridges_trust_boundary` | bool | effective: this project runner is enabled on ≥2 projects of differing trust (e.g. one with protected variables/environments, one without) | `runner.projects` × per-project protected-var/protected-env posture | 12 |
| `_provenance` | object | `{scope}` | — | 08 |

## `agent`

Kubernetes agent `ci_access` (cat-15). The decisive control (in-cluster RBAC) is deferred — these carry `confidence: low` in the corpus.

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `config_path` | string | agent config file | `.gitlab/agents/<name>/config.yaml` | 15 |
| `ci_access_scope` | enum | `project` \| `group` \| `instance` | `ci_access.{projects,groups,instance}` | 12,15 |
| `ci_access_targets` | list | groups/projects granted CI access | `ci_access.groups` / `.projects` | 15 |
| `implicit_config_project` | bool | grant implied by config-project location, not explicit | agent config location | 15 |
| `protected_branches_only` | bool | access limited to protected branches | `protected_branches_only` | 15 |
| `environments_filter` | list | `environments:` scoping (forgeable if self-declared) | `ci_access.environments` | 15 |
| `impersonation` | object | `access_as` impersonation config | `access_as` | 15 |
| `default_permissions` | bool | uses default (broad) permissions | `defaultPermissions` | 04,15 |
| `grant_has_lower_trust_developer` | bool | effective: at least one lower-trust Developer-role (access level 30) member exists in the authorized group subtree who does not otherwise hold cluster access (folds agent grant → group/subgroup/project membership join) | `ci_access.groups[]` × group/subgroup/project `/members/all` | 15 |
| `grant_developer_pushable_unprotected_branch` | bool | effective: an authorized (project-scoped) grant reaches a project where a Developer-role member can push at least one non-protected branch whose pipeline is authorized (folds agent grant → project members + protected-branches join) | `ci_access.projects[]` × `/members/all` × `/protected_branches` | 15 |
| `config_project_developer_reachable` | bool | effective: the implicitly-authorized agent configuration project has Developer-role members (or a Developer-pushable non-protected branch) who are not cluster operators (folds config-project location → its membership + protected-branches join) | agent config project × `/members/all` × `/protected_branches` | 15 |
| `instance_agent_authorization_enabled` | bool | effective: the self-managed admin setting permitting instance-level agent authorization is enabled, so a `ci_access.instance` grant takes effect (folds instance setting onto the agent subject) | instance admin setting for instance-level agent authorization | 15 |
| `environments_filter_wildcard` | bool | the `ci_access` environments filter contains a wildcard entry (`*` or a prefix/suffix wildcard such as `review/*`) that matches attacker-authored environment slugs | `ci_access.*.environments` (shape analysis) | 15 |
| `environments_filter_unprotected` | bool | effective: at least one fixed (non-wildcard) name in the `ci_access` environments filter is absent from the in-scope project's protected-environments list (or protected with a Developer-inclusive deployer list), so the name gates nothing (folds filter → protected-environments API join) | `ci_access.*.environments` × `/projects/:id/protected_environments` | 15 |
| `grant_developer_authors_matching_env_job` | bool | effective: a Developer in an in-scope project can author a job that sets `environment:` to a filter-matching value while running on a non-protected ref (folds agent grant → resolved `.gitlab-ci.yml` + members + protected-branches) | `ci_access` grant × resolved `.gitlab-ci.yml` × `/members/all` × `/protected_branches` | 15 |
| `namespace_plan` | enum | the namespace billing plan: `free` \| `premium` \| `ultimate` — on free, protected environments and impersonation do not exist | namespace/plan metadata API | 15 |
| `grant_protected_ref_developer_writable` | bool | effective: an in-scope project has a protected branch whose push/merge access includes the Developer level, a wildcard protected pattern a Developer may create matching branches under, or a protected tag a Developer may create — so a Developer can land a pipeline on a ref satisfying `protected_branches_only` (folds agent grant → protected-branches + protected-tags API join) | `ci_access` grant × `/protected_branches` × `/protected_tags` | 15 |
| `_provenance` | object | `{project_path}` | — | 15 |

## `credential`

One record per long-lived credential (cat-11). Values are never collected; reachability via a variable is a deferred leg (hence `confidence: medium\|low`).

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `kind` | enum | `project_access_token` \| `group_access_token` \| `personal_access_token` \| `deploy_token` \| `deploy_key` \| `static_cloud_cred` | resource API / heuristic | 11 |
| `scopes` | set | granted scopes | `scopes` | 11 |
| `access_level` | enum | role of the token/backing identity | `access_level` | 11 |
| `non_expiring` | bool | no expiry set | `expires_at == null` | 11 |
| `revoked` | bool | revoked/expired | `revoked` / `expired` | 11 |
| `auto_injected` | bool | structurally injected into CI (e.g. `gitlab-deploy-token`) | `name == "gitlab-deploy-token"` | 11 |
| `in_unprotected_variable` | bool | credential believed reachable via an unprotected variable (deferred) | `cicd_variables` key heuristic | 11 |
| `key_pattern` | enum | variable key matches `*DEPLOY_KEY*` / PAT / cloud-cred pattern | variable key | 11 |
| `deploy_key_fingerprint` | string | public-key fingerprint (for reuse join) | `/deploy_keys` | 11 |
| `can_push` | bool | write-capable deploy key | `can_push` | 11 |
| `backing_identity_breadth` | list | projects/groups the backing identity is a member of | `/users/:id/memberships` | 11 |
| `is_schedule_owner` | bool | the pipeline's triggering identity owns the schedule that starts the run | schedule metadata | 04 |
| `creator_has_target_protected_access` | bool | the credential's creator holds protected-resource access on the target project | membership × `/protected_branches` | 11 |
| `scope_level` | enum | origin scope of an access/deploy token: `project` \| `group` \| `instance` — distinguishes project vs group deploy/access tokens (group tokens inherit tree-wide). Contract has `scope_level` only inside `cicd_variables` entries; this lifts it to the credential subject | resource API (project vs group deploy_tokens / access_tokens endpoint) | 11 |
| `service_account` | bool | the token's backing identity is a GitLab service account (vs a human user), distinguishing scenario 04 from scenario 03 | service-accounts API / user type | 11 |
| `long_lived` | bool | effective: `expires_at` is null OR far in the future (≥ ~330 days out) — covers both the legacy non-expiring service-account token and the current ~1-year default, per scenario 04's core signal which `non_expiring` (`expires_at == null`) alone cannot express | `expires_at` + instance `service_token_expiration_enforced` | 11 |
| `name` | string | the token's name (used in evidence templating; `auto_injected` derives from `name == "gitlab-deploy-token"`) | deploy/access token `name` | 11 |
| `project_uses_oidc` | bool | effective: the credential's project (or inherited group) resolves an `id_tokens:` OIDC path for cloud auth; folds scenario 09's "no `id_tokens` block" compounding signal onto the credential subject so its absence (`!= true`) flags static-key retention | resolved `.gitlab-ci.yml` `id_tokens:` (including `include:`) | 11 |
| `_provenance` | object | `{scope}` | — | 11 |

## `integration`

Webhooks, integrations, pull-mirroring, Pages (cat-14, cat-12).

| Field | Type | Meaning | Source | Families |
|---|---|---|---|---|
| `kind` | enum | `webhook` \| `integration` \| `pull_mirror` \| `pages` | resource type | 12,14 |
| `url` | string | target URL | `url` / `import_url` | 14 |
| `url_mutable` | bool | URL editable by a lower-trust role (redirect/SSRF surface) | member roles × integration | 14 |
| `token_present` | bool | a secret/credential is attached | `token_present` | 14 |
| `custom_headers` | list | custom HTTP headers (may carry creds) | `custom_headers[]` | 14 |
| `allows_local_network` | bool | may reach internal/local addresses | integration × instance `allow_local_requests_*` | 12,14 |
| `mirror.trigger_pipelines` | bool | mirrored refs auto-run CI | mirror settings | 14 |
| `mirror.all_branches` | bool | mirror pulls all branches | mirror settings | 14 |
| `pages.reads_secret` | bool | a Pages job reads a secret into `public/` | job × `pages:` | 14 |
| `webhook_signing_token_present` | bool | webhook has a per-request HMAC signing token (the non-replayable alternative to a shared secret token) | webhook signing-token metadata | 14 |
| `firable_event_trigger` | bool | the webhook/integration has at least one enabled event trigger a lower-trust role can cause on demand (push/note/merge_requests/pipeline/issues), or a Maintainer-invokable Test-settings delivery | hook/integration event-trigger flags | 14 |
| `editor_below_credential_trust` | bool | effective: a role that can edit the delivery/server URL (Maintainer / group Owner) sits below the trust level of the write-only credential attached, and is not the credential-setter | membership roles × hook/integration credential ownership | 14 |
| `mirror.upstream_untrusted_host` | bool | the pull-mirror `import_url` host is external to the project's own group/namespace (lower-trust upstream) | `import_url` host vs instance/group | 14 |
| `mirror.protected_default_branch` | bool | effective: the mirrored default branch is protected, so the auto-triggered mirror pipeline runs in a trusted context | mirror settings × project protected_branches | 14 |
| `mirror.reaches_protected_variable` | bool | effective: a protected CI/CD variable is reachable by the auto-triggered mirror pipeline on the protected mirrored branch | project/group `cicd_variables` × mirror branch protection | 14 |
| `mirror.reaches_unprotected_variable` | bool | effective: an unprotected (or masked) CI/CD variable is reachable by the auto-triggered mirror pipeline on any mirrored branch | project/group `cicd_variables` × mirror all-branches | 14 |
| `mirror.job_token_push_allowed` | bool | effective: the mirroring project permits the CI job token to push to the repository (`ci_push_repository_for_job_token_allowed`) | `project.job_token_push_allowed` folded onto the pull-mirror record | 14 |
| `_provenance` | object | `{project_path}` | — | 12,14 |

## Chain joins (`correlate` keyspaces)

`subject: chain` rules join facts across records. Each keyspace below is a correlation `correlate` (part of normalize, LAB-4288) must materialize; the rule then reads participant fields by role prefix. Names reuse the GitHub set where semantics match (`cache-keyspace`, `deploy-key-reuse`, `env-deployments`).

The `for_each` column is the item-list key each join's output must expose — the rule's `chain_of.for_each` reads it, and `iterChainItems` defaults to `links` when a rule omits it (so an unset `for_each` silently iterates nothing). Every chain rule sets it explicitly; the normalizer must emit each join's tuples under exactly this key. Names reuse the GitHub item names where the join is shared (`cache-keyspace` → `prefix_overlaps`, `deploy-key-reuse` → `reused_keys`, `env-deployments` → `deploys`, edge-lists → `edges`).

| `join:` | `for_each` | Correlates | Participant fields (examples) | Families |
|---|---|---|---|---|
| `dotenv-flow` | `edges` | producer job → consumer job via dotenv artifact | `producer.produces_dotenv`, `producer.runs_on_untrusted_ref`, `consumer.consumes_dotenv`, `consumer.image_from_variable` | 09 |
| `cache-keyspace` | `prefix_overlaps` | jobs sharing a cache key prefix across a trust boundary | `writer.runs_on_untrusted_ref`, `reader.protected_ref_gate`, overlap on `cache.key` | 09 |
| `job-token-allowlist` | `edges` | source project token posture → target project inbound allowlist + triggerer role | `source.inbound_job_token_scope_enabled`, `source.source_ci_writable_by_lower_trust`, `target.job_token_allowlist`, `triggerer.access_level`, `triggerer.is_bot`, `triggerer.is_schedule_owner` (Pipeline Schedules API owner) | 01,04,09 |
| `cross-project-artifact` | `edges` | `needs:project:` consumer → producer project trust | `consumer.cross_project_needs`, `producer.visibility`, `producer.has_developer_reachable_secret` | 02,09 |
| `deploy-key-reuse` | `reused_keys` | same deploy-key fingerprint across projects | `key.deploy_key_fingerprint`, `key.can_push`, `key.creator_has_target_protected_access` (the key's creating user holds access to the `target` project's protected environments/variables — the privilege the pushed pipeline inherits), per-project `access_level`, `source.in_unprotected_variable`, `target.holds_protected_resources` (the `target` project holds protected environments and/or protected CI/CD variables, marking it the higher-trust side of the span) | 11 |
| `protected-var-reachability` | `reachable_vars` | protected variable ↔ the ref path that reaches it. The join itself resolves the two correlations the DSL cannot express in `where` (its predicate RHS is always a literal, never a field reference): (a) the ref/member project lies in the variable's inheritance scope (`group.descendants`, or any project for instance-scope), and (b) `member` belongs to the same project as the `branch`/`tag` participant. It emits only tuples where both hold, so rules carry **only literal-valued predicates** (`var.protected == true`, `branch.push_access_levels ∋ {30}`, `member.access_level == 30`, …). | `var.protected`, `var.scope_level`, `branch.push_access_levels`, `tag.create_access_levels`, `group.default_branch_protection`, `member.access_level` | 01,03,05 |
| `oidc-trust` | `edges` | id_token job ↔ sub-claim narrowing ↔ ref protection | `job.mints_id_token`, `job.runs_on_untrusted_ref`, `project.oidc.sub_claim_components`, `job.environment_name` | 01,10 |
| `agent-ci-access` | `grants` | agent grant ↔ target membership ↔ branch/env guard | `agent.ci_access_scope`, `agent.protected_branches_only`, `agent.environments_filter`, `project.protected_branches` | 12,15 |
| `runner-reachability` | `reachable_runners` | instance/shared runner posture ↔ the instance open-project-creation posture that lets any account reach it | `runner.runner_type`, `runner.is_shared`, `runner.run_untagged`, `runner.ref_protected`, `instance.open_project_creation` | 12 |
| `group-runner-reachability` | `reachable_runners` | group-scoped runner ↔ its owning group's creation-governance posture (inherited to all descendants) | `runner.runner_type`, `runner.run_untagged`, `runner.ref_protected`, `group.group_open_project_creation` | 12 |
| `env-deployments` | `deploys` | protected environment ↔ approver identity | `environment.protected`, `environment.approval_rules[].self_approval_allowed`, `environment.approval_rules[].is_bot` | 07 |
| `mirror-pipeline` | `edges` | pull mirror ↔ auto-run upstream CI ↔ write-back protection | `integration.mirror.trigger_pipelines`, `project.has_cicd_config`, `project.protected_branches` | 14 |
| `group-inheritance` | `edges` | group setting/token/variable ↔ descendant membership | `group.default_membership_role`, `group.cicd_variables`, `group.descendants`, `member.access_level` | 03,11,12 |

## Engine dependencies (not in scope of the rule PRs)

These rules stay inert until three pieces of Go land — none of which is a catalog PR:

1. **Loader dispatch** — `LoadRules` (`internal/github/rules.go:116`) walks a hardcoded `"github"` subtree; a GitLab equivalent (or a platform-parameterized loader) must walk `gitlab`.
2. **Subject-kind registration** — `subjectDirs` (`internal/github/scan.go:15`) must gain the kinds in the table above, or a GitLab rule's subject silently loads zero records.
3. **`normalize` + `correlate` (LAB-4288)** — must emit the records and join keyspaces defined here.

Track these under the engine-generalization ticket; the catalog PRs depend on them to produce findings, and behavioral validation against the firing range (LAB-4297) is gated on all three.
