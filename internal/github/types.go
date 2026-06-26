package github

type LineRange [2]int

type JobProvenance struct {
	WorkflowFile  string    `json:"workflow_file"`
	YAMLLineRange LineRange `json:"yaml_line_range"`
	Repo          string    `json:"repo"`
}

type SourceProvenance struct {
	File      string     `json:"file"`
	LineRange *LineRange `json:"line_range,omitempty"`
}

type TriggerFilter map[string]any

type Step struct {
	StepIndex              int               `json:"step_index"`
	ID                     *string           `json:"id"`
	Uses                   *string           `json:"uses"`
	With                   map[string]any    `json:"with"`
	Run                    *string           `json:"run"`
	Name                   *string           `json:"name"`
	If                     *string           `json:"if"`
	NeedsOutputRefsExec    []NeedsOutputRef  `json:"needs_output_refs_exec"`
	NeedsOutputRefsBinding []NeedsOutputRef  `json:"needs_output_refs_binding"`
	Provenance             *SourceProvenance `json:"_provenance"`
	Classifiers            StepClassifiers   `json:"classifiers"`
}

type NeedsOutputRef struct {
	JobID      string `json:"job_id"`
	OutputName string `json:"output_name"`
}

type JobOutput struct {
	Name                            string            `json:"name"`
	ValueExpression                 string            `json:"value_expression"`
	AttackerContextFieldsReferenced []string          `json:"attacker_context_fields_referenced"`
	ReferencesStepID                *string           `json:"references_step_id"`
	ProducingStepAttackerExecRefs   []string          `json:"producing_step_attacker_exec_refs"`
	Provenance                      *SourceProvenance `json:"_provenance"`
}

type SecretRef struct {
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	StepIndex int    `json:"step_index"` // -1 for job-env-level refs
}

type EnvironmentRef struct {
	Name string  `json:"name"`
	URL  *string `json:"url"`
}

// Inputs is a pointer so a job-level empty map serializes as "inputs":{} while a step-level nil omits the key.
type ReusableCall struct {
	Owner          *string         `json:"owner"`
	Repo           *string         `json:"repo"`
	Path           string          `json:"path"`
	Ref            string          `json:"ref"`
	Kind           string          `json:"kind"`
	RefMutable     bool            `json:"ref_mutable"`
	SecretsInherit bool            `json:"secrets_inherit"`
	Inputs         *map[string]any `json:"inputs,omitempty"`
	JobLevel       bool            `json:"job_level,omitempty"`
}

type LocalCompositeRef struct {
	Uses string `json:"uses"`
}

type ActionRef struct {
	Uses        string  `json:"uses"`
	RefKind     string  `json:"ref_kind"`
	RefMutable  bool    `json:"ref_mutable"`
	ResolvedSHA *string `json:"resolved_sha"` // always emitted (null when unresolved): no omitempty
}

type CacheRef struct {
	KeyTemplate string `json:"key_template"`
	Scope       string `json:"scope"`
}

type ArtifactRef struct {
	Name *string `json:"name"`
}

// Field order mirrors the on-disk key order. Slice fields must be initialized
// non-nil by the normalizer so empties serialize as "[]" (not null).
type Job struct {
	ID         string         `json:"_id"`
	Provenance *JobProvenance `json:"_provenance"`
	Repo       string         `json:"repo"`

	Branch          string `json:"branch"`
	IsDefaultBranch bool   `json:"is_default_branch"`

	WorkflowName     string `json:"workflow_name"`
	WorkflowFilename string `json:"workflow_filename"`
	JobID            string `json:"job_id"`

	Triggers            []string                 `json:"triggers"`
	TriggerFilters      map[string]TriggerFilter `json:"trigger_filters"`
	TriggerClassSummary TriggerClassSummary      `json:"trigger_class_summary"`

	AttackerContextFieldsReferenced        []string `json:"attacker_context_fields_referenced"`
	AttackerContextFieldsReferencedExec    []string `json:"attacker_context_fields_referenced_exec"`
	AttackerContextFieldsReferencedBinding []string `json:"attacker_context_fields_referenced_binding"`

	NeedsOutputRefsExec    []NeedsOutputRef `json:"needs_output_refs_exec"`
	NeedsOutputRefsBinding []NeedsOutputRef `json:"needs_output_refs_binding"`
	NeedsOutputRefs        []NeedsOutputRef `json:"needs_output_refs"`

	RunsOn       []string `json:"runs_on"`
	SelfHosted   bool     `json:"self_hosted"`
	RunnerLabels []string `json:"runner_labels"`
	RunnerGroup  *string  `json:"runner_group"`

	Steps   []Step      `json:"steps"`
	Outputs []JobOutput `json:"outputs"`

	ExecutesCheckedOutCode bool     `json:"executes_checked_out_code"`
	HasCheckoutOfPRRef     bool     `json:"has_checkout_of_pr_ref"`
	Sinks                  []string `json:"sinks"`

	// map[string]any (not a struct) to round-trip the variable {_source, _chain, +winning-layer scopes} key set.
	Permissions map[string]any `json:"permissions"`

	ReadsAnySecret    bool        `json:"reads_any_secret"`
	SecretsReferenced []SecretRef `json:"secrets_referenced"`

	IfConditionsSummary GateClassification `json:"if_conditions_summary"`

	Environment                  *EnvironmentRef `json:"environment"`
	EnvironmentChosenDynamically bool            `json:"environment_chosen_dynamically"`

	InlinedFrom any `json:"_inlined_from"` // always null: recursive inlining not implemented

	CallsReusableWorkflows    []ReusableCall      `json:"calls_reusable_workflows"`
	LocalCompositeActionsUsed []LocalCompositeRef `json:"local_composite_actions_used"`

	MintsIDToken    bool    `json:"mints_id_token"`
	OIDCAudience    *string `json:"oidc_audience"`     // always null
	OIDCSubTemplate *string `json:"oidc_sub_template"` // "repo:<owner>/<repo>:ref:<ref>" when minting

	CacheWrites    []CacheRef    `json:"cache_writes"`
	CacheReads     []CacheRef    `json:"cache_reads"`
	ArtifactWrites []ArtifactRef `json:"artifact_writes"`
	ArtifactReads  []ArtifactRef `json:"artifact_reads"`

	// Agent surface inlined flat to match the on-disk schema.
	AgentActionClass        *string  `json:"agent_action_class"`
	AgentToolsEnabled       []string `json:"agent_tools_enabled"`
	AgentPromptSources      []string `json:"agent_prompt_sources"`
	AgentOutputChannels     []string `json:"agent_output_channels"`
	AgentMCPServers         []string `json:"agent_mcp_servers"`
	AgentBypassPermissions  bool     `json:"agent_bypass_permissions"`
	AgentAllowlistWildcards []string `json:"agent_allowlist_wildcards"`
	AgentActorAllowlistRaw  *string  `json:"agent_actor_allowlist_raw"`

	ActionRefs []ActionRef `json:"action_refs"`
}
