// Package detections provides vulnerability detection for CI/CD workflows
package detections

import "fmt"

type VulnerabilityType string

const (
	VulnActionsInjection            VulnerabilityType = "actions_injection"
	VulnPwnRequest                  VulnerabilityType = "pwn_request"
	VulnReviewInjection             VulnerabilityType = "review_injection"
	VulnTOCTOU                      VulnerabilityType = "toctou"
	VulnArtifactPoison              VulnerabilityType = "artifact_poisoning"
	VulnCachePoisoning              VulnerabilityType = "cache_poisoning"
	VulnSelfHostedRunner            VulnerabilityType = "self_hosted_runner"
	VulnSelfHostedAgent             VulnerabilityType = "self_hosted_agent"
	VulnUnpinnedAction              VulnerabilityType = "unpinned_action"
	VulnExcessivePermissions        VulnerabilityType = "excessive_permissions"
	VulnIncludeInjection            VulnerabilityType = "include_injection"
	VulnMergeRequestUnsafeCheckout  VulnerabilityType = "merge_request_unsafe_checkout"
	VulnMergeRequestSecretsExposure VulnerabilityType = "merge_request_secrets_exposure"
	VulnPullRequestSecretsExposure  VulnerabilityType = "pull_request_secrets_exposure"
	VulnTokenExposure               VulnerabilityType = "token_exposure"

	// Zizmor-inspired detections
	VulnOverprovisionedSecrets  VulnerabilityType = "overprovisioned_secrets"
	VulnGitHubEnv               VulnerabilityType = "github_env"
	VulnHardcodedContainerCreds VulnerabilityType = "hardcoded_container_credentials"
	VulnArtipacked              VulnerabilityType = "artipacked"
	VulnKnownVulnerableActions  VulnerabilityType = "known_vulnerable_actions"
	VulnImpostorCommit          VulnerabilityType = "impostor_commit"
	VulnUnsoundContains         VulnerabilityType = "unsound_contains"
	VulnUnsoundCondition        VulnerabilityType = "unsound_condition"
	VulnUnredactedSecrets       VulnerabilityType = "unredacted_secrets"
	VulnSecretsInherit          VulnerabilityType = "secrets_inherit"
	VulnRefVersionMismatch      VulnerabilityType = "ref_version_mismatch"
	VulnRefConfusion            VulnerabilityType = "ref_confusion"
	VulnBotConditions           VulnerabilityType = "bot_conditions"
	VulnArchivedUses            VulnerabilityType = "archived_uses"
	VulnAnonymousDefinition     VulnerabilityType = "anonymous_definition"
	VulnUseTrustedPublishing    VulnerabilityType = "use_trusted_publishing"
	VulnUnpinnedImages          VulnerabilityType = "unpinned_images"
	VulnUndocumentedPermissions VulnerabilityType = "undocumented_permissions"
	VulnStaleActionRefs         VulnerabilityType = "stale_action_refs"
	VulnObfuscation             VulnerabilityType = "obfuscation"
	VulnMisfeature              VulnerabilityType = "misfeature"
	VulnInsecureCommands        VulnerabilityType = "insecure_commands"
	VulnForbiddenUses           VulnerabilityType = "forbidden_uses"
	VulnConcurrencyLimits       VulnerabilityType = "concurrency_limits"

	VulnAITokenExfiltration    VulnerabilityType = "ai_token_exfiltration"
	VulnAICodeInjection        VulnerabilityType = "ai_code_injection"
	VulnAIWorkflowSabotage     VulnerabilityType = "ai_workflow_sabotage"
	VulnAIMCPAbuse             VulnerabilityType = "ai_mcp_abuse"
	VulnAIPrivilegeEscalation  VulnerabilityType = "ai_privilege_escalation"
	VulnAISupplyChainPoisoning VulnerabilityType = "ai_supply_chain_poisoning"

	VulnSecretScopeRisk          VulnerabilityType = "secret_scope_risk"
	VulnEnvironmentBypass        VulnerabilityType = "environment_bypass"
	VulnCompositeActionRisk      VulnerabilityType = "composite_action_risk"
	VulnDynamicTemplateInjection VulnerabilityType = "dynamic_template_injection"
	VulnReusableWorkflowRisk     VulnerabilityType = "reusable_workflow_risk"

	VulnJenkinsScriptConsole   VulnerabilityType = "jenkins_script_console"
	VulnJenkinsAnonymousAccess VulnerabilityType = "jenkins_anonymous_access"
	VulnJenkinsCSRFDisabled    VulnerabilityType = "jenkins_csrf_disabled"

	// ADO umbrella plugin vulnerability types
	VulnScriptInjection               VulnerabilityType = "script_injection"
	VulnTriggerExploitation           VulnerabilityType = "trigger_exploitation"
	VulnExcessiveJobPermissions       VulnerabilityType = "excessive_job_permissions"
	VulnServiceConnectionHijacking    VulnerabilityType = "service_connection_hijacking"
	VulnOverexposedServiceConnections VulnerabilityType = "overexposed_service_connections"
)

// Attack plugins gate AI probing on membership here.
var AIVulnTypes = []VulnerabilityType{
	VulnAITokenExfiltration,
	VulnAICodeInjection,
	VulnAIWorkflowSabotage,
	VulnAIMCPAbuse,
	VulnAIPrivilegeEscalation,
	VulnAISupplyChainPoisoning,
}

type VulnerabilityClass string

const (
	ClassSupplyChain         VulnerabilityClass = "supply_chain"
	ClassInjection           VulnerabilityClass = "injection"
	ClassPrivilegeEscalation VulnerabilityClass = "privilege_escalation"
	ClassSecretsExposure     VulnerabilityClass = "secrets_exposure"
	ClassRunnerSecurity      VulnerabilityClass = "runner_security"
	ClassRaceCondition       VulnerabilityClass = "race_condition"
	ClassConfiguration       VulnerabilityClass = "configuration"
	ClassAIRisk              VulnerabilityClass = "ai_risk"
)

var AllVulnerabilityTypes = []VulnerabilityType{
	VulnActionsInjection,
	VulnPwnRequest,
	VulnReviewInjection,
	VulnTOCTOU,
	VulnArtifactPoison,
	VulnCachePoisoning,
	VulnSelfHostedRunner,
	VulnSelfHostedAgent,
	VulnUnpinnedAction,
	VulnExcessivePermissions,
	VulnIncludeInjection,
	VulnMergeRequestUnsafeCheckout,
	VulnMergeRequestSecretsExposure,
	VulnPullRequestSecretsExposure,
	VulnTokenExposure,
	VulnOverprovisionedSecrets,
	VulnGitHubEnv,
	VulnHardcodedContainerCreds,
	VulnArtipacked,
	VulnKnownVulnerableActions,
	VulnImpostorCommit,
	VulnUnsoundContains,
	VulnUnsoundCondition,
	VulnUnredactedSecrets,
	VulnSecretsInherit,
	VulnRefVersionMismatch,
	VulnRefConfusion,
	VulnBotConditions,
	VulnArchivedUses,
	VulnAnonymousDefinition,
	VulnUseTrustedPublishing,
	VulnUnpinnedImages,
	VulnUndocumentedPermissions,
	VulnStaleActionRefs,
	VulnObfuscation,
	VulnMisfeature,
	VulnInsecureCommands,
	VulnForbiddenUses,
	VulnConcurrencyLimits,
	VulnAITokenExfiltration,
	VulnAICodeInjection,
	VulnAIWorkflowSabotage,
	VulnAIMCPAbuse,
	VulnAIPrivilegeEscalation,
	VulnAISupplyChainPoisoning,
	VulnSecretScopeRisk,
	VulnEnvironmentBypass,
	VulnCompositeActionRisk,
	VulnDynamicTemplateInjection,
	VulnReusableWorkflowRisk,
	VulnJenkinsScriptConsole,
	VulnJenkinsAnonymousAccess,
	VulnJenkinsCSRFDisabled,
	VulnScriptInjection,
	VulnTriggerExploitation,
	VulnExcessiveJobPermissions,
	VulnServiceConnectionHijacking,
	VulnOverexposedServiceConnections,
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Complexity string

const (
	ComplexityZeroClick Complexity = "zero_click"
	ComplexityLow       Complexity = "low"
	ComplexityMedium    Complexity = "medium"
	ComplexityHigh      Complexity = "high"
)

var VulnerabilityClassMap = map[VulnerabilityType]VulnerabilityClass{
	VulnActionsInjection:              ClassInjection,
	VulnPwnRequest:                    ClassInjection,
	VulnReviewInjection:               ClassInjection,
	VulnTOCTOU:                        ClassRaceCondition,
	VulnArtifactPoison:                ClassSupplyChain,
	VulnCachePoisoning:                ClassSupplyChain,
	VulnSelfHostedRunner:              ClassRunnerSecurity,
	VulnSelfHostedAgent:               ClassRunnerSecurity,
	VulnUnpinnedAction:                ClassSupplyChain,
	VulnExcessivePermissions:          ClassPrivilegeEscalation,
	VulnIncludeInjection:              ClassSupplyChain,
	VulnMergeRequestUnsafeCheckout:    ClassRaceCondition,
	VulnMergeRequestSecretsExposure:   ClassSecretsExposure,
	VulnPullRequestSecretsExposure:    ClassSecretsExposure,
	VulnTokenExposure:                 ClassSecretsExposure,
	VulnOverprovisionedSecrets:        ClassSecretsExposure,
	VulnHardcodedContainerCreds:       ClassSecretsExposure,
	VulnArtipacked:                    ClassSecretsExposure,
	VulnUnredactedSecrets:             ClassSecretsExposure,
	VulnSecretsInherit:                ClassSecretsExposure,
	VulnGitHubEnv:                     ClassInjection,
	VulnUnsoundContains:               ClassInjection,
	VulnUnsoundCondition:              ClassInjection,
	VulnBotConditions:                 ClassInjection,
	VulnInsecureCommands:              ClassInjection,
	VulnKnownVulnerableActions:        ClassSupplyChain,
	VulnImpostorCommit:                ClassSupplyChain,
	VulnRefVersionMismatch:            ClassSupplyChain,
	VulnRefConfusion:                  ClassSupplyChain,
	VulnArchivedUses:                  ClassSupplyChain,
	VulnUseTrustedPublishing:          ClassSupplyChain,
	VulnUnpinnedImages:                ClassSupplyChain,
	VulnStaleActionRefs:               ClassSupplyChain,
	VulnForbiddenUses:                 ClassSupplyChain,
	VulnUndocumentedPermissions:       ClassPrivilegeEscalation,
	VulnAnonymousDefinition:           ClassConfiguration,
	VulnObfuscation:                   ClassConfiguration,
	VulnMisfeature:                    ClassConfiguration,
	VulnConcurrencyLimits:             ClassConfiguration,
	VulnAITokenExfiltration:           ClassAIRisk,
	VulnAICodeInjection:               ClassAIRisk,
	VulnAIWorkflowSabotage:            ClassAIRisk,
	VulnAIMCPAbuse:                    ClassAIRisk,
	VulnAIPrivilegeEscalation:         ClassAIRisk,
	VulnAISupplyChainPoisoning:        ClassAIRisk,
	VulnSecretScopeRisk:               ClassSecretsExposure,
	VulnEnvironmentBypass:             ClassPrivilegeEscalation,
	VulnCompositeActionRisk:           ClassSupplyChain,
	VulnDynamicTemplateInjection:      ClassSupplyChain,
	VulnReusableWorkflowRisk:          ClassSupplyChain,
	VulnJenkinsScriptConsole:          ClassConfiguration,
	VulnJenkinsAnonymousAccess:        ClassConfiguration,
	VulnJenkinsCSRFDisabled:           ClassConfiguration,
	VulnScriptInjection:               ClassInjection,
	VulnTriggerExploitation:           ClassInjection,
	VulnExcessiveJobPermissions:       ClassPrivilegeEscalation,
	VulnServiceConnectionHijacking:    ClassInjection,
	VulnOverexposedServiceConnections: ClassPrivilegeEscalation,
}

// GetVulnerabilityClass returns the class for a vulnerability type
func GetVulnerabilityClass(vt VulnerabilityType) VulnerabilityClass {
	if class, ok := VulnerabilityClassMap[vt]; ok {
		return class
	}
	return ClassInjection
}

type Finding struct {
	Type            VulnerabilityType  `json:"type"`
	Severity        Severity           `json:"severity"`
	Confidence      Confidence         `json:"confidence"`
	Complexity      Complexity         `json:"complexity,omitempty"`
	Platform        string             `json:"platform"` // github, gitlab, bitbucket, azure
	Class           VulnerabilityClass `json:"class"`
	Repository      string             `json:"repository"`
	Workflow        string             `json:"workflow"`
	WorkflowFile    string             `json:"workflow_file,omitempty"` // Path; Workflow above is the display name.
	Job             string             `json:"job,omitempty"`
	Step            string             `json:"step,omitempty"`
	Line            int                `json:"line,omitempty"`
	Trigger         string             `json:"trigger,omitempty"`
	Evidence        string             `json:"evidence"`
	Remediation     string             `json:"remediation,omitempty"`
	Path            []string           `json:"path,omitempty"`
	WorkflowContent string             `json:"workflow_content,omitempty"`
	// Nil unless detailed evidence was collected.
	Details *FindingDetails `json:"details,omitempty"`
}

// Populated only with --detailed, or for web UI display.
type FindingDetails struct {
	// Every detection is expected to populate this.
	LineRanges []LineRange `json:"line_ranges,omitempty"`

	AttackChain []ChainNode `json:"attack_chain,omitempty"`

	// User-controllable context variables reaching the sink.
	InjectableContexts []string `json:"injectable_contexts,omitempty"`

	CheckoutRef string `json:"checkout_ref,omitempty"`

	Permissions []string `json:"permissions,omitempty"`

	// Metadata allows detection-specific data without schema changes
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type LineRange struct {
	Start int    `json:"start"` // 1-indexed
	End   int    `json:"end"`   // 1-indexed, inclusive
	Label string `json:"label,omitempty"`
}

type ChainNode struct {
	NodeType    string `json:"type"` // "trigger", "job", "step"
	Name        string `json:"name"`
	Line        int    `json:"line,omitempty"`
	IfCondition string `json:"if,omitempty"`
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s in %s:%s (severity=%s, confidence=%s)",
		f.Type, f.Workflow, f.Repository, f.Job, f.Severity, f.Confidence)
}
