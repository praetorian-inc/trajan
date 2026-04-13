// Package detections provides vulnerability detection for CI/CD workflows
package detections

import "fmt"

// VulnerabilityType represents the type of CI/CD vulnerability
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

	// AI Prompt Injection vulnerabilities
	VulnAITokenExfiltration    VulnerabilityType = "ai_token_exfiltration"
	VulnAICodeInjection        VulnerabilityType = "ai_code_injection"
	VulnAIWorkflowSabotage     VulnerabilityType = "ai_workflow_sabotage"
	VulnAIMCPAbuse             VulnerabilityType = "ai_mcp_abuse"
	VulnAIPrivilegeEscalation  VulnerabilityType = "ai_privilege_escalation"
	VulnAISupplyChainPoisoning VulnerabilityType = "ai_supply_chain_poisoning"

	// New vulnerability types
	VulnSecretScopeRisk          VulnerabilityType = "secret_scope_risk"
	VulnEnvironmentBypass        VulnerabilityType = "environment_bypass"
	VulnCompositeActionRisk      VulnerabilityType = "composite_action_risk"
	VulnDynamicTemplateInjection VulnerabilityType = "dynamic_template_injection"
	VulnReusableWorkflowRisk     VulnerabilityType = "reusable_workflow_risk"

	// Jenkins-specific vulnerability types
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

// AIVulnTypes lists all AI-related vulnerability types.
// Used by attack plugins to determine if AI probing/exploitation should trigger.
var AIVulnTypes = []VulnerabilityType{
	VulnAITokenExfiltration,
	VulnAICodeInjection,
	VulnAIWorkflowSabotage,
	VulnAIMCPAbuse,
	VulnAIPrivilegeEscalation,
	VulnAISupplyChainPoisoning,
}

// VulnerabilityClass represents cross-platform vulnerability categories
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

// AllVulnerabilityTypes contains all vulnerability types for iteration
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

// PlatformVulnerabilityTypes maps each platform to its relevant vulnerability types.
// Platforms not listed here fall back to AllVulnerabilityTypes.
var PlatformVulnerabilityTypes = map[string][]VulnerabilityType{
	"azuredevops": {
		VulnScriptInjection,
		VulnTriggerExploitation,
		VulnServiceConnectionHijacking,
		VulnDynamicTemplateInjection,
		VulnExcessiveJobPermissions,
		VulnOverexposedServiceConnections,
		VulnSecretScopeRisk,
		VulnEnvironmentBypass,
		VulnSelfHostedAgent,
		VulnAITokenExfiltration,
		VulnAICodeInjection,
		VulnAIWorkflowSabotage,
		VulnAIMCPAbuse,
		VulnAIPrivilegeEscalation,
		VulnAISupplyChainPoisoning,
		VulnUnredactedSecrets,
		VulnTokenExposure,
		VulnPullRequestSecretsExposure,
	},
}

// VulnerabilityTypesForPlatform returns the relevant vulnerability types for a platform.
// Returns AllVulnerabilityTypes if the platform is empty or not in PlatformVulnerabilityTypes.
func VulnerabilityTypesForPlatform(platform string) []VulnerabilityType {
	if platform == "" {
		return AllVulnerabilityTypes
	}
	if types, ok := PlatformVulnerabilityTypes[platform]; ok {
		return types
	}
	return AllVulnerabilityTypes
}

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence represents how confident we are in the finding
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Complexity represents the attack complexity
type Complexity string

const (
	ComplexityZeroClick Complexity = "zero_click"
	ComplexityLow       Complexity = "low"
	ComplexityMedium    Complexity = "medium"
	ComplexityHigh      Complexity = "high"
)


// VulnerabilityClassMap maps vulnerability types to their cross-platform classes
var VulnerabilityClassMap = map[VulnerabilityType]VulnerabilityClass{
	VulnActionsInjection:            ClassInjection,
	VulnPwnRequest:                  ClassInjection,
	VulnReviewInjection:             ClassInjection,
	VulnTOCTOU:                      ClassRaceCondition,
	VulnArtifactPoison:              ClassSupplyChain,
	VulnCachePoisoning:              ClassSupplyChain,
	VulnSelfHostedRunner:            ClassRunnerSecurity,
	VulnSelfHostedAgent:             ClassRunnerSecurity,
	VulnUnpinnedAction:              ClassSupplyChain,
	VulnExcessivePermissions:        ClassPrivilegeEscalation,
	VulnIncludeInjection:            ClassSupplyChain,
	VulnMergeRequestUnsafeCheckout:  ClassRaceCondition,
	VulnMergeRequestSecretsExposure: ClassSecretsExposure,
	VulnPullRequestSecretsExposure:  ClassSecretsExposure,
	VulnTokenExposure:               ClassSecretsExposure,
	// Zizmor SecretsExposure
	VulnOverprovisionedSecrets:  ClassSecretsExposure,
	VulnHardcodedContainerCreds: ClassSecretsExposure,
	VulnArtipacked:              ClassSecretsExposure,
	VulnUnredactedSecrets:       ClassSecretsExposure,
	VulnSecretsInherit:          ClassSecretsExposure,
	// Zizmor Injection
	VulnGitHubEnv:        ClassInjection,
	VulnUnsoundContains:  ClassInjection,
	VulnUnsoundCondition: ClassInjection,
	VulnBotConditions:    ClassInjection,
	VulnInsecureCommands: ClassInjection,
	// Zizmor SupplyChain
	VulnKnownVulnerableActions: ClassSupplyChain,
	VulnImpostorCommit:         ClassSupplyChain,
	VulnRefVersionMismatch:     ClassSupplyChain,
	VulnRefConfusion:           ClassSupplyChain,
	VulnArchivedUses:           ClassSupplyChain,
	VulnUseTrustedPublishing:   ClassSupplyChain,
	VulnUnpinnedImages:         ClassSupplyChain,
	VulnStaleActionRefs:        ClassSupplyChain,
	VulnForbiddenUses:          ClassSupplyChain,
	// Zizmor PrivilegeEscalation
	VulnUndocumentedPermissions: ClassPrivilegeEscalation,
	// Zizmor Configuration
	VulnAnonymousDefinition:    ClassConfiguration,
	VulnObfuscation:            ClassConfiguration,
	VulnMisfeature:             ClassConfiguration,
	VulnConcurrencyLimits:      ClassConfiguration,
	VulnAITokenExfiltration:    ClassAIRisk,
	VulnAICodeInjection:        ClassAIRisk,
	VulnAIWorkflowSabotage:     ClassAIRisk,
	VulnAIMCPAbuse:             ClassAIRisk,
	VulnAIPrivilegeEscalation:  ClassAIRisk,
	VulnAISupplyChainPoisoning: ClassAIRisk,
	// New detection classes
	VulnSecretScopeRisk:          ClassSecretsExposure,
	VulnEnvironmentBypass:        ClassPrivilegeEscalation,
	VulnCompositeActionRisk:      ClassSupplyChain,
	VulnDynamicTemplateInjection: ClassSupplyChain,
	VulnReusableWorkflowRisk:     ClassSupplyChain,
	// Jenkins-specific detection classes
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
	return ClassInjection // default
}

// Finding represents a detected CI/CD security vulnerability
type Finding struct {
	Type            VulnerabilityType  `json:"type"`
	Severity        Severity           `json:"severity"`
	Confidence      Confidence         `json:"confidence"`
	Complexity      Complexity         `json:"complexity,omitempty"`
	Platform        string             `json:"platform"` // github, gitlab, bitbucket, azure
	Class           VulnerabilityClass `json:"class"`    // Cross-platform category
	Repository      string             `json:"repository"`
	Workflow        string             `json:"workflow"`
	WorkflowFile    string             `json:"workflow_file,omitempty"` // File path (e.g., .github/workflows/ci.yml)
	Job             string             `json:"job,omitempty"`
	Step            string             `json:"step,omitempty"`
	Line            int                `json:"line,omitempty"`
	Trigger         string             `json:"trigger,omitempty"`
	Evidence        string             `json:"evidence"`
	Remediation     string             `json:"remediation,omitempty"`
	Path            []string           `json:"path,omitempty"`
	WorkflowContent string             `json:"workflow_content,omitempty"` // Full workflow YAML for code viewer
	// NEW: Optional detailed evidence (nil if not collected)
	Details *FindingDetails `json:"details,omitempty"`
}

// FindingDetails contains optional detailed evidence for a finding.
// Populated when --detailed flag is used or for web UI display.
type FindingDetails struct {
	// LineRanges specifies which lines to highlight (all detections should provide)
	LineRanges []LineRange `json:"line_ranges,omitempty"`

	// AttackChain shows the attack path (for complex detections like pwn-request, injection)
	AttackChain []ChainNode `json:"attack_chain,omitempty"`

	// InjectableContexts lists user-controllable context variables (for injection detections)
	InjectableContexts []string `json:"injectable_contexts,omitempty"`

	// CheckoutRef shows the vulnerable git reference (for pwn-request, toctou)
	CheckoutRef string `json:"checkout_ref,omitempty"`

	// Permissions lists relevant permissions (for permission-related detections)
	Permissions []string `json:"permissions,omitempty"`

	// Metadata allows detection-specific data without schema changes
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// LineRange represents a range of lines to highlight in the source code.
type LineRange struct {
	Start int    `json:"start"`           // 1-indexed line number
	End   int    `json:"end"`             // 1-indexed line number (inclusive)
	Label string `json:"label,omitempty"` // e.g., "vulnerable step", "injection point"
}

// ChainNode represents a node in an attack chain path.
type ChainNode struct {
	NodeType    string `json:"type"`           // "trigger", "job", "step"
	Name        string `json:"name"`           // e.g., "pull_request_target", "build"
	Line        int    `json:"line,omitempty"` // Line number in workflow file
	IfCondition string `json:"if,omitempty"`   // Conditional expression if present
}

// FindingHasType checks if any finding matches the given type.
func FindingHasType(findings []Finding, vulnType VulnerabilityType) bool {
	for _, f := range findings {
		if f.Type == vulnType {
			return true
		}
	}
	return false
}

// String returns a human-readable representation of the finding
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s in %s:%s (severity=%s, confidence=%s)",
		f.Type, f.Workflow, f.Repository, f.Job, f.Severity, f.Confidence)
}
