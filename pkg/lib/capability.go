package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/match"
)

// Triage status strings matching the Chariot platform conventions.
const (
	TriageHigh   = "TH"
	TriageMedium = "TM"
	TriageLow    = "TL"
	TriageInfo   = "TI"
)

// DetectPlatform delegates to match.DetectPlatform for backward compatibility.
var DetectPlatform = match.DetectPlatform

// SDKCapability implements capability.Capability[capmodel.Repository] for
// the Trajan CI/CD security scanner.
type SDKCapability struct{}

// compile-time interface check
var _ capability.Capability[capmodel.Repository] = (*SDKCapability)(nil)

// NewSDKCapability returns a new SDKCapability instance.
func NewSDKCapability() *SDKCapability { return &SDKCapability{} }

func (c *SDKCapability) Name() string { return "trajan" }
func (c *SDKCapability) Description() string {
	return "scans CI/CD pipelines for security vulnerabilities including injection, supply chain, and permission misconfigurations"
}
func (c *SDKCapability) Input() any { return capmodel.Repository{} }

func (c *SDKCapability) Parameters() []capability.Parameter {
	params := match.DefaultParameters()
	return append(params,
		capability.Bool("active_mode", "Enable active attack execution (disabled by default)").
			WithDefault("false"),
		capability.Parameter{
			Name:        "attack_plugins",
			Description: "Attack plugins to execute",
			Type:        "[]string",
			Options:     registry.ListAttackPlugins(),
		},
		capability.Bool("dry_run", "Simulate attacks without making changes").
			WithDefault("true"),
		capability.Int("attack_timeout", "Timeout in seconds for attack execution").
			WithDefault("300"),
		capability.String("c2_repo", "C2 repository for interactive shell and runner-on-runner attacks (e.g., owner/repo)"),
		capability.String("target_os", "Target runner OS for runner-on-runner attacks").
			WithOptions("linux", "win", "macos"),
		capability.String("target_arch", "Target runner architecture for runner-on-runner attacks").
			WithOptions("x64", "arm64"),
		capability.String("runner_labels", "Comma-separated runner labels for targeting specific runners"),
		capability.String("delivery", "Delivery method for AI prompt injection attacks").
			WithOptions("pr", "issue", "comment"),
		capability.String("persistence_method", "Persistence method for persistence attacks").
			WithOptions("workflow", "action", "package"),
	)
}

func (c *SDKCapability) Match(ctx capability.ExecutionContext, input capmodel.Repository) error {
	return match.Repository(ctx, input)
}

// InvokeScanFunc is the function used by Invoke to perform the actual scan.
// Override in tests to avoid real API calls.
var InvokeScanFunc = defaultInvokeScan

func defaultInvokeScan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	return Scan(ctx, cfg)
}

// InvokeAttackFunc is the function used by Invoke to perform attack execution.
// Override in tests to avoid real API calls.
var InvokeAttackFunc = defaultInvokeAttack

func defaultInvokeAttack(ctx context.Context, cfg AttackConfig) (*AttackResult, error) {
	return Attack(ctx, cfg)
}

func (c *SDKCapability) Invoke(ctx capability.ExecutionContext, input capmodel.Repository, output capability.Emitter) error {
	platformName, _ := match.DetectPlatform(input.URL)
	if p, ok := ctx.Parameters.GetString("platform"); ok && p != "" {
		platformName = p
	}

	if platformName == "circleci" {
		slog.Warn("trajan: CircleCI adapter is a stub; skipping scan",
			"repo", input.URL)
		return nil
	}

	token, _ := ctx.Parameters.GetString("token")
	baseURL := ""
	if b, ok := ctx.Parameters.GetString("base_url"); ok {
		baseURL = b
	}

	result, err := InvokeScanFunc(context.Background(), ScanConfig{
		Platform:    platformName,
		Token:       token,
		BaseURL:     baseURL,
		Org:         input.Org,
		Repo:        input.Name,
		Concurrency: 10,
	})
	if err != nil {
		return fmt.Errorf("trajan scan %s/%s on %s: %w", input.Org, input.Name, platformName, err)
	}

	// Log non-fatal scan errors as warnings
	for _, scanErr := range result.Errors {
		slog.Warn("trajan: scan warning", "error", scanErr, "repo", input.URL)
	}

	// Emit discovered workflows as assets
	for _, wf := range result.Workflows {
		if err := output.Emit(capmodel.Asset{
			DNS:  input.URL,
			Name: wf.Path,
		}); err != nil {
			return err
		}
	}

	// Emit findings as risks
	for _, finding := range result.Findings {
		proof := BuildFindingProof(finding)
		status := SeverityToStatus(finding.Severity)
		riskName := fmt.Sprintf("cicd-%s", finding.Type)

		if err := output.Emit(capmodel.Risk{
			Name:       riskName,
			Status:     status,
			Target:     input,
			TargetName: input.URL,
			Source:     "trajan",
			Proof:      proof,
		}); err != nil {
			return err
		}
	}

	// Active attack execution (opt-in, disabled by default)
	activeMode, _ := ctx.Parameters.GetBool("active_mode")
	if !activeMode {
		return nil
	}

	pluginsStr, _ := ctx.Parameters.GetString("attack_plugins")
	if pluginsStr == "" {
		slog.Warn("trajan: active_mode enabled but no plugins specified", "repo", input.URL)
		return nil
	}

	dryRun, _ := ctx.Parameters.GetBool("dry_run")
	timeoutSec, _ := ctx.Parameters.GetInt("attack_timeout")
	if timeoutSec <= 0 {
		timeoutSec = 300
	}

	plugins := strings.Split(pluginsStr, ",")
	for i := range plugins {
		plugins[i] = strings.TrimSpace(plugins[i])
	}

	// Collect plugin-specific options
	extraOpts := make(map[string]string)
	pluginOptKeys := []string{"c2_repo", "target_os", "target_arch", "runner_labels", "delivery", "persistence_method"}
	for _, key := range pluginOptKeys {
		if v, ok := ctx.Parameters.GetString(key); ok && v != "" {
			extraOpts[key] = v
		}
	}
	// Map persistence_method to the "method" key expected by the persistence plugin
	if v, ok := extraOpts["persistence_method"]; ok {
		extraOpts["method"] = v
		delete(extraOpts, "persistence_method")
	}

	attackResult, err := InvokeAttackFunc(context.Background(), AttackConfig{
		Platform:  platformName,
		Token:     token,
		BaseURL:   baseURL,
		Org:       input.Org,
		Repo:      input.Name,
		Plugins:   plugins,
		DryRun:    dryRun,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		ExtraOpts: extraOpts,
	})
	if err != nil {
		return fmt.Errorf("trajan attack %s/%s: %w", input.Org, input.Name, err)
	}

	for _, attackErr := range attackResult.Errors {
		slog.Warn("trajan: attack warning", "error", attackErr, "repo", input.URL)
	}

	successCount := 0
	for _, ar := range attackResult.Results {
		if !ar.Success {
			continue
		}
		successCount++
		riskName := fmt.Sprintf("cicd-attack-%s", ar.Plugin)
		proof, _ := json.MarshalIndent(ar, "", "  ")
		if err := output.Emit(capmodel.Risk{
			Name:       riskName,
			Status:     TriageHigh,
			Target:     input,
			TargetName: input.URL,
			Source:     "trajan",
			Proof:      proof,
		}); err != nil {
			return err
		}
	}

	if len(attackResult.Errors) > 0 && successCount == 0 {
		errMsgs := make([]string, len(attackResult.Errors))
		for i, e := range attackResult.Errors {
			errMsgs[i] = e.Error()
		}
		return fmt.Errorf("trajan: all attack plugins failed: %s", strings.Join(errMsgs, "; "))
	}

	return nil
}

// SeverityToStatus maps Trajan severity levels to Chariot triage statuses.
func SeverityToStatus(severity detections.Severity) string {
	switch severity {
	case detections.SeverityCritical, detections.SeverityHigh:
		return TriageHigh
	case detections.SeverityMedium:
		return TriageMedium
	case detections.SeverityLow:
		return TriageLow
	default:
		return TriageInfo
	}
}

// findingProof is the JSON structure stored in Risk.Proof.
type findingProof struct {
	Type         string `json:"type"`
	Severity     string `json:"severity"`
	Confidence   string `json:"confidence"`
	Complexity   string `json:"complexity,omitempty"`
	Platform     string `json:"platform"`
	Class        string `json:"class"`
	Repository   string `json:"repository"`
	Workflow     string `json:"workflow"`
	WorkflowFile string `json:"workflow_file,omitempty"`
	Job          string `json:"job,omitempty"`
	Step         string `json:"step,omitempty"`
	Line         int    `json:"line,omitempty"`
	Trigger      string `json:"trigger,omitempty"`
	Evidence     string `json:"evidence"`
	Remediation  string `json:"remediation,omitempty"`
}

// BuildFindingProof creates a JSON proof blob from a Trajan detection finding.
func BuildFindingProof(f detections.Finding) []byte {
	p := findingProof{
		Type:         string(f.Type),
		Severity:     string(f.Severity),
		Confidence:   string(f.Confidence),
		Complexity:   string(f.Complexity),
		Platform:     f.Platform,
		Class:        string(f.Class),
		Repository:   f.Repository,
		Workflow:     f.Workflow,
		WorkflowFile: f.WorkflowFile,
		Job:          f.Job,
		Step:         f.Step,
		Line:         f.Line,
		Trigger:      f.Trigger,
		Evidence:     f.Evidence,
		Remediation:  f.Remediation,
	}
	data, _ := json.MarshalIndent(p, "", "  ")
	return data
}
