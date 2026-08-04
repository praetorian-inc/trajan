package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

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
	return match.DefaultParameters()
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
