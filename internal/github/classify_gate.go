package github

import (
	"regexp"
	"strings"
)

var (
	gateLabelContainsRe = regexp.MustCompile(`contains\s*\(\s*github\.event\.pull_request\.labels`)
	gateLabelNameRe     = regexp.MustCompile(`github\.event\.label\.name`)
	gateLabelIndexRe    = regexp.MustCompile(`github\.event\.pull_request\.labels\[`)
	gateActorEqRe       = regexp.MustCompile(`github\.actor\s*==\s*['"][^'"]+['"]`)
	gateFromJSONRe      = regexp.MustCompile(`contains\s*\(\s*fromJSON\s*\(`)
)

func classifyGate(ifExpr *string) GateClassification {
	out := GateClassification{Raw: ifExpr, GateStrength: "none"}
	if ifExpr == nil || *ifExpr == "" {
		return out
	}

	expr := strings.TrimSpace(*ifExpr)
	lc := strings.ToLower(expr)
	if lc == "true" || lc == "${{ true }}" {
		return out
	}

	switch {
	case strings.Contains(lc, "workflow_run.conclusion") ||
		strings.Contains(lc, "github.event.workflow_run.conclusion"):
		out.GateStrength = "pseudo"
		out.GateClassifiers.IsPseudoGateConclusion = true
	case gateLabelContainsRe.MatchString(lc) ||
		gateLabelNameRe.MatchString(lc) ||
		gateLabelIndexRe.MatchString(lc):
		out.GateStrength = "weak"
		out.GateClassifiers.IsLabelGate = true
	case strings.Contains(lc, "author_association"):
		out.GateStrength = "weak"
		out.GateClassifiers.IsAuthorAssocGate = true
	case gateActorEqRe.MatchString(expr) ||
		gateFromJSONRe.MatchString(expr) ||
		strings.Contains(expr, "github.repository_owner =="):
		out.GateStrength = "strong"
	default:
		out.GateStrength = "weak"
	}
	return out
}
