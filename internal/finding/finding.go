// Package finding defines the canonical, provider-independent finding record.
// Every producer (scan now; analyze/agent later) emits this shape, and the
// report renderer consumes only this — it never imports a platform package.
package finding

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// Finding is one self-contained result. A consumer holding a single record —
// no rule files, no run dir — can render and transport it.
type Finding struct {
	FindingID   string `json:"finding_id,omitempty"` // run-local F-NNN; assigned by report at output
	Fingerprint string `json:"fingerprint"`          // stable content hash; computed by the producer
	Producer    string `json:"producer"`             // scan | analyze | agent
	Provider    string `json:"provider"`             // github | gitlab | ado | jenkins

	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity"`   // critical | high | medium | low | info
	Confidence  string `json:"confidence"` // high | medium | low

	Rule    *Rule   `json:"rule"` // null for pure-AI findings (no DSL)
	Subject Subject `json:"subject"`

	Org  string `json:"org,omitempty"` // optional scope handles; absent (not null) when N/A
	Repo string `json:"repo,omitempty"`
	File string `json:"file,omitempty"`

	Code *Code `json:"code"` // nullable; present only when File is a resolved code location

	Evidence    []string       `json:"evidence"` // rendered "why it matched" sentences
	Remediation *Remediation   `json:"remediation,omitempty"`
	Provenance  map[string]any `json:"provenance,omitempty"` // structured backing values + entity handles

	AINotes   *AINotes `json:"ai_notes"`   // null for scan; filled by analyze/agent
	MatchedAt string   `json:"matched_at"` // excluded from fingerprint
}

type Rule struct {
	ID         string `json:"id"`
	URL        string `json:"url,omitempty"` // GitHub deep-link; empty in local/unreleased builds
	ScenarioID string `json:"scenario_id,omitempty"`
	DSL        any    `json:"dsl,omitempty"` // matching logic only (subject + where/chain_of)
}

type Subject struct {
	Kind    string `json:"kind"`              // open string: job, org, repo, environment, chain, ...
	ID      string `json:"id"`                // native id
	Display string `json:"display,omitempty"` // pre-rendered label; renderer never parses ID
}

type Code struct {
	SHA       string `json:"sha,omitempty"` // COMMIT sha when identified; never a blob hash
	LineRange []int  `json:"line_range,omitempty"`
	Snippet   string `json:"snippet"`
}

type Remediation struct {
	Hint       string   `json:"hint,omitempty"`
	References []string `json:"references"`
}

type AINotes struct {
	Text              string `json:"text"`
	Model             string `json:"model,omitempty"`
	GeneratedAt       string `json:"generated_at,omitempty"`
	RevisedSeverity   string `json:"revised_severity,omitempty"`
	RevisedConfidence string `json:"revised_confidence,omitempty"`
	Rationale         string `json:"rationale,omitempty"`
}

// Fingerprint is sha256 over the record minus the non-deterministic fields
// (fingerprint, finding_id, matched_at, ai_notes), hex, first 16 chars. The
// marshal→generic→marshal round-trip canonicalizes the JSON: map keys sort
// recursively and number/whitespace formatting is normalized, so two
// structurally identical findings hash equal regardless of field order or
// source value types.
func Fingerprint(f Finding) string {
	f.Fingerprint = ""
	f.FindingID = ""
	f.MatchedAt = ""
	f.AINotes = nil

	b, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return ""
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum)[:16]
}

var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
var confidenceRank = map[string]int{"high": 3, "medium": 2, "low": 1}

// SeverityRank / ConfidenceRank return 0 for an unknown level so it sorts below
// every known one and is filtered out by any non-zero threshold.
func SeverityRank(s string) int   { return severityRank[s] }
func ConfidenceRank(c string) int { return confidenceRank[c] }
