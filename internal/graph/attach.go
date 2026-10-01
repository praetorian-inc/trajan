package graph

import (
	"slices"

	"github.com/praetorian-inc/trajan/pkg/finding"
)

const (
	ReasonNoTarget           = "no_target"
	ReasonNoSubjectDir       = "no_subject_dir"
	ReasonSubjectUnresolved  = "subject_unresolved"
	ReasonLabelMismatch      = "label_mismatch"
	ReasonNoProjection       = "no_projection"
	ReasonEndpointUnresolved = "endpoint_unresolved"
	ReasonNoFanoutValues     = "no_fanout_values"
)

type UnattachedFinding struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Target      string `json:"target"`
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	Reason      string `json:"reason"`
	Detail      string `json:"detail"`
}

type AttachResult struct {
	Total      int
	Attached   int
	ToNodes    int
	ToEdges    int
	ByReason   map[string]int
	ByRule     map[string]int
	ByTarget   map[string]int
	Unattached []UnattachedFinding
}

func NewAttachResult(reasons []string) *AttachResult {
	byReason := make(map[string]int, len(reasons))
	for _, r := range reasons {
		byReason[r] = 0
	}
	return &AttachResult{
		ByReason:   byReason,
		ByRule:     map[string]int{},
		ByTarget:   map[string]int{},
		Unattached: []UnattachedFinding{},
	}
}

func (r *AttachResult) Fail(f *finding.Finding, target Target, ruleID, reason, detail string) {
	r.ByReason[reason]++
	r.ByRule[ruleID]++
	r.ByTarget[RenderTarget(target)]++
	r.Unattached = append(r.Unattached, UnattachedFinding{
		Fingerprint: f.Fingerprint,
		RuleID:      ruleID,
		Target:      RenderTarget(target),
		SubjectKind: f.Subject.Kind,
		SubjectID:   f.Subject.ID,
		Reason:      reason,
		Detail:      detail,
	})
}

func AppendFinding(fs *[]FindingRef, ref FindingRef) bool {
	if slices.ContainsFunc(*fs, func(x FindingRef) bool { return x.Fingerprint == ref.Fingerprint }) {
		return false
	}
	*fs = append(*fs, ref)
	return true
}

func RuleID(f *finding.Finding) string {
	if f.Rule != nil {
		return f.Rule.ID
	}
	return ""
}
