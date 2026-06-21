package gates

import (
	"github.com/praetorian-inc/trajan/pkg/analysis/flow"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// Detector identifies soft gates that reduce exploitability
type Detector struct {
	patterns []GatePattern
}

// NewDetector creates a detector with standard patterns
func NewDetector() *Detector {
	return &Detector{
		patterns: StandardPatterns(),
	}
}

// DetectGates finds all gates in the path to an injectable node
func (d *Detector) DetectGates(g *graph.Graph, path []string) []flow.GateInfo {
	var gates []flow.GateInfo

	for _, nodeID := range path {
		node, ok := g.GetNode(nodeID)
		if !ok {
			continue
		}

		for _, pattern := range d.patterns {
			if pattern.Match(node) {
				gates = append(gates, flow.GateInfo{
					Type:        pattern.Type,
					Location:    nodeID,
					Description: pattern.Description,
					Confidence:  flow.ConfidenceHigh, // High confidence in gate detection
				})
			}
		}
	}

	return gates
}

// HasBlockingGate checks if any of the gates are blocking
func (d *Detector) HasBlockingGate(gates []flow.GateInfo) bool {
	for _, gate := range gates {
		if IsBlockingGate(gate.Type) {
			return true
		}
	}
	return false
}

// HasSoftGate checks if any of the gates are soft gates
func (d *Detector) HasSoftGate(gates []flow.GateInfo) bool {
	for _, gate := range gates {
		if IsSoftGate(gate.Type) {
			return true
		}
	}
	return false
}

// CalculateConfidence determines finding confidence based on gates
// This adjusts the base confidence level based on detected gates
func (d *Detector) CalculateConfidence(baseConfidence flow.Confidence, gates []flow.GateInfo) flow.Confidence {
	conf := baseConfidence

	// Blocking gates should have already filtered out findings
	// but if we still have them, set confidence to low
	if d.HasBlockingGate(gates) {
		return flow.ConfidenceLow
	}

	// Count soft gates
	softCount := 0
	for _, gate := range gates {
		if IsSoftGate(gate.Type) {
			softCount++
		}
	}
	// Each soft gate reduces confidence by one level
	for i := 0; i < softCount && conf > flow.ConfidenceLow; i++ {
		switch conf {
		case flow.ConfidenceHigh:
			conf = flow.ConfidenceMedium
		case flow.ConfidenceMedium:
			conf = flow.ConfidenceLow
		}
	}

	return conf
}
