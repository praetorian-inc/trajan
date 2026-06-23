package github

// JSON keys deliberately differ from the class strings ("low_trust" vs "low").
// Slices must stay non-nil so empties marshal as [] not null.
type TriggerClassSummary struct {
	LowTrust  []string `json:"low_trust"`
	Medium    []string `json:"medium"`
	HighTrust []string `json:"high_trust"`
}

type StepClassifiers struct {
	SinkClass               *string `json:"sink_class"`
	ExecutesCheckedOutCode  bool    `json:"executes_checked_out_code"`
	IsCheckout              bool    `json:"is_checkout"`
	CheckoutRefField        *string `json:"checkout_ref_field"`
	CheckoutRepositoryField *string `json:"checkout_repository_field"`
	DockerBuildWithLogin    bool    `json:"docker_build_with_login"` // never set true; kept for JSON-schema stability

}

// At most one flag is true: the branch that fired in classifyGate.
type GateClassifiers struct {
	IsPseudoGateConclusion bool `json:"is_pseudo_gate_conclusion"`
	IsLabelGate            bool `json:"is_label_gate"`
	IsAuthorAssocGate      bool `json:"is_author_assoc_gate"`
}

type GateClassification struct {
	Raw             *string         `json:"raw"`
	GateStrength    string          `json:"gate_strength"`
	GateClassifiers GateClassifiers `json:"gate_classifiers"`
}
