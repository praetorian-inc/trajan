package resource

type FindingRef struct {
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
}

type Resource struct {
	Provider  string         `json:"provider"`
	Type      string         `json:"type"`
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	URL       string         `json:"url,omitempty"`
	Hierarchy []string       `json:"hierarchy"`
	Props     map[string]any `json:"props"`
	Findings  []FindingRef   `json:"findings"`
}

type Relationship struct {
	Provider string         `json:"provider"`
	Type     string         `json:"type"`
	From     string         `json:"from"`
	To       string         `json:"to"`
	Props    map[string]any `json:"props"`
	Findings []FindingRef   `json:"findings"`
}
