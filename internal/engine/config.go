package engine

import "github.com/praetorian-inc/trajan/internal/ui"

type RuleScope int

const (
	RuleScopeAll RuleScope = iota
	RuleScopeHierarchy
	RuleScopeRepository
)

const HierarchyScopeSkip = "hierarchy rule scope"

type Config struct {
	Concurrency int
	OutputDir   string
	Dev         bool

	Token       string
	BearerToken string

	BaseURL  string
	Insecure bool

	UI ui.Sink

	Invocation        []string
	DefaultBranchOnly bool
	ForceREST         bool
	RuleScope         RuleScope
}

func (c *Config) Sink() ui.Sink {
	if c == nil || c.UI == nil {
		return ui.Discard
	}
	return c.UI
}
