package engine

import "github.com/praetorian-inc/trajan/internal/ui"

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
}

func (c *Config) Sink() ui.Sink {
	if c == nil || c.UI == nil {
		return ui.Discard
	}
	return c.UI
}
