package chain

import (
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/github"
)

// ChainContext holds typed state passed between plugins in a chain
type ChainContext struct {
	// C2 Repository (set by c2-setup or runner-on-runner)
	C2Repo    string // e.g., "owner/trajan-c2-abc123"
	C2RepoURL string // e.g., "https://github.com/owner/trajan-c2-abc123"

	// Runner Information (set by runner-on-runner)
	Runners []github.Runner

	// Attack Artifacts (accumulated across plugins)
	Artifacts []attacks.Artifact
	GistID    string
	ForkRepo  string
	PRNumber  int

	// Configuration propagated through chain
	TargetOS   string
	TargetArch string
	Labels     []string
	KeepAlive  bool

	// Internal tracking
	executedPlugins []string
	cleanupActions  []attacks.CleanupAction
}

// NewChainContext creates a new context from attack options
func NewChainContext(opts attacks.AttackOptions) *ChainContext {
	ctx := &ChainContext{
		TargetOS:   getOrDefault(opts.ExtraOpts, "target_os", "linux"),
		TargetArch: getOrDefault(opts.ExtraOpts, "target_arch", "x64"),
		KeepAlive:  opts.ExtraOpts["keep_alive"] == "true",
		Artifacts:  make([]attacks.Artifact, 0),
		Labels:     make([]string, 0),
	}

	// Parse labels
	if labels, ok := opts.ExtraOpts["runner_labels"]; ok && labels != "" {
		// Split by comma
		for i, j := 0, 0; j <= len(labels); j++ {
			if j == len(labels) || labels[j] == ',' {
				if j > i {
					ctx.Labels = append(ctx.Labels, labels[i:j])
				}
				i = j + 1
			}
		}
	}
	if len(ctx.Labels) == 0 {
		ctx.Labels = []string{"self-hosted"}
	}

	// Check if C2 repo already provided
	if c2, ok := opts.ExtraOpts["c2_repo"]; ok && c2 != "" {
		ctx.C2Repo = c2
	}

	return ctx
}

// Set stores a typed value in context
func (c *ChainContext) Set(key attacks.ContextKey, value interface{}) {
	switch key {
	case attacks.C2RepoKey:
		if v, ok := value.(string); ok {
			c.C2Repo = v
		}
	case attacks.C2URLKey:
		if v, ok := value.(string); ok {
			c.C2RepoURL = v
		}
	case attacks.RunnersKey:
		if v, ok := value.([]github.Runner); ok {
			c.Runners = v
		}
	case attacks.GistIDKey:
		if v, ok := value.(string); ok {
			c.GistID = v
		}
	case attacks.ForkRepoKey:
		if v, ok := value.(string); ok {
			c.ForkRepo = v
		}
	case attacks.PRNumberKey:
		if v, ok := value.(int); ok {
			c.PRNumber = v
		}
	}
}

// MarkExecuted records that a plugin has completed
func (c *ChainContext) MarkExecuted(pluginName string) {
	c.executedPlugins = append(c.executedPlugins, pluginName)
}

// AddCleanupAction queues a cleanup action for rollback
func (c *ChainContext) AddCleanupAction(action attacks.CleanupAction) {
	c.cleanupActions = append(c.cleanupActions, action)
}

// GetCleanupActions returns all cleanup actions in reverse order (LIFO)
func (c *ChainContext) GetCleanupActions() []attacks.CleanupAction {
	n := len(c.cleanupActions)
	reversed := make([]attacks.CleanupAction, n)
	for i, action := range c.cleanupActions {
		reversed[n-1-i] = action
	}
	return reversed
}

func getOrDefault(m map[string]string, key, defaultValue string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return defaultValue
}
