package github

import (
	"regexp"
	"slices"
	"strings"
)

type CodeownersRule struct {
	Pattern string   `json:"pattern"`
	Owners  []string `json:"owners"`
}

type CodeownersFact struct {
	Present bool             `json:"present"`
	Path    any              `json:"path"`
	Rules   []CodeownersRule `json:"rules"`

	// covers_ci_execution is true only when every probe in ciExecutionProbes
	// resolves to an owner. The probes are representative locations whose
	// content a workflow executes, not an inventory of the repository, so a
	// false here means "CODEOWNERS leaves these locations unowned", never
	// "an executed file is provably unowned".
	CoversWorkflows   bool     `json:"covers_workflows"`
	CoversCIExecution bool     `json:"covers_ci_execution"`
	UncoveredCIPaths  []string `json:"uncovered_ci_paths"`
}

// Owning the workflow file gates which steps run; owning these gates what those
// steps execute, which is the same trust boundary reached one level down.
var ciExecutionProbes = []string{
	".github/workflows/ci.yml",
	".github/actions/build/action.yml",
	"action.yml",
	"scripts/build.sh",
	"Makefile",
}

const workflowProbe = ".github/workflows/ci.yml"

// parseCodeowners returns nil when the repository bundle predates CODEOWNERS
// collection: an absent record must not read as an uncovered one.
func parseCodeowners(v any) *CodeownersFact {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil
	}
	content, present := m["content"].(string)
	out := &CodeownersFact{
		Present:          present,
		Path:             m["path"],
		Rules:            codeownersRules(content),
		UncoveredCIPaths: []string{},
	}
	for _, probe := range ciExecutionProbes {
		if len(codeownersOwners(out.Rules, probe)) == 0 {
			out.UncoveredCIPaths = append(out.UncoveredCIPaths, probe)
		}
	}
	out.CoversCIExecution = len(out.UncoveredCIPaths) == 0
	out.CoversWorkflows = !slices.Contains(out.UncoveredCIPaths, workflowProbe)
	return out
}

func codeownersRules(content string) []CodeownersRule {
	out := []CodeownersRule{}
	for _, line := range strings.Split(content, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out = append(out, CodeownersRule{Pattern: fields[0], Owners: fields[1:]})
	}
	return out
}

// GitHub applies the LAST matching rule, so a later ownerless pattern removes
// ownership a broader earlier one granted.
func codeownersOwners(rules []CodeownersRule, path string) []string {
	var owners []string
	for _, r := range rules {
		if re := codeownersPattern(r.Pattern); re != nil && re.MatchString(path) {
			owners = r.Owners
		}
	}
	return owners
}

// gitignore semantics: a pattern containing a slash anywhere but the end is
// anchored to the repository root, one without matches at any depth, and a
// pattern naming a directory owns everything below it.
func codeownersPattern(pattern string) *regexp.Regexp {
	body := strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/")
	if body == "" {
		return nil
	}
	var b strings.Builder
	b.WriteString("^")
	if !strings.HasPrefix(pattern, "/") && !strings.Contains(body, "/") {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(body); {
		switch {
		case strings.HasPrefix(body[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 3
		case strings.HasPrefix(body[i:], "**"):
			b.WriteString(".*")
			i += 2
		case body[i] == '*':
			b.WriteString("[^/]*")
			i++
		case body[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(body[i : i+1]))
			i++
		}
	}
	switch {
	case strings.HasSuffix(pattern, "/"):
		b.WriteString("/.*")
	case strings.HasSuffix(body, "*"), strings.HasSuffix(body, "?"):
		// GitHub departs from gitignore here: "docs/* will match docs/getting-started.md
		// but not further nested files like docs/build-app/troubleshooting.md".
	default:
		b.WriteString("(?:/.*)?")
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}
