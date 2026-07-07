package github

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"

	yaml "go.yaml.in/yaml/v4"
)

//go:embed sinks.yaml
var sinksYAML []byte

type sinkEntry struct {
	Name                   string `yaml:"name"`
	Match                  string `yaml:"match"`
	Pattern                string `yaml:"pattern"`
	ExecutesCheckedOutCode bool   `yaml:"executes_checked_out_code"`
	compiled               *regexp.Regexp
}

var loadSinks = sync.OnceValue(func() []sinkEntry {
	var doc struct {
		Sinks []sinkEntry `yaml:"sinks"`
	}
	if err := yaml.Unmarshal(sinksYAML, &doc); err != nil {
		panic(fmt.Errorf("parse sinks.yaml: %w", err))
	}
	for i := range doc.Sinks {
		if strings.HasSuffix(doc.Sinks[i].Match, "regex") {
			doc.Sinks[i].compiled = regexp.MustCompile(doc.Sinks[i].Pattern)
		}
	}
	return doc.Sinks
})

func classifyStep(step Step) StepClassifiers {
	out := StepClassifiers{}

	if step.Uses != nil && strings.HasPrefix(*step.Uses, "actions/checkout") {
		out.IsCheckout = true
		if ref := withString(step.With, "ref"); ref != "" {
			out.CheckoutRefField = &ref
		}
		if repo := withString(step.With, "repository"); repo != "" {
			out.CheckoutRepositoryField = &repo
		}
	}

	for _, sink := range loadSinks() {
		switch sink.Match {
		case "run_regex":
			if step.Run != nil && sink.compiled.MatchString(*step.Run) {
				name := sink.Name
				out.SinkClass = &name
				out.ExecutesCheckedOutCode = sink.ExecutesCheckedOutCode
				return out
			}
		case "uses_prefix":
			if step.Uses != nil && strings.HasPrefix(*step.Uses, sink.Pattern) {
				name := sink.Name
				out.SinkClass = &name
				out.ExecutesCheckedOutCode = sink.ExecutesCheckedOutCode
				return out
			}
		case "uses_regex":
			if step.Uses != nil && sink.compiled.MatchString(*step.Uses) {
				name := sink.Name
				out.SinkClass = &name
				out.ExecutesCheckedOutCode = sink.ExecutesCheckedOutCode
				return out
			}
		}
	}

	return out
}

func withString(with map[string]any, key string) string {
	v, _ := with[key].(string)
	return v
}

var checkoutRefNeedles = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.head_ref",
	"github.event.workflow_run.head_sha",
	"github.event.workflow_run.head_branch",
	"github.event.issue.pull_request",
}

var checkoutRepoNeedles = []string{
	"github.event.pull_request.head.repo",
	"github.event.workflow_run.head_repository",
}

func hasCheckoutOfPRRef(checkoutRefField, checkoutRepositoryField *string) bool {
	if checkoutRefField != nil {
		for _, n := range checkoutRefNeedles {
			if strings.Contains(*checkoutRefField, n) {
				return true
			}
		}
	}
	if checkoutRepositoryField != nil {
		for _, n := range checkoutRepoNeedles {
			if strings.Contains(*checkoutRepositoryField, n) {
				return true
			}
		}
	}
	return false
}
