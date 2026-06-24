package github

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	detectionrules "github.com/praetorian-inc/trajan/internal/detection-rules"
	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/finding"
	yaml "go.yaml.in/yaml/v4"
)

// RuleSourceBase is the "<repo>/blob/<ref>" prefix that turns an embedded rule
// path into a browsable URL. Overridable at build time (-ldflags) to pin a
// release ref; set to "" to omit rule.url entirely. Adjust the repo/ref here
// once the rules' permanent home is settled.
var RuleSourceBase = "https://github.com/praetorian-inc/trajan/blob/main"

type Block struct {
	Predicate string
	AllOf     []Block
	AnyOf     []Block
	NoneOf    []Block
	IsCombo   bool
}

func (b *Block) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		b.Predicate = node.Value
		return nil
	}
	var combo struct {
		AllOf  []Block `yaml:"all_of"`
		AnyOf  []Block `yaml:"any_of"`
		NoneOf []Block `yaml:"none_of"`
	}
	if err := node.Decode(&combo); err != nil {
		return err
	}
	b.AllOf, b.AnyOf, b.NoneOf, b.IsCombo = combo.AllOf, combo.AnyOf, combo.NoneOf, true
	return nil
}

// MarshalJSON mirrors UnmarshalYAML so a Block round-trips into the finding's
// rule.dsl as authored: a scalar predicate becomes a bare string, a combo
// becomes {all_of|any_of|none_of}. Value receiver so non-pointer []Block
// elements serialize the same way.
func (b Block) MarshalJSON() ([]byte, error) {
	if !b.IsCombo {
		return json.Marshal(b.Predicate)
	}
	combo := map[string]any{}
	if len(b.AllOf) > 0 {
		combo["all_of"] = b.AllOf
	}
	if len(b.AnyOf) > 0 {
		combo["any_of"] = b.AnyOf
	}
	if len(b.NoneOf) > 0 {
		combo["none_of"] = b.NoneOf
	}
	return json.Marshal(combo)
}

type ChainOf struct {
	Join    string `yaml:"join" json:"join"`
	ForEach string `yaml:"for_each" json:"for_each,omitempty"`
	Where   *Block `yaml:"where" json:"where,omitempty"`
}

// RuleDSL is the matching logic carried in a finding's rule.dsl: the subject
// plus whichever of where/chain_of applies. No metadata (title/severity/...),
// which lives at the finding's top level.
type RuleDSL struct {
	Subject string   `json:"subject,omitempty"`
	Where   *Block   `json:"where,omitempty"`
	ChainOf *ChainOf `json:"chain_of,omitempty"`
}

type Rule struct {
	ID              string   `yaml:"id"`
	ScenarioID      string   `yaml:"scenario_id"`
	Title           string   `yaml:"title"`
	Subject         string   `yaml:"subject"`
	Severity        string   `yaml:"severity"`
	Confidence      string   `yaml:"confidence"`
	Description     string   `yaml:"description"`
	Where           *Block   `yaml:"where"`
	ChainOf         *ChainOf `yaml:"chain_of"`
	Evidence        []string `yaml:"evidence"`
	RemediationHint string   `yaml:"remediation_hint"`

	RuleFile string `yaml:"-"`
}

func (r *Rule) SubjectKind() string {
	if r.Subject == "chain" || r.ChainOf != nil {
		return "chain"
	}
	if r.Subject == "" {
		return "job"
	}
	return r.Subject
}

func LoadRules() ([]Rule, error) {
	var files []string
	err := fs.WalkDir(detectionrules.FS, "github", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(files)

	var rules []Rule
	for _, p := range files {
		b, err := detectionrules.FS.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("bad rule yaml %s: %w", p, err)
		}
		if r.ID == "" || (r.Where == nil && r.ChainOf == nil) {
			continue
		}
		r.RuleFile = p
		rules = append(rules, r)
	}
	return rules, nil
}

func EvaluateRule(rule *Rule, subjects []map[string]any, onError func(error)) []map[string]any {
	var matched []map[string]any
	for _, subj := range subjects {
		ok, err := evaluateBlock(rule.Where, subj)
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("%s subject=%v: %w", rule.ID, subj["_id"], err))
			}
			continue
		}
		if ok {
			matched = append(matched, subj)
		}
	}
	return matched
}

func EvaluateChainRule(rule *Rule, chainData map[string]any, onError func(error)) []map[string]any {
	chain := rule.ChainOf
	if chain == nil || chain.Join == "" {
		if onError != nil {
			onError(fmt.Errorf("%s: chain_of.join missing", rule.ID))
		}
		return nil
	}
	if chainData == nil {
		return nil
	}
	forEach := chain.ForEach
	if forEach == "" {
		forEach = "links"
	}
	items := iterChainItems(chainData, forEach)
	var matched []map[string]any
	for _, item := range items {
		ok, err := evaluateBlock(chain.Where, item)
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("%s chain-item: %w", rule.ID, err))
			}
			continue
		}
		if ok {
			matched = append(matched, item)
		}
	}
	return matched
}

func iterChainItems(chainData map[string]any, forEach string) []map[string]any {
	var cur any = chainData
	for _, part := range strings.Split(forEach, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	list, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func SubjectHash(subject map[string]any) string {
	sid := stringField(subject, "_id")
	if sid == "" {
		sid = stringField(subject, "repo")
	}
	if sid == "" {
		b, _ := json.Marshal(subject) // sorted map keys make the hash deterministic across runs
		sid = string(b)
		if len(sid) > 80 {
			sid = sid[:80]
		}
	}
	sum := sha256.Sum256([]byte(sid))
	return fmt.Sprintf("%x", sum)[:12]
}

// BuildFinding maps a matched subject into a canonical finding. org is the run's
// scope (threaded from scan); it backfills finding.Org for subjects that don't
// carry their own owner (job records don't), and is ignored when they do. runDir
// resolves the collected YAML for the code snippet; pass "" to skip it.
func BuildFinding(rule *Rule, subject map[string]any, kind, org, runDir string) finding.Finding {
	evidence := make([]string, 0, len(rule.Evidence))
	for _, tmpl := range rule.Evidence {
		evidence = append(evidence, renderEvidence(tmpl, subject))
	}

	if org == "" {
		org = cmp.Or(stringField(subject, "org"), stringField(subject, "owner"))
	}

	var remediation *finding.Remediation
	if rule.RemediationHint != "" {
		remediation = &finding.Remediation{Hint: rule.RemediationHint, References: []string{}}
	}

	f := finding.Finding{
		Producer:    "scan",
		Provider:    "github",
		Title:       rule.Title,
		Description: rule.Description,
		Severity:    cmp.Or(rule.Severity, "info"),
		Confidence:  cmp.Or(rule.Confidence, "low"),
		Rule: &finding.Rule{
			ID:         rule.ID,
			URL:        ruleURL(rule.RuleFile),
			ScenarioID: rule.ScenarioID,
			DSL:        buildRuleDSL(rule),
		},
		Subject:     finding.Subject{Kind: kind, ID: stringField(subject, "_id"), Display: subjectDisplay(kind, subject)},
		Org:         org,
		Repo:        stringField(subject, "repo"),
		File:        stringField(subject, "workflow_name"),
		Code:        buildCode(runDir, subject),
		Evidence:    evidence,
		Remediation: remediation,
		Provenance:  buildProvenance(rule, subject),
		MatchedAt:   engine.IsoformatUTC(time.Now()),
	}
	f.Fingerprint = finding.Fingerprint(f)
	return f
}

func buildRuleDSL(rule *Rule) any {
	dsl := RuleDSL{Subject: rule.Subject}
	if rule.ChainOf != nil {
		dsl.ChainOf = rule.ChainOf
	} else {
		dsl.Where = rule.Where
	}
	return dsl
}

func ruleURL(ruleFile string) string {
	if RuleSourceBase == "" || ruleFile == "" {
		return ""
	}
	return RuleSourceBase + "/internal/detection-rules/" + ruleFile
}

// subjectDisplay is a pre-rendered label so the renderer never parses subject.id.
func subjectDisplay(kind string, subject map[string]any) string {
	if kind == "job" {
		var parts []string
		for _, k := range []string{"repo", "workflow_filename", "job_id"} {
			if v := stringField(subject, k); v != "" {
				parts = append(parts, v)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, " › ")
		}
	}
	return stringField(subject, "_id")
}

// buildProvenance carries the structured values that back the rendered evidence
// — the subject fields the evidence templates referenced — plus a pointer to the
// collected input(s) the subject came from. The raw template lives in the rule
// (rule.url), so it isn't repeated here.
func buildProvenance(rule *Rule, subject map[string]any) map[string]any {
	prov := map[string]any{}
	for _, tmpl := range rule.Evidence {
		for _, ref := range evidenceRefs(tmpl) {
			if strings.HasPrefix(ref, "_provenance") {
				continue // the collected-input pointer is added explicitly below
			}
			if v := getPath(subject, ref); v != nil {
				prov[ref] = v
			}
		}
	}
	switch p := subject["_provenance"].(type) {
	case map[string]any:
		for k, v := range p {
			prov["collect."+k] = v
		}
	case []any:
		var files []any
		for _, it := range p {
			if m, ok := it.(map[string]any); ok {
				if file, ok := m["file"]; ok {
					files = append(files, file)
				}
			}
		}
		if len(files) > 0 {
			prov["collect.inputs"] = files
		}
	}
	if len(prov) == 0 {
		return nil
	}
	return prov
}

// buildCode embeds the exact YAML window the subject points at, read from the
// collected workflow, so the finding is self-contained. It is best-effort: a
// subject without a code location, or an unreadable file, yields nil (code stays
// null) — never a scan failure. code.sha (the commit) is left for a later
// collector change; the collector stores a blob hash today, which we never emit.
func buildCode(runDir string, subject map[string]any) *finding.Code {
	prov, ok := subject["_provenance"].(map[string]any)
	if !ok {
		return nil
	}
	wf := stringField(prov, "workflow_file")
	lr := intPair(prov["yaml_line_range"])
	if wf == "" || lr == nil || runDir == "" {
		return nil
	}
	snippet, err := readSnippet(filepath.Join(runDir, wf), lr[0], lr[1])
	if err != nil {
		return nil
	}
	return &finding.Code{LineRange: lr, Snippet: snippet}
}

func readSnippet(path string, start, end int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(b), "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return "", fmt.Errorf("invalid line range [%d,%d] for %s (%d lines)", start, end, path, len(lines))
	}
	return strings.Join(lines[start-1:end], "\n"), nil
}

// intPair coerces a [start,end] range from JSON (float64 elements) or native ints.
func intPair(v any) []int {
	list, ok := v.([]any)
	if !ok || len(list) != 2 {
		return nil
	}
	out := make([]int, 2)
	for i, e := range list {
		switch n := e.(type) {
		case float64:
			out[i] = int(n)
		case int:
			out[i] = n
		default:
			return nil
		}
	}
	return out
}

func stringField(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}
