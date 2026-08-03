package attack

import (
	"cmp"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v4"

	attackplans "github.com/praetorian-inc/trajan/internal/attack-plans"
)

const APIVersion = "trajan.attack/v1"

type Plan struct {
	APIVersion string               `yaml:"apiVersion"`
	ID         string               `yaml:"id"`
	Title      string               `yaml:"title"`
	Scope      []string             `yaml:"scope"`
	Orgs       []string             `yaml:"orgs"`
	Identity   string               `yaml:"identity"`
	Identities []IdentitySpec       `yaml:"identities"`
	Collector  string               `yaml:"collector"`
	Rule       string               `yaml:"rule"`
	Encryption string               `yaml:"encryption"`
	Inputs     map[string]InputSpec `yaml:"inputs"`
	Steps      []Step               `yaml:"steps"`
	Cleanup    []Step               `yaml:"cleanup"`

	// Operator-supplied input overrides, highest precedence first: SetValues
	// (--set) beat SetFileValues (--set-file) beat an input's default. Populated
	// by the CLI before Validate; Validate resolves and type-checks them.
	SetValues     map[string]string
	SetFileValues map[string]any

	// Source is the file path or template id the plan was loaded from, for
	// diagnostics only.
	Source string

	resolvedInputs map[string]any
}

type IdentitySpec struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"`
	From string `yaml:"from"`
}

type InputSpec struct {
	Type     string `yaml:"type"`
	Required bool   `yaml:"required"`
	Default  any    `yaml:"default"`
	Doc      string `yaml:"doc"`
}

// Step is flat: id + uses + as/when + the primitive's own input keys. Keys holds
// everything the registry disambiguates into ports and fields. quoted records
// which scalars were YAML-quoted, by path, so the resolver can honour
// quote-to-force-literal at every depth: a bare word that names a step or input
// is a reference, but the same spelling quoted is the literal string, inside a
// files: map or a params: object as much as at the top level.
type Step struct {
	ID   string
	Uses string
	As   string
	When string
	Keys map[string]any

	quoted map[string]bool
	// isCleanup marks a step of the cleanup: block, which is exempt from the
	// transitive dependent-skip a false when: causes. An undo step gated on a
	// predecessor that skipped is exactly the step that must still run.
	isCleanup bool
}

func (s *Step) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("step must be a mapping")
	}
	s.Keys = map[string]any{}
	s.quoted = map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		var decoded any
		if err := val.Decode(&decoded); err != nil {
			return err
		}
		switch key {
		case "id":
			s.ID = asString(decoded)
		case "uses":
			s.Uses = asString(decoded)
		case "as":
			s.As = asString(decoded)
		case "when":
			s.When = asString(decoded)
		default:
			s.Keys[key] = decoded
			markQuoted(s.quoted, key, val)
		}
	}
	return nil
}

// markQuoted records quoted scalars by the path the resolver reads them back
// under: "params.marker" for a mapping value, "labels.0" for a sequence element.
func markQuoted(into map[string]bool, path string, node *yaml.Node) {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0 {
			into[path] = true
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			markQuoted(into, path+"."+node.Content[i].Value, node.Content[i+1])
		}
	case yaml.SequenceNode:
		for i, item := range node.Content {
			markQuoted(into, fmt.Sprintf("%s.%d", path, i), item)
		}
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// LoadPlan reads a plan from a file path, or, when no such file exists, from the
// embedded template corpus by id.
func LoadPlan(ref string) (*Plan, error) {
	if data, err := os.ReadFile(ref); err == nil {
		p, perr := parsePlan(data)
		if perr != nil {
			return nil, perr
		}
		p.Source = ref
		if p.ID == "" {
			p.ID = strings.TrimSuffix(filepath.Base(ref), filepath.Ext(ref))
		}
		return p, nil
	}
	return LoadTemplate(ref)
}

// A template id is its path under attack-plans without the .yaml extension,
// e.g. "github/pwn-request".
func LoadTemplate(id string) (*Plan, error) {
	data, err := attackplans.FS.ReadFile(id + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("no plan file and no template %q", id)
	}
	p, perr := parsePlan(data)
	if perr != nil {
		return nil, perr
	}
	p.Source = id
	if p.ID == "" {
		p.ID = id
	}
	return p, nil
}

func parsePlan(data []byte) (*Plan, error) {
	var p Plan
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse plan: %w", err)
	}
	for i := range p.Cleanup {
		p.Cleanup[i].isCleanup = true
	}
	return &p, nil
}

// LoadValues reads a --set-file document: a flat mapping of input name to value.
func LoadValues(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vals map[string]any
	if err := yaml.Unmarshal(data, &vals); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return vals, nil
}

func ListTemplates() ([]string, error) {
	var ids []string
	err := fs.WalkDir(attackplans.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		ids = append(ids, strings.TrimSuffix(path, ".yaml"))
		return nil
	})
	return ids, err
}

// collector resolves the plan's collector: through the same one-namespace rule a
// step field uses — a bare word naming a declared input is that input's value,
// anything else is the literal.
func (p *Plan) collector() string {
	if v, ok := p.resolvedInputs[p.Collector]; ok {
		return asString(v)
	}
	return p.Collector
}

// resolveInputs applies the --set › --set-file › default precedence and coerces
// each value to its declared type. A required input with no value and a value
// that fails its type both accumulate as errors.
func (p *Plan) resolveInputs() []error {
	p.resolvedInputs = map[string]any{}
	var errs []error
	for name, spec := range p.Inputs {
		typ := cmp.Or(spec.Type, "string")
		switch {
		case hasKey(p.SetValues, name):
			v, err := coerce(name, typ, p.SetValues[name])
			if err != nil {
				errs = append(errs, err)
				continue
			}
			p.resolvedInputs[name] = v
		case hasKey(p.SetFileValues, name):
			v, err := coerceAny(name, typ, p.SetFileValues[name])
			if err != nil {
				errs = append(errs, err)
				continue
			}
			p.resolvedInputs[name] = v
		case spec.Default != nil:
			v, err := coerceAny(name, typ, spec.Default)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			p.resolvedInputs[name] = v
		case spec.Required:
			errs = append(errs, fmt.Errorf("input %q is required and has no default; pass --set or --set-file", name))
		}
	}
	return errs
}

func coerce(name, typ, raw string) (any, error) {
	switch typ {
	case "string":
		return raw, nil
	case "int":
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, inputTypeErr(name, typ, raw)
		}
		return n, nil
	case "bool":
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, inputTypeErr(name, typ, raw)
		}
		return b, nil
	case "duration":
		if _, err := time.ParseDuration(raw); err != nil {
			return nil, inputTypeErr(name, typ, raw)
		}
		return raw, nil
	case "list":
		parts := strings.Split(raw, ",")
		out := make([]any, 0, len(parts))
		for _, s := range parts {
			out = append(out, strings.TrimSpace(s))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("input %q: unknown type %q", name, typ)
	}
}

// coerceAny validates an already-decoded value (from --set-file or a default)
// against a declared type.
func coerceAny(name, typ string, v any) (any, error) {
	switch typ {
	case "string", "duration":
		s, ok := v.(string)
		if !ok {
			return nil, inputTypeErr(name, typ, v)
		}
		if typ == "duration" {
			if _, err := time.ParseDuration(s); err != nil {
				return nil, inputTypeErr(name, typ, v)
			}
		}
		return s, nil
	case "int":
		switch n := v.(type) {
		case int:
			return n, nil
		case int64:
			return int(n), nil
		case float64:
			return int(n), nil
		default:
			return nil, inputTypeErr(name, typ, v)
		}
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return nil, inputTypeErr(name, typ, v)
		}
		return b, nil
	case "list":
		if l, ok := v.([]any); ok {
			return l, nil
		}
		return nil, inputTypeErr(name, typ, v)
	default:
		return nil, fmt.Errorf("input %q: unknown type %q", name, typ)
	}
}

func inputTypeErr(name, typ string, v any) error {
	return fmt.Errorf("input %q: want %s, got %q", name, typ, fmt.Sprintf("%v", v))
}

func hasKey[V any](m map[string]V, k string) bool {
	_, ok := m[k]
	return ok
}
