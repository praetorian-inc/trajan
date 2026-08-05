// Package payload loads and renders the embedded job-template corpus. A
// fragment is data — an id, a flavor, a typed parameter schema, an optional
// include list and a body — rendered by text/template with << >> delimiters so a
// CI platform's own ${{ }} expressions pass through verbatim.
package payload

import (
	"fmt"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	yaml "go.yaml.in/yaml/v4"

	attackpayloads "github.com/praetorian-inc/trajan/internal/attack-payloads"
)

// MaxIncludeDepth caps composition. It is also what makes an include cycle a
// bounded error rather than a hang.
const MaxIncludeDepth = 3

// Flavor is the rendering context a fragment is written for. It is fixed by the
// primitive that attaches the fragment, never declared by the plan author:
// ${{ secrets.X }} is evaluated only inside workflow YAML, so a secret-capture
// fragment rendered into a checked-out shell file is inert text.
type Flavor string

const (
	Shell         Flavor = "shell"
	WorkflowSteps Flavor = "workflow_steps"
)

type Param struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Required bool   `yaml:"required"`
	Default  any    `yaml:"default"`
	Doc      string `yaml:"doc"`
}

// Permission is a scope the fragment's steps need in whatever job runs them, at
// the level they need it. when narrows the requirement to the parameter values that
// reach the step needing it, so a fragment whose roles touch different surfaces does
// not force a scope on the role that touches none.
type Permission struct {
	Scope string            `yaml:"scope"`
	Level string            `yaml:"level"`
	When  map[string]string `yaml:"when"`
}

type Fragment struct {
	ID          string       `yaml:"id"`
	Summary     string       `yaml:"summary"`
	Flavor      Flavor       `yaml:"flavor"`
	Params      []Param      `yaml:"params"`
	Permissions []Permission `yaml:"permissions"`
	Includes    []string     `yaml:"includes"`
	Body        string       `yaml:"body"`

	File string `yaml:"-"`
}

var corpus = sync.OnceValues(load)

func load() (map[string]Fragment, error) {
	out := map[string]Fragment{}
	var paths []string
	err := fs.WalkDir(attackpayloads.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)

	for _, p := range paths {
		b, err := attackpayloads.FS.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var f Fragment
		if err := yaml.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("bad payload yaml %s: %w", p, err)
		}
		if f.ID == "" {
			return nil, fmt.Errorf("%s: fragment declares no id", p)
		}
		if prior, dup := out[f.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate fragment id %q (also in %s)", p, f.ID, prior.File)
		}
		if f.Flavor != Shell && f.Flavor != WorkflowSteps {
			return nil, fmt.Errorf("%s: flavor must be %s or %s, got %q", p, Shell, WorkflowSteps, f.Flavor)
		}
		for _, prm := range f.Params {
			if _, known := paramTypes[prm.Type]; !known {
				return nil, fmt.Errorf("%s: param %q declares type %q; the vocabulary is string, bool, int, []string, file", p, prm.Name, prm.Type)
			}
		}
		for _, perm := range f.Permissions {
			if perm.Scope == "" {
				return nil, fmt.Errorf("%s: a permissions entry declares no scope", p)
			}
			if perm.Level != "read" && perm.Level != "write" {
				return nil, fmt.Errorf("%s: permissions[%s] declares level %q; a requirement is read or write", p, perm.Scope, perm.Level)
			}
			// A when key that names no param never matches, so the scope would be
			// silently dropped rather than reported as needed.
			for _, k := range slices.Sorted(maps.Keys(perm.When)) {
				if !slices.ContainsFunc(f.Params, func(prm Param) bool { return prm.Name == k }) {
					return nil, fmt.Errorf("%s: permissions[%s] is conditioned on %q, which is not a param this fragment declares", p, perm.Scope, k)
				}
			}
		}
		f.File = p
		out[f.ID] = f
	}
	return out, nil
}

func Get(id string) (Fragment, error) {
	all, err := corpus()
	if err != nil {
		return Fragment{}, err
	}
	f, ok := all[id]
	if !ok {
		return Fragment{}, fmt.Errorf("no payload fragment %q%s", id, nearest(all, id))
	}
	return f, nil
}

func IDs() []string {
	all, err := corpus()
	if err != nil {
		return nil
	}
	return slices.Sorted(maps.Keys(all))
}

// RequiredPermissions is the scopes the fragment's steps need in the job that will
// run them, given the parameters it will render with. A requirement conditioned on a
// value only the run can resolve is left out here and caught by the composing
// primitive, which screens the resolved parameters through this same function before
// it commits anything.
func RequiredPermissions(id string, params map[string]any) ([]Permission, error) {
	root, err := Get(id)
	if err != nil {
		return nil, err
	}
	var out []Permission
	seen := map[string]bool{}

	var walk func(f Fragment, depth int) error
	walk = func(f Fragment, depth int) error {
		if seen[f.ID] || depth > MaxIncludeDepth {
			return nil
		}
		seen[f.ID] = true
		for _, perm := range f.Permissions {
			if conditionHolds(f, perm.When, params) {
				out = append(out, perm)
			}
		}
		for _, inc := range f.Includes {
			sub, err := Get(inc)
			if err != nil {
				return fmt.Errorf("payload %q: %w", f.ID, err)
			}
			if err := walk(sub, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return out, nil
}

func conditionHolds(f Fragment, when map[string]string, params map[string]any) bool {
	for _, k := range slices.Sorted(maps.Keys(when)) {
		v, supplied := params[k]
		if !supplied || v == nil {
			v = paramDefault(f, k)
		}
		if v == nil || unresolved(v) || scalarString(v) != when[k] {
			return false
		}
	}
	return true
}

func paramDefault(f Fragment, name string) any {
	for _, p := range f.Params {
		if p.Name == name {
			return p.Default
		}
	}
	return nil
}

// Unresolved stands in for a value only the run can know — a field read from a
// prior step's handle, or an interpolation over one. Validate counts it as
// supplied and leaves its content to the render pass, which sees the value the
// chain actually produced.
type Unresolved struct{}

func unresolved(v any) bool {
	switch t := v.(type) {
	case Unresolved:
		return true
	case []any:
		return slices.ContainsFunc(t, unresolved)
	}
	return false
}

// Validate is the static half: the fragment exists, its flavor matches the
// primitive attaching it, its include graph is within depth and of one flavor,
// every required parameter is supplied, no supplied key is unknown to the whole
// composition, and every value the caller could resolve offline coerces and
// quotes for the flavor it will render into. It issues no request and writes
// nothing, so the whole composition is checked at once and a value only the run
// can produce is checked for presence alone.
func Validate(id string, want Flavor, params map[string]any) []error {
	root, err := Get(id)
	if err != nil {
		return []error{err}
	}

	var errs []error
	if root.Flavor != want {
		errs = append(errs, fmt.Errorf("payload %q is %s-flavored but this step renders %s fragments", id, root.Flavor, want))
	}
	declared := map[string]bool{}
	seen := map[string]bool{}

	var walk func(f Fragment, depth int)
	walk = func(f Fragment, depth int) {
		if seen[f.ID] {
			return
		}
		seen[f.ID] = true
		for _, p := range f.Params {
			declared[p.Name] = true
			v, supplied := params[p.Name]
			if !supplied || v == nil {
				if p.Required && p.Default == nil {
					errs = append(errs, fmt.Errorf("payload %q requires param %q", f.ID, p.Name))
					continue
				}
				v = p.Default
			}
			if v == nil || unresolved(v) {
				continue
			}
			if _, err := coerce(p, v, f.Flavor); err != nil {
				errs = append(errs, fmt.Errorf("payload %q param %q: %w", f.ID, p.Name, err))
			}
		}
		if depth == MaxIncludeDepth && len(f.Includes) > 0 {
			errs = append(errs, fmt.Errorf("payload %q: includes nest deeper than %d", f.ID, MaxIncludeDepth))
			return
		}
		for _, inc := range f.Includes {
			sub, err := Get(inc)
			if err != nil {
				errs = append(errs, fmt.Errorf("payload %q: %w", f.ID, err))
				continue
			}
			if sub.Flavor != f.Flavor {
				errs = append(errs, fmt.Errorf("payload %q includes %q, which is %s-flavored", f.ID, inc, sub.Flavor))
				continue
			}
			walk(sub, depth+1)
		}
	}
	walk(root, 0)

	return append(errs, unknownParams(id, declared, params)...)
}

func unknownParams(id string, declared map[string]bool, params map[string]any) []error {
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(params)) {
		if !declared[k] {
			errs = append(errs, fmt.Errorf("payload %q has no param %q (has: %s)", id, k, strings.Join(slices.Sorted(maps.Keys(declared)), ", ")))
		}
	}
	return errs
}

// secretNamesParam interpolates into ${{ secrets.X }} and into an env: key, so it
// is held to what Actions accepts as a name on top of the screen every list
// element passes. A name outside it is a workflow that fails at startup on the
// customer's repository: a failed run in their audit trail that produces no
// evidence. The shell flavor screens its own names at runtime because indirect
// expansion is otherwise an injection vector; the workflow flavor cannot screen
// anything, so the screen is here, for both flavors, with nothing exempted from
// it, and before any request is issued.
const secretNamesParam = "secret_names"

var secretNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func checkSecretNames(p Param, v any) error {
	if p.Name != secretNamesParam {
		return nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil // a value that is not a list at all is asList's to report
	}
	for _, it := range items {
		s := scalarString(it)
		if !secretNameRe.MatchString(s) {
			return fmt.Errorf("secret name %q must match %s", s, secretNameRe)
		}
	}
	return nil
}

func nearest(all map[string]Fragment, id string) string {
	family, _, _ := strings.Cut(id, "/")
	var near []string
	for known := range all {
		if kf, _, _ := strings.Cut(known, "/"); kf == family {
			near = append(near, known)
		}
	}
	if len(near) == 0 {
		return ""
	}
	slices.Sort(near)
	return " (in " + family + ": " + strings.Join(near, ", ") + ")"
}
