package payload

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"unicode"
)

// Env carries the values the engine supplies to every fragment rather than the
// author. Both may be empty.
type Env struct {
	PubKey    string
	Collector string
}

// renderContext is a struct rather than a map so .PubKey and .Collector resolve
// even when the engine has nothing to put in them: a fragment that names one is
// asking for whatever the run configured, and no collector configured is a value
// the body decides about, not a render error. They are methods rather than fields
// so each is quoted where a body names it and not before — the public key is a PEM
// block, which no single-line quoting can hold, and a fragment that never names it
// must not fail to render because the run enabled encryption.
type renderContext struct {
	Params map[string]any
	flavor Flavor
	env    Env
}

func (c renderContext) PubKey() (any, error) { return quote(c.flavor, c.env.PubKey) }

func (c renderContext) Collector() (any, error) { return quote(c.flavor, c.env.Collector) }

// shellValue and yamlValue quote themselves when a template prints them but
// compare as their raw text, so `<< .Params.vector >>` is safely quoted while
// `<< if eq .Params.vector "build_script" >>` still matches.
type shellValue string

func (v shellValue) String() string {
	return "'" + strings.ReplaceAll(string(v), "'", `'\''`) + "'"
}

// yamlValue wraps and nothing more, because quote admits nothing that would need
// escaping. A workflow value is read twice over the same text — as a YAML scalar
// (`TRJ_X: << .Params.x >>`) and, inside a `run: |` block, as shell — and the two
// readings agree on exactly one representation: single quotes around one line
// carrying no quote of its own. YAML reads a doubled quote as one and the shell
// does not, so an escape correct for one reading corrupts the other.
type yamlValue string

func (v yamlValue) String() string { return "'" + string(v) + "'" }

// verbatim is the one shape quoteFor does not quote: the operator's file, whose
// content the param exists to carry and whose ${{ }} is the legitimate thing to
// put in it.
type verbatim string

// list carries the same trick one element down, in two directions. Printing the
// whole value emits shell-quoted, space-joined elements, because every position
// that takes a whole list is a shell word list — `for n in << .Params.x >>`,
// `keys=(<< .Params.x >>)`, both of them inside a `run:` block. Ranging over it
// yields each element raw, because an element lands inside
// `${{ secrets.<< $n >> }}` and inside a restore-keys: block, where a quote is
// fatal rather than merely ugly. Both positions appear in the corpus for the same
// param, so neither quoting can be what makes an element safe: that is asList's
// screen, and this quoting only keeps a screened element from word-splitting.
type list []string

func (l list) String() string {
	quoted := make([]string, len(l))
	for i, s := range l {
		quoted[i] = shellValue(s).String()
	}
	return strings.Join(quoted, " ")
}

// Render composes a fragment and its includes into the text a primitive commits.
// Every value a caller supplies is quoted for the fragment's flavor, or screened
// where its position cannot be quoted, or refused — so nothing a caller supplies
// can leave the position the author placed it in, and the only exception is the
// file param the operator supplies on purpose.
func Render(id string, params map[string]any, env Env) (string, error) {
	root, err := Get(id)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := render(&b, root, params, env, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

func render(b *strings.Builder, f Fragment, params map[string]any, env Env, depth int) error {
	if depth > MaxIncludeDepth {
		return fmt.Errorf("payload %q: includes nest deeper than %d", f.ID, MaxIncludeDepth)
	}
	bound, err := bind(f, params)
	if err != nil {
		return err
	}
	for _, inc := range f.Includes {
		sub, err := Get(inc)
		if err != nil {
			return fmt.Errorf("payload %q: %w", f.ID, err)
		}
		if sub.Flavor != f.Flavor {
			return fmt.Errorf("payload %q includes %q, which is %s-flavored", f.ID, inc, sub.Flavor)
		}
		if err := render(b, sub, params, env, depth+1); err != nil {
			return err
		}
	}
	if strings.TrimSpace(f.Body) == "" {
		return nil
	}
	tpl, err := template.New(f.ID).Delims("<<", ">>").Option("missingkey=error").Parse(f.Body)
	if err != nil {
		return fmt.Errorf("payload %q: %w", f.ID, err)
	}
	if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
		b.WriteByte('\n')
	}
	if err := tpl.Execute(b, renderContext{Params: bound, flavor: f.Flavor, env: env}); err != nil {
		return fmt.Errorf("payload %q: %w", f.ID, err)
	}
	return nil
}

// bind resolves each declared param against what the caller supplied, its default,
// and its declared type, and refuses a key the fragment does not declare. A
// fragment that ignores a param it was given renders into a job that measures
// something other than what the plan asked for, so the drop is an error on both the
// static and the render path. Nothing in the corpus includes another fragment; a
// chain that did would have to decide passthrough here before this could hold for
// it.
func bind(f Fragment, given map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(f.Params))
	declared := make(map[string]bool, len(f.Params))
	for _, p := range f.Params {
		declared[p.Name] = true
		v, ok := given[p.Name]
		if !ok || v == nil {
			if p.Required && p.Default == nil {
				return nil, fmt.Errorf("payload %q requires param %q", f.ID, p.Name)
			}
			v = p.Default
		}
		bv, err := coerce(p, v, f.Flavor)
		if err != nil {
			return nil, fmt.Errorf("payload %q param %q: %w", f.ID, p.Name, err)
		}
		out[p.Name] = bv
	}
	if errs := unknownParams(f.ID, declared, given); len(errs) > 0 {
		return nil, errs[0]
	}
	return out, nil
}

// paramTypes is the declared vocabulary, empty meaning string, and the only place
// a supplied value is shaped. load rejects a fragment declaring a type outside it,
// so a vocabulary entry cannot exist without a conversion and a conversion cannot
// exist outside the vocabulary. Each returns the value's Go shape and never its
// rendered form: quoteFor decides that for all of them at once.
var paramTypes = map[string]func(any) (any, error){
	"":         asString,
	"string":   asString,
	"int":      asInt,
	"bool":     asBool,
	"[]string": asList,
	"file":     asFile,
}

func coerce(p Param, v any, f Flavor) (any, error) {
	shape, known := paramTypes[p.Type]
	if !known {
		return nil, fmt.Errorf("unknown param type %q", p.Type)
	}
	if err := checkSecretNames(p, v); err != nil {
		return nil, err
	}
	shaped, err := shape(v)
	if err != nil {
		return nil, err
	}
	return quoteFor(f, shaped)
}

// quoteFor is the single decision about how a value reaches the body, so a type
// added to paramTypes is quoted whether or not its author thought about it. An
// unrecognized shape is an error rather than a raw interpolation, and the one
// shape that must not be quoted says so in its own type.
func quoteFor(f Flavor, v any) (any, error) {
	switch t := v.(type) {
	case verbatim, int, bool:
		return t, nil
	case string:
		return quote(f, t)
	case []string:
		return list(t), nil
	default:
		return nil, fmt.Errorf("no rendered form for %T", v)
	}
}

// quote applies the flavor's escaping. A workflow-flavor value carrying ${{ is
// refused rather than quoted: Actions evaluates expressions inside quoted YAML
// scalars too, so there is no quoting that contains one. A quote of its own or a
// line break is refused for the reason yamlValue documents — and a line break is
// the sharper of the two, because every rendered line is indented by one uniform
// prefix, so a second line of a value arrives at the column the steps sequence
// itself starts at and becomes a step the plan never declared.
func quote(f Flavor, s string) (any, error) {
	if f != WorkflowSteps {
		return shellValue(s), nil
	}
	if strings.Contains(s, "${{") {
		return nil, fmt.Errorf("value contains ${{, which the workflow flavor evaluates however it is quoted")
	}
	for _, r := range s {
		if unquotableInWorkflow(r) {
			return nil, fmt.Errorf("value contains %q, which no quoting contains in a workflow position: the value is read both as a YAML scalar and as shell text inside a run: block, and the two agree only on one line carrying no quote of its own", r)
		}
	}
	return yamlValue(s), nil
}

func unquotableInWorkflow(r rune) bool {
	return r == '\'' || unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

func asString(v any) (any, error) {
	if v == nil {
		return "", nil
	}
	return scalarString(v), nil
}

func asInt(v any) (any, error) {
	switch n := v.(type) {
	case nil:
		return 0, nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return nil, fmt.Errorf("want int, got %q", n)
		}
		return i, nil
	default:
		return nil, fmt.Errorf("want int, got %T", v)
	}
}

func asBool(v any) (any, error) {
	switch t := v.(type) {
	case nil:
		return false, nil
	case bool:
		return t, nil
	case string:
		b, err := strconv.ParseBool(t)
		if err != nil {
			return nil, fmt.Errorf("want bool, got %q", t)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("want bool, got %T", v)
	}
}

// rawElementRe is what an element of a list may be, and it is deliberately not
// the union of the positions it renders into but their intersection: an element
// is interpolated raw into a YAML mapping value, into a ${{ }} expression and
// into shell text, so it carries nothing that any of the three reads as syntax.
// The whole-list position quotes, but that does not help here — a line break
// inside shell quotes still ends the YAML line it was rendered on.
var rawElementRe = regexp.MustCompile(`^[A-Za-z0-9._/+=-]+$`)

func asList(v any) (any, error) {
	if v == nil {
		return []string{}, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("want a list, got %T", v)
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s := scalarString(it)
		if !rawElementRe.MatchString(s) {
			return nil, fmt.Errorf("list element %q must match %s: an element is interpolated raw, so no quoting stands between it and the position it lands in", s, rawElementRe)
		}
		out = append(out, s)
	}
	return out, nil
}

// asFile is the operator escape hatch: quoting a supplied file destroys the
// content the param exists to carry, and screening its ${{ }} would refuse the
// workflow steps that are the legitimate thing to put in it.
func asFile(v any) (any, error) {
	if v == nil {
		return verbatim(""), nil
	}
	return verbatim(scalarString(v)), nil
}

func scalarString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}
