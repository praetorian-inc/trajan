package attack

import "testing"

func TestInputPrecedenceSetBeatsSetFileBeatsDefault(t *testing.T) {
	p := &Plan{
		Inputs:        map[string]InputSpec{"ref": {Type: "string", Default: "from-default"}},
		SetValues:     map[string]string{"ref": "from-set"},
		SetFileValues: map[string]any{"ref": "from-file"},
	}
	if errs := p.resolveInputs(); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if p.resolvedInputs["ref"] != "from-set" {
		t.Fatalf("--set must win, got %v", p.resolvedInputs["ref"])
	}

	p2 := &Plan{
		Inputs:        map[string]InputSpec{"ref": {Type: "string", Default: "from-default"}},
		SetFileValues: map[string]any{"ref": "from-file"},
	}
	p2.resolveInputs()
	if p2.resolvedInputs["ref"] != "from-file" {
		t.Fatalf("--set-file must beat default, got %v", p2.resolvedInputs["ref"])
	}

	p3 := &Plan{Inputs: map[string]InputSpec{"ref": {Type: "string", Default: "from-default"}}}
	p3.resolveInputs()
	if p3.resolvedInputs["ref"] != "from-default" {
		t.Fatalf("default must apply, got %v", p3.resolvedInputs["ref"])
	}
}

// --set marker= is a value the operator typed, not an omission: falling through
// to the default would run the chain under a value they replaced.
func TestInputEmptySetValueBeatsTheDefault(t *testing.T) {
	p := &Plan{
		Inputs:    map[string]InputSpec{"marker": {Type: "string", Default: "from-default"}},
		SetValues: map[string]string{"marker": ""},
	}
	if errs := p.resolveInputs(); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if p.resolvedInputs["marker"] != "" {
		t.Fatalf("an explicit empty --set must win, got %#v", p.resolvedInputs["marker"])
	}
}

func TestInputRequiredWithNoValueFails(t *testing.T) {
	p := &Plan{Inputs: map[string]InputSpec{"reviewer": {Type: "string", Required: true}}}
	errs := p.resolveInputs()
	if len(errs) != 1 || !hasSubstr(errStrings(errs), `input "reviewer" is required`) {
		t.Fatalf("want required-input error, got %v", errs)
	}
}

func TestInputDeclaredTypeMustParse(t *testing.T) {
	p := &Plan{
		Inputs:    map[string]InputSpec{"timeout": {Type: "duration"}},
		SetValues: map[string]string{"timeout": "soon"},
	}
	errs := p.resolveInputs()
	if !hasSubstr(errStrings(errs), `input "timeout": want duration, got "soon"`) {
		t.Fatalf("want duration parse error, got %v", errs)
	}

	pi := &Plan{
		Inputs:    map[string]InputSpec{"n": {Type: "int"}},
		SetValues: map[string]string{"n": "notanumber"},
	}
	if !hasSubstr(errStrings(pi.resolveInputs()), `input "n": want int`) {
		t.Fatalf("want int parse error, got %v", pi.resolveInputs())
	}
}

func TestInputListCoercion(t *testing.T) {
	p := &Plan{
		Inputs:    map[string]InputSpec{"labels": {Type: "list"}},
		SetValues: map[string]string{"labels": "a, b ,c"},
	}
	if errs := p.resolveInputs(); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	got, ok := p.resolvedInputs["labels"].([]any)
	if !ok || len(got) != 3 || got[1] != "b" {
		t.Fatalf("list coercion wrong: %#v", p.resolvedInputs["labels"])
	}
}

func errStrings(errs []error) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Error()
	}
	return out
}
