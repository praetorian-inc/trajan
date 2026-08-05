package attack

import "testing"

// Every shipped template validates against the live registry — the guarantee
// that a template naming a primitive that does not exist, or feeding one
// primitive an output the next cannot accept, fails CI rather than a customer's
// org. Required inputs are supplied with placeholders so only structural
// validity is under test.
func TestEmbeddedTemplatesValidate(t *testing.T) {
	ids, err := ListTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Fatal("no templates embedded")
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			p, err := LoadTemplate(id)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			p.SetValues = map[string]string{}
			for name, spec := range p.Inputs {
				if spec.Required {
					p.SetValues[name] = placeholder(spec.Type)
				}
			}
			for _, e := range Validate(p) {
				if IsWarning(e) {
					continue
				}
				t.Errorf("%s: %v", id, e)
			}
		})
	}
}

func placeholder(typ string) string {
	switch typ {
	case "int":
		return "1"
	case "bool":
		return "true"
	case "duration":
		return "1m"
	default:
		return "placeholder"
	}
}
