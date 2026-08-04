package attack

import (
	"cmp"
	"reflect"
	"slices"
)

// InputView describes one input key of a primitive: whether it is a port (binds
// a prior step's handle) or a field (a scalar), and — for a port — which
// concrete handle kinds satisfy it. It is the surface an agent authors against.
type InputView struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"` // "port" | "field"
	Required    bool     `json:"required,omitempty"`
	Iface       string   `json:"iface,omitempty"`
	SatisfiedBy []string `json:"satisfied_by,omitempty"`
	Type        string   `json:"type,omitempty"`
}

type CatalogView struct {
	Name        string      `json:"name"`
	Summary     string      `json:"summary"`
	Produces    string      `json:"produces"`
	Mutating    bool        `json:"mutating"`
	Reversible  bool        `json:"reversible,omitempty"`
	Destructive bool        `json:"destructive,omitempty"`
	CrossRepo   bool        `json:"cross_repo,omitempty"`
	AppOnly     bool        `json:"app_only,omitempty"`
	OneOf       []string    `json:"one_of,omitempty"`
	Caps        []string    `json:"caps,omitempty"`
	Inputs      []InputView `json:"inputs"`
}

// CatalogViews serializes the live registry: the prompt source an agent authors
// plans from. Because it is generated from the registry, it can never describe a
// primitive that does not exist.
func CatalogViews() []CatalogView {
	var views []CatalogView
	for _, e := range registry {
		views = append(views, viewOf(e))
	}
	slices.SortFunc(views, func(a, b CatalogView) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return views
}

func viewOf(e *entry) CatalogView {
	v := CatalogView{
		Name:        e.spec.Name,
		Summary:     e.spec.Summary,
		Produces:    string(e.spec.Produces),
		Mutating:    e.spec.Mutating,
		Reversible:  e.spec.Reversible,
		Destructive: e.spec.Destructive,
		CrossRepo:   e.spec.CrossRepo,
		AppOnly:     e.spec.AppOnly,
		OneOf:       e.spec.OneOf,
	}
	for _, c := range e.spec.Caps {
		v.Caps = append(v.Caps, string(c))
	}
	for _, port := range e.spec.Ports {
		v.Inputs = append(v.Inputs, InputView{
			Name:        port.Name,
			Kind:        "port",
			Required:    port.Required,
			Iface:       ifaceName(port.Iface),
			SatisfiedBy: satisfyingKinds(port.Iface),
		})
	}
	names, kinds := paramFields(e.paramType)
	for _, f := range names {
		v.Inputs = append(v.Inputs, InputView{
			Name: f,
			Kind: "field",
			Type: kindLabel(kinds[f]),
		})
	}
	slices.SortFunc(v.Inputs, func(a, b InputView) int { return cmp.Compare(a.Name, b.Name) })
	return v
}

func satisfyingKinds(iface reflect.Type) []string {
	var out []string
	for kind := range handleTypes {
		if satisfies(kind, iface) {
			out = append(out, string(kind))
		}
	}
	slices.Sort(out)
	return out
}
