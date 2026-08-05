package attack

import (
	"reflect"
	"slices"
	"testing"
)

// Every port's accepted type is either one of the three port interfaces or a
// concrete registered handle — never an arbitrary interface.
func TestCatalogPortsAreLatticeOrConcrete(t *testing.T) {
	lattice := map[reflect.Type]bool{
		reflect.TypeFor[RepoScoped]():  true,
		reflect.TypeFor[WritableRef](): true,
		reflect.TypeFor[Commentable](): true,
	}
	concrete := map[reflect.Type]bool{}
	for _, ht := range handleTypes {
		concrete[ht] = true
	}
	for _, e := range registry {
		for _, port := range e.spec.Ports {
			if port.Iface.Kind() == reflect.Interface {
				if !lattice[port.Iface] {
					t.Errorf("%s port %q: interface %s is not one of the three ports", e.spec.Name, port.Name, port.Iface)
				}
				continue
			}
			if !concrete[port.Iface] {
				t.Errorf("%s port %q: %s is not a registered handle type", e.spec.Name, port.Name, port.Iface)
			}
		}
	}
}

// Produces is set from the O type parameter, so it must name a real handle kind
// (or None for terminal steps).
func TestCatalogProducesIsAKnownKind(t *testing.T) {
	for _, e := range registry {
		k := e.spec.Produces
		if k == KindNone {
			continue
		}
		if _, ok := handleTypes[k]; !ok {
			t.Errorf("%s produces %q which is not a handle kind", e.spec.Name, k)
		}
	}
}

// Every port must be satisfiable: some registered primitive produces a handle
// that binds it. A port nothing produces is a signature no plan can write, which
// is invisible until an author tries.
func TestCatalogEveryPortHasAProducer(t *testing.T) {
	produced := map[HandleKind]bool{}
	for _, e := range registry {
		produced[e.spec.Produces] = true
	}
	for _, e := range registry {
		for _, port := range e.spec.Ports {
			ok := false
			for kind := range produced {
				if satisfies(kind, port.Iface) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("%s port %q (%s) has no producer in the registry", e.spec.Name, port.Name, ifaceName(port.Iface))
			}
		}
	}
}

// Every handle carrying both owner and repo (i.e. a RepoLoc/RefLoc/IssueLoc)
// must declare RepoScoped — the same-repository check depends on it.
func TestCatalogRepoLocHandlesAreRepoScoped(t *testing.T) {
	rs := reflect.TypeFor[RepoScoped]()
	for kind, ht := range handleTypes {
		fields := handleFieldNames(kind)
		if slices.Contains(fields, "owner") && slices.Contains(fields, "repo") {
			if !ht.Implements(rs) {
				t.Errorf("handle %s carries owner/repo but is not RepoScoped", kind)
			}
		}
	}
}

// The plan grammar is flat, so one key can only mean one thing. Validate resolves
// a key as a port before it looks at the param fields, so a primitive declaring
// both under one name makes the field unreachable and reads the author's scalar as
// a handle reference — with no error, because the port branch matched.
func TestCatalogNoPortShadowsAParamField(t *testing.T) {
	for _, e := range registry {
		fields, _ := paramFields(e.paramType)
		for _, port := range e.spec.Ports {
			if slices.Contains(fields, port.Name) {
				t.Errorf("%s: %q is both a port and a param field, so the field can never be bound", e.spec.Name, port.Name)
			}
		}
	}
}
