package attack

import (
	"cmp"
	"context"
	"fmt"
	"reflect"
	"slices"
)

// Capability is a coarse permission a primitive needs; Session compares it
// against an identity's scopes as an advisory preflight, never a hard gate.
// Every member is a write grant, so a read a primitive also needs cannot be
// declared here and belongs in its Summary, which is then the only channel the
// operator has to it — repo.fork's contents:read is the one such requirement.
type Capability string

const (
	CapContentsWrite  Capability = "contents:write"
	CapWorkflow       Capability = "workflow"
	CapActionsWrite   Capability = "actions:write"
	CapPullRequests   Capability = "pull_requests:write"
	CapIssues         Capability = "issues:write"
	CapChecksWrite    Capability = "checks:write"
	CapDeployments    Capability = "deployments:write"
	CapAdministration Capability = "administration:write"
	CapDeleteRepo     Capability = "delete_repo"
)

// Port is a key that binds a prior step's handle. Iface is one of the three port
// interfaces (bind-by-satisfaction) or a concrete handle type (bind-by-identity);
// the validator decides which by reflect.Type.Kind.
type Port struct {
	Name     string
	Iface    reflect.Type
	Required bool
}

// Accepts declares a port keyed under name. T is an interface when several handle
// kinds may bind (WritableRef), or a concrete handle when exactly one may.
func Accepts[T Handle](name string, required bool) Port {
	return Port{Name: name, Iface: reflect.TypeFor[T](), Required: required}
}

type Spec struct {
	Name     string
	Summary  string
	Ports    []Port
	Caps     []Capability
	Mutating bool
	// Reversible and Destructive are descriptive, not enforced. They reach the
	// catalog and the dry-run inventory, where an operator reviewing a plan reads
	// which steps carry an inverse and which cannot be taken back; nothing in the
	// executor or the validator gates on either. What is enforced is the ledger:
	// an inverse is written ahead of the call that needs one, and cleanup reports
	// every recorded mutation whether or not one was.
	Reversible  bool
	Destructive bool
	CrossRepo   bool // exempt from the same-repository check (pr.open only)

	// OneOf names optional ports of which exactly one must be bound. It is how a
	// primitive reads the same thing from two unrelated sources — a repository or
	// an organization — without a union handle type the lattice cannot express.
	OneOf []string

	// AppOnly marks a primitive only a GitHub App installation token can issue.
	// The validator rejects a plan that names a credential class GitHub answers
	// 403 to, offline, rather than letting the chain discover it mid-run.
	AppOnly bool

	// OriginFrom names the port whose repository the produced handle inherits.
	// Empty means the primitive roots a fresh repository: repo.resolve roots a
	// concrete one from its owner/repo fields, everything else roots an opaque
	// one (a fork lands in the acting identity's namespace, unknowable offline).
	OriginFrom string

	Produces HandleKind // set from the O type parameter, never by the caller
}

// Inputs is how the executor hands a primitive its bound handles and resolved
// field values. Authors never construct it; the flat plan grammar is
// disambiguated into it by the registry.
type Inputs struct {
	ports  map[string]Handle
	fields map[string]any
}

// In returns the handle bound to a port. It panics on a miss because Validate
// has already proven the binding exists and type-checks: a miss is a
// registry/validator disagreement, a program bug, and the executor recovers per
// step so one broken primitive cannot sink a run.
func In[T Handle](in Inputs, port string) T {
	h, ok := in.ports[port]
	if !ok {
		panic(fmt.Sprintf("attack: port %q not bound", port))
	}
	typed, ok := h.(T)
	if !ok {
		panic(fmt.Sprintf("attack: port %q holds %T, not %s", port, h, reflect.TypeFor[T]()))
	}
	return typed
}

// InOpt does not panic where In does: an optional port that no step bound, or one
// bound to another type, is a case the primitive decides for itself.
func InOpt[T Handle](in Inputs, port string) (T, bool) {
	var zero T
	h, ok := in.ports[port]
	if !ok {
		return zero, false
	}
	t, ok := h.(T)
	return t, ok
}

type Fn[P any, O Handle] func(ctx context.Context, s *Session, p P, in Inputs) (O, error)

type entry struct {
	spec      Spec
	paramType reflect.Type
	invoke    func(ctx context.Context, s *Session, p any, in Inputs) (Handle, error)
}

var registry = map[string]*entry{}

// Register erases the generics into a non-generic entry. O is the single source
// of truth for spec.Produces, so the kind table can never drift from the Go
// types. A duplicate name is a program bug and panics at init.
func Register[P any, O Handle](spec Spec, fn Fn[P, O]) {
	var zero O
	spec.Produces = zero.Kind()
	if _, dup := registry[spec.Name]; dup {
		panic("attack: duplicate primitive " + spec.Name)
	}
	registry[spec.Name] = &entry{
		spec:      spec,
		paramType: reflect.TypeFor[P](),
		invoke: func(ctx context.Context, s *Session, p any, in Inputs) (Handle, error) {
			typed, ok := p.(P)
			if !ok {
				return nil, fmt.Errorf("attack: %s was handed params of type %T, not %s", spec.Name, p, reflect.TypeFor[P]())
			}
			return fn(ctx, s, typed, in)
		},
	}
}

// Catalog returns every registered spec, sorted by name for deterministic output.
func Catalog() []Spec {
	specs := make([]Spec, 0, len(registry))
	for _, e := range registry {
		specs = append(specs, e.spec)
	}
	slices.SortFunc(specs, func(a, b Spec) int { return cmp.Compare(a.Name, b.Name) })
	return specs
}

func lookup(name string) (*entry, bool) {
	e, ok := registry[name]
	return e, ok
}

func primitiveNames() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
