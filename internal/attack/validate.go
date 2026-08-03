package attack

import (
	"cmp"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ValidationWarning is a non-fatal diagnostic. It is returned in the same slice
// as errors (the validator is one pass) but never blocks execution; callers
// filter it out with IsWarning.
type ValidationWarning struct{ Msg string }

func (w ValidationWarning) Error() string { return w.Msg }

func IsWarning(err error) bool {
	var w ValidationWarning
	return errors.As(err, &w)
}

var (
	planIDRe = regexp.MustCompile(`^[a-z0-9/_-]+$`)
	stepIDRe = regexp.MustCompile(`^[a-z0-9_-]+$`)
	dotRefRe = regexp.MustCompile(`^[a-z0-9_-]+\.[a-zA-Z0-9_.-]+$`)
	credRe   = regexp.MustCompile(`ghp_|github_pat_|gho_|ghs_|ghu_|-----BEGIN [A-Z ]*PRIVATE KEY-----`)
)

// repoOrigin tracks, offline, which repository a produced handle belongs to.
// concrete is "owner/repo" when it traces to a literal repo.resolve; otherwise
// the handle roots an opaque origin (a fork in the acting identity's namespace,
// unknowable before the run) identified by the step that produced it.
type repoOrigin struct {
	concrete string
	root     string
}

func (o repoOrigin) id() string {
	if o.concrete != "" {
		return o.concrete
	}
	return "@" + o.root
}

func (o repoOrigin) display() string {
	if o.concrete != "" {
		return o.concrete
	}
	return "<" + o.root + ">"
}

type stepInfo struct {
	produced   HandleKind
	origin     repoOrigin
	repoScoped bool
	// idKind is the credential class an identity-producing step resolves to,
	// empty when it cannot be known before the run. It is the offline analogue of
	// Session.ActingKind, carried forwards like origin so a later step can be held
	// to a capability boundary GitHub would otherwise answer 403 to.
	idKind string
}

// Validate is the whole static pass: total, offline, issuing zero requests, and
// returning every problem at once. A non-empty result of non-warning errors is
// the signal that the run never started.
func Validate(p *Plan) []error {
	var errs []error
	add := func(e ...error) { errs = append(errs, e...) }

	if p.APIVersion != APIVersion {
		add(fmt.Errorf("apiVersion must be %q, got %q", APIVersion, p.APIVersion))
	}
	if p.ID != "" && !planIDRe.MatchString(p.ID) {
		add(fmt.Errorf("id %q must match [a-z0-9/_-]+", p.ID))
	}
	if len(p.Scope) == 0 {
		add(fmt.Errorf("scope must list at least one repository"))
	}
	if len(p.Steps) == 0 {
		add(fmt.Errorf("steps must list at least one step"))
	}
	add(p.resolveInputs()...)
	add(collectorCheck(p)...)
	add(credentialLiterals(p)...)
	add(orgsCheck(p)...)
	add(encryptionCheck(p)...)

	inputNames := map[string]bool{}
	for name := range p.Inputs {
		inputNames[name] = true
	}

	info := map[string]stepInfo{}
	prior := map[string]bool{}
	seenIDs := map[string]bool{}

	all := allSteps(p)
	for i := range all {
		st := &all[i]
		add(validateStep(p, st, inputNames, prior, seenIDs, info)...)
		if st.ID != "" {
			prior[st.ID] = true
			seenIDs[st.ID] = true
		}
	}
	add(cacheScopeCheck(p, inputNames)...)
	return errs
}

func validateStep(p *Plan, st *Step, inputNames, prior, seen map[string]bool, info map[string]stepInfo) []error {
	var errs []error
	add := func(e ...error) { errs = append(errs, e...) }

	label := stepLabel(st)

	if st.ID == "" {
		add(fmt.Errorf("%s: missing id", label))
	} else {
		if !stepIDRe.MatchString(st.ID) {
			add(fmt.Errorf("step %q: id must match [a-z0-9_-]+", st.ID))
		}
		if seen[st.ID] {
			add(fmt.Errorf("step %q: duplicate id", st.ID))
		}
		if inputNames[st.ID] {
			add(fmt.Errorf("step %q: id collides with input %q", st.ID, st.ID))
		}
	}

	e, ok := lookup(st.Uses)
	if !ok {
		add(fmt.Errorf("%s: unknown primitive %q%s", label, st.Uses, nearMisses(st.Uses)))
		if st.ID != "" {
			info[st.ID] = stepInfo{origin: repoOrigin{root: st.ID}}
		}
		return errs
	}
	spec := e.spec
	portByName := map[string]Port{}
	for _, port := range spec.Ports {
		portByName[port.Name] = port
	}
	fieldNames, fieldKinds := paramFields(e.paramType)
	fieldSet := map[string]bool{}
	for _, f := range fieldNames {
		fieldSet[f] = true
	}

	bindings := map[string]string{} // port name -> bound prior step id

	for _, k := range sortedKeys(st.Keys) {
		raw := st.Keys[k]
		switch {
		case portByName[k].Name != "":
			boundID, e2 := validatePortBinding(portByName[k], raw, st.quoted[k], inputNames, prior, info)
			add(e2...)
			if boundID != "" {
				bindings[k] = boundID
			}
		case fieldSet[k]:
			add(validateField(st, k, fieldKinds[k], raw, inputNames, prior, info, p)...)
		default:
			add(fmt.Errorf("%s: %s has no input %q (has: %s)", label, st.Uses, k, strings.Join(inputKeyList(spec, fieldNames), ", ")))
		}
	}

	for _, port := range spec.Ports {
		if port.Required && bindings[port.Name] == "" {
			if _, present := st.Keys[port.Name]; !present {
				add(fmt.Errorf("%s: %s requires port %q", label, st.Uses, port.Name))
			}
		}
	}
	add(oneOfCheck(spec, st, bindings)...)
	if spec.Produces == KindOrg {
		add(orgScopeCheck(p, st, inputNames)...)
	}
	if spec.AppOnly {
		add(appIdentityCheck(p, st, spec, bindings, info)...)
	}

	add(validateAs(p, st, inputNames, prior, info)...)
	add(validateWhen(st, prior, info)...)
	add(validatePayloads(st, p, prior)...)
	add(workflowPathCheck(st)...)
	add(workflowEnvelopeCheck(st)...)
	if st.Uses == "run.await" && len(prior) == 0 {
		add(fmt.Errorf("%s: run.await correlates the run its predecessor provoked, and this is the first step; a run the plan does not cause is run.observe", label))
	}
	add(delimiterWarning(st)...)

	origin := computeOrigin(spec, st, bindings, info, inputNames, p)
	if st.ID != "" {
		info[st.ID] = stepInfo{
			produced:   spec.Produces,
			origin:     origin,
			repoScoped: handleIsRepoScoped(spec.Produces),
			idKind:     producedIdentityKind(p, st, spec),
		}
	}

	add(sameRepoCheck(spec, st, bindings, info)...)
	if spec.Mutating && origin.concrete != "" && !scopeAllows(p.Scope, origin.concrete) {
		add(fmt.Errorf("%s mutates %s which is not in scope", strings.TrimSuffix(label, ""), origin.concrete))
	}

	return errs
}

func validatePortBinding(port Port, raw any, quoted bool, inputNames, prior map[string]bool, info map[string]stepInfo) (string, []error) {
	s, isStr := raw.(string)
	if !isStr || quoted || strings.ContainsAny(s, ". ") {
		return "", []error{fmt.Errorf("port %q must name a prior step", port.Name)}
	}
	if inputNames[s] {
		return "", []error{fmt.Errorf("port %q must name a prior step; %q is an input", port.Name, s)}
	}
	if !prior[s] {
		return "", []error{fmt.Errorf("%q references %q which is not a prior step", port.Name, s)}
	}
	boundKind := info[s].produced
	if !satisfies(boundKind, port.Iface) {
		return "", []error{fmt.Errorf("port %q needs %s, but step %q produces %s", port.Name, ifaceName(port.Iface), s, kindName(boundKind))}
	}
	return s, nil
}

func validateField(st *Step, key string, kind reflect.Kind, raw any, inputNames, prior map[string]bool, info map[string]stepInfo, p *Plan) []error {
	label := stepLabel(st)
	switch v := raw.(type) {
	case string:
		if st.quoted[key] {
			errs := typeCheckLiteral(label, key, kind, v)
			// Only the quoted direction is warned about: an unquoted bare word
			// naming an input resolves to that input, which is what the author
			// wrote it for, and quoting it is the direction that silently yields
			// the string instead.
			if inputNames[v] {
				errs = append(errs, ValidationWarning{fmt.Sprintf("%s: %q is quoted, so it is the literal string, not input %q", label, v, v)})
			} else if prior[v] {
				errs = append(errs, ValidationWarning{fmt.Sprintf("%s: %q is quoted, so it is the literal string, not step %q", label, v, v)})
			}
			return errs
		}
		if strings.Contains(v, "${{") {
			return nil // interpolation always stringifies; only meaningful into a string field
		}
		if id, field, ok := splitDotRef(v); ok && prior[id] {
			return validateHandleFieldRef(label, id, field, info)
		}
		if prior[id0(v)] && !strings.Contains(v, ".") {
			suggest := firstField(info[v].produced)
			return []error{fmt.Errorf(`%s: field %q got the handle %q; did you mean %s?`, label, key, v, v+"."+suggest)}
		}
		if inputNames[v] {
			return typeCheckInputRef(label, key, kind, v, p)
		}
		return typeCheckLiteral(label, key, kind, v)
	case bool:
		if kind != reflect.Bool && kind != reflect.Interface {
			return []error{fmt.Errorf("%s: field %q wants %s, got bool", label, key, kindLabel(kind))}
		}
	case int, int64, float64:
		if kind != reflect.Int && kind != reflect.Interface {
			return []error{fmt.Errorf("%s: field %q wants %s, got number", label, key, kindLabel(kind))}
		}
	case []any:
		if kind != reflect.Slice && kind != reflect.Interface {
			return []error{fmt.Errorf("%s: field %q wants %s, got list", label, key, kindLabel(kind))}
		}
	case map[string]any:
		if kind != reflect.Map && kind != reflect.Interface {
			return []error{fmt.Errorf("%s: field %q wants %s, got mapping", label, key, kindLabel(kind))}
		}
	}
	return nil
}

func typeCheckLiteral(label, key string, kind reflect.Kind, v string) []error {
	switch kind {
	case reflect.Int:
		if _, err := strconv.Atoi(v); err != nil {
			return []error{fmt.Errorf("%s: field %q wants int, got %q", label, key, v)}
		}
	case reflect.Bool:
		if _, err := strconv.ParseBool(v); err != nil {
			return []error{fmt.Errorf("%s: field %q wants bool, got %q", label, key, v)}
		}
	}
	return nil
}

func typeCheckInputRef(label, key string, kind reflect.Kind, name string, p *Plan) []error {
	spec, ok := p.Inputs[name]
	if !ok {
		return nil
	}
	itype := spec.Type
	if itype == "" {
		itype = "string"
	}
	want := map[string]reflect.Kind{
		"string":   reflect.String,
		"duration": reflect.String,
		"int":      reflect.Int,
		"bool":     reflect.Bool,
		"list":     reflect.Slice,
	}[itype]
	if kind == reflect.Interface || kind == reflect.String {
		return nil // a string field accepts any input, stringified
	}
	if want != kind {
		return []error{fmt.Errorf("%s: field %q wants %s, but input %q is %s", label, key, kindLabel(kind), name, itype)}
	}
	return nil
}

func validateHandleFieldRef(label, id, field string, info map[string]stepInfo) []error {
	kind := info[id].produced
	fields := handleFieldNames(kind)
	// only the first segment of a nested path is checked against the handle
	seg := field
	if i := strings.IndexByte(field, '.'); i >= 0 {
		seg = field[:i]
	}
	if !slices.Contains(fields, seg) {
		return []error{fmt.Errorf("%s: %s.%s: handle %s has no field %q", label, id, field, kindName(kind), seg)}
	}
	return nil
}

// validateAs resolves as: offline. A step reference is a dependency edge in the
// same backwards-only graph a port binding builds, so it is held to the same rule:
// name an earlier step, and that step must produce an identity. Every other
// spelling has to be a name this run can resolve without the graph — the
// alternative is a plan that discovers its typo as a 401 mid-chain, or worse, a
// step that quietly acts as the default identity rather than the one it named.
func validateAs(p *Plan, st *Step, inputNames, prior map[string]bool, info map[string]stepInfo) []error {
	switch {
	case st.As == "":
		return nil
	case st.As == kindEnv || strings.Contains(st.As, ":"):
		return nil // a from-spec resolved on the spot
	case prior[st.As]:
		if info[st.As].produced != KindIdentity {
			return []error{fmt.Errorf("step %q: as: %q produces %s, not an identity", st.ID, st.As, kindName(info[st.As].produced))}
		}
		return nil
	case declaresIdentity(p, st.As):
		return nil
	case inputNames[st.As]:
		return []error{fmt.Errorf("step %q: as: %q is an input; as: names a declared identity or a prior step that produces one", st.ID, st.As)}
	default:
		return []error{fmt.Errorf("step %q: as: %q is neither a declared identity (%s) nor a prior step producing one; references point only backwards",
			st.ID, st.As, strings.Join(identityNames(p), ", "))}
	}
}

func declaresIdentity(p *Plan, name string) bool {
	return slices.ContainsFunc(p.Identities, func(spec IdentitySpec) bool { return spec.Name == name })
}

func identityNames(p *Plan) []string {
	names := []string{kindEnv}
	for _, spec := range p.Identities {
		if spec.Name != "" {
			names = append(names, spec.Name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

var whenRefRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_-]*)\.[a-zA-Z0-9_.]+`)

// validateWhen holds a gate's references to the same standard as a field's: the
// step is prior, and the path names a field that step's handle actually carries.
// A bare word inside a predicate is not a literal — it is a read — so a typo'd
// path would otherwise evaluate false, skip the step and everything under it, and
// report the gate's negative case as though it had been measured.
func validateWhen(st *Step, prior map[string]bool, info map[string]stepInfo) []error {
	if st.When == "" {
		return nil
	}
	var errs []error
	for _, m := range whenRefRe.FindAllStringSubmatch(stripSingleQuoted(st.When), -1) {
		id, path := m[1], strings.TrimPrefix(m[0], m[1]+".")
		if !prior[id] {
			errs = append(errs, fmt.Errorf("step %q: when references %q which is not a prior step", st.ID, id))
			continue
		}
		errs = append(errs, validateHandleFieldRef(stepLabel(st)+": when", id, path, info)...)
	}
	return errs
}

func computeOrigin(spec Spec, st *Step, bindings map[string]string, info map[string]stepInfo, inputNames map[string]bool, p *Plan) repoOrigin {
	if spec.OriginFrom != "" {
		if boundID := bindings[spec.OriginFrom]; boundID != "" {
			return info[boundID].origin
		}
		return repoOrigin{root: cmpID(st)}
	}
	owner, ook := literalOrInput(st.Keys["owner"], inputNames, p)
	repo, rok := literalOrInput(st.Keys["repo"], inputNames, p)
	if ook && rok {
		return repoOrigin{concrete: owner + "/" + repo}
	}
	return repoOrigin{root: cmpID(st)}
}

func literalOrInput(raw any, inputNames map[string]bool, p *Plan) (string, bool) {
	s, ok := raw.(string)
	if !ok {
		return "", false
	}
	if inputNames[s] {
		if v, present := p.resolvedInputs[s]; present {
			if vs, isStr := v.(string); isStr {
				return vs, true
			}
		}
		return "", false
	}
	return s, true
}

func sameRepoCheck(spec Spec, st *Step, bindings map[string]string, info map[string]stepInfo) []error {
	if spec.CrossRepo {
		return nil
	}
	type bound struct {
		port   string
		origin repoOrigin
	}
	var scoped []bound
	for _, port := range spec.Ports { // spec order, for deterministic messages
		boundID, ok := bindings[port.Name]
		if !ok {
			continue
		}
		bi := info[boundID]
		if !bi.repoScoped {
			continue
		}
		scoped = append(scoped, bound{port.Name, bi.origin})
	}
	for i := 1; i < len(scoped); i++ {
		if scoped[i].origin.id() != scoped[0].origin.id() {
			return []error{fmt.Errorf("step %q binds %q in %s and %q in %s; %s is not cross-repo",
				st.ID, scoped[0].port, scoped[0].origin.display(), scoped[i].port, scoped[i].origin.display(), st.Uses)}
		}
	}
	return nil
}

// cacheRef is the git ref an Actions cache entry is written on, as far as the
// plan text says: a named branch, or the repository's default branch under a
// handle that names no branch of its own.
type cacheRef struct {
	name      string
	isDefault bool
}

// cacheScopeCheck screens the one relationship a cache demonstration stands on.
// An entry is restorable from the ref it was written on, and an entry written on
// the default branch is restorable from every ref — nothing else is. A poison
// scoped to a branch the awaited run is not on is a chain that mutates the
// target, runs to completion, restores nothing, and assembles a finding from a
// demonstration that could not have worked, so it is reported here.
func cacheScopeCheck(p *Plan, inputNames map[string]bool) []error {
	type poison struct {
		step  string
		scope cacheRef
	}
	refs := map[string]cacheRef{}
	var poisons []poison
	var errs []error

	for _, st := range allSteps(p) {
		switch st.Uses {
		case "repo.writable", "repo.fork":
			refs[st.ID] = cacheRef{isDefault: true}
		case "ref.create":
			if name, ok := staticRefName(st.Keys["name"], inputNames, p); ok {
				refs[st.ID] = cacheRef{name: name}
			}
		case "cache.poison":
			scope, known := refs[portTarget(st, "on")]
			if name, ok := staticRefName(st.Keys["scope"], inputNames, p); ok {
				scope, known = cacheRef{name: name}, true
			}
			if known {
				poisons = append(poisons, poison{st.ID, scope})
			}
		case "run.observe":
			awaited, ok := staticRefName(st.Keys["ref"], inputNames, p)
			if !ok {
				continue
			}
			for _, pz := range poisons {
				if pz.scope.isDefault || pz.scope.name == "" || pz.scope.name == awaited {
					continue
				}
				errs = append(errs, ValidationWarning{fmt.Sprintf(
					"step %q writes the cache entry on %s, but step %q awaits a run on %s: a branch-scoped entry is restorable only from that branch, and only an entry written on the default branch is restorable from every ref, so this run would restore nothing",
					pz.step, pz.scope.name, st.ID, awaited)})
			}
		default:
			if e, ok := lookup(st.Uses); ok && e.spec.OriginFrom != "" {
				if inherited, known := refs[portTarget(st, e.spec.OriginFrom)]; known {
					refs[st.ID] = inherited
				}
			}
		}
	}
	return errs
}

// staticRefName resolves a plan value to a branch name when the text alone says
// what it is. An interpolation, a handle read and an input with no value are all
// unknown offline, and an unknown ref is never reported as a mismatch.
func staticRefName(raw any, inputNames map[string]bool, p *Plan) (string, bool) {
	s, ok := literalOrInput(raw, inputNames, p)
	if !ok || s == "" || strings.Contains(s, "${{") {
		return "", false
	}
	if _, _, isHandleRead := splitDotRef(s); isHandleRead {
		return "", false
	}
	return strings.TrimPrefix(s, "refs/heads/"), true
}

func portTarget(st Step, port string) string {
	id, _ := st.Keys[port].(string)
	return id
}

// collectorCheck screens the endpoint a fragment sends its result to. A fragment
// that names one is reaching out of the runner, so plaintext http is refused
// here rather than discovered in a customer's network capture.
func collectorCheck(p *Plan) []error {
	target := p.collector()
	if target == "" {
		return nil
	}
	u, err := url.Parse(target)
	switch {
	case err != nil || u.Host == "":
		return []error{fmt.Errorf("collector %q is not a URL", target)}
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http":
		return []error{fmt.Errorf("collector %q is plaintext http; a result carrying it must not leave the runner in the clear", target)}
	default:
		return []error{fmt.Errorf("collector %q must be an https URL, not %s", target, u.Scheme)}
	}
}

func credentialLiterals(p *Plan) []error {
	var errs []error
	report := func(where string, s string) {
		if credRe.MatchString(s) {
			errs = append(errs, fmt.Errorf("%s looks like a credential; put it in identities and reference it", where))
		}
	}
	report(fmt.Sprintf("plan %q title", p.ID), p.Title)
	for _, spec := range p.Inputs {
		if s, ok := spec.Default.(string); ok {
			report("input default", s)
		}
	}
	scan := func(steps []Step) {
		for i := range steps {
			st := &steps[i]
			for _, k := range sortedKeys(st.Keys) {
				walkStrings(st.Keys[k], func(s string) {
					report(fmt.Sprintf("step %q: %q", st.ID, k), s)
				})
			}
		}
	}
	scan(p.Steps)
	scan(p.Cleanup)
	return errs
}

// orgsCheck screens the organization allowlist. An entry spelled as a repository
// is what this catches: orgs: and scope: are different lists, and a repository
// here would silently match nothing.
func orgsCheck(p *Plan) []error {
	var errs []error
	for _, entry := range p.Orgs {
		switch {
		case strings.TrimSpace(entry) == "":
			errs = append(errs, errors.New("orgs: holds an empty entry"))
		case strings.ContainsAny(entry, "/*"):
			errs = append(errs, fmt.Errorf("orgs: %q must be an organization login, not a repository or a pattern; repositories belong in scope:", entry))
		}
	}
	return errs
}

// orgScopeCheck gates a primitive that roots an organization on the orgs: list.
// Organization scope is enforced by the allowlist rather than by the type system:
// the port lattice's floor is a repository, and an Org handle names none.
func orgScopeCheck(p *Plan, st *Step, inputNames map[string]bool) []error {
	owner, resolved := literalOrInput(st.Keys["owner"], inputNames, p)
	// A login is alphanumerics and hyphens, so a dot means the value is a
	// <step>.<field> reference resolved at run time — where the primitive checks
	// the same list before it reads anything.
	if !resolved || owner == "" || strings.Contains(owner, ".") {
		return nil
	}
	if len(p.Orgs) == 0 {
		return []error{fmt.Errorf("%s: %s names the organization %q and this plan declares no orgs:; that is a separate allowlist from scope:, because an organization names no repository",
			stepLabel(st), st.Uses, owner)}
	}
	if !orgAllows(p.Orgs, owner) {
		return []error{fmt.Errorf("%s: organization %q is not in this plan's orgs: allowlist (%s)", stepLabel(st), owner, strings.Join(p.Orgs, ", "))}
	}
	return nil
}

func orgAllows(orgs []string, owner string) bool {
	return owner != "" && slices.ContainsFunc(orgs, func(entry string) bool { return strings.EqualFold(entry, owner) })
}

// oneOfCheck enforces a spec's exactly-one-of rule over optional ports, which is
// how a primitive reads one thing from two unrelated sources without a union
// handle type.
func oneOfCheck(spec Spec, st *Step, bindings map[string]string) []error {
	if len(spec.OneOf) == 0 {
		return nil
	}
	var bound []string
	for _, name := range spec.OneOf {
		if bindings[name] != "" {
			bound = append(bound, name)
		}
	}
	if len(bound) == 1 {
		return nil
	}
	got := "none"
	if len(bound) > 0 {
		got = strings.Join(bound, " and ")
	}
	return []error{fmt.Errorf("%s: %s takes exactly one of %s; got %s", stepLabel(st), st.Uses, strings.Join(spec.OneOf, " or "), got)}
}

// appIdentityCheck is the offline half of an App-only capability boundary. Only a
// GitHub App installation token can create a check run; a classic or fine-grained
// PAT is answered 403, which is a logged failure in the customer's audit trail
// that produces no evidence. The store records a class per entry, so a plan
// holding the wrong credential fails here rather than mid-chain.
func appIdentityCheck(p *Plan, st *Step, spec Spec, bindings map[string]string, info map[string]stepInfo) []error {
	type candidate struct{ what, kind string }
	cands := []candidate{{actingDescription(st), actingKindOffline(p, st, info)}}
	for _, port := range spec.Ports {
		if port.Iface != reflect.TypeFor[Identity]() {
			continue
		}
		if boundID := bindings[port.Name]; boundID != "" {
			cands = append(cands, candidate{fmt.Sprintf("the identity step %q bound to %s:", boundID, port.Name), info[boundID].idKind})
		}
	}

	var errs []error
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.kind] {
			continue
		}
		seen[c.kind] = true
		switch c.kind {
		case kindPAT, kindFineGrained, kindGhCLI:
			errs = append(errs, fmt.Errorf("%s: %s needs a GitHub App installation token with checks:write, and %s is a %s: GitHub answers 403, which leaves an error in the customer's audit log and no evidence. An Actions GITHUB_TOKEN carries an App identity and can; a PAT of any kind cannot",
				stepLabel(st), st.Uses, c.what, c.kind))
		case "":
			errs = append(errs, ValidationWarning{fmt.Sprintf("%s: %s needs a GitHub App installation token with checks:write, and the class of %s is only known once the run resolves it; a PAT will be refused with 403",
				stepLabel(st), st.Uses, c.what)})
		}
	}
	return errs
}

func actingDescription(st *Step) string {
	if st.As == "" {
		return "the plan's default identity"
	}
	return fmt.Sprintf("the identity this step acts as (%s)", st.As)
}

// actingKindOffline is the offline analogue of Session.ActingKind for one step:
// the class its as: resolves to, or the plan default's when it names none.
func actingKindOffline(p *Plan, st *Step, info map[string]stepInfo) string {
	if si, ok := info[st.As]; ok && si.produced == KindIdentity {
		return si.idKind
	}
	return plannedIdentityKind(p, st.As)
}

// plannedIdentityKind reads a credential class out of the plan text and the
// identity store: a declared kind:, or the store entry a from: names. It is empty
// for an env credential, whose class is the prefix of a token this machine may not
// even hold — unknowable offline, so a warning rather than a refusal.
func plannedIdentityKind(p *Plan, ref string) string {
	switch {
	case ref == "":
		return storedKind(cmp.Or(p.Identity, kindEnv))
	case ref == kindEnv || strings.Contains(ref, ":"):
		return storedKind(ref)
	}
	if i := slices.IndexFunc(p.Identities, func(spec IdentitySpec) bool { return spec.Name == ref }); i >= 0 {
		return cmp.Or(p.Identities[i].Kind, storedKind(p.Identities[i].From))
	}
	return ""
}

func storedKind(from string) string {
	name, isStore := strings.CutPrefix(from, "store:")
	if !isStore {
		return ""
	}
	store, err := LoadIdentityStore()
	if err != nil {
		return ""
	}
	si, _ := store.Get(name)
	return si.Kind
}

// producedIdentityKind is the class an identity-producing step will act as.
// identity.adopt takes its credential out of harvested evidence, so nothing about
// it is knowable until the harvest has run.
func producedIdentityKind(p *Plan, st *Step, spec Spec) string {
	if spec.Produces != KindIdentity || st.Uses != "identity.resolve" {
		return ""
	}
	from, _ := st.Keys["from"].(string)
	return plannedIdentityKind(p, from)
}

func walkStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case []any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	case map[string]any:
		for _, e := range t {
			walkStrings(e, fn)
		}
	}
}

func satisfies(kind HandleKind, iface reflect.Type) bool {
	bt := handleTypes[kind]
	if bt == nil {
		return false
	}
	if iface.Kind() == reflect.Interface {
		return bt.Implements(iface)
	}
	return bt == iface
}

func handleIsRepoScoped(kind HandleKind) bool {
	bt := handleTypes[kind]
	if bt == nil {
		return false
	}
	return bt.Implements(reflect.TypeFor[RepoScoped]())
}

func ifaceName(t reflect.Type) string {
	switch t {
	case reflect.TypeFor[RepoScoped]():
		return "repo_scoped"
	case reflect.TypeFor[WritableRef]():
		return "writable_ref"
	case reflect.TypeFor[Commentable]():
		return "commentable"
	}
	// a concrete handle port: name it by its kind
	for kind, ht := range handleTypes {
		if ht == t {
			return string(kind)
		}
	}
	return t.Name()
}

func kindName(kind HandleKind) string {
	if kind == "" {
		return "nothing"
	}
	return string(kind)
}

func paramFields(t reflect.Type) ([]string, map[string]reflect.Kind) {
	var names []string
	kinds := map[string]reflect.Kind{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		names = append(names, name)
		kinds[name] = f.Type.Kind()
	}
	return names, kinds
}

func handleFieldNames(kind HandleKind) []string {
	t := handleTypes[kind]
	if t == nil {
		return nil
	}
	return structJSONFields(t)
}

func structJSONFields(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			out = append(out, structJSONFields(f.Type)...)
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func firstField(kind HandleKind) string {
	fields := handleFieldNames(kind)
	if len(fields) == 0 {
		return "<field>"
	}
	return fields[0]
}

func inputKeyList(spec Spec, fields []string) []string {
	keys := make([]string, 0, len(spec.Ports)+len(fields))
	for _, port := range spec.Ports {
		keys = append(keys, port.Name)
	}
	keys = append(keys, fields...)
	slices.Sort(keys)
	return keys
}

func scopeAllows(scope []string, concrete string) bool {
	owner, _, _ := strings.Cut(concrete, "/")
	for _, entry := range scope {
		if entry == concrete || entry == owner+"/*" {
			return true
		}
	}
	return false
}

func splitDotRef(s string) (id, field string, ok bool) {
	if !dotRefRe.MatchString(s) {
		return "", "", false
	}
	i := strings.IndexByte(s, '.')
	return s[:i], s[i+1:], true
}

func id0(s string) string {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i]
	}
	return s
}

func stepLabel(st *Step) string {
	if st.ID != "" {
		return "step " + strconv.Quote(st.ID)
	}
	return "step <" + st.Uses + ">"
}

func cmpID(st *Step) string {
	if st.ID != "" {
		return st.ID
	}
	return st.Uses
}

func kindLabel(k reflect.Kind) string {
	switch k {
	case reflect.String:
		return "string"
	case reflect.Int:
		return "int"
	case reflect.Bool:
		return "bool"
	case reflect.Slice:
		return "list"
	case reflect.Map:
		return "mapping"
	default:
		return k.String()
	}
}

func stripSingleQuoted(s string) string {
	var b strings.Builder
	inq := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			inq = !inq
			continue
		}
		if !inq {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// nearMisses lists the registered names closest to an unknown one, so an author
// who typos a primitive gets a pointer instead of a bare rejection.
func nearMisses(name string) string {
	type cand struct {
		name string
		dist int
	}
	var cands []cand
	for _, n := range primitiveNames() {
		d := levenshtein(name, n)
		if d <= 4 || sharesFamily(name, n) {
			cands = append(cands, cand{n, d})
		}
	}
	slices.SortFunc(cands, func(a, b cand) int { return a.dist - b.dist })
	var names []string
	for _, c := range cands {
		names = append(names, c.name)
		if len(names) == 3 {
			break
		}
	}
	if len(names) == 0 {
		return ""
	}
	return " (did you mean: " + strings.Join(names, ", ") + "?)"
}

func sharesFamily(a, b string) bool {
	fa, _, _ := strings.Cut(a, ".")
	fb, _, _ := strings.Cut(b, ".")
	return fa != "" && fa == fb
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
