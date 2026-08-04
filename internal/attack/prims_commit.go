package attack

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/attack/payload"
	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name:       "commit.code",
		Summary:    "Commit non-workflow source onto a writable ref via the Git Data API, including deletions, renames and staged payload fragments.",
		Ports:      []Port{Accepts[WritableRef]("on", true), Accepts[Commit]("expect", false)},
		Caps:       []Capability{CapContentsWrite},
		Mutating:   true,
		Reversible: true,
		OriginFrom: "on",
	}, commitCode)

	Register(Spec{
		Name:       "workflow.commit",
		Summary:    "Commit a workflow document (and any workspace files it needs) onto a branch; trigger:, runs_on:, permissions:, environment:, needs:, timeout_minutes: and secrets: shape the job envelope a workflow_steps fragment cannot emit for itself.",
		Ports:      []Port{Accepts[WritableRef]("on", true), Accepts[Commit]("expect", false)},
		Caps:       []Capability{CapContentsWrite, CapWorkflow},
		Mutating:   true,
		Reversible: true,
		OriginFrom: "on",
	}, workflowCommit)
}

const (
	workflowDir           = ".github/workflows/"
	defaultRunsOn         = "ubuntu-latest"
	defaultTimeoutMinutes = 15
	defaultTrigger        = "push"
)

type commitCodeParams struct {
	Message  string            `yaml:"message"`
	Path     string            `yaml:"path"`
	Content  string            `yaml:"content"`
	Script   string            `yaml:"script"`
	Patch    string            `yaml:"patch"`
	Template string            `yaml:"template"`
	Params   map[string]any    `yaml:"params"`
	Files    map[string]any    `yaml:"files"`
	Delete   []string          `yaml:"delete"`
	Rename   map[string]string `yaml:"rename"`
	Suppress bool              `yaml:"suppress"`
}

type workflowCommitParams struct {
	Message  string            `yaml:"message"`
	Path     string            `yaml:"path"`
	Content  string            `yaml:"content"`
	Template string            `yaml:"template"`
	Params   map[string]any    `yaml:"params"`
	Files    map[string]any    `yaml:"files"`
	Delete   []string          `yaml:"delete"`
	Rename   map[string]string `yaml:"rename"`
	Secrets  string            `yaml:"secrets"`
	Suppress bool              `yaml:"suppress"`

	Trigger          []string          `yaml:"trigger"`
	TriggerWorkflows []string          `yaml:"trigger_workflows"`
	RunsOn           []string          `yaml:"runs_on"`
	Permissions      map[string]string `yaml:"permissions"`
	Environment      string            `yaml:"environment"`
	Needs            []string          `yaml:"needs"`
	TimeoutMinutes   int               `yaml:"timeout_minutes"`
}

func commitCode(ctx context.Context, s *Session, p commitCodeParams, in Inputs) (Commit, error) {
	st := staging{
		files:    p.Files,
		template: p.Template,
		params:   p.Params,
		path:     p.Path,
		content:  p.Content,
		script:   p.Script,
		patch:    p.Patch,
		delete:   p.Delete,
		rename:   p.Rename,
		suppress: p.Suppress,
		flavor:   payload.Shell,
	}
	return authorCommit(ctx, s, in, p.Message, st)
}

func workflowCommit(ctx context.Context, s *Session, p workflowCommitParams, in Inputs) (Commit, error) {
	job, err := p.job()
	if err != nil {
		return Commit{}, err
	}
	st := staging{
		files:    p.Files,
		template: p.Template,
		params:   p.Params,
		path:     p.Path,
		content:  p.Content,
		delete:   p.Delete,
		rename:   p.Rename,
		suppress: p.Suppress,
		flavor:   payload.WorkflowSteps,
		job:      job,
	}
	return authorCommit(ctx, s, in, p.Message, st)
}

func authorCommit(ctx context.Context, s *Session, in Inputs, message string, st staging) (Commit, error) {
	on := In[WritableRef](in, "on").WriteRef()
	if message == "" {
		return Commit{}, errors.New("a commit needs a message")
	}
	if skipCIRe.MatchString(message) {
		return Commit{}, fmt.Errorf("commit message %q suppresses every workflow run, including the one this chain observes", message)
	}
	expect := ""
	if c, ok := InOpt[Commit](in, "expect"); ok {
		expect = c.SHA
	}

	g := s.GitData(on.Owner, on.Repo)
	change, err := st.build(ctx, s, g, on.Ref)
	if err != nil {
		return Commit{}, err
	}
	if change.empty() {
		return Commit{}, errors.New("this commit would change nothing")
	}
	return g.Commit(ctx, on.Ref, message, change, expect)
}

var (
	skipCIRe     = regexp.MustCompile(`(?i)\[(skip ci|ci skip|skip actions|actions skip)\]`)
	secretNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// staging is one commit's worth of authored content, before it becomes blobs.
// commit.code and workflow.commit differ only in the flavor they render and in
// whether the rendered fragment is wrapped in a workflow document.
type staging struct {
	files    map[string]any
	template string
	params   map[string]any
	path     string
	content  string
	script   string
	patch    string
	delete   []string
	rename   map[string]string
	suppress bool
	flavor   payload.Flavor
	job      workflowJob
}

func (st staging) build(ctx context.Context, s *Session, g GitData, ref string) (TreeChange, error) {
	ch := TreeChange{Files: map[string]TreeFile{}, Copies: map[string]string{}}

	add := func(p string, f TreeFile) error {
		if p == "" {
			return errors.New("a staged file needs a path")
		}
		if _, dup := ch.Files[p]; dup {
			return fmt.Errorf("path %q is staged twice in one commit", p)
		}
		if st.flavor == payload.Shell && strings.HasPrefix(p, workflowDir) {
			return fmt.Errorf("%s is under %s, which is a distinct capability boundary: use workflow.commit", p, workflowDir)
		}
		ch.Files[p] = f
		return nil
	}

	if st.template != "" {
		p := st.path
		if p == "" {
			p, _ = st.params["path"].(string)
		}
		body, err := st.render(s, st.template, p, st.params)
		if err != nil {
			return ch, err
		}
		if err := add(p, TreeFile{Bytes: []byte(body), Exec: st.flavor == payload.Shell}); err != nil {
			return ch, err
		}
	}
	if st.content != "" {
		if err := add(st.path, TreeFile{Bytes: []byte(st.content)}); err != nil {
			return ch, err
		}
	}
	if st.script != "" {
		if err := add(st.path, TreeFile{Bytes: []byte(st.script), Exec: true}); err != nil {
			return ch, err
		}
	}
	for _, p := range slices.Sorted(maps.Keys(st.files)) {
		f, err := st.stageEntry(s, p, st.files[p])
		if err != nil {
			return ch, err
		}
		if err := add(p, f); err != nil {
			return ch, err
		}
	}

	if st.patch != "" {
		if err := st.applyPatch(ctx, g, ref, &ch, add); err != nil {
			return ch, err
		}
	}

	for _, from := range slices.Sorted(maps.Keys(st.rename)) {
		to := st.rename[from]
		sha, err := g.BlobSHA(ctx, from, ref)
		if err := s.SoftRead(err, "read "+from); err != nil {
			return ch, fmt.Errorf("rename %s: %w", from, err)
		}
		if sha != "" {
			ch.Copies[to] = sha
		}
		ch.Deletions = append(ch.Deletions, from)
	}
	ch.Deletions = append(ch.Deletions, st.delete...)

	if st.suppress {
		wiped, err := st.suppressed(ctx, s, g, ref, ch)
		if err != nil {
			return ch, err
		}
		ch.Deletions = append(ch.Deletions, wiped...)
	}
	slices.Sort(ch.Deletions)
	ch.Deletions = slices.Compact(ch.Deletions)
	return ch, nil
}

// stageEntry reads one files: value: a scalar is literal content, a mapping is a
// payload fragment rendered to that path.
func (st staging) stageEntry(s *Session, p string, raw any) (TreeFile, error) {
	switch v := raw.(type) {
	case string:
		return TreeFile{Bytes: []byte(v)}, nil
	case map[string]any:
		id, _ := v["template"].(string)
		if id == "" {
			return TreeFile{}, fmt.Errorf("files[%q]: a mapping must name a template", p)
		}
		params, _ := v["params"].(map[string]any)
		body, err := st.render(s, id, p, params)
		if err != nil {
			return TreeFile{}, err
		}
		return TreeFile{Bytes: []byte(body), Exec: st.flavor == payload.Shell}, nil
	case nil:
		return TreeFile{}, fmt.Errorf("files[%q]: no content", p)
	default:
		return TreeFile{}, fmt.Errorf("files[%q]: want a string or a {template, params} mapping, got %T", p, raw)
	}
}

// render turns a fragment into file content. A workflow-flavor fragment renders
// job steps, so it is wrapped in a document here rather than in the corpus: the
// trigger and every job-level key the emitted job carries are the committing
// step's decision, not the fragment's.
func (st staging) render(s *Session, id, at string, params map[string]any) (string, error) {
	body, err := payload.Render(id, params, s.PayloadEnv())
	if err != nil {
		return "", err
	}
	if st.flavor != payload.WorkflowSteps {
		return body, nil
	}
	return composeWorkflow(at, st.job, body, s.PayloadEnv().PubKey), nil
}

func (st staging) applyPatch(ctx context.Context, g GitData, ref string, ch *TreeChange, add func(string, TreeFile) error) error {
	files, err := parsePatch(st.patch)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.newPath == "" {
			ch.Deletions = append(ch.Deletions, f.oldPath)
			continue
		}
		src := ""
		if f.oldPath != "" {
			b, err := g.FileBytes(ctx, f.oldPath, ref)
			if err != nil {
				return fmt.Errorf("patch %s: %w", f.oldPath, err)
			}
			src = string(b)
		}
		out, err := applyHunks(f.newPath, src, f.hunks)
		if err != nil {
			return err
		}
		if err := add(f.newPath, TreeFile{Bytes: []byte(out)}); err != nil {
			return err
		}
		if f.oldPath != "" && f.oldPath != f.newPath {
			ch.Deletions = append(ch.Deletions, f.oldPath)
		}
	}
	return nil
}

// suppressed lists every workflow this commit is not itself writing. It is all
// or nothing by design: the two reference chains want opposite settings, and one
// word in the plan says which.
func (st staging) suppressed(ctx context.Context, s *Session, g GitData, ref string, ch TreeChange) ([]string, error) {
	client, err := s.Client()
	if err != nil {
		return nil, s.SoftRead(err, "list workflows to suppress")
	}
	head, err := getString(ctx, client, gitRefReadPath(g.Owner, g.Repo, ref), "object", "sha")
	if err != nil {
		return nil, s.SoftRead(err, "read "+ref)
	}
	paths, _, err := g.Tree(ctx, head)
	if err != nil {
		return nil, s.SoftRead(err, "read tree "+head)
	}
	var out []string
	for p := range paths {
		if !strings.HasPrefix(p, workflowDir) {
			continue
		}
		if _, written := ch.Files[p]; written {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// secretsEnv turns `secrets: all|<name>` into the job environment the emitted
// workflow carries. The aggregate-secrets variable removes any need to enumerate
// names first; a single name is the narrow form. The spec itself is screened by
// envelopeErrors, offline, before any request is issued.
func secretsEnv(spec string) map[string]string {
	switch {
	case spec == "":
		return nil
	case spec == "all":
		return map[string]string{"TRAJAN_SECRETS": "${{ toJSON(secrets) }}"}
	default:
		return map[string]string{spec: "${{ secrets." + spec + " }}"}
	}
}

// workflowJob is the document envelope a workflow_steps fragment is wrapped in.
// Every field is a key the fragment has no way to emit for itself, and every one
// of them changes what the job can reach rather than what it does.
type workflowJob struct {
	trigger          []string
	triggerWorkflows []string
	runsOn           []string
	permissions      map[string]string
	environment      string
	needs            []string
	timeoutMinutes   int
	env              map[string]string
}

func (p workflowCommitParams) job() (workflowJob, error) {
	var hard []error
	for _, e := range p.envelopeErrors() {
		if !IsWarning(e) {
			hard = append(hard, e)
		}
	}
	if len(hard) > 0 {
		return workflowJob{}, errors.Join(hard...)
	}
	return workflowJob{
		trigger:          p.Trigger,
		triggerWorkflows: p.TriggerWorkflows,
		runsOn:           p.RunsOn,
		permissions:      p.Permissions,
		environment:      p.Environment,
		needs:            p.Needs,
		timeoutMinutes:   p.TimeoutMinutes,
		env:              secretsEnv(p.Secrets),
	}, nil
}

// composeWorkflow wraps rendered steps in a document. The default trigger is the
// push that delivers it, which is the one event the committing step is certain to
// fire; a plan that measures a different boundary names the events it needs.
//
// No permissions: block is emitted unless the plan asked for one. That is
// deliberate: the repository or organization default left in force is itself an
// observable this tool reports on, and an explicit block would replace it with
// ours.
//
// A non-empty pubPEM means the plan set encryption: the fragment steps are then
// bracketed by a setup and a seal step so the marker stream leaves the runner as
// ciphertext rather than in the world-readable log.
func composeWorkflow(at string, job workflowJob, steps, pubPEM string) string {
	name := path.Base(at)
	name = strings.TrimSuffix(name, path.Ext(name))

	if pubPEM != "" {
		setup, seal := sealSteps(pubPEM)
		steps = setup + "\n" + strings.TrimRight(steps, "\n") + "\n" + seal
	}

	var b strings.Builder
	fmt.Fprintf(&b, "name: %s\n\n%s\njobs:\n  verify:\n", name, job.on())
	if len(job.needs) > 0 {
		fmt.Fprintf(&b, "    needs: %s\n", yamlFlowSeq(job.needs))
	}
	fmt.Fprintf(&b, "    runs-on: %s\n", runsOnValue(job.runsOn))
	if len(job.permissions) > 0 {
		b.WriteString("    permissions:\n")
		for _, k := range slices.Sorted(maps.Keys(job.permissions)) {
			fmt.Fprintf(&b, "      %s: %s\n", k, job.permissions[k])
		}
	}
	if job.environment != "" {
		fmt.Fprintf(&b, "    environment: %s\n", yamlScalar(job.environment))
	}
	fmt.Fprintf(&b, "    timeout-minutes: %d\n", cmp.Or(job.timeoutMinutes, defaultTimeoutMinutes))
	if len(job.env) > 0 {
		b.WriteString("    env:\n")
		for _, k := range slices.Sorted(maps.Keys(job.env)) {
			fmt.Fprintf(&b, "      %s: %s\n", k, job.env[k])
		}
	}
	b.WriteString("    steps:\n")
	// Every rendered line shifts by the same prefix: the freeform fragment
	// interpolates an operator-supplied file at column 0, and uneven indentation
	// would corrupt it.
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

// on renders the trigger envelope. workflow_run carries the upstream workflow
// names and is pinned to completed: the requested type fires before the upstream
// job has produced anything, which for a handoff measurement is a run that
// observes nothing.
func (j workflowJob) on() string {
	events := j.trigger
	if len(events) == 0 {
		events = []string{defaultTrigger}
	}
	var b strings.Builder
	b.WriteString("on:\n")
	for _, ev := range events {
		if ev == "workflow_run" {
			fmt.Fprintf(&b, "  workflow_run:\n    workflows: %s\n    types: [completed]\n", yamlFlowSeq(j.triggerWorkflows))
			continue
		}
		fmt.Fprintf(&b, "  %s:\n", ev)
	}
	return b.String()
}

func runsOnValue(labels []string) string {
	switch len(labels) {
	case 0:
		return defaultRunsOn
	case 1:
		return yamlScalar(labels[0])
	default:
		return yamlFlowSeq(labels)
	}
}

var plainScalarRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func yamlScalar(s string) string {
	if plainScalarRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func yamlFlowSeq(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = yamlScalar(s)
	}
	return "[" + strings.Join(out, ", ") + "]"
}

// workflowEvents is what a plan may subscribe a composed job to: every event a
// primitive in this registry can provoke, plus the workflow_run cascade a chain
// measures rather than fires. An event outside the set is a workflow file GitHub
// refuses to parse, so it is refused here instead.
var workflowEvents = []string{
	"create", "delete", "fork", "issue_comment", "issues", "pull_request",
	"pull_request_review", "pull_request_review_comment", "pull_request_target",
	"push", "repository_dispatch", "workflow_dispatch", "workflow_run",
}

// permissionValues is the vocabulary of a permissions: entry; a value outside it is
// a workflow that fails at startup on the customer's repository.
var permissionValues = []string{"read", "write", "none"}

// narrowerPermissionValues are the scopes whose vocabulary is narrower than the
// general one, so a value permissionValues admits still fails the job at startup.
// id-token has no read level at all — it is write or nothing, which is what makes it
// opt-in — and vulnerability-alerts has no write level.
var narrowerPermissionValues = map[string][]string{
	"id-token":             {"write", "none"},
	"vulnerability-alerts": {"read", "none"},
}

func permissionValuesFor(scope string) []string {
	if v, narrower := narrowerPermissionValues[scope]; narrower {
		return v
	}
	return permissionValues
}

// permissionRank orders the levels so a scope asked for at read is satisfied by
// write, and none satisfies nothing.
var permissionRank = map[string]int{"none": 0, "read": 1, "write": 2}

// envelopeErrors is the offline screen on the job envelope, shared by Validate
// and by the primitive body so a value that only resolves at run time is checked
// too. It returns every problem at once, and a ValidationWarning for the one key
// whose correctness this composer cannot establish.
func (p workflowCommitParams) envelopeErrors() []error {
	var errs []error

	if p.Secrets != "" && p.Secrets != "all" && !secretNameRe.MatchString(p.Secrets) {
		errs = append(errs, fmt.Errorf("secrets: %q must be all or a secret name", p.Secrets))
	}

	seen := map[string]bool{}
	for _, ev := range p.Trigger {
		if !slices.Contains(workflowEvents, ev) {
			errs = append(errs, fmt.Errorf("trigger: %q is not an event a plan can subscribe a job to (%s)", ev, strings.Join(workflowEvents, ", ")))
		}
		if seen[ev] {
			errs = append(errs, fmt.Errorf("trigger: %q is declared twice, which is a duplicate key in the emitted on: block", ev))
		}
		seen[ev] = true
	}
	if seen["workflow_run"] && len(p.TriggerWorkflows) == 0 {
		errs = append(errs, errors.New("trigger: workflow_run needs trigger_workflows; unqualified it fires this job on every workflow run in the repository"))
	}
	if len(p.TriggerWorkflows) > 0 && !seen["workflow_run"] {
		errs = append(errs, errors.New("trigger_workflows names the upstream workflows of a workflow_run trigger, which this document does not declare"))
	}
	if p.Secrets != "" && !triggerDeliversSecrets(p.Trigger) {
		errs = append(errs, errors.New("secrets: a document triggered only by pull_request cannot deliver them — a run whose head is a fork gets a read-only token and none of the base repository's secrets; declare pull_request_target to run with the base repository's token and secrets, or push for a same-repository branch"))
	}

	for _, k := range slices.Sorted(maps.Keys(p.Permissions)) {
		// An unrecognized key fails the same way an unrecognized value does — GitHub
		// refuses to parse the document — so it is caught here rather than becoming a
		// failed run in the customer's audit trail that produces no evidence. The
		// vocabulary is the one the pipeline normalizes against, because a scope a plan
		// may name and a scope a finding may report on are the same table.
		if !slices.Contains(github.PermissionScopes, k) {
			errs = append(errs, fmt.Errorf("permissions[%s] is not a token permission scope, so the composed document does not parse (%s)", k, strings.Join(github.PermissionScopes, ", ")))
			continue
		}
		if allowed := permissionValuesFor(k); !slices.Contains(allowed, p.Permissions[k]) {
			errs = append(errs, fmt.Errorf("permissions[%s]: %q must be one of %s", k, p.Permissions[k], strings.Join(allowed, ", ")))
		}
	}
	errs = append(errs, p.permissionScopeErrors()...)
	if p.TimeoutMinutes < 0 {
		errs = append(errs, fmt.Errorf("timeout_minutes: %d is not a duration", p.TimeoutMinutes))
	}
	if p.setsJobKeys() && !p.composes() {
		errs = append(errs, errors.New("the job envelope keys shape a document this step composes from a fragment; this step stages literal content, which is committed exactly as written"))
	}
	if len(p.Needs) > 0 {
		errs = append(errs, ValidationWarning{"needs: names other jobs of the same workflow file, and this step composes a single job; the named jobs must already be in the document or the run cannot start"})
	}
	return errs
}

// permissionScopeErrors cross-checks the permissions: block against what the bound
// fragments declare they need. Specifying any scope sets every unspecified one to
// none, so a block written for one fragment's needs silently strips another's, and
// the result is a plan that validated clean and a job that either fails outright or
// records the negative observation that understates the finding. A scope no default
// ever grants is required even where there is no block at all, because nothing else
// can supply it.
func (p workflowCommitParams) permissionScopeErrors() []error {
	var errs []error
	for _, b := range p.boundFragments() {
		required, err := payload.RequiredPermissions(b.id, b.params)
		if err != nil {
			continue // a fragment that does not load is validatePayloads' to report
		}
		for _, req := range required {
			granted, present := p.Permissions[req.Scope]
			switch {
			case present:
				if permissionRank[granted] < permissionRank[req.Level] {
					errs = append(errs, fmt.Errorf("permissions[%s]: %q is below the %s that %s needs", req.Scope, granted, req.Level, b.id))
				}
			case len(p.Permissions) > 0:
				errs = append(errs, fmt.Errorf("permissions[%s] is absent, and %s needs %s: %s; specifying any permission sets every unspecified one to none, so this block strips it", req.Scope, b.id, req.Scope, req.Level))
			case github.OptInOnlyScopes[req.Scope]:
				errs = append(errs, fmt.Errorf("permissions[%s] is absent, and %s needs %s: %s, which no repository or organization default ever grants; a job that does not name it explicitly cannot have it", req.Scope, b.id, req.Scope, req.Level))
			}
		}
	}
	return errs
}

type boundFragment struct {
	id     string
	params map[string]any
}

// boundFragments is every fragment this step renders into the job it composes: the
// template: it names, and each files: entry that is a fragment mapping rather than
// literal content.
func (p workflowCommitParams) boundFragments() []boundFragment {
	var out []boundFragment
	if p.Template != "" {
		out = append(out, boundFragment{p.Template, p.Params})
	}
	for _, at := range slices.Sorted(maps.Keys(p.Files)) {
		entry, isMapping := p.Files[at].(map[string]any)
		if !isMapping {
			continue
		}
		if id, _ := entry["template"].(string); id != "" {
			params, _ := entry["params"].(map[string]any)
			out = append(out, boundFragment{id, params})
		}
	}
	return out
}

// triggerDeliversSecrets reports whether any declared event runs with the base
// repository's token and secrets. pull_request is the one event whose runs are
// demoted to a read-only token and no secrets when the head is a fork, which is
// the case a plan writing such a document is measuring.
func triggerDeliversSecrets(events []string) bool {
	if len(events) == 0 {
		return true
	}
	return slices.ContainsFunc(events, func(ev string) bool { return ev != "pull_request" })
}

func (p workflowCommitParams) setsJobKeys() bool {
	return len(p.Trigger) > 0 || len(p.TriggerWorkflows) > 0 || len(p.RunsOn) > 0 ||
		len(p.Permissions) > 0 || p.Environment != "" || len(p.Needs) > 0 ||
		p.TimeoutMinutes != 0 || p.Secrets != ""
}

func (p workflowCommitParams) composes() bool {
	if p.Template != "" {
		return true
	}
	return slices.ContainsFunc(slices.Collect(maps.Values(p.Files)), func(v any) bool {
		_, isFragment := v.(map[string]any)
		return isFragment
	})
}
