package ado

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	yaml "go.yaml.in/yaml/v4"
)

//go:embed sinks.yaml
var sinksYAML []byte

type patternEntry struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	compiled *regexp.Regexp
}

type sinkTable struct {
	Exec   []patternEntry `yaml:"exec_sinks"`
	AITask []patternEntry `yaml:"ai_task"`
	AICLI  []patternEntry `yaml:"ai_cli"`
}

var loadSinks = sync.OnceValue(func() sinkTable {
	var t sinkTable
	if err := yaml.Unmarshal(sinksYAML, &t); err != nil {
		panic(fmt.Errorf("parse ado sinks.yaml: %w", err))
	}
	for _, group := range [][]patternEntry{t.Exec, t.AITask, t.AICLI} {
		for i := range group {
			group[i].compiled = regexp.MustCompile(group[i].Pattern)
		}
	}
	return t
})

// executorTask records, for a shell/executor task, the shell dialect and which
// inputs are inline-script sinks (macros expand into a command line) vs argument
// sinks (macros concatenated onto the command line). This is fixed platform
// surface, so it lives in code rather than the data table.
type executorTask struct {
	shell        string
	scriptInputs []string
	argInputs    []string
}

var executorTasks = map[string]executorTask{
	"CmdLine@2":         {"cmd", []string{"script"}, nil},
	"Bash@3":            {"bash", []string{"script"}, []string{"arguments"}},
	"ShellScript@2":     {"bash", nil, []string{"args"}},
	"PowerShell@2":      {"powershell", []string{"script"}, []string{"arguments"}},
	"PowerShell@1":      {"powershell", []string{"script", "inlineScript"}, []string{"arguments"}},
	"PowerShell@0":      {"powershell", []string{"inlineScript"}, []string{"arguments"}},
	"AzureCLI@2":        {"azurecli", []string{"inlineScript"}, []string{"arguments"}},
	"AzureCLI@1":        {"azurecli", []string{"inlineScript"}, []string{"arguments"}},
	"AzurePowerShell@5": {"powershell", []string{"Inline"}, []string{"ScriptArguments"}},
	"Ssh@0":             {"ssh", []string{"inline", "commands"}, nil},
	"BatchScript@1":     {"cmd", nil, []string{"arguments"}},
	"SSH@0":             {"ssh", []string{"inline", "commands"}, nil},
}

var shorthandShells = map[string]string{
	"script": "cmd", "bash": "bash", "powershell": "powershell", "pwsh": "powershell",
}

// Predefined variables populated by the platform from attacker-controlled data
// (commit messages, branch names, PR fields). A `$(var)` reference to one of
// these is the cat-02 `predefined_variable` injection / cat-13 untrusted echo
// source. Keyed lowercase.
var untrustedPredefined = map[string]string{
	"build.sourceversionmessage":             "commit_message",
	"build.sourceversionauthor":              "commit_message",
	"build.sourcebranch":                     "branch_name",
	"build.sourcebranchname":                 "branch_name",
	"build.requestedfor":                     "requestor",
	"build.requestedforemail":                "requestor",
	"system.pullrequest.sourcebranch":        "pr_source_branch",
	"system.pullrequest.targetbranch":        "pr_target_branch",
	"system.pullrequest.sourcerepositoryuri": "pr_source_repo",
	"system.pullrequest.sourcecommitid":      "pr_source_commit",
}

// systemPrefixes mark platform-generated (non-user, non-attacker) variables that
// are NOT a queue-time injection surface. A macro whose name has one of these
// prefixes and is not in untrustedPredefined is treated as safe.
var systemPrefixes = []string{
	"build.", "system.", "agent.", "pipeline.", "environment.", "release.",
	"tf_build", "common.", "endpoint.", "resources.",
}

var (
	reMacro   = regexp.MustCompile(`\$\(([A-Za-z0-9_.]+)\)`)
	reParam   = regexp.MustCompile(`\$\{\{\s*parameters\.([A-Za-z0-9_]+)`)
	reParamIx = regexp.MustCompile(`\$\{\{\s*parameters\[\s*'([^']+)'`)
	reRuntime = regexp.MustCompile(`\$\[\s*variables\[?\s*'?([A-Za-z0-9_.]+)`)
	reVsoLit  = regexp.MustCompile(`##vso\[`)
	reCat     = regexp.MustCompile(`(?i)(^|\s|;|&&|\|)(cat|type|Get-Content|gc)\s+[./\\$]`)
	reHTTP    = regexp.MustCompile(`(?i)(^|\s|;|&&|\|)(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr)\b`)
)

// macroKind classifies a `$(name)` variable reference. "system" macros are not an
// injection surface; "predefined_untrusted" carry attacker-controlled data;
// "user" are pipeline/queue-time variables (the primary cat-02 surface).
func macroKind(name string) string {
	lower := strings.ToLower(name)
	if _, ok := untrustedPredefined[lower]; ok {
		return "predefined_untrusted"
	}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(lower, p) {
			return "system"
		}
	}
	return "user"
}

// macroNames returns the distinct `$(var)` names in a string (order-stable).
func macroNames(s string) []string {
	return uniqueSubmatch(reMacro.FindAllStringSubmatch(s, -1))
}

// paramNames returns the distinct compile-time expansion selectors: `${{ parameters.x }}`,
// `${{ parameters['x'] }}`, and `$[ variables['x'] ]` runtime expressions.
func paramNames(s string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, re := range []*regexp.Regexp{reParam, reParamIx, reRuntime} {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}

func uniqueSubmatch(matches [][]string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// classifyExecSink returns the first exec-sink name matching the script body and
// whether the body executes checked-out code.
func classifyExecSink(script string) (string, bool) {
	for _, e := range loadSinks().Exec {
		if e.compiled.MatchString(script) {
			return e.Name, true
		}
	}
	return "", false
}

func matchesAITask(task string) bool {
	for _, e := range loadSinks().AITask {
		if e.compiled.MatchString(task) {
			return true
		}
	}
	return false
}

func matchesAICLI(script string) bool {
	for _, e := range loadSinks().AICLI {
		if e.compiled.MatchString(script) {
			return true
		}
	}
	return false
}

func aiVendor(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "claude") || strings.Contains(l, "anthropic"):
		return "anthropic"
	case strings.Contains(l, "openai") || strings.Contains(l, "gpt") || strings.Contains(l, "azureopenai"):
		return "azure_openai"
	case strings.Contains(l, "copilot"):
		return "github_copilot"
	case strings.Contains(l, "gemini"):
		return "google_gemini"
	case strings.Contains(l, "bedrock"):
		return "aws_bedrock"
	}
	return "custom_llm"
}

// aiCapabilities infers the AI task/CLI's agentic reach from its script/inputs.
func aiCapabilities(text string) []any {
	l := strings.ToLower(text)
	var caps []any
	add := func(c string) { caps = append(caps, c) }
	if strings.Contains(l, "--allow-tool") || strings.Contains(l, "--tool") || strings.Contains(l, "tools") || strings.Contains(l, "agent") {
		add("tool_exec")
	}
	if strings.Contains(l, "system.accesstoken") {
		add("id_token")
	}
	if strings.Contains(l, "curl") || strings.Contains(l, "wget") || strings.Contains(l, "http") || strings.Contains(l, "egress") {
		add("egress")
	}
	if strings.Contains(l, "commit") || strings.Contains(l, "git push") || strings.Contains(l, "git commit") {
		add("auto_commit")
	}
	if strings.Contains(l, "pull request") || strings.Contains(l, "--pr") || strings.Contains(l, "az repos pr") {
		add("auto_pr")
	}
	if caps == nil {
		caps = []any{}
	}
	return caps
}

var bareBinaries = []string{
	"git", "az", "kubectl", "python", "python3", "dotnet", "npm", "node",
	"terraform", "gpg", "docker", "helm", "aws", "gcloud", "make", "bash",
}

var bareBinaryRes = sync.OnceValue(func() map[string]*regexp.Regexp {
	m := map[string]*regexp.Regexp{}
	for _, bin := range bareBinaries {
		m[bin] = regexp.MustCompile(`(?m)(^|\s|;|&&|\||\()` + regexp.QuoteMeta(bin) + `\s`)
	}
	return m
})

// bareBinaryCalls returns the recognized binaries a script invokes by bare name
// (not an absolute/relative path) — the cat-13 prependpath-shadow sink surface.
func bareBinaryCalls(script string) []string {
	var out []string
	res := bareBinaryRes()
	for _, bin := range bareBinaries {
		if res[bin].MatchString(script) {
			out = append(out, bin)
		}
	}
	return out
}

// tasks that authenticate and write a credential file to the agent workspace —
// the earlier-writes-secret-file precondition for cat-13 artifact exfiltration.
var credWritingTasks = map[string]string{
	"Docker@2":             "~/.docker/config.json",
	"Docker@1":             "~/.docker/config.json",
	"AzureCLI@2":           "~/.azure",
	"AzureCLI@1":           "~/.azure",
	"npmAuthenticate@0":    "~/.npmrc",
	"Kubernetes@1":         "~/.kube/config",
	"KubernetesManifest@1": "~/.kube/config",
}

var reCondVar = regexp.MustCompile(`variables\[\s*'([^']+)'\s*\]|variables\.([A-Za-z0-9_.]+)`)

// conditionVars returns the variable names a step `condition:` reads — the
// setvariable control-flip consumer surface (cat-13).
func conditionVars(cond string) []string {
	var out []string
	for _, m := range reCondVar.FindAllStringSubmatch(cond, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else if m[2] != "" {
			out = append(out, m[2])
		}
	}
	return out
}

// untrustedEcho reports whether a script body prints attacker-controlled data to
// stdout (the cat-13 logging-injection source), and what kind.
func untrustedEcho(body string) (string, bool) {
	for _, name := range macroNames(body) {
		if src, ok := untrustedPredefined[strings.ToLower(name)]; ok {
			return src, true
		}
	}
	switch {
	case reCat.MatchString(body):
		return "file_content", true
	case reHTTP.MatchString(body):
		return "http_response", true
	case reVsoLit.MatchString(body):
		return "literal_vso", true
	}
	return "", false
}

func echoMechanism(shell string) string {
	switch shell {
	case "powershell":
		return "PowerShell"
	case "cmd":
		return "CmdLine"
	}
	return "script"
}

func splitTaskVersion(task string) (id, version string) {
	if i := strings.LastIndex(task, "@"); i >= 0 {
		return task[:i], task[i+1:]
	}
	return task, ""
}

func macroSinkRec(name, location, task string, stepIdx int, settable map[string]bool) map[string]any {
	return map[string]any{
		"macro_name": name, "location": location, "task_name": task, "step_index": stepIdx,
		"is_declared_settable": settable[name], "macro_kind": macroKind(name),
	}
}

func paramSinkRec(name, location, keyword, task string, stepIdx int) map[string]any {
	return map[string]any{
		"param_name": name, "location": location, "keyword": keyword,
		"task_name": task, "step_index": stepIdx,
	}
}

func taskUsageRec(task string, stepIdx int) map[string]any {
	id, version := splitTaskVersion(task)
	rec := map[string]any{"task": task, "task_id": id, "version": version, "step_index": stepIdx}
	switch {
	case executorTasks[task].shell != "":
		rec["is_sink"], rec["sink_form"], rec["sink_kind"] = true, "script", "inline_script"
	case matchesAITask(task):
		rec["is_sink"], rec["sink_form"], rec["sink_kind"] = true, "ai_agent", "ai_task"
	default:
		rec["is_sink"], rec["sink_form"], rec["sink_kind"] = false, "", ""
	}
	return rec
}

func aiTaskRec(task string, inputs map[string]any, stepIdx int) map[string]any {
	blob := task
	for _, k := range sortedKeys(inputs) {
		blob += " " + yamlStr(inputs[k])
	}
	return map[string]any{
		"task_id": task, "vendor": aiVendor(task), "capabilities": aiCapabilities(blob),
		"inputs": inputs, "source": "task", "step_index": stepIdx,
	}
}

func poolExpr(v any) string {
	switch p := v.(type) {
	case string:
		return p
	case map[string]any:
		return yamlStr(p["name"]) + " " + yamlStr(p["vmImage"])
	}
	return ""
}

var compileKeywordInputs = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range scInputNames {
		m[n] = true
	}
	return m
}()

func isCompileKeywordInput(name string) bool { return compileKeywordInputs[name] }

// settableVariablesOf extracts a `variables:` block's `settableVariables:`
// declaration: nil (absent — all overridable), or the restricting name list
// ([] = none). Only the mapping form carries this key.
func settableVariablesOf(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	sv, present := m["settableVariables"]
	if !present {
		return nil
	}
	list, ok := sv.([]any)
	if !ok {
		return []any{}
	}
	out := make([]any, 0, len(list))
	for _, e := range list {
		out = append(out, yamlStr(e))
	}
	return out
}

// settableVarSet is the set of definition variables flagged allowOverride=true —
// the queue-time-settable surface when the org/project limit is enforced.
func settableVarSet(vars map[string]any) map[string]bool {
	out := map[string]bool{}
	for name, v := range vars {
		if entBool(entMap(v)["allowOverride"]) {
			out[name] = true
		}
	}
	return out
}

func mergeSettable(base map[string]bool, extra any) map[string]bool {
	out := make(map[string]bool, len(base))
	for k, v := range base {
		out[k] = v
	}
	if list, ok := extra.([]any); ok {
		for _, e := range list {
			if s, _ := e.(string); s != "" {
				out[s] = true
			}
		}
	}
	return out
}

func sortedSet(m map[string]bool) []any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}
