package ado

import (
	"reflect"
	"testing"
)

func TestMacroKind(t *testing.T) {
	cases := map[string]string{
		"deployTarget":                    "user",
		"buildConfig":                     "user",
		"Build.BuildId":                   "system",
		"Agent.HomeDirectory":             "system",
		"System.DefaultWorkingDirectory":  "system",
		"Build.SourceVersionMessage":      "predefined_untrusted",
		"System.PullRequest.SourceBranch": "predefined_untrusted",
	}
	for name, want := range cases {
		if got := macroKind(name); got != want {
			t.Errorf("macroKind(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestMacroNames(t *testing.T) {
	// distinct names; shell command substitution `$(find ...)` (has spaces) is NOT
	// an ADO macro and must be excluded.
	got := macroNames(`P=$(find . -name '*.zip'); echo $(deployTarget) $(deployTarget) $(Build.BuildId)`)
	want := []string{"deployTarget", "Build.BuildId"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("macroNames = %v, want %v", got, want)
	}
}

func TestParamNames(t *testing.T) {
	got := paramNames(`img:${{ parameters.tag }} $[ variables['containerImage'] ] ${{ parameters.tag }}`)
	want := []string{"tag", "containerImage"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paramNames = %v, want %v", got, want)
	}
}

// parameterRefs and runtimeVarRefs split the selector surface by queue-time
// settability: a ${{ parameters }} selector is always settable, a $[ variables ]
// runtime expression only when declared settable.
func TestParameterVsRuntimeVarRefs(t *testing.T) {
	s := `${{ parameters.tag }} $[ variables['containerImage'] ] ${{ parameters['pool'] }} $[ variables['env'] ]`
	if got, want := parameterRefs(s), []string{"tag", "pool"}; !reflect.DeepEqual(got, want) {
		t.Errorf("parameterRefs = %v, want %v", got, want)
	}
	if got, want := runtimeVarRefs(s), []string{"containerImage", "env"}; !reflect.DeepEqual(got, want) {
		t.Errorf("runtimeVarRefs = %v, want %v", got, want)
	}
}

// cat-02 compile-keyword redirect: a ${{ parameters }} selector is tagged as an
// always-settable parameter (no source_kind), while a $[ variables['x'] ] runtime
// expression is tagged runtime_var and carries its declared-settable state, so the
// correlator can suppress it when the queue-time-settable limit is enforced.
func TestScanCompileKeyword_SourceKind(t *testing.T) {
	var f jobFacts
	scanCompileKeyword(&f, "pool", "${{ parameters.poolName }}", -1, "", nil)
	scanCompileKeyword(&f, "container", "$[ variables['containerImage'] ]", -1, "", map[string]bool{"containerImage": false})
	scanCompileKeyword(&f, "container", "$[ variables['tag'] ]", -1, "", map[string]bool{"tag": true})

	if len(f.paramSinks) != 3 {
		t.Fatalf("want 3 param sinks, got %d: %v", len(f.paramSinks), f.paramSinks)
	}
	param := f.paramSinks[0].(map[string]any)
	if param["param_name"] != "poolName" || param["source_kind"] != nil {
		t.Errorf("parameter sink = %v, want poolName with no source_kind", param)
	}
	unsettable := f.paramSinks[1].(map[string]any)
	if unsettable["param_name"] != "containerImage" || unsettable["source_kind"] != "runtime_var" || unsettable["is_declared_settable"] != false {
		t.Errorf("runtime-var sink = %v, want containerImage/runtime_var/not-settable", unsettable)
	}
	settable := f.paramSinks[2].(map[string]any)
	if settable["source_kind"] != "runtime_var" || settable["is_declared_settable"] != true {
		t.Errorf("declared-settable runtime-var sink = %v", settable)
	}
}

func TestClassifyExecSink(t *testing.T) {
	if _, ok := classifyExecSink("npm ci && npm run build"); !ok {
		t.Error("npm ci should be an exec sink")
	}
	if _, ok := classifyExecSink(`echo "hello world"`); ok {
		t.Error("a bare echo is not an exec sink")
	}
}

func TestUntrustedEcho(t *testing.T) {
	cases := []struct {
		body, want string
		ok         bool
	}{
		{`echo "commit: $(Build.SourceVersionMessage)"`, "commit_message", true},
		{`echo "branch: $(Build.SourceBranchName)"`, "branch_name", true},
		{`cat ./build-info.txt`, "file_content", true},
		{`curl https://api.example/x`, "http_response", true},
		{`echo "safe: $(Build.BuildId)"`, "", false},
	}
	for _, c := range cases {
		got, ok := untrustedEcho(c.body)
		if ok != c.ok || got != c.want {
			t.Errorf("untrustedEcho(%q) = (%q,%v), want (%q,%v)", c.body, got, ok, c.want, c.ok)
		}
	}
}

func TestMatchesAI(t *testing.T) {
	if !matchesAITask("VendorAIReview@2") {
		t.Error("VendorAIReview@2 should match an AI task")
	}
	if matchesAITask("CmdLine@2") {
		t.Error("CmdLine@2 is not an AI task")
	}
	if !matchesAICLI(`claude -p "summarize $BODY" --allow-tool bash`) {
		t.Error("claude CLI should match ai_cli")
	}
	if !matchesAICLI(`gemini -p "Generate a deploy script for $DESC" > gen.sh`) {
		t.Error("gemini CLI should match ai_cli")
	}
	if !matchesAICLI(`codex exec "fix the failing test"`) {
		t.Error("codex CLI should match ai_cli")
	}
	if matchesAICLI("make build") {
		t.Error("make is not an AI CLI")
	}
}

// generate_then_execute is distinguished by the AI redirecting output into a
// script file, NOT by agentic tool_exec: `gemini ... > gen.sh` is
// generate-then-execute; `claude ... --allow-tool bash` (direct/agentic) and a
// non-script redirect are not.
func TestWritesGeneratedScript(t *testing.T) {
	yes := []string{
		`gemini -p "Generate a bash deploy script for $DESC" > gen.sh`,
		`claude -p "write the pipeline" >> build/run.ps1`,
	}
	no := []string{
		`claude -p "review $BODY" --allow-tool bash`,
		`gemini -p "summarize this PR" > summary.md`,
		`echo hello`,
	}
	for _, s := range yes {
		if !writesGeneratedScript(s) {
			t.Errorf("writesGeneratedScript(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if writesGeneratedScript(s) {
			t.Errorf("writesGeneratedScript(%q) = true, want false", s)
		}
	}
}

func TestBareBinaryCalls(t *testing.T) {
	got := bareBinaryCalls("kubectl apply -f ./k8s/\naz account show")
	want := []string{"az", "kubectl"}
	// order follows the bareBinaries registry
	if len(got) != 2 || !contains(got, "kubectl") || !contains(got, "az") {
		t.Errorf("bareBinaryCalls = %v, want %v (any order)", got, want)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// walkSteps mirrors the shape yaml.Unmarshal produces (map[string]any/[]any).

// cat-13 setvariable control-flip (firing-range Bree/296): a banner step echoes
// the untrusted commit message; a later step's condition consumes the variable.
func TestWalkSteps_LoggingControlFlip(t *testing.T) {
	steps := []any{
		map[string]any{"checkout": "self"},
		map[string]any{"script": `echo "Building commit: $(Build.SourceVersionMessage)"`},
		map[string]any{"script": "./deploy.sh", "condition": "eq(variables.deployToProd, 'true')"},
	}
	f := walkSteps(steps, nil)

	if len(f.vsoEchoSources) != 1 {
		t.Fatalf("want 1 vso echo source, got %d", len(f.vsoEchoSources))
	}
	echo := f.vsoEchoSources[0].(map[string]any)
	if echo["untrusted_source"] != "commit_message" || echo["step_index"] != 1 {
		t.Errorf("echo = %v, want commit_message@1", echo)
	}
	if !hasConsumer(f.varConsumers, "deployToProd", 2, "condition") {
		t.Errorf("want deployToProd condition consumer @2, got %v", f.varConsumers)
	}
}

// cat-02 unrestricted macro into a script sink (firing-range Rohan/197).
func TestWalkSteps_MacroScriptSink(t *testing.T) {
	steps := []any{
		map[string]any{"script": "echo $(deployTarget)\n./deploy.sh --env $(deployTarget)"},
	}
	f := walkSteps(steps, map[string]bool{"deployTarget": true})
	if len(f.macroSinks) != 1 { // deduped within the body
		t.Fatalf("want 1 macro sink, got %d: %v", len(f.macroSinks), f.macroSinks)
	}
	ms := f.macroSinks[0].(map[string]any)
	if ms["macro_name"] != "deployTarget" || ms["location"] != "script" ||
		ms["macro_kind"] != "user" || ms["is_declared_settable"] != true {
		t.Errorf("macro sink = %v", ms)
	}
}

// cat-02 settable var into task arguments (firing-range Rohan/198): a macro in a
// Bash@3 `arguments` input is a macro_in_task_input sink; a system var is not.
func TestWalkSteps_ArgumentsSink(t *testing.T) {
	steps := []any{
		map[string]any{"task": "Bash@3", "inputs": map[string]any{
			"targetType": "filePath", "filePath": "build/run.sh", "arguments": "--config $(buildConfig)",
		}},
	}
	f := walkSteps(steps, nil)
	if len(f.macroSinks) != 1 {
		t.Fatalf("want 1 macro sink, got %d", len(f.macroSinks))
	}
	ms := f.macroSinks[0].(map[string]any)
	if ms["location"] != "task_input" || ms["macro_name"] != "buildConfig" || ms["task_name"] != "Bash@3" {
		t.Errorf("arguments sink = %v", ms)
	}
}

// cat-02 freeform parameter into a compile-time keyword (firing-range Rohan/201).
func TestWalkSteps_ParamCompileKeyword(t *testing.T) {
	steps := []any{
		map[string]any{"task": "AzureCLI@2", "inputs": map[string]any{
			"azureSubscription": "${{ parameters.connection }}", "scriptType": "bash",
			"scriptLocation": "inlineScript", "inlineScript": "az account show",
		}},
	}
	f := walkSteps(steps, nil)
	if !hasParamSink(f.paramSinks, "connection", "compile_keyword", "azureSubscription") {
		t.Errorf("want connection compile_keyword sink on azureSubscription, got %v", f.paramSinks)
	}
}

func hasConsumer(list []any, name string, step int, via string) bool {
	for _, e := range list {
		m := e.(map[string]any)
		if m["name"] == name && m["step_index"] == step && m["via"] == via {
			return true
		}
	}
	return false
}

func hasParamSink(list []any, name, loc, keyword string) bool {
	for _, e := range list {
		m := e.(map[string]any)
		if m["param_name"] == name && m["location"] == loc && m["keyword"] == keyword {
			return true
		}
	}
	return false
}

// collectSteps must gather steps from every deployment lifecycle hook, not just
// deploy — preDeploy/postRouteTraffic/on.failure steps carry real task facts.
func TestCollectSteps_DeploymentHooks(t *testing.T) {
	m := map[string]any{"strategy": map[string]any{"runOnce": map[string]any{
		"preDeploy":        map[string]any{"steps": []any{map[string]any{"script": "echo pre"}}},
		"deploy":           map[string]any{"steps": []any{map[string]any{"script": "echo deploy"}}},
		"routeTraffic":     map[string]any{"steps": []any{map[string]any{"script": "echo route"}}},
		"postRouteTraffic": map[string]any{"steps": []any{map[string]any{"script": "echo post"}}},
		"on": map[string]any{
			"failure": map[string]any{"steps": []any{map[string]any{"script": "echo fail"}}},
			"success": map[string]any{"steps": []any{map[string]any{"script": "echo ok"}}},
		},
	}}}
	if got := len(collectSteps(m)); got != 6 {
		t.Errorf("collectSteps gathered %d hook steps, want 6", got)
	}
}
