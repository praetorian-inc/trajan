package gitlab

import (
	"slices"
	"testing"
)

func parseJob(t *testing.T, yaml string) map[string]any {
	t.Helper()
	p, err := parseCIPipeline([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestParseCIPipelineSpecHeader(t *testing.T) {
	// A spec: header document precedes ---; the pipeline is the second document.
	p := parseJob(t, "spec:\n  inputs:\n    version:\n      default: latest\n---\ndeploy:\n  script:\n    - ./release.sh $[[ inputs.version ]]\n")
	names := jobNames(p)
	if !slices.Equal(names, []string{"deploy"}) {
		t.Fatalf("jobNames=%v want [deploy]", names)
	}
}

func TestParseCIPipelineCommentOnlyIsEmpty(t *testing.T) {
	p, err := parseCIPipeline([]byte("# only a comment\n"))
	if err != nil || p != nil {
		t.Fatalf("comment-only should be (nil,nil); got p=%v err=%v", p, err)
	}
}

func TestJobNamesFiltersReservedAndHidden(t *testing.T) {
	p := parseJob(t, "variables:\n  X: 1\nstages: [build]\n.hidden:\n  script: [x]\nbuild:\n  script: [y]\npages:\n  script: [z]\n")
	names := jobNames(p)
	slices.Sort(names)
	if !slices.Equal(names, []string{"build", "pages"}) {
		t.Fatalf("jobNames=%v want [build pages] (pages is a real job, .hidden/variables/stages excluded)", names)
	}
}

func TestResolveTriggersMergeRequestOnly(t *testing.T) {
	// A rule pinning $CI_PIPELINE_SOURCE == "merge_request_event" narrows the set.
	p := parseJob(t, "test:\n  script: [x]\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n")
	tr := resolveTriggers(entMap(p["test"]), nil)
	if !slices.Equal(tr, []string{"merge_request_event"}) {
		t.Fatalf("triggers=%v want [merge_request_event]", tr)
	}
}

func TestResolveTriggersUnconstrainedIsBroad(t *testing.T) {
	// A ref-name rule does not constrain the pipeline source: broad reachability.
	p := parseJob(t, "test:\n  script: [x]\n  rules:\n    - if: '$CI_COMMIT_BRANCH == \"main\"'\n")
	tr := resolveTriggers(entMap(p["test"]), nil)
	if !hasMergeRequestTrigger(tr) || len(tr) != len(allTriggers) {
		t.Fatalf("triggers=%v want full set", tr)
	}
}

func TestProtectedRefGate(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"strong", "j:\n  script: [x]\n  rules:\n    - if: '$CI_COMMIT_REF_PROTECTED == \"true\"'\n", "strong"},
		{"weak-default", "j:\n  script: [x]\n  rules:\n    - if: '$CI_COMMIT_REF_NAME == \"main\"'\n", "weak"},
		{"weak-tag", "j:\n  script: [x]\n  rules:\n    - if: '$CI_COMMIT_TAG'\n", "weak"},
		{"none", "j:\n  script: [x]\n", "none"},
		{"none-feature", "j:\n  script: [x]\n  rules:\n    - if: '$CI_COMMIT_BRANCH =~ /^deploy/'\n", "none"},
	}
	for _, c := range cases {
		p := parseJob(t, c.yaml)
		if got := protectedRefGate(entMap(p["j"]), nil); got != c.want {
			t.Errorf("%s: gate=%q want %q", c.name, got, c.want)
		}
	}
}

func TestRunsOnUntrustedRef(t *testing.T) {
	if runsOnUntrustedRef([]string{"push"}, "strong") {
		t.Error("strong gate must not be untrusted-ref reachable")
	}
	if !runsOnUntrustedRef([]string{"merge_request_event"}, "none") {
		t.Error("MR-event with no gate must be untrusted-ref reachable")
	}
	if runsOnUntrustedRef([]string{"push"}, "weak") {
		t.Error("weak gate (protected branch pin) is not untrusted")
	}
}

func TestClassifyIncludesRemoteUntrusted(t *testing.T) {
	inc, f := classifyIncludes([]any{
		map[string]any{"remote": "https://vendor.example.com/build.yml"},
	}, "gitlab.example.org", "trajan-fr-group")
	if len(inc) != 1 {
		t.Fatalf("want 1 include, got %d", len(inc))
	}
	tup := inc[0].(map[string]any)
	if tup["type"] != "remote" || tup["cross_trust"] != true {
		t.Errorf("remote from foreign host must be cross_trust: %v", tup)
	}
	if !f.remoteUntrustedHost {
		t.Error("unpinned foreign remote must flag remoteUntrustedHost")
	}
}

func TestClassifyIncludesRemoteCleartext(t *testing.T) {
	_, f := classifyIncludes([]any{
		map[string]any{"remote": "http://vendor.example.com/build.yml"},
	}, "gitlab.example.org", "ns")
	if !f.remoteCleartext {
		t.Error("http:// remote with no integrity must flag cleartext")
	}
}

func TestClassifyIncludesProjectMutableCrossTrust(t *testing.T) {
	// A project include at a branch ref (main) in a different namespace is mutable
	// cross-trust; a pinned SHA is not.
	_, mutable := classifyIncludes([]any{
		map[string]any{"project": "shared/ci-templates", "ref": "main", "file": "/x.yml"},
	}, "gitlab.example.org", "trajan-fr-group")
	if !mutable.mutableCrossTrust {
		t.Error("branch ref in foreign namespace must flag mutableCrossTrust")
	}
	_, pinned := classifyIncludes([]any{
		map[string]any{"project": "shared/ci-templates", "ref": "0123456789abcdef0123456789abcdef01234567", "file": "/x.yml"},
	}, "gitlab.example.org", "trajan-fr-group")
	if pinned.mutableCrossTrust {
		t.Error("40-hex SHA ref must not be mutable")
	}
}

func TestIsPinnedRef(t *testing.T) {
	if !isPinnedRef("0123456789abcdef0123456789abcdef01234567") {
		t.Error("40-hex is pinned")
	}
	if !isPinnedRef("v1.2.3") {
		t.Error("semver tag is pinned")
	}
	if isPinnedRef("main") || isPinnedRef("~latest") || isPinnedRef("") {
		t.Error("branch/moving/empty ref is mutable")
	}
}

func TestDotenvProducerAndContent(t *testing.T) {
	p := parseJob(t, "build_env:\n  script:\n    - echo \"API_TOKEN=$(get-token)\" > deploy.env\n  artifacts:\n    reports:\n      dotenv: deploy.env\n")
	job := entMap(p["build_env"])
	if !producesDotenv(job) {
		t.Error("artifacts:reports:dotenv must produce dotenv")
	}
	if !dotenvContentAttackerInfluenced(job) {
		t.Error("command substitution into .env is attacker-influenced")
	}
}

func TestConsumesDotenv(t *testing.T) {
	p := parseJob(t, "producer:\n  script: [x]\n  artifacts: {reports: {dotenv: a.env}}\nconsumer:\n  needs: [producer]\n  script: [y]\n")
	producers := dotenvProducers(p)
	if !consumesDotenv(entMap(p["consumer"]), producers) {
		t.Error("needs: a dotenv producer must consume dotenv")
	}
	if consumesDotenv(entMap(p["producer"]), producers) {
		t.Error("producer with no needs does not consume")
	}
}

func TestDotenvInheritanceNarrowing(t *testing.T) {
	p := parseJob(t, "a:\n  needs: [x]\n  dependencies: []\n  script: [y]\nb:\n  needs: [x]\n  script: [y]\n")
	if dotenvInheritanceUnnarrowed(entMap(p["a"])) {
		t.Error("dependencies: [] narrows inheritance")
	}
	if !dotenvInheritanceUnnarrowed(entMap(p["b"])) {
		t.Error("no narrowing directive is unnarrowed")
	}
}

func TestCacheKeyStaticCrossBoundary(t *testing.T) {
	static := parseJob(t, "j:\n  cache:\n    key: global-cache\n    paths: [node_modules/]\n  script: [x]\n")
	if !cacheKeyStaticCrossBoundary(entMap(static["j"])) {
		t.Error("a static literal key collides across the boundary")
	}
	scoped := parseJob(t, "j:\n  cache:\n    key: $CI_COMMIT_REF_SLUG\n    paths: [node_modules/]\n  script: [x]\n")
	if cacheKeyStaticCrossBoundary(entMap(scoped["j"])) {
		t.Error("a ref-slug key is per-ref, not cross-boundary")
	}
	files := parseJob(t, "j:\n  cache:\n    key: {files: [package-lock.json]}\n    paths: [node_modules/]\n  script: [x]\n")
	if cacheKeyStaticCrossBoundary(entMap(files["j"])) {
		t.Error("a content-addressed key is not the static case")
	}
}

func TestImageMutableTag(t *testing.T) {
	if !imageMutableTag("node:latest") {
		t.Error("latest is mutable")
	}
	if !imageMutableTag("registry/app") {
		t.Error("no tag defaults to latest (mutable)")
	}
	if imageMutableTag("node@sha256:" + repeat("a", 64)) {
		t.Error("digest-pinned is immutable")
	}
	if imageMutableTag("$IMAGE") {
		t.Error("variable image is classified by image_from_variable, not mutable-tag")
	}
	if imageMutableTag("node:20.1.0") {
		t.Error("a fixed semantic version tag is not mutable")
	}
}

func repeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}

func TestJobTokenCrossProjectUse(t *testing.T) {
	cases := map[string]string{
		"git push https://gitlab-ci-token:$CI_JOB_TOKEN@host/repo.git":      "git_push",
		"curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" $URL/terraform/state/x": "terraform_state",
		"curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" $URL/packages":          "read",
		"echo hello": "none",
	}
	for script, want := range cases {
		if got := jobTokenCrossProjectUse(script); got != want {
			t.Errorf("script %q: use=%q want %q", script, got, want)
		}
	}
}

func TestAttackerInputFields(t *testing.T) {
	got := attackerInputFields("echo $CI_MERGE_REQUEST_TITLE; git checkout $CI_COMMIT_REF_NAME; run $[[ inputs.x ]]")
	slices.Sort(got)
	want := []string{"component_input", "mr_metadata", "ref_name"}
	if !slices.Equal(got, want) {
		t.Fatalf("attacker fields=%v want %v", got, want)
	}
	if len(attackerInputFields("echo hello")) != 0 {
		t.Error("constant script has no attacker input")
	}
}

func TestCrossProjectNeeds(t *testing.T) {
	p := parseJob(t, "generate:\n  needs:\n    - {project: shared/manifests, job: publish, ref: main, artifacts: true}\n    - build\n  script: [x]\n")
	cross := crossProjectNeeds(entMap(p["generate"]))
	if len(cross) != 1 {
		t.Fatalf("want 1 cross-project need (bare 'build' excluded), got %d", len(cross))
	}
	n := cross[0].(map[string]any)
	if n["project"] != "shared/manifests" || n["artifacts"] != true {
		t.Errorf("cross need=%v", n)
	}
	if !artifactSourceRefMutable(entMap(p["generate"])) {
		t.Error("ref: main is a mutable branch")
	}
}

func TestReusesOnDiskCheckout(t *testing.T) {
	p := parseJob(t, "j:\n  variables:\n    GIT_STRATEGY: fetch\n  script: [x]\n")
	if !reusesOnDiskCheckout(entMap(p["j"]), nil) {
		t.Error("GIT_STRATEGY: fetch reuses on-disk state")
	}
	clean := parseJob(t, "j:\n  script: [x]\n")
	if reusesOnDiskCheckout(entMap(clean["j"]), nil) {
		t.Error("default clone is a clean checkout")
	}
}

func TestChildPipelineFromCrossProjectArtifact(t *testing.T) {
	p := parseJob(t, "generate:\n  needs:\n    - {project: shared/x, job: publish, ref: main, artifacts: true}\n  artifacts: {paths: [out.yml]}\n  script: [x]\nrun-children:\n  trigger:\n    include:\n      - {artifact: out.yml, job: generate}\n")
	crossJobs := crossNeedJobNames(p, nil)
	if !childPipelineFromCrossProjectArtifact(entMap(p["run-children"]), crossJobs) {
		t.Error("trigger:include:artifact from a cross-project-needs generator must fire")
	}
	if childPipelineFromCrossProjectArtifact(entMap(p["generate"]), crossJobs) {
		t.Error("the generator itself does not trigger a child pipeline")
	}
}

func TestCachePathsExecutable(t *testing.T) {
	exec := parseJob(t, "j:\n  cache: {paths: [node_modules/], key: k}\n  script: [x]\n")
	if !cachePathsExecutable(entMap(exec["j"])) {
		t.Error("node_modules/ is an executable dependency dir")
	}
	inert := parseJob(t, "j:\n  cache: {paths: [reports/], key: k}\n  script: [x]\n")
	if cachePathsExecutable(entMap(inert["j"])) {
		t.Error("reports/ is inert data")
	}
}

func TestDuoFlowAutonomousWrite(t *testing.T) {
	if !duoFlowAutonomousWrite([]byte("tools:\n  - post_comment\n  - push\n")) {
		t.Error("write tools with no approval gate is autonomous")
	}
	if duoFlowAutonomousWrite([]byte("tools:\n  - post_comment\napproval: required\n")) {
		t.Error("an approval gate is not autonomous")
	}
	if duoFlowAutonomousWrite(nil) {
		t.Error("absent config is not autonomous")
	}
}

func TestMergeDefault(t *testing.T) {
	// default: image applies to a job that does not set image; job image wins.
	def := map[string]any{"image": "default:1", "tags": []any{"shared"}}
	job := map[string]any{"image": "override:1", "script": []any{"x"}}
	m := mergeDefault(job, def)
	if imageRef(m) != "override:1" {
		t.Errorf("job image must override default, got %q", imageRef(m))
	}
	if len(runnerTags(m)) != 1 {
		t.Error("default tags must apply when the job sets none")
	}
}
