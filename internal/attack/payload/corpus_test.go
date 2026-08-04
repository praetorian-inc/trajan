package payload

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

// runShell executes a rendered body the way the customer's runner would and returns
// the trajan- fields it emitted, so a fragment is measured by what it reports rather
// than by what its text looks like. Git's global and system config are cut out: the
// probes under test read config, and a developer's own ~/.gitconfig would otherwise
// decide the result.
func runShell(t *testing.T, script, dir string, env ...string) (map[string]string, string) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("body exited %v:\n%s", err, out)
	}
	return markerFields(string(out)), string(out)
}

func markerFields(out string) map[string]string {
	fields := map[string]string{}
	for _, tok := range strings.Fields(out) {
		name, value, ok := strings.Cut(tok, "=")
		if ok && strings.HasPrefix(name, "trajan-") {
			fields[strings.TrimPrefix(name, "trajan-")] = value
		}
	}
	return fields
}

func readerRunBlock(t *testing.T, steps string) string {
	t.Helper()
	var c composed
	if err := yaml.Unmarshal([]byte(compose(steps)), &c); err != nil {
		t.Fatalf("composed document does not parse: %v", err)
	}
	s := c.Jobs["verify"].Steps
	if len(s) != 2 {
		t.Fatalf("reader branch rendered %d steps, want 2", len(s))
	}
	return s[1].Run
}

// actions/cache/restore reports three states, not two: "true" for an exact match on
// the primary key, "false" for a partial match through restore-keys, and — because
// the action returns before ever setting the output when nothing was restored — the
// empty string for a miss. The restore-keys fallback is the fact this fragment
// exists to measure, so folding it onto the same value as the miss reports the
// measurement backwards.
func TestCacheHitDistinguishesTheThreeRestoreStates(t *testing.T) {
	out, err := Render("t-04/cache-handoff", map[string]any{
		"marker": "m1", "role": "reader", "restore_keys": []any{"node-deps-"},
	}, Env{})
	if err != nil {
		t.Fatal(err)
	}
	run := readerRunBlock(t, out)

	cases := []struct {
		name       string
		hit        string
		matchedKey string
		want       string
	}{
		{"exact match on the primary key", "true", "m1", "true"},
		{"partial match through restore-keys", "false", "node-deps-abc", "false"},
		{"nothing restored, output never set", "", "", "none"},
	}
	seen := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			fields, raw := runShell(t, run, dir, "TRJ_HIT="+c.hit, "TRJ_MATCHED="+c.matchedKey)
			if got := fields["cache-hit"]; got != c.want {
				t.Errorf("cache-hit output %q reported as %q, want %q\n%s", c.hit, got, c.want, raw)
			}
			if prior, dup := seen[fields["cache-hit"]]; dup {
				t.Errorf("%q and %q both report cache-hit=%s, so the two are indistinguishable in the report",
					prior, c.name, fields["cache-hit"])
			}
			seen[fields["cache-hit"]] = c.name
		})
	}
}

// GITHUB_TOKEN is not a default environment variable, so probing the environment
// alone reports absence in a job that holds the token by every route that matters.
// What a checkout leaves behind is the reachable credential, and the fragment must
// establish that it is there without putting any part of it in the run log.
func TestTokenReachabilityProbe(t *testing.T) {
	body, err := Render("t-07/checked-out-code-execution", map[string]any{
		"marker": "m1", "vector": "build_script", "path": "build.sh",
	}, Env{})
	if err != nil {
		t.Fatal(err)
	}

	const header = "AUTHORIZATION: basic eDphY2Nlc3NfdG9rZW46Z2hzX1RFU1RTRUNSRVQ="
	const secret = "ghs_TESTSECRET"

	newRepo := func(t *testing.T, persist bool) string {
		t.Helper()
		dir := t.TempDir()
		script := "git init -q ."
		if persist {
			script += " && git config --local 'http.https://github.com/.extraheader' '" + header + "'"
		}
		runShell(t, script, dir)
		return dir
	}

	t.Run("a checkout that persisted credentials is evidenced", func(t *testing.T) {
		dir := newRepo(t, true)
		fields, raw := runShell(t, body, dir)
		if got := fields["token-persisted"]; got != "true" {
			t.Errorf("token-persisted=%q, want true: the credential is reachable from this tree\n%s", got, raw)
		}
		// The whole point of probing for the key name rather than the value.
		for _, leak := range []string{secret, header, "AUTHORIZATION", "basic "} {
			if strings.Contains(raw, leak) {
				t.Errorf("the probe put credential material in the log: found %q\n%s", leak, raw)
			}
		}
	})

	t.Run("persist-credentials false is a measured negative", func(t *testing.T) {
		dir := newRepo(t, false)
		fields, raw := runShell(t, body, dir)
		if got := fields["token-persisted"]; got != "false" {
			t.Errorf("token-persisted=%q, want false\n%s", got, raw)
		}
	})

	t.Run("no work tree is unknown, not a claimed absence", func(t *testing.T) {
		dir := t.TempDir()
		if err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run(); err == nil {
			t.Skip("temp dir is inside a git work tree")
		}
		fields, raw := runShell(t, body, dir)
		if got := fields["token-persisted"]; got != "unknown" {
			t.Errorf("token-persisted=%q, want unknown: absence was not measured here\n%s", got, raw)
		}
	})

	// A job holding the token by the route that actually occurs must not report no
	// token at all, which understates the finding.
	t.Run("the environment probe is reported separately", func(t *testing.T) {
		dir := newRepo(t, true)
		fields, _ := runShell(t, body, dir)
		if fields["token-env"] != "false" {
			t.Errorf("token-env=%q, want false with GITHUB_TOKEN unset", fields["token-env"])
		}
		if fields["token-persisted"] != "true" {
			t.Error("an unset GITHUB_TOKEN must not be reported as the token being unreachable")
		}

		fields, _ = runShell(t, body, dir, "GITHUB_TOKEN=x")
		if fields["token-env"] != "true" {
			t.Errorf("token-env=%q, want true where the workflow mapped it into env", fields["token-env"])
		}
	})
}

// A fragment's declared scopes are what the composing step screens a permissions:
// block against, so a requirement that only applies to one role must not be reported
// for the other — and one that applies unconditionally must survive the defaults.
// required: asserts that a value arrived, not that it holds anything, so an empty
// list reaches the body — and there the shell flavor rendered `for name in ; do`,
// which bash refuses. The fragment then died before emitting its marker, which is
// the one thing a harvest reads as a payload that never executed. The workflow
// flavor has always refused the case out loud; this brings the shell one to the same
// standard. bash -n is the wrong oracle here: it parses the whole file, including a
// loop the guard makes unreachable.
func TestSecretReachabilityShellRefusesAnEmptyNameList(t *testing.T) {
	body, err := Render("t-01/secret-reachability-shell", map[string]any{
		"marker":       "m1",
		"secret_names": []any{},
	}, Env{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	out, runErr := exec.Command("bash", "-c", body).CombinedOutput()
	got := string(out)
	if runErr == nil {
		t.Fatalf("an empty name list must be refused rather than measured, got:\n%s", got)
	}
	if strings.Contains(got, "syntax error") {
		t.Fatalf("the degenerate loop was still reached:\n%s", got)
	}
	if !strings.Contains(got, "trajan-marker=m1") {
		t.Errorf("the refusal must arrive inside the marker envelope, or it reads as never having run; got:\n%s", got)
	}
	if !strings.Contains(got, "trajan-error=secret-names-empty") {
		t.Errorf("want the negative stated explicitly, got:\n%s", got)
	}
}

func TestRequiredPermissions(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		params map[string]any
		want   []Permission
	}{
		{
			"the cross-run consumer reaches the REST API",
			"t-05/artifact-handoff",
			map[string]any{"role": "consumer", "consumer_mode": "workflow_run"},
			[]Permission{{Scope: "actions", Level: "read"}},
		},
		{
			"the same-run consumer reads through the runner and needs nothing",
			"t-05/artifact-handoff",
			map[string]any{"role": "consumer", "consumer_mode": "same_run"},
			nil,
		},
		{
			"consumer_mode defaulted to same_run is still nothing",
			"t-05/artifact-handoff",
			map[string]any{"role": "consumer"},
			nil,
		},
		{
			"the producer is not charged the consumer's scope",
			"t-05/artifact-handoff",
			map[string]any{"role": "producer", "consumer_mode": "workflow_run"},
			nil,
		},
		{
			"a value only the run resolves is left to the run",
			"t-05/artifact-handoff",
			map[string]any{"role": "consumer", "consumer_mode": Unresolved{}},
			nil,
		},
		{
			"an unconditional requirement holds on defaults alone",
			"t-03/oidc-subject-claim",
			map[string]any{"marker": "m"},
			[]Permission{{Scope: "id-token", Level: "write"}},
		},
		{
			"a fragment touching neither surface declares nothing",
			"t-04/cache-handoff",
			map[string]any{"marker": "m", "role": "reader"},
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := RequiredPermissions(c.id, c.params)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("RequiredPermissions = %v, want %v", got, c.want)
			}
			for i, w := range c.want {
				if got[i].Scope != w.Scope || got[i].Level != w.Level {
					t.Errorf("[%d] = %s: %s, want %s: %s", i, got[i].Scope, got[i].Level, w.Scope, w.Level)
				}
			}
		})
	}
}

// Every fragment that pins an action must pin a major that is still served. A
// floating major is the reference these fragments carry on purpose, so the corpus is
// checked for the shape rather than for a digest.
func TestPinnedActionMajors(t *testing.T) {
	want := map[string]string{
		"actions/cache/save":        "v6",
		"actions/cache/restore":     "v6",
		"actions/upload-artifact":   "v7",
		"actions/download-artifact": "v8",
	}
	found := map[string]bool{}
	for _, id := range IDs() {
		f, err := Get(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(f.Body, "\n") {
			_, ref, isUses := strings.Cut(strings.TrimSpace(line), "uses:")
			if !isUses {
				continue
			}
			action, major, ok := strings.Cut(strings.TrimSpace(ref), "@")
			if !ok {
				t.Errorf("%s: %q pins no version", id, ref)
				continue
			}
			found[action] = true
			if w, known := want[action]; known && major != w {
				t.Errorf("%s pins %s@%s, want @%s", id, action, major, w)
			}
		}
	}
	for action := range want {
		if !found[action] {
			t.Errorf("%s is no longer used by any fragment; drop it from this test", action)
		}
	}
}
