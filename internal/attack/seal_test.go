package attack

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

const testSealPubPEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n"

func stepScript(t *testing.T, rendered string) string {
	t.Helper()
	var steps []struct {
		Run string `yaml:"run"`
	}
	if err := yaml.Unmarshal([]byte(rendered), &steps); err != nil {
		t.Fatalf("rendered step is not YAML: %v", err)
	}
	if len(steps) != 1 || steps[0].Run == "" {
		t.Fatalf("expected one step carrying a run: body, got %d", len(steps))
	}
	return steps[0].Run
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o500); err != nil {
		t.Fatal(err)
	}
}

// The seal marks its own envelope and the harvest recognizes it by that prefix, so
// the agreement lives in two files with nothing in the type system holding it
// together. Drifting either side does not break a build: it makes the harvest read
// this run's sealing having failed as a job that was never ours to seal, and report
// a plaintext stream in the customer's log over a job whose steps never ran.
func TestSealFailureIsAttributedToThisRunAndNotThePayload(t *testing.T) {
	payloadOnly := []harvestFragment{{Marker: "portus-hop3", Error: "beacon-unreachable"}}
	if got := sealStepReported(payloadOnly); got != "" {
		t.Errorf("a payload's own error was read as this run's seal failing: %q", got)
	}

	withSeal := append(payloadOnly, harvestFragment{Marker: randMarker(), Error: "crypto-toolchain-unavailable"})
	if got := sealStepReported(withSeal); got != "crypto-toolchain-unavailable" {
		t.Errorf("the seal step's own error was not attributable to this run: got %q", got)
	}
}

// The redirect has to reach the step's own shell and stop there. BASH_ENV is
// sourced on every non-interactive bash startup, so a tool that ships as a bash
// script — az is one — becomes a shell that sources it too, and the redirect then
// replaces the stdout that its caller's $(...) is reading. The caller takes the
// empty string and reports its own negative while the value sits in the sealed
// stream, which is the one outcome the evidence grammar exists to prevent. The
// test runs the emitted script rather than asserting on its text, because the
// defect was in what the script did and not in whether a line was present.
func TestSealRedirectLeavesCommandSubstitutionIntact(t *testing.T) {
	for _, required := range []string{"bash", "base64"} {
		if _, err := exec.LookPath(required); err != nil {
			t.Skipf("%s is not available", required)
		}
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	writeExecutable(t, filepath.Join(bin, "node"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "credential-tool"), "#!/usr/bin/env bash\necho THE-SECRET\n")

	env := slices.Concat(os.Environ(), []string{
		"RUNNER_TEMP=" + tmp,
		"GITHUB_ENV=" + filepath.Join(tmp, "github-env"),
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	run := func(script string, extra ...string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = slices.Concat(env, extra)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
	}

	setup, _ := sealSteps(testSealPubPEM)
	run(stepScript(t, setup))

	redirect := filepath.Join(tmp, "trajan-redirect.sh")
	if _, err := os.Stat(redirect); err != nil {
		t.Fatalf("the setup step wrote no redirect script: %v", err)
	}
	run(`v=$(credential-tool); echo the-step-own-output; echo "captured=[$v]"`, "BASH_ENV="+redirect)

	collected, err := os.ReadFile(filepath.Join(tmp, "trajan-collect"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(collected)

	if !strings.Contains(got, "captured=[THE-SECRET]") {
		t.Errorf("the step captured nothing from a bash-script child, so $(...) read a replaced stdout; collected:\n%s", got)
	}
	if !strings.Contains(got, "the-step-own-output") {
		t.Errorf("the step's own output stayed out of the collection file, so the redirect did not apply; collected:\n%s", got)
	}
	if slices.ContainsFunc(strings.Split(got, "\n"), func(line string) bool { return strings.TrimSpace(line) == "THE-SECRET" }) {
		t.Errorf("the child's output was diverted into the collection file instead of reaching its caller; collected:\n%s", got)
	}
}
