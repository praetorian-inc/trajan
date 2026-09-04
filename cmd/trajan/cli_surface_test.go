package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/clisurface"
)

// updateGoldens rewrites the generated CLI-surface artifacts instead of
// checking them. "make cli-docs" is the documented way to set it.
var updateGoldens = flag.Bool("update", false,
	"rewrite docs/cli-surface.json, docs/CLI.md and the generated README.md regions from the live cobra tree")

// cliDocs builds the Docs every test in this file reads its paths, its regions
// and its regenerate command from. The SDK's defaults for the four artifact
// paths and the two README regions are the layout trajan commits, so they are
// left unset: that keeps the layout a single documented default rather than a
// copy of one.
//
// The two lint scopes are the exception, and are stated here rather than
// defaulted, because trajan's scope is a decision trajan owns rather than an
// inherited default -- pinning both locally is what keeps a future change to an
// SDK default from silently narrowing (or widening) this gate's reach.
//
//   - LintedMarkdown: the SDK default is READMEPath alone. trajan's
//     hand-written docs that name CLI surface are README.md, CONTRIBUTING.md
//     ("declaring --token leaf-locally") and SECURITY.md (which names the
//     attack mode), so all three are policed. AGENTS.md and CLAUDE.md are
//     deliberately excluded: they are generated agent-instruction mirrors, not
//     documents a contributor may hand-edit to satisfy a lint finding.
//     ".github/GITHUB_ACTION.md" is excluded because it documents Action
//     inputs and, measured, contains no backticked long flag at all -- adding
//     it would widen the walk without widening the coverage.
//   - LintedGoDirs: "cmd", "internal" and "pkg" all exist in this repository
//     and all three hold code whose comments name flags, so the value happens
//     to equal today's SDK default. It is spelled out anyway, for the reason
//     above.
//
// It is a constructor rather than a package-level value so a configuration that
// stopped validating fails the test that uses it, with New's error, instead of
// panicking during package initialization where no test owns the failure.
func cliDocs(t *testing.T) *clisurface.Docs {
	t.Helper()
	docs, err := clisurface.New(clisurface.Config{
		RegenerateCommand: "make cli-docs",
		// "README.md" is spelled out rather than shared with the READMEPath
		// default just above it: the SDK keeps that default unexported, and a
		// composite literal cannot read the field it is initializing.
		LintedMarkdown: []string{"README.md", "CONTRIBUTING.md", "SECURITY.md"},
		LintedGoDirs:   []string{"cmd", "internal", "pkg"},
	})
	require.NoError(t, err)
	return docs
}

// TestCLISurface is the drift gate. It walks the live cobra tree, compares it
// against the committed surface, and compares the committed generated files
// against what that surface renders. Without -update it never writes.
func TestCLISurface(t *testing.T) {
	docs := cliDocs(t)
	cfg := docs.Config()
	root := repoRoot(t)
	live := clisurface.Walk(rootCmd)

	if *updateGoldens {
		require.NoError(t, docs.Write(root, live))
		t.Logf("regenerated %s", strings.Join(docs.GeneratedPaths(), ", "))
		return
	}

	golden, err := os.ReadFile(filepath.Join(root, cfg.JSONPath))
	require.NoErrorf(t, err, "%s is missing; create it with %q", cfg.JSONPath, cfg.RegenerateCommand)
	documented, err := docs.ParseJSON(golden)
	require.NoError(t, err)

	// Fail with require.Fail rather than require.Empty: Empty dumps the raw
	// findings slice on one unwrapped line before printing the formatted
	// message, so every finding prints twice, once unreadable and once
	// formatted. Fail only prints the formatted report.
	if findings := clisurface.Diff(documented, live); len(findings) > 0 {
		require.Fail(t, "CLI surface drift", docs.Report(findings))
	}

	stale, err := docs.CheckArtifacts(root, live)
	require.NoError(t, err)
	if len(stale) > 0 {
		assert.Fail(t, "generated CLI documentation is stale", stalenessReport(stale))
	}
}

// TestCLISurfaceDocLint fails when a document or a Go comment names a flag or a
// subcommand the CLI does not accept.
func TestCLISurfaceDocLint(t *testing.T) {
	docs := cliDocs(t)
	root := repoRoot(t)
	allow, err := docs.LoadAllowlist(root)
	require.NoError(t, err)

	issues, scope, err := docs.LintRepo(root, clisurface.Walk(rootCmd), allow)
	require.NoError(t, err)

	// Log the scope on a pass as well as a failure. An empty issue list is only
	// good news if the run actually read something, and a lint walk that
	// silently reached nothing -- a renamed directory, an allowlist that grew to
	// cover everything, entries skipped for not being regular files -- reads
	// exactly like a clean repository. LintReport prints this on a failure; the
	// log is how a passing run says it too. Named fields rather than %+v:
	// LintScope has no String method, so a verb would dump its internals.
	// GoFiles is a count and not a list because trajan has hundreds of them,
	// which is the same choice LintReport's own coverage line makes.
	t.Logf("linted %d markdown file(s) [%s] and %d Go file(s) under %d Go dir(s) [%s], with %d token(s) allowlisted; skipped %d entr(y/ies) that are not regular files [%s]",
		len(scope.MarkdownFiles), scopeList(scope.MarkdownFiles),
		len(scope.GoFiles), len(scope.GoDirs), scopeList(scope.GoDirs),
		len(scope.Allowlist.Entries()),
		len(scope.SkippedIrregular), scopeList(scope.SkippedIrregular))

	if len(issues) > 0 {
		assert.Fail(t, "documentation names flags the CLI does not accept", clisurface.LintReport(issues, scope))
	}
}

// TestCLISurfaceGateDetectsRename proves the gate reddens. A gate only ever
// observed passing is not known to work, so this renames a real flag on the
// real tree and asserts the diff reports exactly that rename, then feeds the
// linter documents naming a flag the CLI does not accept and asserts each is
// reported with file:line.
//
// The fixture is --org on "trajan ado whoami". It is a leaf-local flag on a
// subcommand that exists only as a local variable inside newAdoCmd, so reaching
// it at all is the same traversal the gate depends on: a walk that stopped at
// the platform roots could not find it, and this test would fail rather than
// quietly prove nothing. It is also unique in the tree -- the ado persistent
// flags are --concurrency and --output-dir -- so renaming it moves exactly one
// flag on exactly one command.
func TestCLISurfaceGateDetectsRename(t *testing.T) {
	docs := cliDocs(t)
	documented := clisurface.Walk(rootCmd)

	t.Run("renaming a registered flag is reported", func(t *testing.T) {
		// This mutates a flag on the shared tree hanging off the package-level
		// rootCmd and restores it in Cleanup. It is safe only because nothing in
		// this package calls t.Parallel: do not add it here or to any test that
		// reads the command tree, or the two will race on the rename. pflag also
		// keys its lookup map by the original name, so only VisitAll -- which is
		// what Walk uses -- observes the change.
		whoami := findCommand(t, rootCmd, "ado", "whoami")
		flagObj := whoami.Flags().Lookup("org")
		require.NotNil(t, flagObj, "the fixture flag must exist for this test to mean anything")
		t.Cleanup(func() { flagObj.Name = "org" })
		flagObj.Name = "orq"

		findings := clisurface.Diff(documented, clisurface.Walk(rootCmd))

		require.Len(t, findings, 2, "a rename is exactly one removal and one addition, and nothing else:\n%s",
			docs.Report(findings))
		// Findings are sorted by command then flag name, so the old name ("org")
		// is reported before the new one ("orq").
		assert.Equal(t, clisurface.FlagRemoved, findings[0].Kind)
		assert.Equal(t, "org", findings[0].Flag)
		assert.Equal(t, "trajan ado whoami", findings[0].Command)
		assert.Equal(t, clisurface.FlagUndocumented, findings[1].Kind)
		assert.Equal(t, "orq", findings[1].Flag)
		assert.Equal(t, "trajan ado whoami", findings[1].Command)
		assert.Contains(t, findings[0].String(),
			`flag --org on "trajan ado whoami" is in the generated docs but cobra no longer accepts it`)
		assert.Contains(t, findings[1].String(),
			`flag --orq on "trajan ado whoami" is registered by cobra but missing from the generated docs`)
	})

	t.Run("the tree is restored", func(t *testing.T) {
		assert.Empty(t, clisurface.Diff(documented, clisurface.Walk(rootCmd)),
			"the rename above must not leak into the rest of the suite")
	})

	t.Run("a document naming a removed flag is reported", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		doc := "Historic note.\n\n```bash\ntrajan ado whoami --org acme --azure-pat REDACTED\n```\n"
		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1, "--org is real and --azure-pat is not, so exactly one token is reported")
		assert.Equal(t, "--azure-pat", issues[0].Token)
		assert.Equal(t, "trajan ado whoami", issues[0].Command)
		assert.Contains(t, issues[0].String(),
			`docs/example.md:4: --azure-pat is not a flag of "trajan ado whoami"`)
		assert.Contains(t, issues[0].String(), docs.Config().AllowlistPath,
			"the message says how to allow a deliberate mention")
	})

	t.Run("a backticked flag name in prose is reported", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		// The prose arm of the linter reads backticked spans only, and checks
		// them against the union of every flag in the tree rather than against
		// one command -- so the issue carries no Command. This sub-test exists
		// because the arm is easy to believe in and hard to see: an unbackticked
		// mention is never read, so a probe written without backticks passes for
		// the wrong reason.
		doc := "Authenticate with `--azure-pat` before collecting.\n"
		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1)
		assert.Equal(t, "--azure-pat", issues[0].Token)
		assert.Empty(t, issues[0].Command, "a prose token is checked against the whole surface")
		assert.Contains(t, issues[0].String(),
			"docs/example.md:1: --azure-pat is not a flag of any command in the CLI")
	})

	t.Run("an unbackticked prose mention is not read at all", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		// The complement of the sub-test above, and the reason it is worth
		// having: outside a fenced block the linter only reads code spans, so
		// bare prose is invisible to it. Pinning that here means a future change
		// that starts reading bare prose shows up as this test failing rather
		// than as a repository-wide flood of findings nobody predicted.
		doc := "Authenticate with --azure-pat before collecting.\n"
		assert.Empty(t, docs.LintMarkdown(documented, "docs/example.md", doc, empty))
	})

	t.Run("the allowlist suppresses a deliberate mention", func(t *testing.T) {
		allow, err := docs.ParseAllowlist("--azure-pat # renamed to --azure-bearer-token; the migration note names the old flag\n")
		require.NoError(t, err)

		doc := "Historic note: `--azure-pat`.\n\n```bash\ntrajan ado whoami --azure-pat REDACTED\n```\n"
		assert.Empty(t, docs.LintMarkdown(documented, "docs/example.md", doc, allow),
			"the allowlist must suppress the token in a fenced invocation and in prose alike")
	})

	t.Run("a flag from a sibling platform is not accepted by ado", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		// --org-detections-only is real, but on "trajan ado scan" rather than on
		// "trajan ado whoami". A linter that checked tokens against the union of
		// the tree everywhere -- rather than against the command each fenced
		// invocation actually resolves to -- would pass this document, so this
		// sub-test is what distinguishes the two behaviors.
		doc := "```bash\ntrajan ado whoami --org-detections-only\n```\n"
		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1)
		assert.Equal(t, "--org-detections-only", issues[0].Token)
		assert.Equal(t, "trajan ado whoami", issues[0].Command)
	})
}

// findCommand resolves a command by walking child names from cmd, and fails the
// test when a name is not found. cobra's own Find is deliberately not used: it
// treats unmatched words as positional arguments and returns the deepest
// command it did match, so a typo or a moved subcommand would silently resolve
// to an ancestor and a fixture would assert against the wrong command.
func findCommand(t *testing.T, cmd *cobra.Command, names ...string) *cobra.Command {
	t.Helper()
	for _, name := range names {
		var next *cobra.Command
		for _, child := range cmd.Commands() {
			if child.Name() == name {
				next = child
				break
			}
		}
		require.NotNilf(t, next, "%q has no subcommand %q", cmd.CommandPath(), name)
		cmd = next
	}
	return cmd
}

// repoRoot locates the repository root; a test's working directory is its own
// package directory, and the generated artifacts are repo-relative.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := clisurface.FindRepoRoot(wd)
	require.NoError(t, err)
	return root
}

// stalenessReport renders stale artifacts one per line.
func stalenessReport(stale []clisurface.Staleness) string {
	lines := make([]string, 0, len(stale))
	for i := range stale {
		lines = append(lines, stale[i].String())
	}
	return strings.Join(lines, "\n")
}

// scopeList renders one LintScope path list for the coverage log, naming the
// empty list rather than logging an empty bracket a reader has to interpret.
// The SDK renders its own report the same way, but with an unexported helper.
func scopeList(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
