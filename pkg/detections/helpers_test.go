package detections

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildChainFromNodes_Empty(t *testing.T) {
	chain := BuildChainFromNodes()
	assert.Nil(t, chain)
}

func TestIsExecutionSink(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		// Empty input is not a sink.
		{"empty", "", false},

		// Existing tools — regression coverage so we don't accidentally drop them.
		{"npm install", "npm install", true},
		{"yarn install", "yarn install", true},
		{"node script.js", "node script.js", true},
		{"bash inline", "bash -c 'do_stuff'", true},
		{"echo only", "echo hello", false},

		// pnpm — the empirical PR 1 driver. TanStack-class attacks use pnpm install.
		{"pnpm install (prefix)", "pnpm install", true},
		{"pnpm i (prefix)", "pnpm i", true},
		{"pnpm run build (prefix)", "pnpm run build", true},
		{"pnpm build (prefix)", "pnpm build", true},
		{"pnpm test (prefix)", "pnpm test", true},
		{"multiline pnpm install", "echo hi\npnpm install", true},

		// Gato-X-mirrored sinks listed in the PR 1 brief. Each executes arbitrary
		// code from a checked-out repo or restored cache.
		{"bun install", "bun install", true},
		{"bun run dev", "bun run dev", true},
		{"poetry install", "poetry install", true},
		{"cargo build", "cargo build", true},
		{"cargo run", "cargo run", true},
		{"go run main.go", "go run main.go", true},
		{"go generate ./...", "go generate ./...", true},
		{"make build", "make build", true},
		{"mvn package", "mvn package", true},
		{"gradle build", "gradle build", true},
		{"pytest tests/", "pytest tests/", true},

		// Negative cases: confirm the new "go run "/"go generate " prefixes don't
		// over-match other go subcommands. (Args avoid "./" since the preexisting
		// "./" pattern in executionPatterns matches that on its own — out of
		// scope for PR 1.)
		{"go fmt is not a sink", "go fmt main.go", false},
		{"go vet is not a sink", "go vet pkg/foo", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsExecutionSink(c.cmd)
			assert.Equal(t, c.want, got, "IsExecutionSink(%q)", c.cmd)
		})
	}
}
