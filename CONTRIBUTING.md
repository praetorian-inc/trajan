# Contributing to Trajan

This doc covers the dev setup, project structure, and how to add plugins or new platforms.

## Table of contents

- [Getting started](#getting-started)
- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Architecture overview](#architecture-overview)
- [Adding a detection plugin](#adding-a-detection-plugin)
- [Adding a platform](#adding-a-platform)
- [Testing](#testing)
- [Code style](#code-style)
- [Commit messages](#commit-messages)
- [Pull requests](#pull-requests)
- [Reporting issues](#reporting-issues)

## Getting started

1. Fork the repository on GitHub.
2. Clone your fork locally:

```bash
git clone git@github.com:<your-username>/trajan.git
cd trajan
```

3. Add the upstream remote:

```bash
git remote add upstream git@github.com:praetorian-inc/trajan.git
```

4. Create a feature branch:

```bash
git checkout -b feature/my-change
```

## Development setup

### Prerequisites

- **Go 1.24+** (the module is set to Go 1.25.3, but 1.24+ will work)
- **golangci-lint** for linting (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)
- **Docker** (optional, needed for Jenkins integration tests)

### Build and run

```bash
# Download dependencies
make deps

# Build the CLI binary to bin/trajan
make build

# Run all tests
make test

# Format code
make fmt

# Run linters
make lint
```

### WASM / browser build

Trajan can also run in the browser via WebAssembly:

```bash
./browser/build.sh   # Build WASM binary
./browser/serve.sh   # Start dev server at http://localhost:8080
```

## Project layout

```
cmd/
  trajan/               CLI entry point and subcommands
    github/             GitHub subcommands (scan, enumerate, search)
    ado/                Azure DevOps subcommands
    gitlab/             GitLab subcommands
    jenkins/            Jenkins subcommands
    jfrog/              JFrog subcommands
  trajan-wasm/          WASM entry point for browser builds

internal/
  registry/             Global detection and platform registries
  cmdutil/              Shared CLI flag helpers

pkg/
  platforms/            Platform interface and shared config types
  analysis/
    graph/              Workflow graph (nodes, edges, tags, traversal)
    parser/             Per-platform YAML parsers → NormalizedWorkflow
    flow/               Taint tracking, flow context, gate types
    gates/              Gate detection patterns and confidence adjustment
    expression/         GitHub Actions expression evaluator with taint propagation
  detections/           Detection interface, base helpers, shared logic
    shared/             Cross-platform helpers (taint sources, AI patterns)
  scanner/              Scan orchestration
  output/               Terminal output or JSON
  config/               Configuration and local storage

  github/               GitHub: platform, client, detections
  gitlab/               GitLab: platform, client, detections
  azuredevops/          Azure DevOps: platform, client, detections
  jenkins/              Jenkins: platform, client, detections
  jfrog/                JFrog: platform, client, token probing

browser/                WASM UI (HTML, JS, CSS, build scripts)
```

## Architecture overview

The analysis pipeline has four layers, each defined by an interface:

### 1. Platform (fetch workflows)

Every CI/CD platform implements `platforms.Platform`:

```go
type Platform interface {
    Name() string
    Init(ctx context.Context, config Config) error
    Scan(ctx context.Context, target Target) (*ScanResult, error)
}
```

`Scan` enumerates repositories and returns raw workflow YAML.

### 2. Parser (normalize YAML)

Each platform provides a `parser.WorkflowParser` that converts its native YAML into a shared `NormalizedWorkflow`:

```go
type WorkflowParser interface {
    Platform() string
    CanParse(path string) bool
    Parse(data []byte) (*NormalizedWorkflow, error)
}
```

### 3. Graph (unified representation)

`analysis.BuildGraphFromNormalized()` turns any `NormalizedWorkflow` into a `graph.Graph`, a directed graph of `WorkflowNode → JobNode → StepNode` with typed edges (`contains`, `uses`, `depends`, `triggers`, `includes`) and security-relevant tags (`TagInjectable`, `TagCheckout`, `TagSelfHostedRunner`, etc.).

### 4. Detection (find vulnerabilities)

All detections implement `detections.Detection` and operate on the shared graph:

```go
type Detection interface {
    Name() string
    Platform() string
    Severity() Severity
    Detect(ctx context.Context, g *graph.Graph) ([]Finding, error)
}
```

### Taint and gates

- **Taint** tracks user-controllable data (PR titles, comment bodies, workflow inputs, etc.) as it flows through env vars, expressions, and steps. When tainted data reaches a dangerous sink (like a `run:` command), it's an injection vulnerability.
- **Gates** are security controls along the path to an injectable step. Blocking gates (deployment approval, permission checks) suppress findings. Soft gates (label requirements, author association checks) reduce confidence.

## Adding a detection plugin

Detection plugins live under `pkg/<platform>/detections/<name>/`. They all follow the same pattern:

1. Create the package, e.g. `pkg/github/detections/myplugin/myplugin.go`

2. Register in `init()` so the scanner picks it up automatically:

```go
package myplugin

import (
    "context"

    "github.com/praetorian-inc/trajan/internal/registry"
    "github.com/praetorian-inc/trajan/pkg/analysis/graph"
    "github.com/praetorian-inc/trajan/pkg/detections"
    "github.com/praetorian-inc/trajan/pkg/detections/base"
)

func init() {
    registry.RegisterDetection("github", "my-plugin", func() detections.Detection {
        return New()
    })
}

type Plugin struct {
    base.BaseDetection
}

func New() *Plugin {
    return &Plugin{
        BaseDetection: base.NewBaseDetection("my-plugin", "github", detections.SeverityHigh),
    }
}

func (p *Plugin) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
    // Query nodes by type or tag, traverse edges, check taint, etc.
    return nil, nil
}
```

3. Add a blank import in `pkg/detections/all/all.go` so the `init()` runs.

4. Add `myplugin_test.go` with table-driven tests that build a graph from YAML fixtures and assert on expected findings.

## Adding a platform

To add support for a new CI/CD platform:

1. Create the platform package: `pkg/<platform>/platform.go` implementing `platforms.Platform`.
2. Create a parser: `pkg/analysis/parser/<platform>.go` implementing `parser.WorkflowParser`. Register it in the parser's `init()`.
3. Create an API client: `pkg/<platform>/client.go` with rate limiting, pagination, and authentication.
4. Add platform-specific taint sources: if the platform has its own expression language with user-controllable inputs, add them to `pkg/detections/shared/taintsources/`.
5. Add detections: create detection plugins under `pkg/<platform>/detections/`.
6. Add CLI commands: wire up subcommands under `cmd/trajan/<platform>/`.
7. Add tests: unit tests for the parser and client, integration tests for detections.

Use `pkg/github/` and `pkg/azuredevops/` as a reference.

## Testing

### Running tests

```bash
# All tests
make test

# Specific package
go test -v ./pkg/analysis/graph/...

# With coverage
make test-coverage
# Opens coverage.html in browser
```

### Writing tests

- Use `testify/assert` and `testify/require` (already a dependency).
- Use table-driven tests with descriptive subtest names.
- For detection tests: build a `graph.Graph` from YAML fixtures, run `Detect()`, and assert on the returned findings.
- For parser tests: provide raw YAML and assert on the `NormalizedWorkflow` output.

### Integration tests

Jenkins integration tests need a running Jenkins instance:

```bash
make jenkins-test-up        # Start Jenkins in Docker
make jenkins-integration    # Run integration tests
make jenkins-test-down      # Tear down
```

## Code style

### Formatting and linting

All code must pass `golangci-lint`. The project uses these linters (configured in `.golangci.yml`):

- `errcheck`: unchecked errors (including type assertions and blank identifiers)
- `govet`: standard Go vet checks
- `staticcheck`: advanced static analysis
- `unused`: dead code
- `gosimple`: simplification suggestions
- `ineffassign`: ineffectual assignments
- `gocyclo`: cyclomatic complexity (max 15)
- `gofmt` / `goimports`: formatting and import ordering
- `misspell`: spelling mistakes in comments

Run `make fmt` and `make lint` before submitting.

### Guidelines

- Keep functions focused. If cyclomatic complexity exceeds 15, break it up.
- Check all errors. Use `require.NoError(t, err)` in tests.
- Avoid global mutable state outside of `init()` registrations.
- Use `context.Context` for cancellation and timeouts in all I/O paths.
- Prefer returning `(result, error)` over panicking.

## Commit messages

This project uses **conventional commits**. Each commit message should have a type prefix:

| Prefix | Use for |
|--------|---------|
| `feat:` | New features |
| `fix:` | Bug fixes |
| `refactor:` | Code restructuring without behavior change |
| `chore:` | Build, CI, dependency, or tooling changes |
| `test:` | Adding or updating tests |
| `docs:` | Documentation changes |

Concise summary in the imperative mood. Add detail in the body if the "why" isn't obvious from the diff.

```
feat: add GitLab CI runner enumeration via pipeline logs

fix: resolve context-unaware polling loops in agent-exec and secrets-dump

refactor: namespace attack plugin registry keys as platform/name
```

## Pull requests

1. One logical change per PR. If you're fixing a bug and adding a feature, split them.
2. `make test` and `make lint` must pass.
3. Describe what changed and why. Link to related issues.
4. Add tests for new functionality. Detection plugins need test coverage.
5. Keep diffs reviewable. Avoid unrelated formatting changes or large generated blocks.

### PR checklist

- [ ] Tests pass (`make test`)
- [ ] Lints pass (`make lint`)
- [ ] New plugin registered in `init()` and imported in `all.go`
- [ ] Commit messages follow conventional commit format
- [ ] Documentation updated if adding user-facing features

## Reporting issues

When opening an issue, include:

- What you expected vs. what happened
- Steps to reproduce (workflow YAML, CLI command, flags)
- Trajan version (`trajan version`)
- Go version (`go version`)
- OS and architecture

For security vulnerabilities, email security@praetorian.com instead of opening a public issue.
