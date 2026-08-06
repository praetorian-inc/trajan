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
- **Neo4j** (optional, needed for `graph` and `push`)

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

## Project layout

```
cmd/
  trajan/               CLI entry point
    github/             GitHub subcommands
    gitlab/             GitLab subcommands
    ado/                Azure DevOps subcommands

internal/               The current phased pipeline
  engine/               Run directories, phase state, bounded runners, credential resolution
  github/               GitHub: collect, normalize, scan, correlate
  gitlab/               GitLab: collect, normalize, scan
  ado/                  Azure DevOps: collect, normalize, scan
  detection-rules/      Embedded YAML rule corpus, one directory per category
  dsl/                  Rule expression language: operators and evaluation
  finding/              Finding shape and severity/confidence handling
  report/               Renderers (json, jsonl, md, html)
  graph/                Neo4j schema, node/edge construction, push
  attack/               Attack primitives, plan loading, session and cleanup
  attack-plans/         Embedded attack plan YAML
  attack-payloads/      Embedded job-template corpus rendered into plans
  registry/             Detection and platform registries
  ui/                   Humanized phase output

pkg/                    Legacy stack, no longer reachable from the CLI
  platforms/            Platform interface and shared config types
  analysis/             Workflow graph, per-platform parsers, taint and gate analysis
  detections/           Go detection-plugin interface and shared helpers
  scanner/              Scan orchestration
  output/               Terminal and JSON output
  lib/                  Library surface wrapping the legacy engine
  gitlab/ azuredevops/ jenkins/ jfrog/ bitbucket/
                        Per-platform clients and Go detection plugins
```

Detections for the three supported platforms are YAML under `internal/detection-rules/`, evaluated by `internal/dsl`. The Go detection plugins under `pkg/detections/` belong to the retired engine and are not run by any CLI command.

## Architecture overview

A run is a sequence of phases, each reading the previous phase's output from disk and writing its own. Every phase is independently re-runnable against an existing run directory, which is what makes a failed scan cheap to retry without re-collecting.

```
collect → normalize → scan → findings
                   ↘ graph → push (Neo4j)
                   ↘ attack
```

Each platform package under `internal/` exposes the same three entry points:

```go
func Collect(ctx context.Context, cfg *engine.Config, locator string) (string, error)
func Normalize(ctx context.Context, runDir string) error
func Scan(ctx context.Context, runDir string, opts ScanOptions) error
```

**Collect** talks to the platform API and writes raw responses as `json.RawMessage` under `00-collect/`, one file per surface. Optional surfaces that return 403 or 404 are recorded as unobserved rather than treated as empty, so a rule can tell "no branch protection" apart from "could not read branch protection".

**Normalize** folds those raw responses into explicit per-subject records under `10-normalize/`. This is where the fields rules key on are computed. Empty values that rules test against serialize as `[]` or `null` rather than being omitted.

**Scan** evaluates the rule corpus over those records and writes findings to `20-scan/`.

`internal/engine` owns the run directory layout, phase state, the bounded concurrency runners (`engine.Run` and `engine.RunPartial`), and credential resolution.

### Taint and gates

- **Taint** tracks user-controllable data (PR titles, comment bodies, workflow inputs, etc.) as it flows through env vars, expressions, and steps. When tainted data reaches a dangerous sink (like a `run:` command), it's an injection vulnerability.
- **Gates** are security controls along the path to an injectable step. Blocking gates (deployment approval, permission checks) suppress findings. Soft gates (label requirements, author association checks) reduce confidence.

## Adding a detection

Detections are YAML, not Go. There is no plugin to register and no code to compile — drop a file under `internal/detection-rules/<platform>/<category>/` and it is embedded and evaluated on the next build. The corpus is currently 94 GitHub, 141 GitLab and 66 ADO rules.

```yaml
id: cat-01/issue-comment-checkout
scenario_id: cat-01/10
title: "issue_comment chatops checks out PR ref and executes it"
subject: job
graph: attack(PWN_REQUEST)
severity: critical
confidence: high
description: >
  A workflow triggered by issue_comment resolves the PR linked from the comment,
  checks out its head ref, and executes code from that ref.

where:
  all_of:
    - triggers ∋ {issue_comment}
    - has_checkout_of_pr_ref == true
    - executes_checked_out_code == true
  none_of:
    - if_conditions_summary.gate_strength == "strong"

evidence:
  - "issue_comment job checks out PR head and runs code from it."
  - "Gate strength: {{ if_conditions_summary.gate_strength }}"

remediation_hint: >
  Require author-association == OWNER or compare against an explicit maintainer
  list; do not gate on a substring match of the comment body alone.
```

`subject` selects which normalized record kind the rule runs against — `job`, `chain`, `project`, `org`, `merge_request`, `environment` and others. `where` combines predicates under `all_of`, `any_of` and `none_of`. Predicate operators come from `internal/dsl`: `==`, `!=`, `>=`, `<=`, `>`, `<`, `∋` (contains), `⊆` (subset of), `matches`, and `in`. The word forms ` contains ` and ` subset_of ` are accepted as aliases of the symbols. `evidence` strings interpolate record fields with `{{ field }}`.

The important constraint: **a rule can only test fields that normalize actually emits.** If the field you need does not exist on the record, the work is in `internal/<platform>/normalize_entities.go`, not in the rule. Adding a computed boolean there is usually the right move when a predicate would otherwise need logic the DSL cannot express.

Test rules against the firing-range scenarios rather than against what the implementation happens to produce.

## Adding a platform

1. Create `internal/<platform>/` with `Collect`, `Normalize` and `Scan` matching the signatures above.
2. Add a client with pagination, rate-limit handling and soft-fail on 403/404 for optional surfaces.
3. Add credential resolution to `internal/engine/credential.go`, following the existing precedence: `TRAJAN_<PLATFORM>_TOKEN`, then the platform's conventional variables, then `--token`.
4. Add `internal/detection-rules/<platform>/` and include it in that package's `//go:embed` directive. A `.keep` stub is enough to start — the `all:` embed prefix makes an otherwise-empty directory embeddable.
5. Wire subcommands under `cmd/trajan/<platform>/`, declaring `--token` leaf-locally on the subcommands that authenticate.

Use `internal/gitlab/` as the reference; it is the most recently built of the three.

## Testing

### Running tests

```bash
# All tests
make test

# Specific package
go test -v ./internal/dsl/...

# With coverage
make test-coverage
# Opens coverage.html in browser
```

### Writing tests

- Use `testify/assert` and `testify/require` (already a dependency).
- Use table-driven tests with descriptive subtest names.
- For detection tests: build a `graph.Graph` from YAML fixtures, run `Detect()`, and assert on the returned findings.
- For parser tests: provide raw YAML and assert on the `NormalizedWorkflow` output.

## Code style

### Formatting and linting

All code must pass `golangci-lint`. The linters enabled in `.golangci.yml` are:

- `errcheck`: unchecked errors, including type assertions
- `govet`: standard Go vet checks
- `staticcheck`: advanced static analysis
- `unused`: dead code
- `ineffassign`: ineffectual assignments
- `misspell`: spelling mistakes in comments
- `unconvert`: redundant type conversions
- `gocritic`: style and performance diagnostics

`gofmt` and `goimports` run as formatters rather than linters.

Run `make fmt` and `make lint` before submitting. `make lint` passes `--max-same-issues 0 --max-issues-per-linter 0`, which is deliberate: golangci-lint's defaults cap how many findings of each kind it reports, so a run without them can look clean while issues remain.

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
