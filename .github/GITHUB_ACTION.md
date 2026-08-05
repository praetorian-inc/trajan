# Trajan GitHub Action

Trajan can run as a composite GitHub Action. It scans the selected GitHub
repository, renders HTML, Markdown, and JSONL reports, writes a concise job
summary, and uploads the reports as a workflow artifact.

The initial implementation builds the Trajan source pinned by the Action ref and
supports Linux runners.

## Use the Action

```yaml
name: Trajan

on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  contents: read
  actions: read

jobs:
  trajan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan CI/CD configuration
        uses: praetorian-inc/trajan@feat/github-action
        with:
          fail-on-severity: none
```

No checkout step is required in the consumer repository. Trajan reads the
target through GitHub's APIs.

During development, the value after `@` can be a branch. For a released Action,
use a full commit SHA for the strongest immutable pin, a fixed version such as
`v1.1.0`, or the moving compatible `v1` tag.

## Expanded coverage

The built-in `${{ github.token }}` covers repository source and workflows, but
not Trajan's complete settings and organization collection. The Action marks
`degraded=true` when Trajan records unavailable collection operations.

For expanded coverage, store a fine-grained PAT as an Actions secret and pass it
explicitly:

```yaml
      - uses: praetorian-inc/trajan@feat/github-action
        with:
          token: ${{ secrets.TRAJAN_TOKEN }}
          fail-on-severity: high
```

Do not use the PAT configuration for fork-originated pull requests. GitHub does
not expose repository secrets to those runs.

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `token` | `github.token` | Token used by the Trajan collector |
| `scope` | `github.repository` | Repository (`owner/name`) or organization to scan |
| `artifact-name` | `trajan-report` | Uploaded artifact name |
| `retention-days` | `14` | Artifact retention period |
| `fail-on-severity` | `none` | Fail after upload for `info`, `low`, `medium`, `high`, or `critical` findings |
| `force-rest` | `true` | Avoid the current git transport's token-in-process-argument behavior, with reduced all-branch collection |

The Action exposes report paths, artifact URL, finding count, and degraded state
as outputs.

## Testing a branch

You do not need to merge the Action to `main` before testing it.

From another repository, reference the branch directly:

```yaml
uses: praetorian-inc/trajan@feat/github-action
```

To test inside this repository, the `Test GitHub Action` workflow checks out the
selected branch and invokes `uses: ./`. Open the Actions tab, select that
workflow, choose **Run workflow**, and select the feature branch.

A successful test has all of the following:

1. The source build completes.
2. Collect, normalize, and scan complete, with unavailable permissions reported
   as degraded rather than hidden.
3. The job summary contains severity counts.
4. The `trajan-report` artifact contains `findings.html`, `findings.md`, and
   `findings.jsonl`.
5. The output step prints the finding count, degraded state, and artifact URL.

The Action defaults to report-only behavior. Set `fail-on-severity: high`, for
example, only after validating expected results; the failure is applied after
the report artifact is uploaded.
