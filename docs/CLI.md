<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# trajan CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:fcf86499bcbef7d9f84fef59a9f57d6423f70d77f29a96ff657ad1c97c30c991`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`trajan`](#trajan) | *(none)* | Trajan - CI/CD Security Scanner |
| [`trajan ado`](#trajan-ado) | *(none)* | Trajan - Azure DevOps |
| [`trajan ado collect`](#trajan-ado-collect) | *(none)* | Collect raw Azure DevOps configuration for an org/project |
| [`trajan ado normalize`](#trajan-ado-normalize) | *(none)* | Normalize collected Azure DevOps data into structural node/edge records |
| [`trajan ado report`](#trajan-ado-report) | *(none)* | Render findings (json\|jsonl\|md\|html\|all) from a scanned run |
| [`trajan ado run`](#trajan-ado-run) | *(none)* | Wrapper: collect, normalize, scan in one process |
| [`trajan ado scan`](#trajan-ado-scan) | *(none)* | Evaluate ADO detection rules over a normalized run |
| [`trajan ado whoami`](#trajan-ado-whoami) | *(none)* | Resolve the token and print the authenticated identity and reachable surfaces |
| [`trajan github`](#trajan-github) | `gh` | GitHub platform |
| [`trajan github analyze`](#trajan-github-analyze) | *(none)* | Run deeper analysis over the graph |
| [`trajan github attack`](#trajan-github-attack) | *(none)* | Author, validate and run authorized verification chains |
| [`trajan github attack catalog`](#trajan-github-attack-catalog) | *(none)* | List the primitive registry (the prompt source for plan authoring) |
| [`trajan github attack cleanup`](#trajan-github-attack-cleanup) | *(none)* | Replay a run's recorded inverses and report what was and was not undone |
| [`trajan github attack identity`](#trajan-github-attack-identity) | *(none)* | Manage the credential store (~/.trajan/identities.json) |
| [`trajan github attack identity add`](#trajan-github-attack-identity-add) | *(none)* | Add or replace an identity; the secret is read from stdin or --token-env, never argv |
| [`trajan github attack identity list`](#trajan-github-attack-identity-list) | *(none)* | List stored identities (never their secrets) |
| [`trajan github attack identity rm`](#trajan-github-attack-identity-rm) | *(none)* | Remove an identity |
| [`trajan github attack plan`](#trajan-github-attack-plan) | *(none)* | Work with attack plans |
| [`trajan github attack plan list`](#trajan-github-attack-plan-list) | *(none)* | List the embedded plan templates |
| [`trajan github attack plan validate`](#trajan-github-attack-plan-validate) | *(none)* | Validate a plan file or embedded template offline, reporting every error at once |
| [`trajan github attack resume`](#trajan-github-attack-resume) | *(none)* | Resume a run: completed steps are skipped and a killed watch resumes the watch |
| [`trajan github attack run`](#trajan-github-attack-run) | *(none)* | Run a plan. Dry run unless --execute is passed |
| [`trajan github collect`](#trajan-github-collect) | *(none)* | Collect raw GitHub Actions configuration for an org or repo |
| [`trajan github graph`](#trajan-github-graph) | *(none)* | Build importable graph nodes/edges from normalized facts and findings |
| [`trajan github normalize`](#trajan-github-normalize) | *(none)* | Normalize collected data into fact records |
| [`trajan github push`](#trajan-github-push) | *(none)* | Push facts + findings into the graph |
| [`trajan github report`](#trajan-github-report) | *(none)* | Render findings (json\|jsonl\|md\|html\|all) from a scanned run |
| [`trajan github run`](#trajan-github-run) | *(none)* | Wrapper: collect, normalize, scan in one process |
| [`trajan github scan`](#trajan-github-scan) | *(none)* | Evaluate category rules over normalized facts |
| [`trajan github whoami`](#trajan-github-whoami) | *(none)* | Resolve the token and print the authenticated identity and scopes |
| [`trajan gitlab`](#trajan-gitlab) | `gl` | GitLab platform |
| [`trajan gitlab analyze`](#trajan-gitlab-analyze) | *(none)* | Run deeper analysis over the graph |
| [`trajan gitlab attack`](#trajan-gitlab-attack) | *(none)* | Active exploitation (reserved) |
| [`trajan gitlab collect`](#trajan-gitlab-collect) | *(none)* | Collect raw GitLab CI configuration for a group, subgroup, or project |
| [`trajan gitlab normalize`](#trajan-gitlab-normalize) | *(none)* | Normalize collected data into fact records |
| [`trajan gitlab push`](#trajan-gitlab-push) | *(none)* | Push facts + findings into the graph |
| [`trajan gitlab report`](#trajan-gitlab-report) | *(none)* | Render findings (json\|jsonl\|md\|html\|all) from a scanned run |
| [`trajan gitlab run`](#trajan-gitlab-run) | *(none)* | Wrapper: collect, normalize, scan in one process |
| [`trajan gitlab scan`](#trajan-gitlab-scan) | *(none)* | Evaluate category rules over normalized facts |
| [`trajan gitlab whoami`](#trajan-gitlab-whoami) | *(none)* | Resolve the token and print the authenticated identity and scopes |
| [`trajan search`](#trajan-search) | *(none)* | Search for repositories with self-hosted runners (hidden) |
| [`trajan version`](#trajan-version) | *(none)* | Print version information |

## `trajan`

Trajan - CI/CD Security Scanner

- Usage: `trajan`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan ado`

Trajan - Azure DevOps

- Usage: `trajan ado`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--output-dir` |  | string | `./trajan-out` | run output directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan ado collect`

Collect raw Azure DevOps configuration for an org/project

- Usage: `trajan ado collect [locator]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--azure-bearer-token` |  | string |  | bearer token (prefer AZURE_BEARER_TOKEN/SYSTEM_ACCESSTOKEN env; this flag is an escape hatch) |
| `--token` |  | string |  | PAT (prefer TRAJAN_ADO_TOKEN/ADO_PAT/AZURE_DEVOPS_PAT/AZDO_PAT/AZURE_DEVOPS_EXT_PAT env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan ado normalize`

Normalize collected Azure DevOps data into structural node/edge records

- Usage: `trajan ado normalize`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan ado report`

Render findings (json|jsonl|md|html|all) from a scanned run

- Usage: `trajan ado report`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `jsonl` | output format: json\|jsonl\|md\|html\|all |
| `--min-confidence` |  | string | `low` | drop findings below this confidence |
| `--min-severity` |  | string | `info` | drop findings below this severity |
| `--out` |  | string |  | destination dir, or '-' for stdout (default: the run dir) |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan ado run`

Wrapper: collect, normalize, scan in one process

- Usage: `trajan ado run [locator]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--azure-bearer-token` |  | string |  | bearer token (prefer AZURE_BEARER_TOKEN/SYSTEM_ACCESSTOKEN env; this flag is an escape hatch) |
| `--token` |  | string |  | PAT (prefer TRAJAN_ADO_TOKEN/ADO_PAT/AZURE_DEVOPS_PAT/AZDO_PAT/AZURE_DEVOPS_EXT_PAT env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan ado scan`

Evaluate ADO detection rules over a normalized run

- Usage: `trajan ado scan`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--org-detections-only` |  | bool | `false` | evaluate only org-subject (org-level) rules |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan ado whoami`

Resolve the token and print the authenticated identity and reachable surfaces

- Usage: `trajan ado whoami`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--azure-bearer-token` |  | string |  | bearer token (prefer AZURE_BEARER_TOKEN/SYSTEM_ACCESSTOKEN env; this flag is an escape hatch) |
| `--org` |  | string |  | Azure DevOps organization (default: ORG_NAME) |
| `--token` |  | string |  | PAT (prefer TRAJAN_ADO_TOKEN/ADO_PAT/AZURE_DEVOPS_PAT/AZDO_PAT/AZURE_DEVOPS_EXT_PAT env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github`

GitHub platform

- Usage: `trajan github`
- Aliases: `gh`
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--output-dir` |  | string | `./trajan-out` | run output directory |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github analyze`

Run deeper analysis over the graph

- Usage: `trajan github analyze`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--detailed` | `-d` | bool | `false` | expand output |
| `--no-graph` | `-G` | bool | `false` | analyze in-memory (no Neo4j) |
| `--path` | `-p` | string |  | run directory (default: latest) |
| `--write-back` | `-w` | bool | `false` | persist analysis results |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack`

Author, validate and run authorized verification chains

- Usage: `trajan github attack`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack catalog`

List the primitive registry (the prompt source for plan authoring)

- Usage: `trajan github attack catalog`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--json` |  | bool | `false` | emit the full registry as JSON |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack cleanup`

Replay a run's recorded inverses and report what was and was not undone

- Usage: `trajan github attack cleanup [<plan-id>]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--dry-run` |  | bool | `false` | list the inverses without issuing them |
| `--path` | `-p` | string |  | run directory to clean up (default: latest) |
| `--token` |  | string |  | API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack identity`

Manage the credential store (~/.trajan/identities.json)

- Usage: `trajan github attack identity`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack identity add`

Add or replace an identity; the secret is read from stdin or --token-env, never argv

- Usage: `trajan github attack identity add <name>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--kind` |  | string | `pat` | pat\|fine_grained\|app_installation\|oidc\|gh_cli |
| `--note` |  | string |  | free-text note |
| `--token-env` |  | string |  | read the secret from this environment variable instead of stdin |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack identity list`

List stored identities (never their secrets)

- Usage: `trajan github attack identity list`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack identity rm`

Remove an identity

- Usage: `trajan github attack identity rm <name>`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack plan`

Work with attack plans

- Usage: `trajan github attack plan`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack plan list`

List the embedded plan templates

- Usage: `trajan github attack plan list`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack plan validate`

Validate a plan file or embedded template offline, reporting every error at once

- Usage: `trajan github attack plan validate <plan|template-id>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--set` |  | stringArray | `[]` | set an input: --set key=value (repeatable) |
| `--set-file` |  | string |  | YAML file of input values |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack resume`

Resume a run: completed steps are skipped and a killed watch resumes the watch

- Usage: `trajan github attack resume [<plan-id>]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--keep-cipher` |  | bool | `false` | keep the harvest's persisted ciphertext after a successful decrypt instead of discarding it |
| `--path` | `-p` | string |  | run directory to resume (default: latest) |
| `--step-delay` |  | duration | `0s` | sleep between steps to absorb read-after-write propagation lag |
| `--token` |  | string |  | API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch) |
| `--until` |  | string |  | resume up to and including this step id, then stop again |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github attack run`

Run a plan. Dry run unless --execute is passed

- Usage: `trajan github attack run <plan|template-id>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--dry-run` |  | bool | `false` | render every mutation without sending one (the default) |
| `--execute` |  | bool | `false` | issue mutations against the target; passing it is the authorization assertion |
| `--keep-cipher` |  | bool | `false` | keep the harvest's persisted ciphertext after a successful decrypt instead of discarding it |
| `--path` | `-p` | string |  | attach to an existing run directory (default: mint one) |
| `--set` |  | stringArray | `[]` | set an input: --set key=value (repeatable) |
| `--set-file` |  | string |  | YAML file of input values |
| `--step-delay` |  | duration | `0s` | sleep between steps to absorb read-after-write propagation lag |
| `--token` |  | string |  | API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch) |
| `--until` |  | string |  | run up to and including this step id, then stop; cleanup is left for the resume |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github collect`

Collect raw GitHub Actions configuration for an org or repo

- Usage: `trajan github collect <locator>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` |  | string |  | API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github graph`

Build importable graph nodes/edges from normalized facts and findings

- Usage: `trajan github graph`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github normalize`

Normalize collected data into fact records

- Usage: `trajan github normalize`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github push`

Push facts + findings into the graph

- Usage: `trajan github push`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--neo4j-pass` |  | string |  | Neo4j password |
| `--neo4j-url` |  | string | `bolt://localhost:7687` | Neo4j Bolt URL |
| `--neo4j-user` |  | string | `neo4j` | Neo4j user |
| `--path` | `-p` | string |  | run directory (default: latest) |
| `--reset` |  | bool | `false` | delete every node in the database before pushing |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github report`

Render findings (json|jsonl|md|html|all) from a scanned run

- Usage: `trajan github report [locator]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `jsonl` | output format: json\|jsonl\|md\|html\|all |
| `--min-confidence` |  | string | `low` | drop findings below this confidence |
| `--min-severity` |  | string | `info` | drop findings below this severity |
| `--out` |  | string |  | destination dir, or '-' for stdout (default: stdout for json/jsonl, run dir for md/html) |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github run`

Wrapper: collect, normalize, scan in one process

- Usage: `trajan github run <locator>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` |  | string |  | API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github scan`

Evaluate category rules over normalized facts

- Usage: `trajan github scan [locator]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--org-detections-only` |  | bool | `false` | evaluate only org-subject (org-level) rules |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan github whoami`

Resolve the token and print the authenticated identity and scopes

- Usage: `trajan github whoami`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` |  | string |  | API token (prefer TRAJAN_GH_TOKEN/GH_TOKEN/GITHUB_TOKEN env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab`

GitLab platform

- Usage: `trajan gitlab`
- Aliases: `gl`
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab analyze`

Run deeper analysis over the graph

- Usage: `trajan gitlab analyze`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--detailed` | `-d` | bool | `false` | expand output |
| `--no-graph` | `-G` | bool | `false` | analyze in-memory (no Neo4j) |
| `--path` | `-p` | string |  | run directory (default: latest) |
| `--write-back` | `-w` | bool | `false` | persist analysis results |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab attack`

Active exploitation (reserved)

- Usage: `trajan gitlab attack`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab collect`

Collect raw GitLab CI configuration for a group, subgroup, or project

- Usage: `trajan gitlab collect <locator>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` |  | string |  | API token (prefer TRAJAN_GL_TOKEN/GITLAB_TOKEN/GL_TOKEN/CI_JOB_TOKEN env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab normalize`

Normalize collected data into fact records

- Usage: `trajan gitlab normalize`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab push`

Push facts + findings into the graph

- Usage: `trajan gitlab push`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--neo4j-pass` |  | string |  | Neo4j password |
| `--neo4j-url` |  | string | `bolt://localhost:7687` | Neo4j Bolt URL |
| `--neo4j-user` |  | string | `neo4j` | Neo4j user |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab report`

Render findings (json|jsonl|md|html|all) from a scanned run

- Usage: `trajan gitlab report [locator]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--format` |  | string | `jsonl` | output format: json\|jsonl\|md\|html\|all |
| `--min-confidence` |  | string | `low` | drop findings below this confidence |
| `--min-severity` |  | string | `info` | drop findings below this severity |
| `--out` |  | string |  | destination dir, or '-' for stdout (default: the run dir) |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab run`

Wrapper: collect, normalize, scan in one process

- Usage: `trajan gitlab run <locator>`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` |  | string |  | API token (prefer TRAJAN_GL_TOKEN/GITLAB_TOKEN/GL_TOKEN/CI_JOB_TOKEN env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab scan`

Evaluate category rules over normalized facts

- Usage: `trajan gitlab scan [locator]`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--group-detections-only` |  | bool | `false` | evaluate only group-subject rules |
| `--path` | `-p` | string |  | run directory (default: latest) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan gitlab whoami`

Resolve the token and print the authenticated identity and scopes

- Usage: `trajan gitlab whoami`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--token` |  | string |  | API token (prefer TRAJAN_GL_TOKEN/GITLAB_TOKEN/GL_TOKEN/CI_JOB_TOKEN env; this flag is an escape hatch) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--concurrency` |  | int | `8` | max concurrent API workers |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--insecure` |  | bool | `false` | skip TLS verify (self-signed self-hosted) |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--output-dir` |  | string | `./trajan-out` | run output directory |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--url` |  | string | `https://gitlab.com` | GitLab base URL (self-hosted) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan search`

Search for repositories with self-hosted runners

- Usage: `trajan search`
- Aliases: *(none)*
- Hidden: not shown in `--help` output

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--org` |  | string |  | Organization to search within |
| `--output-file` |  | string |  | Output file for results |
| `--provider` | `-p` | string | `sourcegraph` | Search provider (sourcegraph; for github use: trajan github search) |
| `--query` | `-q` | string |  | Custom search query |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |

## `trajan version`

Print version information

- Usage: `trajan version`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--debug` |  | bool | `false` | raw slog records instead of humanized output |
| `--no-color` |  | bool | `false` | disable color (also honors NO_COLOR) |
| `--proxy` |  | string |  | HTTP proxy URL (e.g., http://proxy:8080) |
| `--socks-proxy` |  | string |  | SOCKS5 proxy URL (e.g., socks5://proxy:1080) |
| `--verbose` | `-v` | bool | `false` | verbose output (hidden) |
