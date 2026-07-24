# GitLab rearch — P0 handover

P0 stands up the GitLab phased-pipeline skeleton (LAB-5030). This note records the seam: what P0 freezes versus what each later phase fills in. The mental model is that P0 delivers the *interface and contract* — the package, the entrypoint signatures, the CLI tree, and the on-disk phase model — and every later phase replaces exactly one stub body and adds its implementation files **without changing the signatures P0 froze**.

## What P0 delivered (the frozen contract)

- `internal/gitlab/gitlab.go` — the package with real entrypoint signatures, every one returning `engine.ErrNotImplemented`.
- `cmd/trajan/gitlab/gitlab.go` — a single-file phased CLI mirroring `cmd/trajan/github/github.go` (`whoami/collect/normalize/scan/report/push/analyze/attack/run`), wired to the stubs; `report`/`push`/`analyze` reuse the shared `report.Run` / `graph.Push` / `graph.Analyze`.
- Clean cutover: the legacy `enumerate` / monolithic `scan` / `attack` CLI is deleted. `pkg/gitlab` is untouched and remains the port-from source for later phases.

The contract for anyone picking up a later phase: flip one stub from `ErrNotImplemented` to real, add files under `internal/gitlab/` (mirroring `internal/github`'s split), and do **not** reshape the entrypoints or the CLI.

## Stub → who picks it up

| Stub P0 leaves | Picked up by | Done when |
|---|---|---|
| `Collect(ctx, cfg, locator) (runDir, error)` | P2 — LAB-4287 (API collectors) + LAB-4367 (rate-limit) | writes raw surfaces under `00-collect/`, soft-fails blocked ones |
| `WhoAmI(ctx) error` | P2 — LAB-4287 (auth half) | prints identity + detected scopes/role |
| `ParseScope(locator)` + `Scope`/`ScopeKind` | P2 — LAB-4287 | resolves `group` / `group/subgroup` / `group/subgroup/project` → run-dir slug + traversal seed |
| `Normalize(ctx, runDir) error` | P3 — LAB-4288 (normalize + correlate) | emits fact records matching `docs/gitlab/gitlab-normalized-fields.md` |
| `Scan(ctx, runDir, ScanOptions) error` | P4 (thin driver), gated on P1 — LAB-4987 (generalize the DSL engine); rules merged via LAB-4980–4984 | runs the 141 rules over normalized facts |
| `ScanOptions{GroupOnly}` | P4 | group-subject rules honor the flag |

`report` already works after P0 (shared `report.Run`). `push`/`analyze` are wired but only do useful work once P3 produces facts and graph resource types exist (LAB-4290 emit, LAB-4404 analyzer).

`ParseScope`/`Scope`/`ScopeKind` are intentionally present but unused at P0 — they are P2's handover placeholder, not dead code to trim.

## What P0 deliberately left out, and where it lands

| Not in P0 | Lands in |
|---|---|
| The `pkg/gitlab` monolith (client, enumerate, `include_resolver`, `log_parser`) | P2/P3 port it into `internal/gitlab` |
| Self-hosted `--url` flag (dropped to mirror github; **must return** — self-hosted GitLab is a first-class target) | P2 collect (LAB-4287) |
| `--token` / `cmdutil.GetTokenForPlatform` handling | P2 auth (LAB-4287) |
| `attack` subcommand (a stub, like github's) | LAB-4403 (re-arch attack plugins) |
| `-o` report-shorthand collision panic (inherited verbatim from `github.go`; reproduces on `github report --help` too) | separate platform-wide fix, not GitLab-specific |

## One-liner

P0 = the skeleton compiles and the CLI is real, but every phase returns "not implemented." Each later ticket (P1 engine, P2 collect, P3 normalize, P4 scan) makes exactly one of those return real data, in dependency order, without touching the frame.
