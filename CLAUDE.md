# CLAUDE.md

Trajan — a CI/CD security scanner (GitHub Actions, GitLab CI, Azure DevOps, Jenkins, JFrog). Go. **When in doubt, favor less code.**

The GitHub platform is being rebuilt as a phased, on-disk pipeline under
`internal/{engine,github,finding,report,detection-rules,graph}` (collect →
normalize → scan → push → analyze, plus a `run` wrapper). The other platforms
still live under `pkg/`. The conventions below are binding for all new code, and
especially for the `internal/` GitHub stack.

## Rules

- **Never commit or push anything unless explicitly requested.**

## Think before coding

Don't assume. Don't hide confusion. Surface tradeoffs.

- Figure out how your assumptions impact the architecture and vision. If uncertain, **ask**.
- If multiple interpretations exist with varying implications, **present them** — don't pick silently.
- If a simpler approach exists, **say so**. Push back when warranted.
- If something is unclear, **name what's confusing**. Ask.

## Comments

- **Only for genuinely non-obvious logic. Default to none.**
- A comment earns its place by explaining a **why** a competent Go reader couldn't infer from the code itself.
- No decorative comments. No name-restating comments. No doc-comment-per-identifier ritual. No section-divider banners.

## Go design principles

- **Modern Go ≤ 1.25.** Use the current standard library and language surface: `any`, `slices`/`maps`/`cmp`, `min`/`max`/`clear`, `cmp.Or`, `errors.Is`/`errors.As`, `wg.Go`, `t.Context()`, `b.Loop()`. Do **not** use 1.26-only features.
- **YAGNI is paramount.** Don't build abstractions, surfaces, or options before they're needed. No speculative generality.
- **DRY is a close second** — pragmatic, not dogmatic. Don't deduplicate at the cost of clarity or a premature abstraction.
- **Concurrency:** in the `internal/` stack reuse the engine's bounded runners — `engine.Run[I,O]` (abort on first error) and `engine.RunPartial[I,O]` (drop a failed item via `onError`, continue) — instead of hand-rolling `errgroup`/`WaitGroup`. Bound work by `--concurrency`. **Always honor `ctx`.**
- **Errors — fatal vs non-fatal.** A returned `error` means non-recoverable (IO, load, or a contract violation) → abort the phase. Per-item failures are *not* fatal: route them to an `onError func(error)` callback or accumulate in `timer.Errors`, and continue. One bad subject / repo / rule must never sink the whole run.
- **Soft-fail collection.** Optional API surfaces that return 403/404 → skip and mark, never abort. Gate optional collection on the permission you actually detected so you don't 403-storm endpoints the token can't see.
- **JSON:** collected `data` is raw (`json.RawMessage`); normalized records use explicit shapes. Empties that rules key on serialize as `[]`/`null` — don't omit them. Reserve `omitempty`/`omitzero` for genuinely optional keys.
- **Logging:** `log/slog`.
- **Don't make unnecessary decisions / don't write unnecessary code.** Match the idiom and density of the surrounding code.

## Unit tests

- **Test real behavior, not the shape of the code.** Target true-conditional logic and edge cases — classifier decision trees, DSL operators, boundary conditions. **Not** coverage-matching.
- **No unnecessary tests.** A test exists to catch a real way the code can be wrong.
- **In-package, as assisting `_test.go` files** alongside the code they test. Do **not** put unit tests in a single `tests/` directory.
- **Test against an independent oracle, not the code just written:** the firing-range scenarios (`fr-NN-MM-*` in `ghektestorg`) are ground truth. Never assert what the implementation happens to produce.
- **Authored at verification time** — after the code runs end-to-end, not before.

## Verification (`internal/attack`)

Detection reports that a configuration looks wrong. Verification runs a short authorized sequence of calls against the customer's own system to establish whether the weakness is actually reachable, so they can fix it and confirm the fix. A chain is a flat YAML plan under `internal/attack-plans/<platform>/`; `Validate` returns every error at once, offline, issuing zero requests, and a non-empty result means the run never started. Declaration order is topological order, which is why there is no scheduler and no cycle detection.

**Two plugin systems, deliberately unlike each other.** A detection is data: a YAML rule under `internal/detection-rules/<platform>/cat-NN-<topic>/`, evaluated by one generic engine, because a rule is a predicate over collected JSON and nothing more. A verification primitive is typed Go registered with `Register[P, O](Spec, Fn)` — declared ports, capabilities and input fields, one handle type out — because a primitive issues a request and must carry its own inverse, and because its edges are decided by `reflect.Type.Implements` against the compiled registry rather than by a runtime check. Adding a detection is a YAML file; adding a chain is a YAML plan; only a new *irreducible step* is Go.

**Invariants, not conventions.** Nothing in the type system enforces all of these, and a change that weakens one is not a tradeoff to make quietly:

- **Write-ahead ledger.** `Session.Mutate` is the only route to the write client. The inverse is written to the ledger *before* the call, so a process killed between call and result still leaves a replayable undo record. `Declare` is the same discipline for state a job creates rather than a request of ours.
- **Inert by default.** Without `--execute` a run records every request it would issue and sends none. A dry run renders the whole sequence, not just as far as the first step that needs a real answer.
- **Scope gating.** `Mutate` and `Declare` reject a target outside the plan's repository allowlist before anything else happens.
- **Fails locally, not on the customer's system.** Confirm capability with a read before issuing a change the target would refuse. A request that 403s or 422s is an entry in their audit trail that produces no evidence, so checking first is both safer and better engineering.
- **A fact the tool could not read is never reported as a measurement that came out negative.** `Measurement` is a tri-state — value, known, reason — whose zero value is unmeasured, so a producer that never sets one cannot claim a negative. `when:` refuses a step whose gate resolves to an unestablished value rather than reading it as false: `false` is what a real negative looks like, and the gate decides whether to change the customer's system.

**The payload corpus** is `internal/attack-payloads/<platform>/t-NN/`, one YAML fragment per file — id, summary, flavor, typed param schema, optional includes, body. Flavor is `shell` or `workflow_steps` and is fixed by the primitive attaching the fragment, never declared by the plan: `${{ secrets.X }}` is inert text in a checked-out shell file. Bodies render with `<<`/`>>` delimiters so a platform's own `${{ }}` passes through verbatim. Evidence is the line grammar `trajan-<field>=<value>`, bracketed by `trajan-marker=<m>` and `trajan-marker-end=<m>`; the marker is what attributes a line to this run and what makes **"never ran" distinguishable from "ran and the thing was not reachable"**. A fragment preserves that distinction by emitting its negative explicitly rather than emitting nothing, and records that something was reachable rather than what it contained.

**Cleanup reports four buckets, and putting an item in the wrong one is the worst class of defect here.** `reversed` — the inverse ran and the resource is as it was. `partial` — the inverse ran and something it cannot reach survives: a cache entry a run already restored, a closed pull request that still exists. `irreversible` — the call has no inverse: a merge, a delivered notification, data that left the environment. `failed` — an inverse was attempted and refused, commonly a fork the credential cannot delete. Never widen a claim; a reversal that is really partial tells the customer something is clean when it is not.
