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
