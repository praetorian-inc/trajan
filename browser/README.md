# Trajan browser (WASM) scanner

Runs Trajan's YAML detection pipeline (collect → normalize → scan → HTML report)
entirely in the browser. Attack and graph are not included.

## Build

From the repo root:

```sh
make wasm          # browser/trajan.wasm + wasm_exec.js + report.css
make wasm-serve    # http://localhost:8080
make wasm-dist     # browser/trajan-standalone.html (single file)
```

## Usage

1. Open the UI.
2. Choose GitHub, GitLab, or Azure DevOps.
3. Enter a locator (`org/repo`, group, `org/project`, or HTTPS URL) and a token.
4. Run scan. Findings render in the same HTML report used by the CLI and GitHub Action.

Tokens stay in memory for the page session. They are not written to `localStorage`.

## CORS

Cloud GitHub, GitLab, and Azure DevOps generally allow browser `Authorization` via CORS
(verified against all six Azure DevOps `hostBase` hosts: `dev.azure.com`,
`vsrm`, `feeds`, `extmgmt`, `vssps`, `almsearch`). The default build does **not**
require a proxy.

If a host blocks you (common for self-hosted GitLab):

```sh
TRAJAN_WASM_PROXY=1 make wasm-serve
```

Then point requests through `/azdo-proxy/{host}/...` or `/cors-proxy/{host}/...`
(see `server.go`). The default build does not require a proxy.

## Layout

| File | Role |
|------|------|
| `fs-shim.js` | In-memory `fs` + `path` for Go's js/wasm runtime |
| `bridge.js` / `app.js` | WASM loader and UI |
| `report.css` | Copied from `internal/report/assets` on `make wasm` |
| `shell.css` | Scan form chrome |
| `server.go` | Dev static server (+ optional CORS proxy) |

## API

```js
await trajan.initialize({ outputDir: "/run", concurrency: 8, onLog })
await trajan.whoami({ platform, token, baseUrl, org })
await trajan.scan({ platform, locator, token, baseUrl, bearerToken, orgOnly })
await trajan.report({ runDir, format: "html" })
trajan.cancel()
trajan.version()
```
