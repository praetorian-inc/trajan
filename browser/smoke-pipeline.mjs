#!/usr/bin/env node
/**
 * Fixture-based Scan + report under WASM + memfs (no network).
 */
import path from "node:path";
import fsNode from "node:fs";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { performance } from "node:perf_hooks";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = path.join(__dirname, "trajan.wasm");
if (!fsNode.existsSync(wasmPath)) {
  console.error("missing browser/trajan.wasm — run make wasm first");
  process.exit(1);
}

const sandbox = {
  console, Date, TextEncoder, TextDecoder, Uint8Array, Array, Map, Set, Error,
  Promise, Object, JSON, Math, Number, String, Boolean, parseInt, parseFloat,
  setTimeout, clearTimeout, setInterval, clearInterval, performance,
  crypto: webcrypto, fetch: globalThis.fetch, WebAssembly,
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.self = sandbox;

vm.runInNewContext(fsNode.readFileSync(path.join(__dirname, "fs-shim.js"), "utf8"), sandbox);
vm.runInNewContext(fsNode.readFileSync(path.join(__dirname, "wasm_exec.js"), "utf8"), sandbox);

const go = new sandbox.Go();
const result = await WebAssembly.instantiate(fsNode.readFileSync(wasmPath), go.importObject);
go.run(result.instance);
await new Promise((r) => setTimeout(r, 100));

await sandbox.trajanInitialize({ outputDir: "/run", concurrency: 4 });

const runDir = "/run/2026-01-01-0000-gh-fixture";
const fs = sandbox.fs;
const call = (fn, ...args) => new Promise((resolve, reject) => {
  fn(...args, (err, value) => (err ? reject(err) : resolve(value)));
});

async function mkdirp(p) {
  const parts = p.split("/").filter(Boolean);
  let cur = "";
  for (const part of parts) {
    cur += "/" + part;
    try {
      await call(fs.mkdir, cur, 0o755);
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
    }
  }
}

await mkdirp(runDir + "/10-normalize/jobs");
sandbox.__trajanFS.writeFile(runDir + "/_meta.json", JSON.stringify({
  run_id: "2026-01-01-0000-gh-fixture",
  platform: "gh",
  scope: "fixture/repo",
  org: "fixture",
  last_phase: 1,
  phases: [],
  started_at: "2026-01-01T00:00:00+00:00",
  invocation: ["wasm-smoke"],
}, null, 2));

sandbox.__trajanFS.writeFile(runDir + "/10-normalize/jobs/fr-01__ci__build.json", JSON.stringify({
  _id: "fr-01__ci__build",
  triggers: ["pull_request_target"],
  has_checkout_of_pr_ref: true,
  executes_checked_out_code: true,
  if_conditions_summary: { gate_strength: "weak" },
}, null, 2));

const summary = await sandbox.trajanScan({ platform: "github", runDir });
if (!summary.runDir) throw new Error("scan missing runDir: " + JSON.stringify(summary));

const rep = await sandbox.trajanReport({ runDir: summary.runDir, format: "html" });
if (!rep.content || !rep.content.includes("<style>")) {
  throw new Error("report HTML not self-contained");
}
if (!rep.content.includes("Trajan") || !rep.content.includes("finding")) {
  throw new Error("report HTML missing expected markers");
}

console.log("pipeline smoke: ok", "findings=" + (summary.total ?? "?"), "html_bytes=" + rep.bytes);
