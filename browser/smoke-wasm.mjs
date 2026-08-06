#!/usr/bin/env node
/**
 * Load trajan.wasm under the fs shim and call initialize().
 * Validates Go ↔ memfs for MintRunDir / report paths.
 */
import path from "node:path";
import fsNode from "node:fs";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";
import { performance } from "node:perf_hooks";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const wasmPath = path.join(__dirname, "trajan.wasm");
if (!fsNode.existsSync(wasmPath)) {
  console.error("missing browser/trajan.wasm — run make wasm first");
  process.exit(1);
}

const sandbox = {
  console,
  Date,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  Array,
  Map,
  Set,
  Error,
  Promise,
  Object,
  JSON,
  Math,
  Number,
  String,
  Boolean,
  parseInt,
  parseFloat,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  performance,
  crypto: webcrypto,
  fetch: globalThis.fetch,
  WebAssembly,
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.self = sandbox;

vm.runInNewContext(fsNode.readFileSync(path.join(__dirname, "fs-shim.js"), "utf8"), sandbox);
vm.runInNewContext(fsNode.readFileSync(path.join(__dirname, "wasm_exec.js"), "utf8"), sandbox);

const go = new sandbox.Go();
const buf = fsNode.readFileSync(wasmPath);
const result = await WebAssembly.instantiate(buf, go.importObject);
go.run(result.instance);
await new Promise((r) => setTimeout(r, 100));

if (typeof sandbox.trajanInitialize !== "function") {
  throw new Error("trajanInitialize missing");
}

const init = await sandbox.trajanInitialize({
  outputDir: "/run",
  concurrency: 4,
  onLog(level, msg) {
    // quiet
  },
});
if (!init || !init.ok) throw new Error("initialize failed: " + JSON.stringify(init));

const listed = sandbox.__trajanFS.list("/");
if (!listed.includes("run")) throw new Error("/run not created: " + JSON.stringify(listed));

const ver = sandbox.trajanVersion();
console.log("wasm-init smoke: ok", ver.version, "outputDir=" + init.outputDir);
