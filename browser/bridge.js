/**
 * Trajan WASM bridge — loads Go, installs the Promise API on window.trajan.
 * Requires fs-shim.js before wasm_exec.js.
 */
class TrajanBridge {
  constructor() {
    this.ready = false;
    this._loading = null;
  }

  async init(wasmURL = "trajan.wasm") {
    if (this.ready) return;
    if (this._loading) return this._loading;
    this._loading = this._load(wasmURL);
    await this._loading;
    this.ready = true;
  }

  async _load(wasmURL) {
    if (typeof Go === "undefined") {
      throw new Error("wasm_exec.js not loaded");
    }
    if (typeof globalThis.fs?.open !== "function" || globalThis.fs.constants?.O_CREAT === -1) {
      throw new Error("fs-shim.js must load before wasm_exec.js");
    }

      const go = new Go();
    let result;
    const url = typeof _wasmDataUrl === "function" ? _wasmDataUrl() : wasmURL;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`failed to fetch ${wasmURL}: ${response.status}`);
    }
    const contentType = response.headers.get("Content-Type") || "";
    if (typeof WebAssembly.instantiateStreaming === "function" && contentType.includes("application/wasm")) {
      result = await WebAssembly.instantiateStreaming(response, go.importObject);
    } else {
      const buffer = await response.arrayBuffer();
      result = await WebAssembly.instantiate(buffer, go.importObject);
    }
    go.run(result.instance);
    await new Promise((r) => setTimeout(r, 50));

    for (const name of ["trajanInitialize", "trajanScan", "trajanReport", "trajanCancel", "trajanVersion"]) {
      if (typeof globalThis[name] !== "function") {
        throw new Error(`${name} not exported from WASM`);
      }
    }
  }

  async initialize(opts = {}) {
    await this.init(opts.wasmURL);
    return unwrap(await globalThis.trajanInitialize(opts));
  }

  async whoami(opts) {
    return unwrap(await globalThis.trajanWhoAmI(opts));
  }

  async scan(opts) {
    return unwrap(await globalThis.trajanScan(opts));
  }

  async report(opts) {
    return unwrap(await globalThis.trajanReport(opts));
  }

  cancel() {
    return globalThis.trajanCancel();
  }

  version() {
    return globalThis.trajanVersion();
  }
}

function unwrap(result) {
  if (result && typeof result === "object" && result.error && !result.ok && result.runDir === undefined && result.content === undefined) {
    // reject path already throws; some handlers return {error}
    if (Object.keys(result).length === 1) throw new Error(result.error);
  }
  return result;
}

window.trajan = new TrajanBridge();
