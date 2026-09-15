#!/usr/bin/env node
/**
 * Smoke-test the in-memory fs/path shims against the callback shapes
 * Go's syscall/fs_js.go expects.
 */
import path from "node:path";
import fsNode from "node:fs";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const shimSrc = fsNode.readFileSync(path.join(__dirname, "fs-shim.js"), "utf8");
const sandbox = { console, Date, TextEncoder, TextDecoder, Uint8Array, Map, Set, Error };
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
vm.runInNewContext(shimSrc, sandbox);

const { fs, path: jspath, __trajanFS } = sandbox;

function call(fn, ...args) {
  return new Promise((resolve, reject) => {
    fn(...args, (err, value) => (err ? reject(err) : resolve(value)));
  });
}

try {
  await call(fs.mkdir, "/run", 0o755);
  await call(fs.mkdir, "/run/demo", 0o755);
  const fd = await call(fs.open, "/run/demo/hello.txt", fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_TRUNC, 0o644);
  const payload = new TextEncoder().encode("scan-ok\n");
  const buf = new Uint8Array(payload);
  const n = await call(fs.write, fd, buf, 0, buf.length, null);
  if (n !== buf.length) throw new Error("write length mismatch");
  await call(fs.close, fd);

  const entries = await call(fs.readdir, "/run/demo");
  if (!Array.isArray(entries) || !entries.includes("hello.txt")) {
    throw new Error("readdir failed: " + JSON.stringify(entries));
  }

  const rfd = await call(fs.open, "/run/demo/hello.txt", fs.constants.O_RDONLY, 0);
  const out = new Uint8Array(32);
  const rn = await call(fs.read, rfd, out, 0, 32, null);
  await call(fs.close, rfd);
  const text = new TextDecoder().decode(out.subarray(0, rn));
  if (text !== "scan-ok\n") throw new Error("read mismatch: " + JSON.stringify(text));

  const resolved = jspath.resolve("/run", "demo", "hello.txt");
  if (resolved !== "/run/demo/hello.txt") throw new Error("path.resolve: " + resolved);

  const st = await call(fs.stat, "/run/demo");
  if (!st.isDirectory()) throw new Error("stat dir");

  __trajanFS.reset();
  console.log("fs-shim smoke: ok");
} catch (e) {
  console.error("fs-shim smoke: FAIL", e);
  process.exit(1);
}
