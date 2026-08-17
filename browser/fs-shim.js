/**
 * In-memory Node-compatible fs + path shims for Go's js/wasm runtime.
 * Install before wasm_exec.js so Go does not keep the ENOSYS stubs.
 *
 * Callbacks match Go's syscall/fs_js.go:
 *   read/write → (err, n)
 *   everything else → (err, value)  — never spread arrays
 */
(function installTrajanFS(global) {
  "use strict";

  const S_IFDIR = 0o040000;
  const S_IFREG = 0o100000;

  const constants = {
    O_RDONLY: 0,
    O_WRONLY: 1,
    O_RDWR: 2,
    O_CREAT: 0o100,
    O_EXCL: 0o200,
    O_TRUNC: 0o1000,
    O_APPEND: 0o2000,
    O_DIRECTORY: 0o200000,
  };

  function err(code, msg) {
    const e = new Error(msg || code);
    e.code = code;
    return e;
  }

  function normalize(p) {
    if (!p) return "/";
    p = String(p).replace(/\\/g, "/");
    const abs = p.startsWith("/");
    const parts = [];
    for (const seg of p.split("/")) {
      if (!seg || seg === ".") continue;
      if (seg === "..") {
        if (parts.length) parts.pop();
        continue;
      }
      parts.push(seg);
    }
    const out = (abs ? "/" : "") + parts.join("/");
    return out || (abs ? "/" : ".");
  }

  function dirname(p) {
    p = normalize(p);
    if (p === "/") return "/";
    const i = p.lastIndexOf("/");
    if (i <= 0) return "/";
    return p.slice(0, i) || "/";
  }

  function basename(p) {
    p = normalize(p);
    if (p === "/") return "/";
    const i = p.lastIndexOf("/");
    return i < 0 ? p : p.slice(i + 1);
  }

  // path → { type: 'dir'|'file', mode, data?: Uint8Array, mtimeMs, ... }
  const nodes = new Map();
  nodes.set("/", { type: "dir", mode: 0o755, mtimeMs: Date.now() });

  let nextFD = 3;
  const fds = new Map(); // fd → { path, flags, pos }

  function get(path) {
    return nodes.get(normalize(path));
  }

  function ensureParent(path) {
    const d = dirname(path);
    if (!get(d)) throw err("ENOENT", "no such file or directory: " + d);
    if (get(d).type !== "dir") throw err("ENOTDIR", "not a directory: " + d);
  }

  function makeStat(node) {
    const isDir = node.type === "dir";
    const size = isDir ? 0 : (node.data ? node.data.length : 0);
    const mode = (isDir ? S_IFDIR : S_IFREG) | (node.mode & 0o777);
    const now = node.mtimeMs || Date.now();
    return {
      dev: 1,
      ino: 1,
      mode,
      nlink: 1,
      uid: 0,
      gid: 0,
      rdev: 0,
      size,
      blksize: 4096,
      blocks: Math.ceil(size / 512) || 0,
      atimeMs: now,
      mtimeMs: now,
      ctimeMs: now,
      isDirectory() { return isDir; },
      isFile() { return !isDir; },
      isSymbolicLink() { return false; },
    };
  }

  function listDir(path) {
    path = normalize(path);
    const node = get(path);
    if (!node) throw err("ENOENT", path);
    if (node.type !== "dir") throw err("ENOTDIR", path);
    const prefix = path === "/" ? "/" : path + "/";
    const names = new Set();
    for (const key of nodes.keys()) {
      if (key === path || !key.startsWith(prefix)) continue;
      const rest = key.slice(prefix.length);
      const slash = rest.indexOf("/");
      names.add(slash === -1 ? rest : rest.slice(0, slash));
    }
    return [...names].sort();
  }

  function cbify(fn) {
    return function (...args) {
      const callback = args[args.length - 1];
      try {
        const result = fn(...args.slice(0, -1));
        callback(null, result);
      } catch (e) {
        callback(e);
      }
    };
  }

  const fs = {
    constants,

    writeSync(fd, buf) {
      // stdout/stderr: mirror wasm_exec default logging
      if (fd === 1 || fd === 2) {
        const text = typeof buf === "string" ? buf : new TextDecoder().decode(buf);
        const lines = text.split("\n");
        for (let i = 0; i < lines.length - (text.endsWith("\n") ? 1 : 0); i++) {
          if (lines[i] !== "") console.log(lines[i]);
        }
        if (!text.endsWith("\n") && lines[lines.length - 1]) {
          // keep partial line buffering simple: just print
        }
        return buf.length !== undefined ? buf.length : Buffer.byteLength(text);
      }
      throw err("EBADF", "writeSync: bad fd " + fd);
    },

    write: cbify(function (fd, buf, offset, length, position) {
      if (fd === 1 || fd === 2) {
        const slice = buf.subarray(offset, offset + length);
        fs.writeSync(fd, slice);
        return length;
      }
      const h = fds.get(fd);
      if (!h) throw err("EBADF", "bad fd");
      const node = get(h.path);
      if (!node || node.type !== "file") throw err("EBADF", "not a file");
      const pos = position == null ? h.pos : position;
      const src = buf.subarray(offset, offset + length);
      if (pos + src.length > node.data.length) {
        const next = new Uint8Array(pos + src.length);
        next.set(node.data);
        node.data = next;
      }
      node.data.set(src, pos);
      node.mtimeMs = Date.now();
      if (position == null) h.pos = pos + src.length;
      return src.length;
    }),

    read: cbify(function (fd, buffer, offset, length, position) {
      const h = fds.get(fd);
      if (!h) throw err("EBADF", "bad fd");
      const node = get(h.path);
      if (!node) throw err("EBADF", "missing");
      if (node.type === "dir") throw err("EISDIR", h.path);
      const pos = position == null ? h.pos : position;
      const available = Math.max(0, node.data.length - pos);
      const n = Math.min(length, available);
      buffer.set(node.data.subarray(pos, pos + n), offset);
      if (position == null) h.pos = pos + n;
      return n;
    }),

    open: cbify(function (path, flags, mode) {
      path = normalize(path);
      flags = flags | 0;
      mode = mode || 0o666;
      let node = get(path);
      const wantDir = (flags & constants.O_DIRECTORY) !== 0;
      const creat = (flags & constants.O_CREAT) !== 0;
      const excl = (flags & constants.O_EXCL) !== 0;
      const trunc = (flags & constants.O_TRUNC) !== 0;
      const wr = (flags & constants.O_WRONLY) !== 0 || (flags & constants.O_RDWR) !== 0;

      if (!node) {
        if (!creat) throw err("ENOENT", path);
        ensureParent(path);
        node = { type: "file", mode: mode & 0o777, data: new Uint8Array(0), mtimeMs: Date.now() };
        nodes.set(path, node);
      } else if (excl && creat) {
        throw err("EEXIST", path);
      }

      if (wantDir && node.type !== "dir") throw err("ENOTDIR", path);
      if (node.type === "dir" && wr && !wantDir) throw err("EISDIR", path);
      if (trunc && node.type === "file") {
        node.data = new Uint8Array(0);
        node.mtimeMs = Date.now();
      }

      const fd = nextFD++;
      let pos = 0;
      if ((flags & constants.O_APPEND) !== 0 && node.type === "file") pos = node.data.length;
      fds.set(fd, { path, flags, pos });
      return fd;
    }),

    close: cbify(function (fd) {
      if (fd <= 2) return undefined;
      if (!fds.has(fd)) throw err("EBADF", "bad fd");
      fds.delete(fd);
      return undefined;
    }),

    fstat: cbify(function (fd) {
      if (fd <= 2) {
        return makeStat({ type: "file", mode: 0o666, data: new Uint8Array(0), mtimeMs: Date.now() });
      }
      const h = fds.get(fd);
      if (!h) throw err("EBADF", "bad fd");
      const node = get(h.path);
      if (!node) throw err("ENOENT", h.path);
      return makeStat(node);
    }),

    lstat: cbify(function (path) {
      const node = get(path);
      if (!node) throw err("ENOENT", path);
      return makeStat(node);
    }),

    stat: cbify(function (path) {
      const node = get(path);
      if (!node) throw err("ENOENT", path);
      return makeStat(node);
    }),

    mkdir: cbify(function (path, perm) {
      path = normalize(path);
      if (get(path)) throw err("EEXIST", path);
      ensureParent(path);
      nodes.set(path, { type: "dir", mode: (perm || 0o755) & 0o777, mtimeMs: Date.now() });
      return undefined;
    }),

    readdir: cbify(function (path) {
      return listDir(path);
    }),

    rmdir: cbify(function (path) {
      path = normalize(path);
      const node = get(path);
      if (!node) throw err("ENOENT", path);
      if (node.type !== "dir") throw err("ENOTDIR", path);
      if (listDir(path).length) throw err("ENOTEMPTY", path);
      nodes.delete(path);
      return undefined;
    }),

    unlink: cbify(function (path) {
      path = normalize(path);
      const node = get(path);
      if (!node) throw err("ENOENT", path);
      if (node.type === "dir") throw err("EISDIR", path);
      nodes.delete(path);
      return undefined;
    }),

    rename: cbify(function (from, to) {
      from = normalize(from);
      to = normalize(to);
      const node = get(from);
      if (!node) throw err("ENOENT", from);
      ensureParent(to);
      if (get(to)) {
        // overwrite file; refuse non-empty dir
        const existing = get(to);
        if (existing.type === "dir" && listDir(to).length) throw err("ENOTEMPTY", to);
        nodes.delete(to);
      }
      nodes.delete(from);
      nodes.set(to, node);
      // move children if directory
      if (node.type === "dir") {
        const prefix = from === "/" ? "/" : from + "/";
        const toPrefix = to === "/" ? "/" : to + "/";
        const moves = [];
        for (const key of nodes.keys()) {
          if (key.startsWith(prefix)) moves.push(key);
        }
        for (const key of moves) {
          const n = nodes.get(key);
          nodes.delete(key);
          nodes.set(toPrefix + key.slice(prefix.length), n);
        }
      }
      return undefined;
    }),

    truncate: cbify(function (path, length) {
      const node = get(path);
      if (!node) throw err("ENOENT", path);
      if (node.type !== "file") throw err("EISDIR", path);
      const next = new Uint8Array(length);
      next.set(node.data.subarray(0, Math.min(node.data.length, length)));
      node.data = next;
      node.mtimeMs = Date.now();
      return undefined;
    }),

    ftruncate: cbify(function (fd, length) {
      const h = fds.get(fd);
      if (!h) throw err("EBADF", "bad fd");
      return fs.truncate.length; // unused; call sync path
    }),

    fsync: cbify(function () { return undefined; }),
    chmod: cbify(function () { return undefined; }),
    fchmod: cbify(function () { return undefined; }),
    chown: cbify(function () { return undefined; }),
    fchown: cbify(function () { return undefined; }),
    lchown: cbify(function () { return undefined; }),
    utimes: cbify(function (path) {
      const node = get(path);
      if (!node) throw err("ENOENT", path);
      node.mtimeMs = Date.now();
      return undefined;
    }),
    link: cbify(function () { throw err("ENOSYS", "link"); }),
    symlink: cbify(function () { throw err("ENOSYS", "symlink"); }),
    readlink: cbify(function () { throw err("EINVAL", "not a symlink"); }),
  };

  // Fix ftruncate to actually truncate via open handle
  fs.ftruncate = cbify(function (fd, length) {
    const h = fds.get(fd);
    if (!h) throw err("EBADF", "bad fd");
    const node = get(h.path);
    if (!node || node.type !== "file") throw err("EINVAL", "not a file");
    const next = new Uint8Array(length);
    next.set(node.data.subarray(0, Math.min(node.data.length, length)));
    node.data = next;
    node.mtimeMs = Date.now();
    return undefined;
  });

  global.fs = fs;

  global.path = {
    resolve(...segments) {
      let resolved = "";
      for (const seg of segments) {
        if (!seg) continue;
        const s = String(seg).replace(/\\/g, "/");
        if (s.startsWith("/")) resolved = s;
        else resolved = resolved ? resolved.replace(/\/+$/, "") + "/" + s : s;
      }
      return normalize(resolved || "/");
    },
    dirname,
    basename,
    join(...parts) {
      return normalize(parts.filter(Boolean).join("/"));
    },
  };

  if (!global.process) {
    global.process = {};
  }
  Object.assign(global.process, {
    getuid() { return -1; },
    getgid() { return -1; },
    geteuid() { return -1; },
    getegid() { return -1; },
    getgroups() { return []; },
    pid: 1,
    ppid: 0,
    umask() { return 0; },
    cwd() { return "/"; },
    chdir() { throw err("ENOSYS", "chdir"); },
  });

  // Helpers for the Go bridge / tests
  global.__trajanFS = {
    readFile(path) {
      const node = get(path);
      if (!node || node.type !== "file") throw err("ENOENT", path);
      return new TextDecoder().decode(node.data);
    },
    writeFile(path, text) {
      path = normalize(path);
      ensureParent(path);
      nodes.set(path, {
        type: "file",
        mode: 0o644,
        data: new TextEncoder().encode(String(text)),
        mtimeMs: Date.now(),
      });
    },
    list(path) {
      return listDir(path || "/");
    },
    reset() {
      nodes.clear();
      nodes.set("/", { type: "dir", mode: 0o755, mtimeMs: Date.now() });
      fds.clear();
      nextFD = 3;
    },
  };
})(typeof globalThis !== "undefined" ? globalThis : window);
