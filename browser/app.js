(() => {
  const $ = (id) => document.getElementById(id);
  const form = $("scanForm");
  const platformEl = $("platform");
  const progress = $("progress");
  const status = $("status");
  const errorEl = $("error");
  const idle = $("idle");
  const results = $("results");
  const frame = $("results-frame");
  const runBtn = $("runBtn");
  const cancelBtn = $("cancelBtn");
  const whoamiBtn = $("whoamiBtn");

  let scanning = false;

  function setPlatformUI() {
    const p = platformEl.value;
    $("baseUrlField").hidden = p !== "gitlab";
    $("bearerField").hidden = p !== "ado";
    const ph = {
      github: "org or org/repo",
      gitlab: "group or group/project",
      ado: "org or org/project",
    };
    $("locator").placeholder = ph[p] || "scope";
  }

  platformEl.addEventListener("change", setPlatformUI);
  setPlatformUI();

  function log(line) {
    const stamp = new Date().toISOString().slice(11, 19);
    progress.textContent += `[${stamp}] ${line}\n`;
    progress.scrollTop = progress.scrollHeight;
  }

  function showError(msg) {
    errorEl.hidden = !msg;
    errorEl.textContent = msg || "";
  }

  function setBusy(busy) {
    scanning = busy;
    runBtn.disabled = busy;
    whoamiBtn.disabled = busy;
    cancelBtn.disabled = !busy;
    status.textContent = busy ? "Scanning…" : "Ready";
  }

  function optsFromForm() {
    return {
      platform: platformEl.value,
      locator: $("locator").value.trim(),
      token: $("token").value,
      baseUrl: $("baseUrl").value.trim(),
      bearerToken: $("bearerToken").value,
    };
  }

  async function boot() {
    try {
      await window.trajan.initialize({
        outputDir: "/run",
        concurrency: 8,
        onLog(level, msg, attrs) {
          const extra = attrs && Object.keys(attrs).length
            ? " " + Object.entries(attrs).map(([k, v]) => `${k}=${v}`).join(" ")
            : "";
          log(`${level.toLowerCase()}  ${msg}${extra}`);
        },
      });
      const v = window.trajan.version();
      $("versionLine").textContent = `Trajan WASM ${v.version} · ${v.gitCommit}`;
      status.textContent = "Ready";
      log("WASM ready");
    } catch (e) {
      status.textContent = "Failed to load";
      showError(e.message || String(e));
    }
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("");
    progress.textContent = "";
    results.hidden = true;
    idle.hidden = true;
    setBusy(true);
    const opts = optsFromForm();
    try {
      log(`whoami ${opts.platform}`);
      const id = await window.trajan.whoami(opts);
      log(`identity ${JSON.stringify(id)}`);
      log(`scan ${opts.platform} ${opts.locator}`);
      const summary = await window.trajan.scan(opts);
      log(`scan complete runDir=${summary.runDir} findings=${summary.total ?? "?"}`);
      const rep = await window.trajan.report({
        runDir: summary.runDir,
        format: "html",
      });
      frame.srcdoc = rep.content;
      results.hidden = false;
      status.textContent = `Done · ${summary.total ?? 0} findings`;
    } catch (e) {
      const msg = (e && e.error) || e.message || String(e);
      showError(msg);
      idle.hidden = false;
      idle.textContent = "Scan failed. See the error above.";
      status.textContent = "Failed";
      log("error " + msg);
    } finally {
      setBusy(false);
    }
  });

  whoamiBtn.addEventListener("click", async () => {
    showError("");
    setBusy(true);
    try {
      const id = await window.trajan.whoami(optsFromForm());
      log("whoami " + JSON.stringify(id));
      status.textContent = "Token ok";
    } catch (e) {
      const msg = (e && e.error) || e.message || String(e);
      showError(msg);
      status.textContent = "Whoami failed";
    } finally {
      setBusy(false);
    }
  });

  cancelBtn.addEventListener("click", () => {
    window.trajan.cancel();
    log("cancel requested");
  });

  boot();
})();
