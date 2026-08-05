(function () {
  var root = document.documentElement;

  function resolvedTheme() {
    var t = root.dataset.theme;
    if (t === "light" || t === "dark") { return t; }
    return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  // file:// pages get no storage in some browsers, so persistence is best-effort
  // and the toggle still works for the session either way.
  try {
    var saved = localStorage.getItem("trajan-theme");
    if (saved === "light" || saved === "dark") { root.dataset.theme = saved; }
  } catch (e) { /* storage unavailable */ }

  document.getElementById("theme").addEventListener("click", function () {
    var next = resolvedTheme() === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("trajan-theme", next); } catch (e) { /* storage unavailable */ }
  });

  var toTop = document.getElementById("toTop");
  addEventListener("scroll", function () { toTop.hidden = scrollY < 400; }, { passive: true });
  toTop.addEventListener("click", function () { scrollTo({ top: 0, behavior: "smooth" }); });

  var q = document.getElementById("q");
  if (!q) { return; } // empty report: no findings, so nothing below applies

  var cards = Array.prototype.slice.call(document.querySelectorAll("article.finding"));
  var toggles = Array.prototype.slice.call(document.querySelectorAll("[data-filter]"));
  var ruleToggles = toggles.filter(function (b) { return b.dataset.filter === "rule"; });
  var shown = document.getElementById("shown");
  var empty = document.getElementById("empty");
  var expand = document.getElementById("expandAll");
  var clearRules = document.getElementById("clearRules");

  // Titles only: matching the whole card meant a common word in a description or
  // provenance value pulled in findings that had nothing to do with the query.
  var haystack = new WeakMap();
  cards.forEach(function (c) {
    var h = c.querySelector("h2");
    haystack.set(c, h ? h.textContent.toLowerCase() : "");
  });

  function selected(kind) {
    return toggles
      .filter(function (b) { return b.dataset.filter === kind && b.getAttribute("aria-pressed") === "true"; })
      .map(function (b) { return b.dataset.value; });
  }

  function apply() {
    var sev = selected("sev"), conf = selected("conf"), rules = selected("rule");
    var term = q.value.trim().toLowerCase();
    var n = 0;
    cards.forEach(function (c) {
      // No rule selected means every rule, so the sidebar starts unfiltered.
      var ok = sev.indexOf(c.dataset.sev) >= 0 &&
               conf.indexOf(c.dataset.conf) >= 0 &&
               (rules.length === 0 || rules.indexOf(c.dataset.rule) >= 0) &&
               (term === "" || haystack.get(c).indexOf(term) >= 0);
      c.hidden = !ok;
      if (ok) { n++; }
    });
    shown.textContent = n;
    empty.hidden = n > 0;
    if (clearRules) { clearRules.hidden = rules.length === 0; }
  }

  toggles.forEach(function (b) {
    b.addEventListener("click", function () {
      b.setAttribute("aria-pressed", b.getAttribute("aria-pressed") === "true" ? "false" : "true");
      apply();
    });
  });
  q.addEventListener("input", apply);

  document.querySelectorAll("[data-jump]").forEach(function (b) {
    b.addEventListener("click", function () {
      var target = cards.find(function (c) { return !c.hidden && c.dataset.sev === b.dataset.jump; });
      if (target) { target.scrollIntoView({ behavior: "smooth", block: "start" }); }
    });
  });

  var ruleQ = document.getElementById("ruleQ");
  if (ruleQ) {
    ruleQ.addEventListener("input", function () {
      var term = ruleQ.value.trim().toLowerCase();
      ruleToggles.forEach(function (b) {
        b.hidden = term !== "" && b.dataset.value.toLowerCase().indexOf(term) < 0;
      });
      // A category whose every rule is filtered out should not leave a stray header.
      document.querySelectorAll(".rule-group").forEach(function (g) {
        g.hidden = !g.querySelector(".rule-row:not([hidden])");
      });
    });
  }

  if (clearRules) {
    clearRules.addEventListener("click", function () {
      ruleToggles.forEach(function (b) { b.setAttribute("aria-pressed", "false"); });
      apply();
    });
  }

  document.getElementById("reset").addEventListener("click", function () {
    toggles.forEach(function (b) {
      b.setAttribute("aria-pressed", b.dataset.filter === "rule" ? "false" : "true");
    });
    q.value = "";
    if (ruleQ) { ruleQ.value = ""; ruleQ.dispatchEvent(new Event("input")); }
    apply();
  });

  function setDetails(open) {
    document.querySelectorAll("details.more").forEach(function (d) { d.open = open; });
  }

  expand.addEventListener("click", function () {
    var open = expand.dataset.open !== "true";
    setDetails(open);
    expand.dataset.open = open ? "true" : "false";
    expand.textContent = open ? "Collapse all" : "Expand all";
  });

  // Printing a report should not silently drop whatever sits behind a toggle.
  addEventListener("beforeprint", function () { setDetails(true); });

  apply();
})();
