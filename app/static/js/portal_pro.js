/* HobeRadius customer portal — sidebar view router + backups interactions.
   External file because the panel CSP is `script-src 'self'` (no inline JS).

   Everything is wired with document-level delegated listeners attached at
   load, so no single failing block can stop the rest, and dynamically/late
   elements still work. Templated URLs arrive via data-* attributes. */
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }
  function app() { return $("pp-app"); }

  // ───────────────────────── view router ─────────────────────────
  function showView(view, push) {
    var root = app();
    if (!root || !view) return;
    var views = root.querySelectorAll("[data-pp-pane]");
    var found = false;
    views.forEach(function (v) {
      var on = v.getAttribute("data-pp-pane") === view;
      v.style.display = on ? "flex" : "none";
      v.classList.toggle("is-active", on);
      if (on) found = true;
    });
    if (!found) return;
    root.querySelectorAll("[data-pp-view]").forEach(function (l) {
      l.classList.toggle("is-active", l.getAttribute("data-pp-view") === view);
    });
    if (push && location.hash !== "#" + view) {
      try { history.replaceState(null, "", "#" + view); } catch (e) {}
    }
    closeDrawer();
    if (view === "backups") { try { autoloadSummaries(); } catch (e) {} }
    try { root.scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { window.scrollTo(0, 0); }
  }

  function closeDrawer() {
    var s = $("pp-side"), sc = $("pp-scrim");
    if (s) s.classList.remove("is-open");
    if (sc) sc.classList.remove("is-open");
  }

  // ───────────────────────── modals ─────────────────────────
  function closeModals() {
    document.querySelectorAll(".pp-modal.is-open").forEach(function (m) {
      m.classList.remove("is-open");
      m.style.display = "none";
    });
  }
  function openModal(m) { if (m) { m.style.display = "flex"; m.classList.add("is-open"); } }

  function openDetails(more) {
    var modal = $("pp-modal"); if (!modal) return;
    var mT = $("pp-modal-title"), mI = $("pp-modal-ico"), mS = $("pp-modal-status"),
        mD = $("pp-modal-desc"), mL = $("pp-modal-limits"), mLB = $("pp-modal-limits-block");
    if (mT) mT.textContent = more.getAttribute("data-name") || "—";
    if (mI) mI.className = "fa-solid fa-" + (more.getAttribute("data-icon") || "circle-info");
    if (mS) { mS.className = more.getAttribute("data-status-cls") || "pp-svc-status is-off";
      mS.innerHTML = '<span class="dot"></span> ' + (more.getAttribute("data-status") || "—"); }
    if (mD) mD.textContent = more.getAttribute("data-desc") || "—";
    var lim = (more.getAttribute("data-limits") || "").trim();
    if (mLB && mL) {
      if (lim) { mLB.style.display = ""; mL.innerHTML = '<i class="fa-solid fa-gauge"></i> ' + lim; }
      else { mLB.style.display = "none"; }
    }
    openModal(modal);
  }

  // ───────────────────────── restore modal ─────────────────────────
  function restoreValidate() {
    var ack = $("pp-restore-ack"), conf = $("pp-restore-confirm"), sub = $("pp-restore-submit");
    if (!sub) return;
    sub.disabled = !(ack && ack.checked && conf && (conf.value || "").trim().toUpperCase() === "RESTORE");
  }
  function openRestore(btn) {
    var modal = $("pp-restore-modal"), form = $("pp-restore-form"),
        ref = $("pp-restore-ref"), ack = $("pp-restore-ack"), conf = $("pp-restore-confirm");
    var id = btn.getAttribute("data-pp-restore");
    if (form) {
      var tpl = form.getAttribute("data-action-tpl") || "";
      form.setAttribute("action", /\/0\/restore$/.test(tpl)
        ? tpl.replace(/\/0\/restore$/, "/" + id + "/restore")
        : "/portal/backups/" + id + "/restore");
    }
    if (ref) ref.textContent = btn.getAttribute("data-ref") || "#" + id;
    if (ack) ack.checked = false;
    if (conf) conf.value = "";
    restoreValidate();
    openModal(modal);
  }

  // ───────────────────────── backup content summary ─────────────────────────
  function labelEsc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
  function summaryUrl(id) {
    var root = app();
    var tpl = root ? (root.getAttribute("data-summary-url") || "") : "";
    if (tpl && /\/0\/summary$/.test(tpl)) return tpl.replace(/\/0\/summary$/, "/" + id + "/summary");
    return "/portal/backups/" + id + "/summary";
  }
  function loadSummary(box, id) {
    if (!box || box.getAttribute("data-loaded") === "1") return;
    box.setAttribute("data-loaded", "1");
    var body = box.querySelector(".pp-sum-body");
    if (body) body.innerHTML = '<span class="pp-sum-msg">…جارٍ قراءة محتوى النسخة</span>';
    fetch(summaryUrl(id), { headers: { "X-Requested-With": "fetch" }, credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!body) return;
        if (!d || !d.ok || !d.items || !d.items.length) {
          body.innerHTML = '<span class="pp-sum-msg">تعذّر قراءة محتوى هذه النسخة أو لا تحتوي جداول معروفة.</span>';
          return;
        }
        var html = '<div class="pp-sum-grid">';
        d.items.forEach(function (it) {
          html += '<div class="pp-sum-cell"><div class="v">' + it.count + '</div><div class="l">' + labelEsc(it.label) + "</div></div>";
        });
        body.innerHTML = html + "</div>";
      })
      .catch(function () {
        box.setAttribute("data-loaded", "0");
        if (body) body.innerHTML = '<span class="pp-sum-msg">تعذّر الاتصال لقراءة المحتوى.</span>';
      });
  }
  function toggleSummary(btn) {
    var id = btn.getAttribute("data-pp-summary");
    var box = $("pp-sum-" + id);
    if (!box) return;
    var isOpen = box.style.display === "block";
    box.style.display = isOpen ? "none" : "block";   // inline style → independent of CSS cache
    box.classList.toggle("is-open", !isOpen);
    if (!isOpen) loadSummary(box, id);
  }
  // Pre-fetch each backup's content summary but keep the box COLLAPSED by
  // default — the «المحتوى» button reveals it (already loaded → instant).
  function autoloadSummaries() {
    document.querySelectorAll("[data-pp-summary]").forEach(function (btn) {
      var id = btn.getAttribute("data-pp-summary");
      var box = $("pp-sum-" + id);
      if (!box) return;
      loadSummary(box, id);   // fetch + render into the hidden box
    });
  }
  // Direct (non-delegated) click binding so the show/hide toggle is reliable.
  function bindSummaryButtons() {
    document.querySelectorAll("[data-pp-summary]").forEach(function (btn) {
      if (btn.__ppBound) return;
      btn.__ppBound = true;
      btn.addEventListener("click", function (e) {
        e.preventDefault(); e.stopPropagation();
        try { toggleSummary(btn); } catch (x) {}
      });
    });
  }

  // ───────────────────────── service category tabs + search ─────────────────────────
  function activeCatKey() {
    var chip = document.querySelector("#pp-cats .pp-cat-chip.is-active");
    return chip ? chip.getAttribute("data-pp-cat") : null;
  }
  function selectCat(key) {
    document.querySelectorAll("#pp-cats .pp-cat-chip").forEach(function (c) {
      c.classList.toggle("is-active", c.getAttribute("data-pp-cat") === key);
    });
    document.querySelectorAll("#pp-cat-root .pp-cat-pane").forEach(function (p) {
      p.style.display = p.getAttribute("data-pp-catpane") === key ? "flex" : "none";
      p.classList.toggle("is-active", p.getAttribute("data-pp-catpane") === key);
    });
    var s = $("pp-svc-search"); if (s) s.value = "";
    applySearch();
  }
  function applySearch() {
    var root = $("pp-cat-root"); if (!root) return;
    var key = activeCatKey();
    var pane = key ? root.querySelector('[data-pp-catpane="' + key + '"]') : null;
    if (!pane) return;
    var s = $("pp-svc-search");
    var q = (s && s.value || "").trim().toLowerCase();
    var shown = 0;
    pane.querySelectorAll(".pp-svc").forEach(function (c) {
      var ok = !q || (c.getAttribute("data-name") || "").indexOf(q) !== -1;
      c.style.display = ok ? "" : "none";
      if (ok) shown++;
    });
    pane.querySelectorAll(".pp-svc-grid").forEach(function (grid) {
      var any = Array.prototype.some.call(grid.querySelectorAll(".pp-svc"), function (c) { return c.style.display !== "none"; });
      grid.style.display = any ? "" : "none";
      var h = grid.previousElementSibling;
      if (h && h.classList.contains("pp-group-h")) h.style.display = any ? "" : "none";
    });
    var nr = $("pp-svc-noresult"); if (nr) nr.style.display = shown ? "none" : "";
  }

  function togglePwd(btn) {
    var inp = document.querySelector(btn.getAttribute("data-pwd-toggle"));
    if (!inp) return;
    var on = inp.type === "password";
    inp.type = on ? "text" : "password";
    var ic = btn.querySelector("i");
    if (ic) { ic.classList.toggle("fa-eye", !on); ic.classList.toggle("fa-eye-slash", on); }
  }

  // ───────────────────────── single delegated click router ─────────────────────────
  document.addEventListener("click", function (e) {
    var t;
    if ((t = e.target.closest("[data-pp-restore]"))) { e.preventDefault(); try { openRestore(t); } catch (x) {} return; }
    if ((t = e.target.closest("[data-pp-more]")))    { try { openDetails(t); } catch (x) {} return; }
    if (e.target.closest("[data-pp-close]"))         { closeModals(); return; }
    if (e.target.classList && e.target.classList.contains("pp-modal")) { closeModals(); return; }
    if ((t = e.target.closest("[data-pwd-toggle]"))) { e.preventDefault(); try { togglePwd(t); } catch (x) {} return; }
    if ((t = e.target.closest("[data-pp-view]")))    { showView(t.getAttribute("data-pp-view"), true); return; }
    if ((t = e.target.closest("[data-pp-go]")))      { showView(t.getAttribute("data-pp-go"), true); return; }
    if ((t = e.target.closest(".pp-cat-chip")))      { selectCat(t.getAttribute("data-pp-cat")); return; }
    if (e.target.closest("#pp-burger")) {
      var s = $("pp-side"), sc = $("pp-scrim");
      if (s) s.classList.toggle("is-open"); if (sc) sc.classList.toggle("is-open");
      return;
    }
    if (e.target.id === "pp-scrim") closeDrawer();
  });

  document.addEventListener("input", function (e) {
    if (e.target.id === "pp-svc-search") applySearch();
    if (e.target.id === "pp-restore-confirm") restoreValidate();
  });
  document.addEventListener("change", function (e) {
    if (e.target.id === "pp-restore-ack") restoreValidate();
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeModals(); });

  // initial view from the URL hash (deep-link)
  function boot() {
    var h = (location.hash || "").replace("#", "");
    if (h) showView(h, false);
    // Pre-load all backup summaries so the content is ready/visible without a click,
    // and bind reliable direct toggle listeners on the content buttons.
    try { autoloadSummaries(); } catch (e) {}
    try { bindSummaryButtons(); } catch (e) {}
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
