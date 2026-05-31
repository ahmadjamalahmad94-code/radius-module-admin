/* HobeRadius customer portal — sidebar view router + backups interactions.
   Loaded as an external file because the panel CSP is `script-src 'self'`
   (inline scripts are blocked). Templated URLs arrive via data-* attributes. */
(function () {
  "use strict";
  function init() {
    var app = document.getElementById("pp-app");
    if (!app) return;
    var side = document.getElementById("pp-side");
    var scrim = document.getElementById("pp-scrim");
    var burger = document.getElementById("pp-burger");

    // ── view router ──
    var views = app.querySelectorAll("[data-pp-pane]");
    var links = app.querySelectorAll("[data-pp-view]");
    function closeDrawer() {
      if (side) side.classList.remove("is-open");
      if (scrim) scrim.classList.remove("is-open");
    }
    function show(view, push) {
      var found = false;
      views.forEach(function (v) {
        var on = v.getAttribute("data-pp-pane") === view;
        v.classList.toggle("is-active", on);
        if (on) found = true;
      });
      if (!found) { show("overview", push); return; }
      links.forEach(function (l) {
        l.classList.toggle("is-active", l.getAttribute("data-pp-view") === view);
      });
      if (push && location.hash !== "#" + view) {
        history.replaceState(null, "", "#" + view);
      }
      closeDrawer();
      try { app.scrollIntoView({ behavior: "smooth", block: "start" }); }
      catch (e) { window.scrollTo(0, 0); }
    }
    links.forEach(function (l) {
      l.addEventListener("click", function () { show(l.getAttribute("data-pp-view"), true); });
    });
    app.querySelectorAll("[data-pp-go]").forEach(function (b) {
      b.addEventListener("click", function () { show(b.getAttribute("data-pp-go"), true); });
    });
    var initial = (location.hash || "").replace("#", "");
    if (initial) show(initial, false);

    // ── mobile drawer ──
    if (burger) burger.addEventListener("click", function () {
      side.classList.toggle("is-open");
      scrim.classList.toggle("is-open");
    });
    if (scrim) scrim.addEventListener("click", closeDrawer);

    // ── service category tabs + scoped search ──
    var cats = document.getElementById("pp-cats");
    var catRoot = document.getElementById("pp-cat-root");
    var svcSearch = document.getElementById("pp-svc-search");
    var noRes = document.getElementById("pp-svc-noresult");
    var activeCat = null;
    function paneFor(key) { return catRoot ? catRoot.querySelector('[data-pp-catpane="' + key + '"]') : null; }
    function applySearch() {
      if (!catRoot) return;
      var pane = paneFor(activeCat);
      if (!pane) return;
      var q = ((svcSearch && svcSearch.value) || "").trim().toLowerCase();
      var shown = 0;
      pane.querySelectorAll(".pp-svc").forEach(function (c) {
        var ok = !q || (c.getAttribute("data-name") || "").indexOf(q) !== -1;
        c.style.display = ok ? "" : "none";
        if (ok) shown++;
      });
      // hide group header + its grid when the grid has no visible card
      pane.querySelectorAll(".pp-svc-grid").forEach(function (grid) {
        var any = Array.prototype.some.call(grid.querySelectorAll(".pp-svc"), function (c) {
          return c.style.display !== "none";
        });
        grid.style.display = any ? "" : "none";
        var h = grid.previousElementSibling;
        if (h && h.classList.contains("pp-group-h")) h.style.display = any ? "" : "none";
      });
      if (noRes) noRes.style.display = shown ? "none" : "";
    }
    function selectCat(key) {
      if (!cats) return;
      cats.querySelectorAll(".pp-cat-chip").forEach(function (c) {
        c.classList.toggle("is-active", c.getAttribute("data-pp-cat") === key);
      });
      catRoot.querySelectorAll(".pp-cat-pane").forEach(function (p) {
        p.classList.toggle("is-active", p.getAttribute("data-pp-catpane") === key);
      });
      activeCat = key;
      if (svcSearch) svcSearch.value = "";
      applySearch();
    }
    if (cats) cats.addEventListener("click", function (e) {
      var c = e.target.closest(".pp-cat-chip");
      if (c) selectCat(c.getAttribute("data-pp-cat"));
    });
    if (svcSearch) svcSearch.addEventListener("input", applySearch);
    var firstChip = cats ? cats.querySelector(".pp-cat-chip.is-active") : null;
    if (firstChip) activeCat = firstChip.getAttribute("data-pp-cat");

    // ── password reveal ──
    document.querySelectorAll("[data-pwd-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var inp = document.querySelector(btn.getAttribute("data-pwd-toggle"));
        if (!inp) return;
        var on = inp.type === "password";
        inp.type = on ? "text" : "password";
        var ic = btn.querySelector("i");
        if (ic) { ic.classList.toggle("fa-eye", !on); ic.classList.toggle("fa-eye-slash", on); }
      });
    });

    // ── modals (shared open/close) ──
    function openModal(m) { if (m) m.classList.add("is-open"); }
    function closeModals() {
      document.querySelectorAll(".pp-modal.is-open").forEach(function (m) { m.classList.remove("is-open"); });
    }
    document.addEventListener("click", function (e) {
      if (e.target.closest("[data-pp-close]")) { closeModals(); return; }
      if (e.target.classList && e.target.classList.contains("pp-modal")) closeModals();
    });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeModals(); });

    // ── service details modal ──
    var modal = document.getElementById("pp-modal");
    var mT = document.getElementById("pp-modal-title"), mI = document.getElementById("pp-modal-ico");
    var mS = document.getElementById("pp-modal-status"), mD = document.getElementById("pp-modal-desc");
    var mL = document.getElementById("pp-modal-limits"), mLB = document.getElementById("pp-modal-limits-block");
    document.addEventListener("click", function (e) {
      var more = e.target.closest("[data-pp-more]");
      if (!more) return;
      mT.textContent = more.getAttribute("data-name") || "—";
      if (mI) mI.className = "fa-solid fa-" + (more.getAttribute("data-icon") || "circle-info");
      mS.className = more.getAttribute("data-status-cls") || "pp-svc-status is-off";
      mS.innerHTML = '<span class="dot"></span> ' + (more.getAttribute("data-status") || "—");
      mD.textContent = more.getAttribute("data-desc") || "—";
      var lim = (more.getAttribute("data-limits") || "").trim();
      if (lim) { mLB.style.display = ""; mL.innerHTML = '<i class="fa-solid fa-gauge"></i> ' + lim; }
      else { mLB.style.display = "none"; }
      openModal(modal);
    });

    // ── restore modal ──
    var rModal = document.getElementById("pp-restore-modal");
    var rForm = document.getElementById("pp-restore-form");
    var rRef = document.getElementById("pp-restore-ref");
    var rAck = document.getElementById("pp-restore-ack");
    var rConfirm = document.getElementById("pp-restore-confirm");
    var rSubmit = document.getElementById("pp-restore-submit");
    var rTpl = rForm ? rForm.getAttribute("data-action-tpl") : "";
    function rValidate() {
      if (!rSubmit) return;
      rSubmit.disabled = !(rAck.checked && (rConfirm.value || "").trim().toUpperCase() === "RESTORE");
    }
    document.addEventListener("click", function (e) {
      var b = e.target.closest("[data-pp-restore]");
      if (!b) return;
      var id = b.getAttribute("data-pp-restore");
      if (rForm && rTpl) rForm.setAttribute("action", rTpl.replace(/\/0\/restore$/, "/" + id + "/restore"));
      if (rRef) rRef.textContent = b.getAttribute("data-ref") || "#" + id;
      if (rAck) rAck.checked = false;
      if (rConfirm) rConfirm.value = "";
      rValidate();
      openModal(rModal);
    });
    if (rAck) rAck.addEventListener("change", rValidate);
    if (rConfirm) rConfirm.addEventListener("input", rValidate);

    // ── backup content summary (on-demand) ──
    // Direct listeners (not delegated) so a single misbehaving handler can't
    // swallow the click; each is wrapped so it never silently no-ops.
    var sumTpl = app.getAttribute("data-summary-url") || "";
    function labelEsc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
    function buildSummaryUrl(id) {
      if (sumTpl && /\/0\/summary$/.test(sumTpl)) return sumTpl.replace(/\/0\/summary$/, "/" + id + "/summary");
      return "/portal/backups/" + id + "/summary"; // hard fallback
    }
    function handleSummary(btn) {
      var id = btn.getAttribute("data-pp-summary");
      var box = document.getElementById("pp-sum-" + id);
      if (!box) return;
      var open = box.classList.toggle("is-open");
      if (!open) return;
      if (box.getAttribute("data-loaded") === "1") return;
      var body = box.querySelector(".pp-sum-body");
      if (body) body.innerHTML = '<span class="pp-sum-msg">…جارٍ قراءة محتوى النسخة</span>';
      fetch(buildSummaryUrl(id), { headers: { "X-Requested-With": "fetch" }, credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          box.setAttribute("data-loaded", "1");
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
          if (body) body.innerHTML = '<span class="pp-sum-msg">تعذّر الاتصال لقراءة المحتوى.</span>';
        });
    }
    document.querySelectorAll("[data-pp-summary]").forEach(function (btn) {
      btn.addEventListener("click", function () { try { handleSummary(btn); } catch (e) {} });
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
