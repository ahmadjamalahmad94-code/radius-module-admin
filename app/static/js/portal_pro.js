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
    // Guard FIRST: if no pane matches (e.g. an unknown #hash like #gdrive, which
    // is an in-pane anchor, not a view name), bail BEFORE touching any styles —
    // otherwise the loop would set display:none on EVERY pane and blank the whole
    // body, hiding even the server-rendered default (overview).
    var exists = false;
    views.forEach(function (v) { if (v.getAttribute("data-pp-pane") === view) exists = true; });
    if (!exists) return;
    views.forEach(function (v) {
      var on = v.getAttribute("data-pp-pane") === view;
      v.style.display = on ? "flex" : "none";
      v.classList.toggle("is-active", on);
    });
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
    // append a tier line to the description block when the card carries one
    var mTier = $("pp-modal-tier-block");
    var tierLabel = (more.getAttribute("data-tier-label") || "").trim();
    var tierTone = (more.getAttribute("data-tier-tone") || "violet").trim();
    if (mTier) {
      if (tierLabel) {
        mTier.style.display = "";
        mTier.innerHTML = '<span class="pp-tier-badge pp-tier-' + tierTone + '">'
          + '<i class="fa-solid fa-' + (tierTone === "green" ? "gift" : tierTone === "teal" ? "gauge-simple" : "tag") + '"></i> '
          + escText(tierLabel) + "</span>";
      } else {
        mTier.style.display = "none";
      }
    }
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

  // ───────────────────────── delete modal ─────────────────────────
  function deleteValidate() {
    var ack = $("pp-delete-ack"), conf = $("pp-delete-confirm"), sub = $("pp-delete-submit");
    if (!sub) return;
    sub.disabled = !(ack && ack.checked && conf && (conf.value || "").trim().toUpperCase() === "DELETE");
  }
  function openDelete(btn) {
    var modal = $("pp-delete-modal"), form = $("pp-delete-form"),
        ref = $("pp-delete-ref"), ack = $("pp-delete-ack"), conf = $("pp-delete-confirm");
    var id = btn.getAttribute("data-pp-delete");
    if (form) {
      var tpl = form.getAttribute("data-action-tpl") || "";
      form.setAttribute("action", /\/0\/delete$/.test(tpl)
        ? tpl.replace(/\/0\/delete$/, "/" + id + "/delete")
        : "/portal/backups/" + id + "/delete");
    }
    if (ref) ref.textContent = btn.getAttribute("data-ref") || "#" + id;
    if (ack) ack.checked = false;
    if (conf) conf.value = "";
    deleteValidate();
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
  function activeTierKey() {
    var chip = document.querySelector("#pp-tier-filter .pp-tier-chip.is-active");
    return chip ? (chip.getAttribute("data-tier") || "all") : "all";
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
  function selectTier(tier) {
    document.querySelectorAll("#pp-tier-filter .pp-tier-chip").forEach(function (c) {
      c.classList.toggle("is-active", c.getAttribute("data-tier") === tier);
    });
    applySearch();
  }
  function applySearch() {
    var root = $("pp-cat-root"); if (!root) return;
    var key = activeCatKey();
    var pane = key ? root.querySelector('[data-pp-catpane="' + key + '"]') : null;
    if (!pane) return;
    var s = $("pp-svc-search");
    var q = (s && s.value || "").trim().toLowerCase();
    var tier = activeTierKey();
    var shown = 0;
    pane.querySelectorAll(".pp-svc").forEach(function (c) {
      var nameOk = !q || (c.getAttribute("data-name") || "").indexOf(q) !== -1;
      var cardTier = c.getAttribute("data-tier") || "paid";
      var tierOk = (tier === "all") || (cardTier === tier);
      var ok = nameOk && tierOk;
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

  // ───────────────────────── activate / upgrade modals ─────────────────────────
  // The activation + upgrade modals are SINGLE shared dialogs. Each card carries
  // the spec layout in data-fields (a JSON list of {key,label,hint}). On open we
  // build the inputs into the modal body and point the form at the right URL.
  function escAttr(s) { return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
  function escText(s) { var d = document.createElement("div"); d.textContent = (s == null ? "" : String(s)); return d.innerHTML; }
  function parseJsonAttr(value, fallback) {
    if (!value) return fallback;
    try { return JSON.parse(value); } catch (e) { return fallback; }
  }
  function buildSpecInputs(host, fields, currentLimits, namePrefix) {
    if (!host) return;
    host.innerHTML = "";
    if (!fields || !fields.length) {
      host.innerHTML = '<div class="pp-spec-empty">'
        + '<i class="fa-solid fa-circle-info"></i> '
        + 'لا تتطلّب هذه الخدمة مواصفات كميّة. أرسل الطلب وسنتواصل معك لاتفاق التفاصيل وعرض السعر.'
        + "</div>";
      return;
    }
    var html = "";
    var isUpgrade = !!currentLimits;
    fields.forEach(function (f) {
      var key = (f && f.key) || "";
      if (!key) return;
      var label = escText(f.label || key);
      var hint = escText(f.hint || "");
      var unit = escText(f.unit || "");
      // A field may be conditionally visible (e.g. the per-Mbps tunnel specs show
      // only for the tunnel METHOD) — carry show_when on the wrapper so the
      // controlling <select> can toggle it.
      var sw = f.show_when || null;
      var swAttr = "";
      if (sw && sw.field) {
        var vals = (sw["in"] || []).map(function (v) { return String(v); }).join("|");
        swAttr = ' data-show-when-field="' + escAttr(sw.field) + '" data-show-when-vals="' + escAttr(vals) + '"';
      }
      // CHOICE fields (e.g. the IP-change method) render a <select>; the default
      // option pre-selects so a plain submit still carries a valid method.
      if (String(f.type || "") === "choice") {
        var opts = f.options || [];
        var defChoice = (f["default"] != null) ? String(f["default"]) : "";
        var selHtml = "";
        var selHint = hint;
        opts.forEach(function (o) {
          var ov = String(o.value);
          var sel = (ov === defChoice) ? " selected" : "";
          selHtml += '<option value="' + escAttr(ov) + '"' + sel + ">" + escText(o.label || ov) + "</option>";
        });
        html += '<div class="pp-spec-field"' + swAttr + ">"
          + '<label for="' + namePrefix + "-" + escAttr(key) + '">' + label + "</label>"
          + '<select id="' + namePrefix + "-" + escAttr(key) + '" '
            + 'name="spec_' + escAttr(key) + '" '
            + 'data-spec-choice="' + escAttr(key) + '">' + selHtml + "</select>"
          + (selHint ? '<div class="pp-hint">' + selHint + "</div>" : "")
          + "</div>";
        return;
      }
      var cur = (currentLimits && currentLimits[key] != null) ? currentLimits[key] : "";
      // SMART bounds per service type: the schema carries min/max/step/default.
      // For an UPGRADE the floor is the CURRENT value (upgrades only go up);
      // for an ACTIVATION the sensible per-type default pre-fills the field.
      var minV = (f.min != null) ? Number(f.min) : 0;
      if (isUpgrade && cur !== "" && Number(cur) > minV) minV = Number(cur);
      var maxV = (f.max != null) ? Number(f.max) : null;
      var stepV = (f.step != null) ? Number(f.step) : 1;
      var defV = (f["default"] != null) ? f["default"] : "";
      var preset = cur !== "" ? cur : defV;
      var curBadge = (cur !== "" && cur !== null && cur !== undefined)
        ? ' <span class="pp-current">الحالي: ' + escText(cur) + (unit ? " " + unit : "") + "</span>" : "";
      var unitBadge = unit ? ' <span class="pp-unit">' + unit + "</span>" : "";
      html += '<div class="pp-spec-field"' + swAttr + ">"
        + '<label for="' + namePrefix + "-" + escAttr(key) + '">' + label + unitBadge + curBadge + "</label>"
        + '<input type="number" '
          + 'min="' + escAttr(minV) + '" '
          + (maxV != null ? 'max="' + escAttr(maxV) + '" ' : "")
          + 'step="' + escAttr(stepV) + '" '
          + 'id="' + namePrefix + "-" + escAttr(key) + '" '
          + 'name="spec_' + escAttr(key) + '" '
          + 'placeholder="' + escAttr(preset !== "" ? preset : "—") + '" '
          + 'value="' + (preset !== "" ? escAttr(preset) : "") + '">'
        + (hint ? '<div class="pp-hint">' + hint + "</div>" : "")
        + "</div>";
    });
    host.innerHTML = html;
    wireSpecChoiceToggles(host);
  }
  // Show/hide spec fields whose ``show_when`` references a choice <select>, and
  // keep them in sync when the choice changes. Hidden inputs are disabled so the
  // server never receives a stale per-method value (e.g. Mbps for server-IP).
  function wireSpecChoiceToggles(host) {
    if (!host) return;
    var selects = host.querySelectorAll("select[data-spec-choice]");
    if (!selects.length) return;
    function apply() {
      var values = {};
      selects.forEach(function (s) { values[s.getAttribute("data-spec-choice")] = s.value; });
      host.querySelectorAll("[data-show-when-field]").forEach(function (wrap) {
        var field = wrap.getAttribute("data-show-when-field");
        var vals = (wrap.getAttribute("data-show-when-vals") || "").split("|");
        var show = vals.indexOf(String(values[field])) !== -1;
        wrap.style.display = show ? "" : "none";
        wrap.querySelectorAll("input, select, textarea").forEach(function (el) { el.disabled = !show; });
      });
    }
    selects.forEach(function (s) { s.addEventListener("change", apply); });
    apply();
  }
  function openActivate(btn) {
    var modal = $("pp-activate-modal"); if (!modal) return;
    var name = btn.getAttribute("data-service-name") || "خدمة";
    var icon = btn.getAttribute("data-icon") || "paper-plane";
    var action = btn.getAttribute("data-action") || "";
    var fields = parseJsonAttr(btn.getAttribute("data-fields"), []);
    var title = $("pp-activate-title"); if (title) title.textContent = "طلب تفعيل: " + name;
    var ico = $("pp-activate-ico"); if (ico) ico.className = "fa-solid fa-" + icon;
    var form = $("pp-activate-form"); if (form) form.setAttribute("action", action);
    buildSpecInputs($("pp-activate-fields"), fields, null, "pp-act");
    var notes = $("pp-activate-notes"); if (notes) notes.value = "";
    openModal(modal);
  }
  function openUpgrade(btn) {
    var modal = $("pp-upgrade-modal"); if (!modal) return;
    var name = btn.getAttribute("data-service-name") || "خدمة";
    var icon = btn.getAttribute("data-icon") || "arrow-up";
    var action = btn.getAttribute("data-action") || "";
    var fields = parseJsonAttr(btn.getAttribute("data-fields"), []);
    var current = parseJsonAttr(btn.getAttribute("data-current-limits"), {});
    var title = $("pp-upgrade-title"); if (title) title.textContent = "ترقية: " + name;
    var ico = $("pp-upgrade-ico"); if (ico) ico.className = "fa-solid fa-" + icon;
    var form = $("pp-upgrade-form"); if (form) form.setAttribute("action", action);
    buildSpecInputs($("pp-upgrade-fields"), fields, current, "pp-upg");
    var notes = $("pp-upgrade-notes"); if (notes) notes.value = "";
    // reset to default upgrade target
    var first = modal.querySelector('input[name="upgrade_target"][value="more_capacity"]');
    if (first) first.checked = true;
    openModal(modal);
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
    if ((t = e.target.closest("[data-pp-restore]")))  { e.preventDefault(); try { openRestore(t); } catch (x) {} return; }
    if ((t = e.target.closest("[data-pp-delete]")))   { e.preventDefault(); try { openDelete(t); } catch (x) {} return; }
    if ((t = e.target.closest("[data-pp-activate]"))) { e.preventDefault(); try { openActivate(t); } catch (x) {} return; }
    if ((t = e.target.closest("[data-pp-upgrade]")))  { e.preventDefault(); try { openUpgrade(t); } catch (x) {} return; }
    if ((t = e.target.closest("[data-pp-more]")))     { try { openDetails(t); } catch (x) {} return; }
    if (e.target.closest("[data-pp-close]"))          { closeModals(); return; }
    if (e.target.classList && e.target.classList.contains("pp-modal")) { closeModals(); return; }
    if ((t = e.target.closest("[data-pwd-toggle]")))  { e.preventDefault(); try { togglePwd(t); } catch (x) {} return; }
    if ((t = e.target.closest("[data-pp-view]")))     { showView(t.getAttribute("data-pp-view"), true); return; }
    if ((t = e.target.closest("[data-pp-go]")))       { showView(t.getAttribute("data-pp-go"), true); return; }
    if ((t = e.target.closest("#pp-tier-filter .pp-tier-chip"))) { selectTier(t.getAttribute("data-tier") || "all"); return; }
    if ((t = e.target.closest(".pp-cat-chip")))       { selectCat(t.getAttribute("data-pp-cat")); return; }
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
    if (e.target.id === "pp-delete-confirm") deleteValidate();
  });
  document.addEventListener("change", function (e) {
    if (e.target.id === "pp-restore-ack") restoreValidate();
    if (e.target.id === "pp-delete-ack") deleteValidate();
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeModals(); });

  // initial view from the URL (deep-link). Supports both ?view=<name>
  // (used by server-side post-redirects, e.g. the WhatsApp PRG) and #<name>.
  // ?view= wins; falling back to the hash keeps the old behavior intact.
  // Anchor → view aliases: some #anchors point at a card INSIDE a pane rather
  // than naming a pane. Map them to the owning view so a deep-link opens it.
  var VIEW_ALIASES = { gdrive: "backups" };
  function initialView() {
    var v = "";
    try {
      var qs = new URLSearchParams(location.search || "");
      v = (qs.get("view") || "").trim();
    } catch (e) { /* URLSearchParams unsupported → fall through to hash */ }
    if (!v) v = (location.hash || "").replace("#", "");
    return VIEW_ALIASES[v] || v;
  }
  function boot() {
    var h = initialView();
    if (h) showView(h, false);
    // Pre-load all backup summaries so the content is ready/visible without a click,
    // and bind reliable direct toggle listeners on the content buttons.
    try { autoloadSummaries(); } catch (e) {}
    try { bindSummaryButtons(); } catch (e) {}
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
