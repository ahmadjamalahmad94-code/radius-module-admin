// Script-view modal — opens when an operator clicks «عرض السكربت» on a
// pending-onboarding row. Loads the rendered .rsc from the server, shows
// it in a scrollable monospace block, and exposes نسخ + تنزيل actions.
//
// Owner rules:
//   * NO native alert()/confirm(); toast for status feedback + ESC/backdrop
//     to dismiss the modal.
//   * CSP-safe external script. No inline handlers.
//   * The script body is NEVER logged client-side either (we don't
//     console.log it; we only render it into the DOM and the download blob).

(function () {
  "use strict";

  const scriptTag = document.currentScript || (function () {
    const all = document.getElementsByTagName("script");
    return all[all.length - 1];
  })();
  const TEMPLATE = scriptTag.dataset.scriptUrl
    || "/admin/fleet/onboarding/jobs/0/script";
  // feat/active-node-view-script-reimport — a second template URL for
  // the node-keyed route so the JS can show the script for an ACTIVE
  // node (whose job is past the pending tab). Falls back to deriving
  // a node URL from the job URL pattern if the page didn't pass one
  // explicitly. Both routes return the same JSON shape — only the id
  // and the URL prefix differ.
  const NODE_TEMPLATE = scriptTag.dataset.nodeScriptUrl
    || "/admin/fleet/onboarding/chr-nodes/0/script";

  function urlFor(id, kind) {
    const template = (kind === "node") ? NODE_TEMPLATE : TEMPLATE;
    return template.replace(/\/0\/script$/, "/" + encodeURIComponent(id) + "/script");
  }

  // ────────────────────────────────────────────────────────────────────
  // Toast — reuse the host the rest of the dashboard uses, or build one.
  // ────────────────────────────────────────────────────────────────────
  function ensureToastHost() {
    let host = document.getElementById("fd-toast-host");
    if (host) return host;
    host = document.createElement("div");
    host.id = "fd-toast-host";
    host.setAttribute("aria-live", "polite");
    host.setAttribute("aria-atomic", "true");
    host.style.cssText =
      "position:fixed;inset-inline-end:24px;bottom:24px;z-index:1200;" +
      "display:flex;flex-direction:column;gap:10px;max-width:360px";
    document.body.appendChild(host);
    return host;
  }
  function toast(kind, message, opts) {
    const host = ensureToastHost();
    opts = opts || {};
    const node = document.createElement("div");
    node.style.cssText =
      "background:#fff;border:1px solid #e5e7eb;border-radius:14px;" +
      "box-shadow:0 22px 40px -18px rgba(15,23,42,.32);padding:14px 16px;" +
      "display:flex;gap:10px;align-items:flex-start";
    const colors = { info:"#0284c7", success:"#047857", warn:"#b45309", error:"#b91c1c" };
    const icons  = {
      info: "fa-circle-info", success: "fa-circle-check",
      warn: "fa-triangle-exclamation", error: "fa-circle-xmark",
    };
    node.innerHTML =
      '<i class="fa-solid ' + icons[kind || "info"] + '" style="color:' +
      colors[kind || "info"] + ';font-size:16px;margin-top:2px"></i>' +
      '<div style="font-size:13px;color:#0f172a;line-height:1.55;flex:1"></div>' +
      '<button type="button" aria-label="إغلاق" style="background:transparent;border:none;cursor:pointer;color:#6b7280;font-size:14px"><i class="fa-solid fa-xmark"></i></button>';
    node.children[1].textContent = message || "";
    node.children[2].addEventListener("click", () => node.remove());
    host.appendChild(node);
    const ttl = opts.ttl != null ? opts.ttl : 4500;
    if (ttl > 0) setTimeout(() => { if (node.parentNode) node.remove(); }, ttl);
  }

  // ────────────────────────────────────────────────────────────────────
  // Modal handles
  // ────────────────────────────────────────────────────────────────────
  const modal      = document.getElementById("fd-script-modal");
  const titleEl    = document.getElementById("fd-sm-title");
  const subEl      = document.getElementById("fd-sm-sub");
  const filenameEl = document.getElementById("fd-sm-filename");
  const statusEl   = document.getElementById("fd-sm-status");
  const shaEl      = document.getElementById("fd-sm-sha");
  const scriptEl   = document.getElementById("fd-sm-script");
  const bytesEl    = document.getElementById("fd-sm-bytes");
  const importEl   = document.getElementById("fd-sm-import-cmd");
  // fix/script-modal-buttons-reachable — TWO copy + TWO download buttons:
  // one pair in the modal header (always visible above the fold) and one
  // pair in the body above the script <pre> (legacy position). Both pairs
  // share the same handlers; either can be clicked.
  const copyBtns = [
    document.getElementById("fd-sm-copy"),
    document.getElementById("fd-sm-copy-top"),
  ].filter(Boolean);
  const dlBtns = [
    document.getElementById("fd-sm-download"),
    document.getElementById("fd-sm-download-top"),
  ].filter(Boolean);
  const closeBtn   = document.getElementById("fd-sm-close");
  const doneBtn    = document.getElementById("fd-sm-done");

  // Body cached for copy + download so we never re-request the script while
  // the modal is open.
  let currentScript = "";
  let currentBlobUrl = null;

  // Arabic state explanations the modal echoes alongside the status pill.
  const STATUS_AR = {
    keys_generated:   "تم توليد المفاتيح",
    script_generated: "تم توليد السكربت",
    pushed:           "تم الدفع للعقدة",
    verifying:        "قيد التحقّق",
    active:           "نشطة",
  };

  function clearBlob() {
    if (currentBlobUrl) {
      URL.revokeObjectURL(currentBlobUrl);
      currentBlobUrl = null;
    }
  }

  // fix/pause-livepoll-while-modal-open — raise + clear the generic
  // pause signal so the dashboard's live-poll (data-live-rows replace
  // + count-up rAF storm) doesn't run UNDERNEATH this modal and freeze
  // the renderer with the ~900-line script <pre>. The signal is BOTH
  // a window flag (read by live_poll.isExternalPaused()) AND a body
  // data-attribute (for any future declarative consumer). Plus we fire
  // hobe:poll-pause / hobe:poll-resume events so the poller resumes
  // immediately on close (vs waiting for the next tick to notice).
  function pausePoll() {
    try {
      window.__hobePausePoll = true;
      if (document.body && document.body.dataset) {
        document.body.dataset.pollPaused = "1";
      }
      document.dispatchEvent(new CustomEvent("hobe:poll-pause"));
    } catch (_err) { /* never break the modal on a signal error */ }
  }
  function resumePoll() {
    try {
      window.__hobePausePoll = false;
      if (document.body && document.body.dataset) {
        delete document.body.dataset.pollPaused;
      }
      document.dispatchEvent(new CustomEvent("hobe:poll-resume"));
    } catch (_err) { /* never break the modal on a signal error */ }
  }

  function closeModal() {
    if (!modal) return;
    modal.style.display = "none";
    document.removeEventListener("keydown", onKey);
    clearBlob();
    currentScript = "";
    resumePoll();
  }
  function openModal() {
    if (!modal) return;
    // Pause BEFORE we make the modal visible so the very next tick the
    // poller would have fired is already short-circuited.
    pausePoll();
    modal.style.display = "flex";
    document.addEventListener("keydown", onKey);
  }
  function onKey(e) { if (e.key === "Escape") closeModal(); }

  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (doneBtn)  doneBtn.addEventListener("click",  closeModal);
  if (modal) {
    modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
  }

  // ────────────────────────────────────────────────────────────────────
  // Copy + download
  // ────────────────────────────────────────────────────────────────────
  // fix/script-modal-buttons-reachable — bind BOTH copy buttons
  // (header + body) to the same handler so either is clickable.
  function flashCopyBtn(btn) {
    const ic = btn.querySelector(".fd-pj-icon");
    const ok = btn.querySelector(".fa-check");
    if (ic) ic.style.display = "none";
    if (ok) ok.style.display = "inline-block";
    setTimeout(() => {
      if (ic) ic.style.display = "";
      if (ok) ok.style.display = "none";
    }, 1500);
  }

  copyBtns.forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!currentScript) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(currentScript);
        } else {
          // Fallback for HTTP / older browsers: select the <pre> and execCommand.
          const range = document.createRange();
          range.selectNodeContents(scriptEl);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
          document.execCommand("copy");
          sel.removeAllRanges();
        }
        // Flash BOTH copy buttons so the operator gets feedback no matter
        // which one they clicked.
        copyBtns.forEach(flashCopyBtn);
        toast("success", "تم نسخ السكربت إلى الحافظة.");
      } catch (_err) {
        toast("error", "تعذّر النسخ التلقائي — حدّد النص يدوياً ثم Ctrl+C.", { ttl: 6000 });
      }
    });
  });

  function setDownload(filename, body) {
    if (!dlBtns.length) return;
    clearBlob();
    const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
    currentBlobUrl = URL.createObjectURL(blob);
    // Mirror the same href + filename onto every download button so the
    // header copy and the body copy both produce identical downloads.
    dlBtns.forEach((b) => {
      b.href = currentBlobUrl;
      b.download = filename || "chr-node.rsc";
    });
  }

  // ────────────────────────────────────────────────────────────────────
  // Open + load
  //   kind: "job" (pending-card route) | "node" (active-node route).
  //   Both routes return the same JSON shape — only the URL differs.
  // ────────────────────────────────────────────────────────────────────
  async function openFor(id, nodeName, kind) {
    kind = kind || "job";
    if (!modal) return;
    // Reset display state.
    if (titleEl)    titleEl.textContent    = "سكربت RouterOS — " + (nodeName || "#" + id);
    if (filenameEl) filenameEl.textContent = "—";
    if (statusEl)   statusEl.textContent   = "جارٍ التحميل";
    if (shaEl)      shaEl.textContent      = "—";
    if (scriptEl)   scriptEl.textContent   = "— جارٍ التحميل —";
    if (bytesEl)    bytesEl.textContent    = "—";
    // Reset BOTH download buttons (header + body) when a new modal opens.
    dlBtns.forEach((b) => { b.href = "#"; b.removeAttribute("download"); });
    openModal();

    try {
      const res = await fetch(urlFor(id, kind), {
        method: "GET",
        headers: { "Accept": "application/json" },
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.ok) {
        const reason = body.message || body.error || ("HTTP " + res.status);
        if (scriptEl) scriptEl.textContent = "(لم يُحمَّل السكربت)";
        toast("error", "تعذّر تحميل السكربت: " + reason, { ttl: 8000 });
        return;
      }
      currentScript = body.script || "";
      if (filenameEl) filenameEl.textContent = body.filename || "node.rsc";
      if (statusEl)   statusEl.textContent   = STATUS_AR[body.status] || body.status || "—";
      if (shaEl)      shaEl.textContent      = body.sha256 || "—";
      if (scriptEl)   scriptEl.textContent   = currentScript;
      if (bytesEl)    bytesEl.textContent    = String(currentScript.length);
      if (importEl)   importEl.textContent   = "/import file=" + (body.filename || "<filename>.rsc");
      setDownload(body.filename || "node.rsc", currentScript);
      let okMsg = "تم تحميل السكربت — مُولّد لهذه العقدة فقط.";
      if (kind === "node" && body.needs_reimport) {
        okMsg = "تم تحميل السكربت الجديد بعد تصحيح مفتاح اللوحة — أعد استيراده على هذه العقدة.";
      }
      toast("success", okMsg);
    } catch (_err) {
      if (scriptEl) scriptEl.textContent = "(خطأ شبكي)";
      toast("error", "خطأ شبكي — تعذّر الوصول لخادم اللوحة.", { ttl: 7000 });
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // EVENT DELEGATION — single document-level listener
  //
  // fix/dashboard-buttons-event-delegation — the fleet dashboard
  // rewrites node-card / pending-card markup after init (see
  // live_poll.js's `data-live-rows` replace path + the tab content
  // injection on tab switch). A per-button addEventListener at init
  // time silently dies on every replaced/late-rendered button — the
  // exact live bug the owner saw: «عرض السكربت» on active node cards
  // did nothing, no console error, because the buttons in the
  // dashboard's «عقد CHR» tab were re-created after the JS bound the
  // ORIGINAL set.
  //
  // One delegated listener at `document` survives every DOM rewrite
  // and binds every present-or-future button matching the selector.
  // We use .closest() so a click on the icon INSIDE the button still
  // resolves to the button element + its dataset.
  //
  //   .fd-pj-view-script  — pending-card path,  data-job-id  → kind="job"
  //   .fd-node-view-script — active-node path,   data-node-id → kind="node"
  // Both flow through the same modal via openFor(id, name, kind).
  // ────────────────────────────────────────────────────────────────────
  document.addEventListener("click", function (e) {
    var btn = e.target && e.target.closest
      ? e.target.closest(".fd-pj-view-script, .fd-node-view-script")
      : null;
    if (!btn) return;
    // Prevent any accidental form-submit / link-follow.
    e.preventDefault();
    var isNode = btn.classList.contains("fd-node-view-script");
    var id, name, kind;
    if (isNode) {
      id = btn.dataset.nodeId;
      name = btn.dataset.nodeName || ("#" + id);
      kind = "node";
    } else {
      id = btn.dataset.jobId;
      name = btn.dataset.jobName || ("#" + id);
      kind = "job";
    }
    if (!id) return;   // defensive — a button without an id is a render bug
    openFor(id, name, kind);
  });
})();
