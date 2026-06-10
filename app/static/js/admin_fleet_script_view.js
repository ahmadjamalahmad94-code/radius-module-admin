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

  function urlFor(id) {
    return TEMPLATE.replace(/\/0\/script$/, "/" + encodeURIComponent(id) + "/script");
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
  const copyBtn    = document.getElementById("fd-sm-copy");
  const dlBtn      = document.getElementById("fd-sm-download");
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

  function closeModal() {
    if (!modal) return;
    modal.style.display = "none";
    document.removeEventListener("keydown", onKey);
    clearBlob();
    currentScript = "";
  }
  function openModal() {
    if (!modal) return;
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
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
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
        // Swap the icon to a green checkmark for ~1.5s to confirm.
        const ic = copyBtn.querySelector(".fd-pj-icon");
        const ok = copyBtn.querySelector(".fa-check");
        if (ic) ic.style.display = "none";
        if (ok) ok.style.display = "inline-block";
        toast("success", "تم نسخ السكربت إلى الحافظة.");
        setTimeout(() => {
          if (ic) ic.style.display = "";
          if (ok) ok.style.display = "none";
        }, 1500);
      } catch (_err) {
        toast("error", "تعذّر النسخ التلقائي — حدّد النص يدوياً ثم Ctrl+C.", { ttl: 6000 });
      }
    });
  }

  function setDownload(filename, body) {
    if (!dlBtn) return;
    clearBlob();
    const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
    currentBlobUrl = URL.createObjectURL(blob);
    dlBtn.href = currentBlobUrl;
    dlBtn.download = filename || "chr-node.rsc";
  }

  // ────────────────────────────────────────────────────────────────────
  // Open + load
  // ────────────────────────────────────────────────────────────────────
  async function openFor(jobId, nodeName) {
    if (!modal) return;
    // Reset display state.
    if (titleEl)    titleEl.textContent    = "سكربت RouterOS — " + (nodeName || "#" + jobId);
    if (filenameEl) filenameEl.textContent = "—";
    if (statusEl)   statusEl.textContent   = "جارٍ التحميل";
    if (shaEl)      shaEl.textContent      = "—";
    if (scriptEl)   scriptEl.textContent   = "— جارٍ التحميل —";
    if (bytesEl)    bytesEl.textContent    = "—";
    if (dlBtn)      { dlBtn.href = "#"; dlBtn.removeAttribute("download"); }
    openModal();

    try {
      const res = await fetch(urlFor(jobId), {
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
      toast("success", "تم تحميل السكربت — مُولّد لهذه العقدة فقط.");
    } catch (_err) {
      if (scriptEl) scriptEl.textContent = "(خطأ شبكي)";
      toast("error", "خطأ شبكي — تعذّر الوصول لخادم اللوحة.", { ttl: 7000 });
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // Wire the per-row buttons.
  // ────────────────────────────────────────────────────────────────────
  document.querySelectorAll(".fd-pj-view-script").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id   = btn.dataset.jobId;
      const name = btn.dataset.jobName || ("#" + id);
      openFor(id, name);
    });
  });
})();
