// Pending onboarding-jobs card — «متابعة» (advance) + «حذف» (delete).
//
// Owner rules honored:
//   * NO native alert() / confirm(). Confirmation routes through the
//     #fd-pj-confirm dialog; messages via the page's #fd-toast-host (reused
//     from the health-check toast host) or a fallback host if absent.
//   * CSP-safe external script; no inline handlers anywhere.
//   * Per-row spinner while a call is in flight; row removed (delete) or
//     repainted (advance) on success; toast on failure carries body.message.

(function () {
  "use strict";

  const scriptTag = document.currentScript || (function () {
    const all = document.getElementsByTagName("script");
    return all[all.length - 1];
  })();
  const ADVANCE_TEMPLATE = scriptTag.dataset.advanceUrl || "/admin/fleet/onboarding/jobs/0/advance";
  const DELETE_TEMPLATE  = scriptTag.dataset.deleteUrl  || "/admin/fleet/onboarding/jobs/0/delete";

  function advanceUrl(id) {
    return ADVANCE_TEMPLATE.replace(/\/0\/advance$/, "/" + encodeURIComponent(id) + "/advance");
  }
  function deleteUrl(id) {
    return DELETE_TEMPLATE.replace(/\/0\/delete$/, "/" + encodeURIComponent(id) + "/delete");
  }

  function csrfToken() {
    const el = document.querySelector('#fd-pending-csrf input[name="_csrf_token"]')
      || document.querySelector('#fd-csrf-form input[name="_csrf_token"]');
    return el ? el.value : "";
  }

  // ────────────────────────────────────────────────────────────────────
  // Toast — reuse the page's host (the health-check toast host), or build
  // a fallback at the bottom-end of the viewport if it's not present.
  // ────────────────────────────────────────────────────────────────────
  function ensureToastHost() {
    let host = document.getElementById("fd-toast-host");
    if (host) return host;
    host = document.createElement("div");
    host.id = "fd-toast-host";
    host.setAttribute("aria-live", "polite");
    host.setAttribute("aria-atomic", "true");
    host.style.cssText =
      "position:fixed;inset-inline-end:24px;bottom:24px;z-index:1100;" +
      "display:flex;flex-direction:column;gap:10px;max-width:360px";
    document.body.appendChild(host);
    return host;
  }

  function toast(kind, message, opts) {
    const host = ensureToastHost();
    opts = opts || {};
    const node = document.createElement("div");
    node.className = "fd-toast fd-toast--" + (kind || "info");
    // Inline fallback styles — if dashboard.css is present these are no-ops.
    node.style.cssText =
      "background:#fff;border:1px solid #e5e7eb;border-radius:14px;" +
      "box-shadow:0 22px 40px -18px rgba(15,23,42,.32);padding:14px 16px;" +
      "display:flex;gap:10px;align-items:flex-start";
    const iconColor = {
      info:    "#0284c7",
      success: "#047857",
      warn:    "#b45309",
      error:   "#b91c1c",
    }[kind || "info"];
    const iconName = {
      info:    "fa-circle-info",
      success: "fa-circle-check",
      warn:    "fa-triangle-exclamation",
      error:   "fa-circle-xmark",
    }[kind || "info"];
    const icon = document.createElement("i");
    icon.className = "fa-solid " + iconName + " fd-toast-icon";
    icon.style.cssText = "color:" + iconColor + ";font-size:16px;margin-top:2px";
    const msg = document.createElement("div");
    msg.className = "fd-toast-msg";
    msg.style.cssText = "font-size:13px;color:#0f172a;line-height:1.55;flex:1";
    msg.textContent = message || "";
    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "إغلاق");
    closeBtn.style.cssText = "background:transparent;border:none;cursor:pointer;color:#6b7280;font-size:14px";
    closeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    closeBtn.addEventListener("click", () => node.remove());
    node.appendChild(icon);
    node.appendChild(msg);
    node.appendChild(closeBtn);
    host.appendChild(node);
    const ttl = opts.ttl != null ? opts.ttl : 5200;
    if (ttl > 0) setTimeout(() => { if (node.parentNode) node.remove(); }, ttl);
  }

  // ────────────────────────────────────────────────────────────────────
  // Styled confirm dialog → Promise<boolean>
  // ────────────────────────────────────────────────────────────────────
  const confirmEl    = document.getElementById("fd-pj-confirm");
  const confirmMsg   = document.getElementById("fd-pj-confirm-msg");
  const confirmOk    = document.getElementById("fd-pj-confirm-ok");
  const confirmCanc  = document.getElementById("fd-pj-confirm-cancel");

  function confirmDialog(message) {
    return new Promise((resolve) => {
      if (!confirmEl) { resolve(true); return; }
      confirmMsg.textContent = message || "هل أنت متأكد؟";
      confirmEl.style.display = "flex";
      function close(r) {
        confirmEl.style.display = "none";
        confirmOk.removeEventListener("click", onOk);
        confirmCanc.removeEventListener("click", onCancel);
        confirmEl.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
        resolve(r);
      }
      function onOk()      { close(true); }
      function onCancel()  { close(false); }
      function onBackdrop(e) { if (e.target === confirmEl) close(false); }
      function onKey(e)    { if (e.key === "Escape") close(false); }
      confirmOk.addEventListener("click", onOk);
      confirmCanc.addEventListener("click", onCancel);
      confirmEl.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);
    });
  }

  // ────────────────────────────────────────────────────────────────────
  // Helpers
  // ────────────────────────────────────────────────────────────────────
  function setBusy(btn, busy) {
    if (!btn) return;
    btn.classList.toggle("is-busy", !!busy);
    btn.disabled = !!busy;
  }
  async function safeJson(res) {
    try { return await res.json(); } catch (_) { return {}; }
  }
  function rowFor(jobId) {
    return document.querySelector('#fd-pending-tbody [data-job-id="' + jobId + '"]');
  }
  function pendingCount() {
    return document.querySelectorAll("#fd-pending-tbody .pj-card").length;
  }
  function refreshPageAfterChange() {
    // A full page reload keeps every dependent surface in sync — the KPI
    // strip, the ranking card, the «عقد CHR» table — without us
    // re-implementing the dashboard's data pipeline client-side. Defer
    // briefly so the success toast is visible during the fade.
    setTimeout(() => { window.location.reload(); }, 900);
  }

  // ────────────────────────────────────────────────────────────────────
  // EVENT DELEGATION — single document-level listener for BOTH
  // .fd-pj-advance and .fd-pj-delete.
  //
  // fix/dashboard-buttons-event-delegation — the previous binding
  // walked the DOM at init and called addEventListener per button.
  // The fleet dashboard rewrites pending-card markup on every tab
  // switch / live-poll row replace, so any button rendered AFTER
  // init silently became dead. One delegated listener at `document`
  // matches every present-or-future button via .closest().
  //
  // Async handlers (advance, delete) get their button reference from
  // the matched element, so the busy/idle visual states still work.
  // ────────────────────────────────────────────────────────────────────
  async function handleAdvance(btn) {
    const id   = btn.dataset.jobId;
    const name = btn.dataset.jobName || ("#" + id);
    setBusy(btn, true);
    try {
      const res = await fetch(advanceUrl(id), {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({}),
      });
      const body = await safeJson(res);
      if (!res.ok || !body.ok) {
        const reason = body.message || body.error || ("HTTP " + res.status);
        toast("error", "تعذّر متابعة الجوب «" + name + "»: " + reason, { ttl: 8000 });
        return;
      }
      if (body.advanced) {
        const created = body.chr_id ? (" · عقدة #" + body.chr_id) : "";
        toast("success",
          "تم دفع الجوب «" + name + "» إلى «" + (body.status || "—") + "»" + created);
      } else {
        toast("info", "الجوب «" + name + "» وصل بالفعل لأبعد ما يمكن من اللوحة.");
      }
      refreshPageAfterChange();
    } catch (_err) {
      toast("error", "خطأ شبكي — تعذّر الوصول لخادم اللوحة.", { ttl: 8000 });
    } finally {
      setBusy(btn, false);
    }
  }

  async function handleDelete(btn) {
    const id     = btn.dataset.jobId;
    const name   = btn.dataset.jobName || ("#" + id);
    const chrId  = (btn.dataset.chrId || "").trim();

    let msg = "حذف جوب التسجيل «" + name + "»؟";
    if (chrId) {
      msg += " ستُحذف أيضاً العقدة المرتبطة #" + chrId
          + " (حالتها «تجهيز» — لم تُفعَّل بعد).";
    } else {
      msg += " هذا الجوب لم ينشئ عقدة بعد، لن تتأثّر أي عقدة موجودة.";
    }
    const ok = await confirmDialog(msg);
    if (!ok) return;

    setBusy(btn, true);
    try {
      const res = await fetch(deleteUrl(id), {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({ remove_node: !!chrId }),
      });
      const body = await safeJson(res);
      if (!res.ok || !body.ok) {
        const reason = body.message || body.error || ("HTTP " + res.status);
        toast("error", "تعذّر حذف الجوب «" + name + "»: " + reason, { ttl: 8000 });
        return;
      }
      const row = rowFor(id);
      if (row) row.remove();
      const nodeBit = body.node_removed ? " (والعقدة المرتبطة)" : "";
      toast("success", "تم حذف الجوب «" + name + "»" + nodeBit + ".");
      refreshPageAfterChange();
    } catch (_err) {
      toast("error", "خطأ شبكي — تعذّر الوصول لخادم اللوحة.", { ttl: 8000 });
    } finally {
      setBusy(btn, false);
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // Boot — one document listener covers every present + future button.
  // ────────────────────────────────────────────────────────────────────
  document.addEventListener("click", function (e) {
    var t = e.target;
    if (!t || !t.closest) return;
    var advBtn = t.closest(".fd-pj-advance");
    if (advBtn) { e.preventDefault(); handleAdvance(advBtn); return; }
    var delBtn = t.closest(".fd-pj-delete");
    if (delBtn) { e.preventDefault(); handleDelete(delBtn); return; }
  });
})();
