// fleet/ui — front-door settings page.
//
// Owner rules:
//   * NO native alert() / confirm(). All confirmations route through the
//     styled #ff-confirm dialog; all status messages through #ff-toast-host.
//   * NEVER read or echo the Cloudflare API token from the DOM. The
//     password input lives in a server-rendered form that POSTs to a
//     dedicated route; this script never touches its value.
//   * CSP: script-src 'self' — no inline handlers.
//
(function () {
  "use strict";

  const scriptTag = document.currentScript || (function () {
    const all = document.getElementsByTagName("script");
    return all[all.length - 1];
  })();
  const PREVIEW_URL = scriptTag.dataset.previewUrl || "/admin/fleet/dns/preview";
  const APPLY_URL = scriptTag.dataset.applyUrl || "/admin/fleet/dns/apply";

  function csrfToken() {
    const el = document.querySelector('#ff-csrf-host input[name="_csrf_token"]');
    return el ? el.value : "";
  }

  // ────────────────────────────────────────────────────────────────────
  // Toast host
  // ────────────────────────────────────────────────────────────────────
  const toastHost = document.getElementById("ff-toast-host");
  function toast(kind, message, opts) {
    if (!toastHost) return;
    opts = opts || {};
    const node = document.createElement("div");
    node.className = "ff-toast ff-toast--" + (kind || "info");
    const iconClass = {
      info: "fa-circle-info",
      success: "fa-circle-check",
      warn: "fa-triangle-exclamation",
      error: "fa-circle-xmark",
    }[kind || "info"];
    const icon = document.createElement("i");
    icon.className = "fa-solid " + iconClass + " ff-toast-icon";
    const msg = document.createElement("div");
    msg.className = "ff-toast-msg";
    msg.textContent = message || "";
    const closeBtn = document.createElement("button");
    closeBtn.className = "ff-toast-close";
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "إغلاق");
    closeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    closeBtn.addEventListener("click", () => node.remove());
    node.appendChild(icon);
    node.appendChild(msg);
    node.appendChild(closeBtn);
    toastHost.appendChild(node);
    const ttl = opts.ttl != null ? opts.ttl : 4500;
    if (ttl > 0) setTimeout(() => { if (node.parentNode) node.remove(); }, ttl);
  }

  // ────────────────────────────────────────────────────────────────────
  // Styled confirm dialog → Promise<boolean>
  // ────────────────────────────────────────────────────────────────────
  const confirmEl = document.getElementById("ff-confirm");
  const confirmMsg = document.getElementById("ff-confirm-msg");
  const confirmOk = document.getElementById("ff-confirm-ok");
  const confirmCancel = document.getElementById("ff-confirm-cancel");
  function confirmDialog(message) {
    return new Promise((resolve) => {
      if (!confirmEl) return resolve(true);
      confirmMsg.textContent = message || "هل أنت متأكد؟";
      confirmEl.classList.add("is-open");
      function close(result) {
        confirmEl.classList.remove("is-open");
        confirmOk.removeEventListener("click", onOk);
        confirmCancel.removeEventListener("click", onCancel);
        confirmEl.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
        resolve(result);
      }
      function onOk() { close(true); }
      function onCancel() { close(false); }
      function onBackdrop(e) { if (e.target === confirmEl) close(false); }
      function onKey(e) { if (e.key === "Escape") close(false); }
      confirmOk.addEventListener("click", onOk);
      confirmCancel.addEventListener("click", onCancel);
      confirmEl.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);
    });
  }

  // ────────────────────────────────────────────────────────────────────
  // Token «تغيير» button — intercept submit to wrap with confirm dialog
  // ────────────────────────────────────────────────────────────────────
  const clearBtn = document.getElementById("ff-token-clear-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      const msg = clearBtn.dataset.confirm
        || "هل تريد مسح توكن Cloudflare الحالي؟";
      const ok = await confirmDialog(msg);
      if (!ok) return;
      const form = clearBtn.closest("form");
      if (form) form.submit();
    });
  }

  // Mode card highlight on radio change.
  document.querySelectorAll('input[name="mode"]').forEach((r) => {
    r.addEventListener("change", () => {
      document.querySelectorAll(".ff-mode-card").forEach((c) => {
        const inp = c.querySelector('input[name="mode"]');
        c.classList.toggle("is-selected", inp && inp.checked);
      });
    });
  });

  // ────────────────────────────────────────────────────────────────────
  // Arabic mode labels (must mirror the server-side dict)
  // ────────────────────────────────────────────────────────────────────
  const MODE_LABELS_AR = {
    free: "مجاني — سجلات A موزونة / استبعاد",
    paid: "مدفوع — موازنة Cloudflare",
  };

  // ────────────────────────────────────────────────────────────────────
  // Preview + Apply
  // ────────────────────────────────────────────────────────────────────
  const previewBtn = document.getElementById("ff-preview-btn");
  const applyBtn = document.getElementById("ff-apply-btn");
  const resultPane = document.getElementById("ff-result");
  const currentHost = document.getElementById("ff-current-host");

  function setBusy(btn, busy) {
    if (!btn) return;
    const main = btn.querySelector("i.fa-solid:not(.fa-spinner):not(.ff-toast-icon)");
    const spin = btn.querySelector(".fa-spinner");
    if (main) main.style.display = busy ? "none" : "";
    if (spin) spin.style.display = busy ? "inline-block" : "none";
    btn.disabled = !!busy;
  }

  if (previewBtn) {
    previewBtn.addEventListener("click", async () => {
      setBusy(previewBtn, true);
      try {
        const res = await fetch(PREVIEW_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
          body: JSON.stringify({}),
        });
        const body = await safeJson(res);
        if (!res.ok || !body.ok) {
          showError("تعذّر إجراء المعاينة: " + (body.error || ("HTTP " + res.status)));
          return;
        }
        renderResult(body.preview, /*isApply*/ false);
        renderCurrent(body.preview);
        toast("info", "تمت المعاينة — لم يحدث أي تغيير على Cloudflare.");
      } catch (_err) {
        showError("خطأ شبكي — تعذّر الوصول لخادم اللوحة.");
      } finally {
        setBusy(previewBtn, false);
      }
    });
  }

  if (applyBtn) {
    applyBtn.addEventListener("click", async () => {
      const ok = await confirmDialog(
        applyBtn.dataset.confirm
        || "هل تريد طلب التطبيق على Cloudflare الآن؟"
      );
      if (!ok) return;
      setBusy(applyBtn, true);
      try {
        const res = await fetch(APPLY_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
          body: JSON.stringify({}),
        });
        const body = await safeJson(res);
        if (!res.ok || !body.ok) {
          showError("تعذّر التطبيق: " + (body.error || ("HTTP " + res.status)));
          return;
        }
        renderResult(body.result, /*isApply*/ true);
        renderCurrent(body.result);
        const kind = body.result && body.result.applied ? "success" : "warn";
        const summary = body.result && body.result.applied
          ? "تم التطبيق على Cloudflare."
          : (body.result && body.result.reason) || "لم يُطبَّق فعلاً — تحقّق من السبب أدناه.";
        toast(kind, summary, { ttl: 7000 });
      } catch (_err) {
        showError("خطأ شبكي — تعذّر الوصول لخادم اللوحة.");
      } finally {
        setBusy(applyBtn, false);
      }
    });
  }

  // ────────────────────────────────────────────────────────────────────
  // Result rendering
  // ────────────────────────────────────────────────────────────────────
  function renderResult(p, isApply) {
    if (!resultPane) return;
    if (!p) { resultPane.style.display = "none"; return; }
    resultPane.classList.remove("is-error");
    resultPane.style.display = "block";

    const sourceLabel = p.source === "reconciler"
      ? "المُنسِّق الفعلي" : "تقدير مؤقت في اللوحة";
    const modeLabel = p.mode_label_ar || MODE_LABELS_AR[p.mode] || p.mode;
    const changeLabel = p.would_change
      ? "سيتغيّر — المجموعة المخططة تختلف عن آخر نشر."
      : "لا تغيير — المجموعة الحالية تطابق المخططة.";

    let html = '<div class="ff-result-head"><i class="fa-solid fa-' +
      (isApply ? "cloud-arrow-up" : "eye") + '"></i> ' +
      (isApply ? "نتيجة التطبيق" : "نتيجة المعاينة") +
      ' — <span style="color:#475569">' + escapeHtml(sourceLabel) + "</span></div>";

    html += '<div class="ff-row"><span class="ff-row-key">النطاق</span>' +
      '<span class="ff-row-val mono">' + escapeHtml(p.fqdn || "") + "</span></div>";
    html += '<div class="ff-row"><span class="ff-row-key">الوضع</span>' +
      '<span class="ff-row-val">' + escapeHtml(modeLabel) + "</span></div>";
    html += '<div class="ff-row"><span class="ff-row-key">حالة التغيير</span>' +
      '<span class="ff-row-val">' + escapeHtml(changeLabel) + "</span></div>";

    if (isApply) {
      html += '<div class="ff-row"><span class="ff-row-key">طُبِّق فعلاً؟</span>' +
        '<span class="ff-row-val">' +
        (p.applied ? '<span class="ff-pill ff-pill--ok">نعم</span>'
                   : '<span class="ff-pill ff-pill--warn">لا</span>') +
        "</span></div>";
    }
    if (p.reason) {
      html += '<div class="ff-row"><span class="ff-row-key">السبب</span>' +
        '<span class="ff-row-val">' + escapeHtml(p.reason) + "</span></div>";
    }

    // Intended set
    const aList = (p.intended && p.intended.A) || [];
    if (aList.length) {
      html += '<div style="margin-top:10px;font-weight:700">المجموعة المخططة (A)</div>';
      html += '<table class="ff-tbl"><thead><tr>'
        + "<th>العقدة</th><th>IP</th><th>الوزن</th></tr></thead><tbody>";
      aList.forEach((row) => {
        html += "<tr>" +
          '<td class="mono">' + escapeHtml(row.name || ("#" + row.node_id)) + "</td>" +
          '<td class="mono">' + escapeHtml(row.ip) + "</td>" +
          "<td>" + formatWeight(row.weight) + "</td>" +
          "</tr>";
      });
      html += "</tbody></table>";
    } else {
      html += '<div style="margin-top:10px;color:#b91c1c">' +
        "لا توجد عقد صحيحة الآن — لن يُنشر أي شيء (حماية ضد التفريغ)." + "</div>";
    }

    resultPane.innerHTML = html;
  }

  function renderCurrent(p) {
    if (!currentHost) return;
    const cur = p && p.current;
    if (!cur) { currentHost.innerHTML = '<div class="ff-hint">لا توجد قراءة بعد.</div>'; return; }
    let html = '<div class="ff-row"><span class="ff-row-key">سجلات A المنشورة</span>' +
      '<span class="ff-row-val mono">' +
      ((cur.A && cur.A.length) ? escapeHtml(cur.A.join(", ")) : "—") +
      "</span></div>";
    if (cur.AAAA && cur.AAAA.length) {
      html += '<div class="ff-row"><span class="ff-row-key">سجلات AAAA المنشورة</span>' +
        '<span class="ff-row-val mono">' + escapeHtml(cur.AAAA.join(", ")) + "</span></div>";
    }
    html += '<div class="ff-row"><span class="ff-row-key">TTL</span>' +
      '<span class="ff-row-val mono">' + (cur.ttl != null ? cur.ttl + " ث" : "—") + "</span></div>";
    if (cur.last_change_reason) {
      html += '<div class="ff-row"><span class="ff-row-key">آخر سبب تغيير</span>' +
        '<span class="ff-row-val">' + escapeHtml(cur.last_change_reason) + "</span></div>";
    }
    currentHost.innerHTML = html;
  }

  function showError(text) {
    if (!resultPane) return;
    resultPane.style.display = "block";
    resultPane.classList.add("is-error");
    resultPane.textContent = text;
    toast("error", text, { ttl: 7000 });
  }

  function formatWeight(w) {
    if (w == null) return "—";
    return Number(w).toFixed(2);
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function safeJson(res) {
    try { return await res.json(); } catch (_) { return {}; }
  }
})();
