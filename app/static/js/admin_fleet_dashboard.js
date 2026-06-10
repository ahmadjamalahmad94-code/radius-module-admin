// fleet/ui dashboard — health/metrics view, AJAX check_now.
//
// Owner rules honoured:
//   * NO native alert() / confirm() — styled toast host + Promise-based
//     confirm dialog only (markup lives at the bottom of dashboard.html).
//   * CSP: script-src 'self' — no inline handlers; all wiring happens here.
//   * RTL-safe (the template is dir-inherited from <html lang="ar" dir="rtl">).

(function () {
  "use strict";

  // ────────────────────────────────────────────────────────────────────
  // Endpoint URLs come from data-* on the script tag so the Python side
  // (url_for) stays the single source of truth.
  // ────────────────────────────────────────────────────────────────────
  const scriptTag = document.currentScript || (function () {
    const all = document.getElementsByTagName("script");
    return all[all.length - 1];
  })();
  const CHECK_ONE_TEMPLATE = scriptTag.dataset.checkOneUrl || "/admin/fleet/chr-nodes/0/check-now";
  const CHECK_ALL_URL = scriptTag.dataset.checkAllUrl || "/admin/fleet/chr-nodes/check-all";

  function checkOneUrl(id) {
    // The Jinja side calls url_for(..., node_id=0) so we just swap the 0.
    return CHECK_ONE_TEMPLATE.replace(/\/0\/check-now$/, "/" + encodeURIComponent(id) + "/check-now");
  }

  // CSRF token from the dedicated form at the top of the page.
  function csrfToken() {
    const el = document.querySelector('#fd-csrf-form input[name="_csrf_token"]');
    return el ? el.value : "";
  }

  // ────────────────────────────────────────────────────────────────────
  // Toast host
  // ────────────────────────────────────────────────────────────────────
  const toastHost = document.getElementById("fd-toast-host");
  function toast(kind, message, opts) {
    if (!toastHost) return;
    opts = opts || {};
    const node = document.createElement("div");
    node.className = "fd-toast fd-toast--" + (kind || "info");
    const iconClass = {
      info: "fa-circle-info",
      success: "fa-circle-check",
      warn: "fa-triangle-exclamation",
      error: "fa-circle-xmark",
    }[kind || "info"];
    const icon = document.createElement("i");
    icon.className = "fa-solid " + iconClass + " fd-toast-icon";
    const msg = document.createElement("div");
    msg.className = "fd-toast-msg";
    msg.textContent = message || "";
    const closeBtn = document.createElement("button");
    closeBtn.className = "fd-toast-close";
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "إغلاق");
    closeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    closeBtn.addEventListener("click", () => node.remove());
    node.appendChild(icon);
    node.appendChild(msg);
    node.appendChild(closeBtn);
    toastHost.appendChild(node);
    const ttl = opts.ttl != null ? opts.ttl : 4200;
    if (ttl > 0) setTimeout(() => { if (node.parentNode) node.remove(); }, ttl);
  }

  // ────────────────────────────────────────────────────────────────────
  // Styled confirm dialog — Promise<boolean>
  // ────────────────────────────────────────────────────────────────────
  const confirmEl = document.getElementById("fd-confirm");
  const confirmMsg = document.getElementById("fd-confirm-msg");
  const confirmOk = document.getElementById("fd-confirm-ok");
  const confirmCancel = document.getElementById("fd-confirm-cancel");
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
  // Arabic labels — mirror the server-rendered template exactly.
  // ────────────────────────────────────────────────────────────────────
  const HEALTH_AR = {
    up:        { label: "متّصلة",      cls: "fd-badge--up"   },
    degraded:  { label: "متدهورة",    cls: "fd-badge--deg"  },
    down:      { label: "مفصولة",     cls: "fd-badge--down" },
    unknown:   { label: "غير معروفة", cls: "fd-badge--unk"  },
  };

  function fmtMs(v)        { return v == null ? "—" : (Number(v).toFixed(1) + " ms"); }
  function fmtPct(v)       { return v == null ? "—" : (Number(v).toFixed(1) + "%"); }
  function fmtPctRound(v)  { return v == null ? "—" : (Math.round(Number(v)) + "%"); }
  function fmtGB(bytes) {
    if (bytes == null) return "—";
    return (Number(bytes) / 1073741824).toFixed(2) + " GB";
  }
  function fmtDate(iso) {
    if (!iso) return "لم تتواصل بعد";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const pad = (n) => String(n).padStart(2, "0");
    return d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate())
      + " " + pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds());
  }

  function badge(state) {
    const cfg = HEALTH_AR[state] || HEALTH_AR.unknown;
    return '<span class="fd-badge ' + cfg.cls + '"><i class="fa-solid fa-circle"></i> ' + cfg.label + "</span>";
  }

  // ────────────────────────────────────────────────────────────────────
  // Row updates from JSON payload returned by the server
  // ────────────────────────────────────────────────────────────────────
  function applyRowPayload(row) {
    const tr = document.querySelector('tr[data-node-id="' + row.id + '"]');
    if (!tr) return;
    const h = row.health || {};
    const m = row.metric || {};

    // Health badge cell — preserve the lifecycle/drain sub-badges that were
    // rendered server-side; replace the leading state badge only.
    const healthCell = tr.querySelector('[data-cell="health-state"]');
    if (healthCell) {
      const subs = healthCell.querySelectorAll(".fd-badge:not(:first-child)");
      const subsHtml = Array.from(subs).map((b) => b.outerHTML).join("");
      const transHtml = h.last_transition
        ? '<div class="fd-mini" data-cell="health-transition">آخر تحوّل: <span class="mono">' +
          escapeHtml(h.last_transition) + "</span></div>"
        : "";
      healthCell.innerHTML = badge(h.state) + subsHtml + transHtml;
    }

    const cpuCell = tr.querySelector('[data-cell="metric-cpu"]');
    if (cpuCell) {
      let html = '<span class="fd-num-emph num">' + fmtPct(m.cpu_pct) + "</span>";
      if (m.mem_pct != null) {
        html += '<div class="fd-mini">ذاكرة: <span class="num">' + fmtPctRound(m.mem_pct) + "</span></div>";
      }
      cpuCell.innerHTML = html;
    }

    const rttCell = tr.querySelector('[data-cell="metric-rtt"]');
    if (rttCell) {
      rttCell.innerHTML = m.ping_rtt_ms != null
        ? '<span class="fd-num-emph num">' + fmtMs(m.ping_rtt_ms) + "</span>"
        : '<span style="color:#9ca3af">— لا يوجد —</span>';
    }

    const lastSeenCell = tr.querySelector('[data-cell="last-seen"]');
    if (lastSeenCell) {
      const ts = m.ts; // server prefers metric ts in NodeView.last_seen_at
      lastSeenCell.innerHTML = ts
        ? 'آخر تواصل: <time class="num" data-iso="' + escapeAttr(ts) + '">' + fmtDate(ts) + "</time>"
        : "لم تتواصل بعد";
    }

    const sessionsCell = tr.querySelector('[data-cell="metric-sessions"]');
    if (sessionsCell) {
      const cur = m.active_sessions != null ? m.active_sessions : 0;
      const cap = row.max_sessions || 1;
      const pct = cap ? Math.round((cur * 100) / cap) : 0;
      sessionsCell.innerHTML =
        '<span class="fd-num-emph num">' + cur + "</span>" +
        '<span style="color:#9ca3af"> / </span><span class="num">' + row.max_sessions + "</span>" +
        '<div class="fd-mini num">' + pct + "% من السعة</div>";
    }

    const rxCell = tr.querySelector('[data-cell="metric-rx"]');
    if (rxCell) rxCell.innerHTML = "↓ <span class=\"num\">" + fmtGB(m.rx_bytes) + "</span>";
    const txCell = tr.querySelector('[data-cell="metric-tx"]');
    if (txCell) txCell.innerHTML = "↑ <span class=\"num\">" + fmtGB(m.tx_bytes) + "</span>";
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/"/g, "&quot;");
  }

  // ────────────────────────────────────────────────────────────────────
  // Single-node check
  // ────────────────────────────────────────────────────────────────────
  function bindSingleCheckButtons() {
    document.querySelectorAll(".fd-check-one").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const nodeId = btn.dataset.nodeId;
        const nodeName = btn.dataset.nodeName || ("#" + nodeId);
        const ok = await confirmDialog("هل تريد طلب فحص فوري للعقدة «" + nodeName + "»؟");
        if (!ok) return;
        await runCheck([Number(nodeId)], btn);
      });
    });
  }

  async function runCheck(nodeIds, btn) {
    const tr = btn ? btn.closest("tr") : null;
    if (tr) tr.classList.add("is-checking");
    if (btn) {
      btn.classList.add("is-busy");
      btn.disabled = true;
    }
    try {
      const res = await fetch(checkOneUrl(nodeIds[0]), {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({}),
      });
      const body = await safeJson(res);
      if (!res.ok || !body.ok) {
        toast("error", "تعذّر إجراء الفحص: " + (body.error || ("HTTP " + res.status)));
        return;
      }
      applyRowPayload(body.row);
      recomputeKpis();
      const result = body.result || {};
      const stateLabel = (HEALTH_AR[result.state] || HEALTH_AR.unknown).label;
      const via = result.checked === "monitor" ? "عبر مراقب الصحّة" : "(تقدير محلّي مؤقت)";
      toast(
        result.state === "up" ? "success" : (result.state === "down" ? "error" : "info"),
        "اكتمل الفحص — الحالة الآن: " + stateLabel + " " + via
      );
    } catch (err) {
      toast("error", "خطأ شبكي — تعذّر الوصول لخادم اللوحة.");
    } finally {
      if (tr) tr.classList.remove("is-checking");
      if (btn) {
        btn.classList.remove("is-busy");
        btn.disabled = false;
      }
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // Check-all
  // ────────────────────────────────────────────────────────────────────
  const checkAllBtn = document.getElementById("fd-check-all-btn");
  if (checkAllBtn) {
    checkAllBtn.addEventListener("click", async () => {
      const msg = checkAllBtn.dataset.confirm || "هل تريد طلب فحص فوري لجميع عقد الأسطول؟";
      const ok = await confirmDialog(msg);
      if (!ok) return;
      setBusy(checkAllBtn, true);
      // Mark every row as busy.
      document.querySelectorAll("#fd-nodes-tbl tbody tr").forEach((tr) => tr.classList.add("is-checking"));
      try {
        const res = await fetch(CHECK_ALL_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
          body: JSON.stringify({}),
        });
        const body = await safeJson(res);
        if (!res.ok || !body.ok) {
          toast("error", "تعذّر إجراء الفحص الجماعي: " + (body.error || ("HTTP " + res.status)));
          return;
        }
        (body.rows || []).forEach(applyRowPayload);
        recomputeKpis();
        const counts = countByState(body.rows || []);
        toast(
          "success",
          "اكتمل الفحص الجماعي — " +
            "متّصلة: " + counts.up + " · " +
            "متدهورة: " + counts.degraded + " · " +
            "مفصولة: " + counts.down + " · " +
            "غير معروفة: " + counts.unknown,
          { ttl: 6000 }
        );
      } catch (err) {
        toast("error", "خطأ شبكي — تعذّر الوصول لخادم اللوحة.");
      } finally {
        setBusy(checkAllBtn, false);
        document.querySelectorAll("#fd-nodes-tbl tbody tr").forEach((tr) => tr.classList.remove("is-checking"));
      }
    });
  }

  function setBusy(btn, busy) {
    if (!btn) return;
    const icon = btn.querySelector(".fa-rotate-icon, .fa-bolt");
    const spin = btn.querySelector(".fa-spinner");
    if (icon) icon.style.display = busy ? "none" : "";
    if (spin) spin.style.display = busy ? "inline-block" : "none";
    btn.disabled = !!busy;
  }

  // ────────────────────────────────────────────────────────────────────
  // KPI strip — recompute from the visible badges so single-node refreshes
  // also keep the strip in sync.
  // ────────────────────────────────────────────────────────────────────
  function recomputeKpis() {
    const cells = document.querySelectorAll('#fd-nodes-tbl [data-cell="health-state"] .fd-badge:first-child');
    const c = { up: 0, degraded: 0, down: 0, unknown: 0 };
    cells.forEach((el) => {
      if (el.classList.contains("fd-badge--up")) c.up++;
      else if (el.classList.contains("fd-badge--deg")) c.degraded++;
      else if (el.classList.contains("fd-badge--down")) c.down++;
      else c.unknown++;
    });
    setText("kpi-health-up", c.up);
    setText("kpi-health-deg", c.degraded);
    setText("kpi-health-down", c.down);
    setText("kpi-health-unk", c.unknown);
  }
  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val);
  }

  function countByState(rows) {
    const c = { up: 0, degraded: 0, down: 0, unknown: 0 };
    rows.forEach((r) => {
      const s = (r.health && r.health.state) || "unknown";
      c[s] = (c[s] || 0) + 1;
    });
    return c;
  }

  async function safeJson(res) {
    try { return await res.json(); } catch (_) { return {}; }
  }

  // ────────────────────────────────────────────────────────────────────
  // Single-node live-metrics poll — bypasses the 60s background worker.
  // ────────────────────────────────────────────────────────────────────
  function bindPollMetricsButtons() {
    document.querySelectorAll(".fd-poll-metrics").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const url = btn.dataset.url;
        const nodeName = btn.dataset.nodeName || ("#" + btn.dataset.nodeId);
        if (!url) {
          toast("error", "تعذّر تحديد عنوان الطلب.");
          return;
        }
        const tr = btn.closest("tr");
        if (tr) tr.classList.add("is-checking");
        btn.classList.add("is-busy");
        btn.disabled = true;
        try {
          const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
            body: JSON.stringify({}),
          });
          const body = await safeJson(res);
          if (!res.ok || !body.ok) {
            const detail = body.detail || body.error || ("HTTP " + res.status);
            toast("error",
              "تعذّر قراءة المقاييس للعقدة «" + nodeName + "»: " + detail,
              { ttl: 6500 });
            return;
          }
          if (body.row) applyRowPayload(body.row);
          recomputeKpis();
          const summary = body.summary || {};
          if ((summary.error_count || 0) > 0) {
            const first = (summary.errors || [])[0] || ["", ""];
            toast("warning",
              "العقدة «" + nodeName + "» — تعذّرت القراءة: " + (first[1] || "خطأ غير معروف"));
          } else {
            toast("success",
              "تمت قراءة المقاييس من «" + nodeName + "» (مصدر: control).");
          }
        } catch (err) {
          toast("error", "خطأ شبكي — تعذّر الوصول لخادم اللوحة.");
        } finally {
          if (tr) tr.classList.remove("is-checking");
          btn.classList.remove("is-busy");
          btn.disabled = false;
        }
      });
    });
  }

  // ────────────────────────────────────────────────────────────────────
  // Boot
  // ────────────────────────────────────────────────────────────────────
  bindSingleCheckButtons();
  bindPollMetricsButtons();
})();
