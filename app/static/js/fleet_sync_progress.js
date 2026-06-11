/* fleet_sync_progress.js — live staged progress for zero-touch fleet sync.
 *
 * No background workers: create a job, then poll /tick on an interval. Each
 * tick runs ONE real backend stage and returns the full job state, which we
 * render. The bar only moves when real state changes.
 */
(function () {
  "use strict";

  var script = document.currentScript;
  var CREATE_URL = script.getAttribute("data-create-url");
  var JOB_URL_TMPL = script.getAttribute("data-job-url");   // .../jobs/0.json
  var TICK_URL_TMPL = script.getAttribute("data-tick-url"); // .../jobs/0/tick
  var LATEST_JOB = (script.getAttribute("data-latest-job") || "").trim();

  var TICK_INTERVAL = 650; // ms between ticks — lively but not chatty

  var els = {
    startFleet: document.getElementById("zt-start-fleet"),
    overall: document.getElementById("zt-overall"),
    status: document.getElementById("zt-status"),
    nDone: document.getElementById("zt-n-done"),
    nWarn: document.getElementById("zt-n-warn"),
    nFailed: document.getElementById("zt-n-failed"),
    pct: document.getElementById("zt-pct"),
    bar: document.getElementById("zt-bar"),
    barFill: document.getElementById("zt-bar-fill"),
    panelApply: document.getElementById("zt-panel-apply"),
    nodes: document.getElementById("zt-nodes"),
    empty: document.getElementById("zt-empty"),
    toastHost: document.getElementById("zt-toast-host"),
  };

  var activeJobId = null;
  var polling = false;

  function csrfToken() {
    var inp = document.querySelector("#zt-csrf input[name=csrf_token]");
    return inp ? inp.value : "";
  }

  function jobUrl(id) { return JOB_URL_TMPL.replace(/0\.json$/, id + ".json"); }
  function tickUrl(id) { return TICK_URL_TMPL.replace(/\/0\/tick$/, "/" + id + "/tick"); }

  function toast(kind, msg) {
    if (!els.toastHost) return;
    var node = document.createElement("div");
    node.className = "zt-toast zt-toast--" + (kind || "info");
    var icon = { success: "fa-circle-check", error: "fa-circle-xmark", info: "fa-circle-info" }[kind || "info"];
    node.innerHTML = '<i class="fa-solid ' + icon + '"></i><div>' + escapeHtml(msg) + "</div>";
    els.toastHost.appendChild(node);
    setTimeout(function () { if (node.parentNode) node.remove(); }, 5200);
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function postJson(url, body) {
    var res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
      body: JSON.stringify(body || {}),
    });
    var data = await res.json().catch(function () { return {}; });
    return { ok: res.ok, data: data };
  }

  async function getJson(url) {
    var res = await fetch(url, { headers: { "X-CSRFToken": csrfToken() } });
    var data = await res.json().catch(function () { return {}; });
    return { ok: res.ok, data: data };
  }

  // ── Stage icon presentation ────────────────────────────────────────────
  var STAGE_ICON = {
    pending: { cls: "ic-pending", fa: "fa-circle" },
    running: { cls: "ic-running", fa: "fa-spinner zt-spin" },
    done:    { cls: "ic-done",    fa: "fa-check" },
    warn:    { cls: "ic-warn",    fa: "fa-triangle-exclamation" },
    failed:  { cls: "ic-failed",  fa: "fa-xmark" },
    blocked: { cls: "ic-blocked", fa: "fa-ban" },
  };

  function nodePill(state) {
    var map = {
      running: ['running', 'fa-spinner zt-spin', 'جارٍ'],
      done:    ['done', 'fa-check', 'مكتملة'],
      warn:    ['warn', 'fa-triangle-exclamation', 'تنبيه'],
      failed:  ['failed', 'fa-xmark', 'توقّفت'],
      blocked: ['blocked', 'fa-ban', 'محجوبة'],
    };
    var m = map[state] || map.running;
    return '<span class="zt-pill ' + m[0] + '"><i class="fa-solid ' + m[1] + '"></i> ' + m[2] + '</span>';
  }

  function renderStage(stage, index, isRunning) {
    var state = isRunning && stage.state === "pending" ? "running" : stage.state;
    var ic = STAGE_ICON[state] || STAGE_ICON.pending;
    var sev = (state === "failed") ? "sev-failed" : (state === "warn" ? "sev-warn" : "");
    var html = '<div class="zt-stage ' + sev + (state === "running" ? " is-running" : "") + '">';
    html += '<div class="zt-stage-ic ' + ic.cls + '"><i class="fa-solid ' + ic.fa + '"></i></div>';
    html += '<div>';
    html += '<div class="zt-stage-label"><span class="zt-stage-num">' + (index + 1) + '.</span>' + escapeHtml(stage.label_ar) + '</div>';
    if (stage.reason) html += '<div class="zt-stage-reason">' + escapeHtml(stage.reason) + '</div>';
    if (stage.value) html += '<div class="zt-stage-value">' + escapeHtml(stage.value) + '</div>';
    html += '</div></div>';
    return html;
  }

  function renderNode(node) {
    var cls = "zt-node state-" + node.node_state;
    var html = '<article class="' + cls + '" data-node-id="' + node.node_id + '">';
    html += '<header class="zt-node-head">';
    html += '<div class="zt-node-name"><i class="fa-solid fa-server" style="color:#64748b"></i>' + escapeHtml(node.name) + '</div>';
    html += '<span class="zt-node-ip">' + escapeHtml(node.wg_mgmt_ip || "—") + '</span>';
    html += nodePill(node.node_state);
    if (node.needs_reimport) html += '<span class="zt-pill reimport"><i class="fa-solid fa-rotate-right"></i> يلزم إعادة استيراد</span>';
    html += '</header><div class="zt-stages">';
    for (var i = 0; i < node.stages.length; i++) {
      html += renderStage(node.stages[i], i, node.running_stage === i);
    }
    html += '</div></article>';
    return html;
  }

  function renderPanelApply(pa) {
    if (!pa || (pa.available === undefined)) { els.panelApply.hidden = true; return; }
    var cls, icon, msg;
    if (!pa.available) {
      cls = "warn"; icon = "fa-circle-info";
      msg = pa.message || "أداة المزامنة على مضيف اللوحة غير مثبّتة — يتم النشر والتحقّق فعلياً دون تطبيق محلي.";
    } else if (pa.applied) {
      cls = "ok"; icon = "fa-circle-check"; msg = pa.message || "تمت مزامنة نظراء wg-mgmt على مضيف اللوحة.";
    } else {
      cls = "bad"; icon = "fa-circle-xmark"; msg = pa.message || "تعذّر تطبيق نظراء اللوحة.";
    }
    els.panelApply.className = "zt-panel-apply " + cls;
    els.panelApply.innerHTML = '<i class="fa-solid ' + icon + '"></i> ' + escapeHtml(msg);
    els.panelApply.hidden = false;
  }

  function render(job) {
    if (!job) return;
    els.overall.hidden = false;
    els.empty.hidden = true;

    var p = job.progress || { percent: 0, counts: {} };
    var counts = p.counts || {};
    els.nDone.textContent = counts.done || 0;
    els.nWarn.textContent = counts.warn || 0;
    els.nFailed.textContent = (counts.failed || 0) + (counts.blocked || 0);
    els.pct.textContent = (p.percent || 0) + "%";
    els.barFill.style.width = (p.percent || 0) + "%";

    var anyFailed = (counts.failed || 0) > 0;
    els.barFill.classList.toggle("is-failed", anyFailed && job.status === "done");

    if (job.status === "done") {
      els.bar.classList.remove("is-active");
      if (anyFailed) {
        els.status.className = "zt-status-pill failed";
        els.status.innerHTML = '<i class="fa-solid fa-circle-xmark"></i> اكتمل مع إخفاقات';
      } else {
        els.status.className = "zt-status-pill done";
        els.status.innerHTML = '<i class="fa-solid fa-circle-check"></i> اكتملت المزامنة';
      }
    } else {
      els.bar.classList.add("is-active");
      els.status.className = "zt-status-pill running";
      els.status.innerHTML = '<i class="fa-solid fa-spinner zt-spin"></i> جارٍ…';
    }

    renderPanelApply(job.panel_apply);

    var html = "";
    for (var i = 0; i < job.nodes.length; i++) html += renderNode(job.nodes[i]);
    els.nodes.innerHTML = html || "";
    if (!job.nodes.length) {
      els.empty.hidden = false;
      els.empty.textContent = "لا توجد عقد CHR مُسجّلة بعد لمزامنتها.";
    }
  }

  async function pollLoop(jobId) {
    if (polling) return;
    polling = true;
    while (true) {
      var r = await postJson(tickUrl(jobId), {});
      if (!r.ok || !r.data.ok) {
        toast("error", (r.data && r.data.message) || "تعذّر متابعة المزامنة.");
        break;
      }
      render(r.data.job);
      if (r.data.job.status === "done") {
        var c = (r.data.job.progress.counts) || {};
        if ((c.failed || 0) > 0) toast("error", "اكتملت المزامنة مع " + ((c.failed || 0) + (c.blocked || 0)) + " مرحلة متوقّفة — راجع البطاقات.");
        else toast("success", "اكتملت إعادة مزامنة الأسطول بنجاح.");
        break;
      }
      await sleep(TICK_INTERVAL);
    }
    polling = false;
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  async function startFleet() {
    els.startFleet.disabled = true;
    try {
      var r = await postJson(CREATE_URL, { scope: "fleet" });
      if (!r.ok || !r.data.ok) { toast("error", (r.data && r.data.message) || "تعذّر بدء المزامنة."); return; }
      activeJobId = r.data.job.id;
      render(r.data.job);
      toast("info", "بدأت إعادة مزامنة الأسطول — جارٍ تنفيذ المراحل الحقيقية…");
      pollLoop(activeJobId);
    } finally {
      els.startFleet.disabled = false;
    }
  }

  async function resumeLatest(id) {
    var r = await getJson(jobUrl(id));
    if (!r.ok || !r.data.ok) return;
    activeJobId = id;
    render(r.data.job);
    if (r.data.job.status !== "done") pollLoop(id);
  }

  if (els.startFleet) els.startFleet.addEventListener("click", startFleet);

  // Auto-resume the most recent job (e.g. one started by a panel-key cascade).
  var urlJob = new URLSearchParams(window.location.search).get("job");
  if (urlJob && /^\d+$/.test(urlJob)) resumeLatest(urlJob);
  else if (LATEST_JOB && /^\d+$/.test(LATEST_JOB)) resumeLatest(LATEST_JOB);
})();
