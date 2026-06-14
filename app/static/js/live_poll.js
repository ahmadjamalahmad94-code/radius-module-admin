// feat/panel-live-data-5s — shared live-data poller for admin pages.
//
// Auto-discovers any element carrying `data-live-endpoint="<url>"` and polls
// it every 5 seconds (or `data-live-interval` seconds), updating child
// elements bound by `data-live-bind="<path>"`, `data-live-pct="<path>"`,
// `data-live-class-map`, or `data-live-toggle`. Pauses while the tab is
// hidden, backs off on error, and renders a small «مباشر • آخر تحديث: …»
// indicator on each polled region. SSR-first: the page always works
// without JS — the poller only keeps already-rendered values fresh.
//
// Owner rules respected:
//   * No alert/confirm. No external deps.
//   * RTL-friendly Arabic copy.
//   * Pauses on visibilitychange (no waste when tab is in the background).
//   * Backoff on error (5s → 10s → 20s → 40s, cap 60s) so a flaky panel
//     doesn't hammer the server.
//   * Smooth: count-up animates numeric changes over ~350ms; non-numeric
//     writes only when the value actually changed (no DOM thrash).
//
// Public attribute contract (used by templates):
//
//   <div data-live-endpoint="/admin/fleet/live.json"
//        data-live-interval="5"
//        data-live-indicator>
//     <span data-live-bind="overview.sessions">0</span>
//     <span data-live-bind="overview.online_pct" data-live-suffix="%">0</span>
//     <div  data-live-pct="overview.util_pct"></div>
//     <span data-live-class="status.state"
//           data-live-class-map='{"up":"fd-badge--up","down":"fd-badge--down"}'>
//       ...
//     </span>
//     <div  data-live-replace="rows.outerHTML"></div>  <!-- whole subtree -->
//     <small data-live-indicator-text>—</small>
//   </div>
(function () {
  "use strict";

  const DEFAULT_INTERVAL_MS = 5000;
  const ERROR_BACKOFFS_MS = [5000, 10000, 20000, 40000, 60000];
  const ANIM_MS = 350;

  // ──────────────────────────────────────────────────────────────────
  // Helpers
  // ──────────────────────────────────────────────────────────────────

  function get(obj, path) {
    if (obj == null) return undefined;
    const parts = String(path || "").split(".");
    let cur = obj;
    for (let i = 0; i < parts.length; i++) {
      if (cur == null) return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  function tryParseJson(s, fallback) {
    if (s == null || s === "") return fallback;
    try { return JSON.parse(s); } catch (_) { return fallback; }
  }

  function isNumericLike(v) {
    return typeof v === "number" && Number.isFinite(v);
  }

  // fix/pause-livepoll-while-modal-open — external pause signal.
  //
  // Heavy modals (script-view) freeze the renderer if the poll keeps
  // running underneath them: every tick re-renders data-live-rows + an
  // rAF count-up storm fires across dozens of nodes, while the modal's
  // ~900-line <pre> already saturates layout. Chrome's renderer becomes
  // unresponsive on the live panel until the modal closes -- so the
  // operator can't click نسخ/تنزيل.
  //
  // The signal is GENERIC -- any page-level UI (script modal, the data-
  // chr connection modal, a future heavy preview) can set it without
  // knowing live-poll internals:
  //
  //   * window.__hobePausePoll = true   (programmatic)
  //   * document.body.dataset.pollPaused = "1"   (declarative)
  //
  // Either signal pauses every poller's tick + skips the rAF count-up.
  // Clearing both signals resumes; on resume each poller fetches once
  // immediately so the user sees fresh data when the modal closes.
  function isExternalPaused() {
    if (typeof window !== "undefined" && window.__hobePausePoll === true) return true;
    const body = (typeof document !== "undefined") ? document.body : null;
    if (body && body.dataset && body.dataset.pollPaused === "1") return true;
    // fix/direct-script-download-and-freeze — belt-and-braces DOM
    // check. The previous fix relied on the modal calling pausePoll()
    // before display:flex, but live debugging showed
    // window.__hobePausePoll stayed falsy on the owner's panel even
    // with the modal open (a second handler / a future modal could
    // bypass the flag plumbing). Reading the modal's computed display
    // directly catches every open path -- if any known heavy modal
    // is visible, we pause unconditionally.
    if (typeof document !== "undefined" && document.getElementById) {
      const sel = ["#fd-script-modal", "#fd-pj-confirm", "#fd-orphan-modal"];
      for (let i = 0; i < sel.length; i++) {
        const el = document.getElementById(sel[i].slice(1));
        if (!el) continue;
        // Inline style is the cheap path (the modal toggles
        // style.display = "flex" / "none"). getComputedStyle is the
        // slow path; only fall back to it when inline isn't set.
        const inline = el.style && el.style.display;
        if (inline && inline !== "none") return true;
        if (!inline && typeof window !== "undefined" && window.getComputedStyle) {
          try {
            if (window.getComputedStyle(el).display !== "none") return true;
          } catch (_e) { /* hostile env -- fall through */ }
        }
      }
    }
    return false;
  }

  // Smooth count-up for numbers. Skips animation for tiny deltas, first
  // paint, OR when the external pause signal is on (no rAF storm under
  // a heavy modal). When paused we still write the final value so the
  // text doesn't go stale on resume.
  function animateNumber(el, from, to, suffix) {
    suffix = suffix || "";
    if (!Number.isFinite(from) || Math.abs(to - from) <= 1 || ANIM_MS <= 0
        || isExternalPaused()) {
      el.textContent = formatNumber(to) + suffix;
      return;
    }
    const start = performance.now();
    function tick(now) {
      // If something opened a heavy modal mid-animation, abort the rAF
      // chain and write the final value -- avoids running 30 concurrent
      // rAF loops behind a frozen modal.
      if (isExternalPaused()) {
        el.textContent = formatNumber(to) + suffix;
        return;
      }
      const t = Math.min(1, (now - start) / ANIM_MS);
      // easeOutCubic
      const e = 1 - Math.pow(1 - t, 3);
      const v = from + (to - from) * e;
      el.textContent = formatNumber(Math.round(v)) + suffix;
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function formatNumber(n) {
    if (typeof n !== "number") return String(n);
    if (!Number.isFinite(n)) return "—";
    // No locale (page is RTL but numerals are kept Western for tabular-nums).
    return String(n);
  }

  // ──────────────────────────────────────────────────────────────────
  // Per-region poller
  // ──────────────────────────────────────────────────────────────────

  class LivePoller {
    constructor(root) {
      this.root = root;
      this.url = root.getAttribute("data-live-endpoint");
      this.interval = Math.max(
        1000,
        (Number(root.getAttribute("data-live-interval")) || 5) * 1000
      ) || DEFAULT_INTERVAL_MS;
      this.errorStreak = 0;
      this.timer = null;
      this.lastTickAt = null;
      this.lastOk = null;
      this.paused = false;
      this.inFlight = false;
      this.indicatorText = root.querySelector("[data-live-indicator-text]");
      this.indicatorDot  = root.querySelector("[data-live-indicator-dot]");
      // For each bound element, remember the last numeric value so count-up
      // animates from the previous number.
      this._lastNumeric = new WeakMap();
    }

    start() {
      if (!this.url) return;
      // Kick off immediately so the user sees fresh data on the first
      // load even if the SSR snapshot is a few seconds old.
      this.tick();
      this.schedule(this.interval);
      document.addEventListener("visibilitychange", () => this.onVisibility());
      // fix/pause-livepoll-while-modal-open — listen for the generic
      // pause/resume events any page-level UI can fire. Same semantic
      // as the visibilitychange handler.
      document.addEventListener("hobe:poll-pause",  () => this.onExtPauseChange());
      document.addEventListener("hobe:poll-resume", () => this.onExtPauseChange());
    }

    onVisibility() {
      if (document.hidden) {
        this.paused = true;
        this.clear();
        this.renderIndicator();
      } else if (this.paused && !isExternalPaused()) {
        this.paused = false;
        // Refetch immediately so the user sees fresh data on tab focus.
        this.tick();
        this.schedule(this.interval);
      }
    }

    // External-pause coalescer. When the signal flips ON we clear the
    // timer + flag paused; when it flips OFF we resume + fetch once
    // immediately so the user sees fresh data on modal-close.
    onExtPauseChange() {
      if (isExternalPaused()) {
        this.paused = true;
        this.clear();
        this.renderIndicator();
      } else if (this.paused && !document.hidden) {
        this.paused = false;
        this.tick();
        this.schedule(this.interval);
      }
    }

    schedule(ms) {
      this.clear();
      if (this.paused) return;
      // fix/direct-script-download-and-freeze — if the external pause
      // signal flipped on between the previous tick finishing and this
      // schedule call, do NOT arm a new timer. The next resume event
      // will re-arm.
      if (isExternalPaused()) {
        this.paused = true;
        this.renderIndicator();
        return;
      }
      this.timer = setTimeout(() => this.tick(), ms);
    }

    clear() {
      if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    }

    async tick() {
      // fix/pause-livepoll-while-modal-open — also short-circuit on the
      // external pause signal so an open modal halts the render storm.
      // We DO NOT re-schedule here; onExtPauseChange will re-arm when
      // the signal clears.
      if (this.inFlight || document.hidden || isExternalPaused()) {
        if (isExternalPaused()) {
          this.paused = true;
          this.clear();
          this.renderIndicator();
        }
        return;
      }
      this.inFlight = true;
      try {
        const res = await fetch(this.url, {
          credentials: "same-origin",
          headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
        });
        if (!res.ok) throw new Error("HTTP " + res.status);
        const data = await res.json();
        if (data && data.ok === false) throw new Error(data.error || "not_ok");
        this.errorStreak = 0;
        this.lastOk = new Date();
        this.applyData(data);
        this.renderIndicator();
        this.schedule(this.interval);
      } catch (err) {
        this.errorStreak++;
        this.renderIndicator(err);
        const backoff = ERROR_BACKOFFS_MS[
          Math.min(this.errorStreak - 1, ERROR_BACKOFFS_MS.length - 1)
        ];
        this.schedule(backoff);
      } finally {
        this.inFlight = false;
        this.lastTickAt = new Date();
      }
    }

    applyData(payload) {
      // Helper: should this element be skipped by the GLOBAL pass because
      // it lives inside a `data-live-rows` container that will handle it
      // with a per-row record? Without this skip we'd double-bind: once
      // against the global payload (wrong key) and once against the row.
      const inRows = (el) => !!el.closest("[data-live-rows]");

      // 1) data-live-bind="path"  — write payload[path] into textContent.
      //    Supports `data-live-suffix=" %"` and `data-live-empty="—"`.
      this.root.querySelectorAll("[data-live-bind]").forEach((el) => {
        if (inRows(el)) return;
        const path = el.getAttribute("data-live-bind");
        const suffix = el.getAttribute("data-live-suffix") || "";
        const empty = el.getAttribute("data-live-empty") || "—";
        const v = get(payload, path);
        if (v == null || v === "") {
          if (el.textContent !== empty) el.textContent = empty;
          return;
        }
        if (isNumericLike(v)) {
          const prev = this._lastNumeric.get(el);
          this._lastNumeric.set(el, v);
          animateNumber(el, prev != null ? prev : v, v, suffix);
        } else {
          const next = String(v) + suffix;
          if (el.textContent !== next) el.textContent = next;
        }
      });

      // 2) data-live-pct="path" — write `width: <v>%` on the element. Numeric.
      this.root.querySelectorAll("[data-live-pct]").forEach((el) => {
        if (inRows(el)) return;
        const path = el.getAttribute("data-live-pct");
        const v = get(payload, path);
        const n = Number.isFinite(+v) ? Math.max(0, Math.min(100, +v)) : 0;
        // Avoid retriggering CSS transitions when the value didn't change.
        const cur = el.style.width;
        const next = n + "%";
        if (cur !== next) el.style.width = next;
      });

      // 3) data-live-class="path" + data-live-class-map='{"<value>":"<class>"}'
      //    Removes all values of the map then adds the matching one.
      this.root.querySelectorAll("[data-live-class]").forEach((el) => {
        if (inRows(el)) return;
        const path = el.getAttribute("data-live-class");
        const map = tryParseJson(el.getAttribute("data-live-class-map"), {});
        const v = get(payload, path);
        Object.values(map).forEach((cls) => { if (cls) el.classList.remove(cls); });
        const want = map[String(v)];
        if (want) el.classList.add(want);
      });

      // 4) data-live-toggle="path" — value truthy → element visible.
      this.root.querySelectorAll("[data-live-toggle]").forEach((el) => {
        if (inRows(el)) return;
        const path = el.getAttribute("data-live-toggle");
        const v = get(payload, path);
        el.style.display = v ? "" : "none";
      });

      // 5) data-live-html="path" — replace innerHTML of the element. Endpoints
      //    MUST return server-rendered, trusted HTML in this field (used for
      //    repeating rows / cards). Skipped if the payload key is missing
      //    so a partial response doesn't blank the panel.
      this.root.querySelectorAll("[data-live-html]").forEach((el) => {
        const path = el.getAttribute("data-live-html");
        const v = get(payload, path);
        if (typeof v === "string") {
          // Only swap when changed — avoids reflow + breaking focus/hover.
          if (el.innerHTML !== v) el.innerHTML = v;
        }
      });

      // 6) data-live-rows="<path-to-array>" + data-live-row-key="<key>"
      //    A repeating-rows pattern: the container looks up
      //    payload[path-to-array] (a list of records), keys it by
      //    record[row-key], and for each descendant carrying
      //    `data-live-row-id="<value>"` resolves its inner data-live-*
      //    against that specific record. Used by the fleet dashboard so
      //    the per-node tiles (CPU / sessions / RTT / RX-TX / last seen
      //    / health state) refresh smoothly per row, with no DOM swap.
      this.root.querySelectorAll("[data-live-rows]").forEach((container) => {
        const path = container.getAttribute("data-live-rows");
        const key  = container.getAttribute("data-live-row-key") || "id";
        const list = get(payload, path);
        if (!Array.isArray(list)) return;
        const byKey = {};
        for (const rec of list) {
          if (rec == null) continue;
          const k = rec[key];
          if (k == null) continue;
          byKey[String(k)] = rec;
        }
        container.querySelectorAll("[data-live-row-id]").forEach((row) => {
          const rid = row.getAttribute("data-live-row-id");
          const rec = byKey[String(rid)];
          if (!rec) return;
          this._applyRowBindings(row, rec);
        });
      });

      // 7) Generic fire-and-forget event so per-page JS can react if needed.
      this.root.dispatchEvent(new CustomEvent("live:update", {
        bubbles: true, detail: { payload },
      }));
    }

    // Apply data-live-bind / data-live-pct / data-live-class /
    // data-live-toggle / data-live-html bindings scoped under a single
    // row, against a single record. The row is the local payload — paths
    // are resolved against the record, not the global payload.
    _applyRowBindings(row, rec) {
      row.querySelectorAll("[data-live-bind]").forEach((el) => {
        const path = el.getAttribute("data-live-bind");
        const suffix = el.getAttribute("data-live-suffix") || "";
        const empty = el.getAttribute("data-live-empty") || "—";
        const v = get(rec, path);
        if (v == null || v === "") {
          if (el.textContent !== empty) el.textContent = empty;
          return;
        }
        if (isNumericLike(v)) {
          const prev = this._lastNumeric.get(el);
          this._lastNumeric.set(el, v);
          animateNumber(el, prev != null ? prev : v, v, suffix);
        } else {
          const next = String(v) + suffix;
          if (el.textContent !== next) el.textContent = next;
        }
      });
      row.querySelectorAll("[data-live-pct]").forEach((el) => {
        const v = get(rec, el.getAttribute("data-live-pct"));
        const n = Number.isFinite(+v) ? Math.max(0, Math.min(100, +v)) : 0;
        const next = n + "%";
        if (el.style.width !== next) el.style.width = next;
      });
      row.querySelectorAll("[data-live-class]").forEach((el) => {
        const map = tryParseJson(el.getAttribute("data-live-class-map"), {});
        const v = get(rec, el.getAttribute("data-live-class"));
        Object.values(map).forEach((cls) => { if (cls) el.classList.remove(cls); });
        const want = map[String(v)];
        if (want) el.classList.add(want);
      });
      row.querySelectorAll("[data-live-toggle]").forEach((el) => {
        const v = get(rec, el.getAttribute("data-live-toggle"));
        el.style.display = v ? "" : "none";
      });
    }

    renderIndicator(err) {
      if (!this.indicatorText && !this.indicatorDot) return;
      if (this.indicatorDot) {
        this.indicatorDot.classList.remove("live-dot--ok", "live-dot--err", "live-dot--paused");
        if (this.paused)      this.indicatorDot.classList.add("live-dot--paused");
        else if (err)         this.indicatorDot.classList.add("live-dot--err");
        else                  this.indicatorDot.classList.add("live-dot--ok");
      }
      if (this.indicatorText) {
        if (this.paused) {
          // The pause may be from the tab going hidden OR from an
          // open modal (script-view, etc). Distinguish for clarity.
          this.indicatorText.textContent = isExternalPaused()
            ? "إيقاف مؤقت — نافذة مفتوحة"
            : "إيقاف مؤقت — التبويب في الخلفية";
        } else if (err) {
          this.indicatorText.textContent =
            "تعذّر التحديث — إعادة المحاولة بعد قليل";
        } else if (this.lastOk) {
          const ago = Math.max(0, Math.round((Date.now() - this.lastOk.getTime()) / 1000));
          this.indicatorText.textContent =
            "آخر تحديث: " + (ago < 2 ? "الآن" : "قبل " + ago + " ثانية");
        }
      }
    }
  }

  // ──────────────────────────────────────────────────────────────────
  // Auto-discovery + tiny global heartbeat that nudges all indicators
  // every second so the «آخر تحديث: قبل N ثانية» counter ticks visibly.
  // ──────────────────────────────────────────────────────────────────

  const _pollers = [];

  function boot() {
    document.querySelectorAll("[data-live-endpoint]").forEach((root) => {
      const p = new LivePoller(root);
      p.start();
      _pollers.push(p);
    });
    if (_pollers.length > 0) {
      setInterval(() => {
        for (const p of _pollers) p.renderIndicator();
      }, 1000);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  // Expose a tiny API for tests + ad-hoc per-page JS.
  window.LivePoll = {
    instances: _pollers,
    get,
    _Poller: LivePoller,
  };
})();
