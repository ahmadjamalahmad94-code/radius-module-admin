/* TweetSMS settings — reveal a stored secret + a LIVE auto-refreshing balance.
   External file because the panel CSP is `script-src 'self'` (inline JS is
   blocked). Route URLs come from the [data-tweetsms-js] element's data-*
   attributes; the CSRF token is read from the page's hidden _csrf_token field. */
(function () {
  "use strict";
  var root = document.querySelector("[data-tweetsms-js]");
  if (!root) return;
  var REVEAL_URL = root.getAttribute("data-reveal-url") || "";
  var BALANCE_URL = root.getAttribute("data-balance-url") || "";
  var POLL_MS = parseInt(root.getAttribute("data-balance-poll-ms"), 10) || 60000;
  var CONFIGURED = root.getAttribute("data-balance-configured") === "1";

  function csrf() {
    var n = document.querySelector('input[name="_csrf_token"]');
    return n ? n.value : "";
  }

  function post(url, params) {
    var body = new URLSearchParams();
    body.append("_csrf_token", csrf());
    Object.keys(params || {}).forEach(function (k) { body.append(k, params[k]); });
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "X-CSRFToken": csrf(),
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = null;
        try { j = JSON.parse(t); } catch (e) { /* non-JSON error page */ }
        return { ok: r.ok, status: r.status, j: j };
      });
    });
  }

  // ── Reveal a stored secret into its input (super-admin only) ──
  Array.prototype.forEach.call(root.querySelectorAll("[data-tss-reveal]"), function (btn) {
    btn.addEventListener("click", function () {
      var field = btn.getAttribute("data-tss-reveal");
      var input = document.getElementById("tss-" + field);
      if (!input || !REVEAL_URL) return;
      btn.disabled = true;
      post(REVEAL_URL, { field: field }).then(function (res) {
        btn.disabled = false;
        var j = res.j;
        if (res.ok && j && j.ok) {
          input.type = "text";
          input.value = j.value;
          setTimeout(function () { input.value = ""; input.type = "password"; }, 20000);
        } else {
          input.placeholder = (j && j.message) || ("تعذّر الإظهار (رمز " + res.status + ").");
        }
      }).catch(function () {
        btn.disabled = false;
        input.placeholder = "تعذّر الاتصال.";
      });
    });
  });

  // ── Live account balance — auto-refresh on load + every POLL_MS, paused while
  //    the tab is hidden, with exponential back-off on repeated failures and a
  //    manual refresh affordance. Reuses the existing /balance JSON endpoint. ──
  var balBtn = document.getElementById("tss-balance-btn");
  var balOut = document.getElementById("tss-balance-out");
  var balMeta = document.getElementById("tss-balance-meta");
  var balIcon = document.getElementById("tss-balance-icon");

  if (balBtn && balOut && balMeta && BALANCE_URL) {
    var MAX_BACKOFF_MS = 15 * 60 * 1000; // cap repeated-failure back-off at 15 min
    var lastOkAt = 0;        // epoch ms of the last successful fetch (0 = never)
    var fails = 0;           // consecutive failures (drives back-off)
    var inFlight = false;    // a request is currently outstanding
    var timer = null;        // pending poll timeout id
    var hardError = false;   // last result was an error (suppress "آخر تحديث")

    function meta(text, color) {
      balMeta.textContent = text;
      balMeta.style.color = color || "#64748b";
    }

    function fmtAgo(ms) {
      var s = Math.round(ms / 1000);
      if (s < 10) return "الآن";
      if (s < 60) return "منذ ثوانٍ";
      var m = Math.round(s / 60);
      if (m < 60) return "منذ " + m + " دقيقة";
      var h = Math.round(m / 60);
      return "منذ " + h + " ساعة";
    }

    function showAgo() {
      if (hardError || !lastOkAt) return;
      meta("آخر تحديث: " + fmtAgo(Date.now() - lastOkAt));
    }

    function spinning(on) {
      balBtn.disabled = on;
      if (balIcon) { if (on) balIcon.classList.add("fa-spin"); else balIcon.classList.remove("fa-spin"); }
    }

    function schedule(delay) {
      if (timer) clearTimeout(timer);
      timer = setTimeout(tick, delay);
    }

    function tick() {
      // Don't hit the external API while the tab is backgrounded; re-arm cheaply.
      if (document.hidden) { schedule(POLL_MS); return; }
      refresh(false);
    }

    function refresh(manual) {
      if (inFlight || !CONFIGURED) return;
      inFlight = true;
      spinning(true);
      hardError = false;
      meta("جارٍ التحديث…");
      post(BALANCE_URL, {}).then(function (res) {
        inFlight = false;
        spinning(false);
        var j = res.j;
        if (res.ok && j && j.ok) {
          fails = 0;
          hardError = false;
          lastOkAt = Date.now();
          balOut.style.color = "#15803d";
          balOut.textContent = j.balance;
          showAgo();
          schedule(POLL_MS);
        } else {
          fails += 1;
          hardError = true;
          balOut.style.color = "#b91c1c";
          if (!lastOkAt) balOut.textContent = "—";
          meta((j && j.message) || ("تعذّر جلب الرصيد — تحقق من بيانات TweetSMS (رمز " + res.status + ")."), "#b91c1c");
          schedule(backoff());
        }
      }).catch(function () {
        inFlight = false;
        spinning(false);
        fails += 1;
        hardError = true;
        balOut.style.color = "#b91c1c";
        if (!lastOkAt) balOut.textContent = "—";
        meta("تعذّر جلب الرصيد — تحقق من اتصال الشبكة.", "#b91c1c");
        schedule(backoff());
      });
    }

    // Exponential back-off after consecutive failures so we don't hammer the
    // external TweetSMS API (or our own server) when creds/network are bad.
    function backoff() {
      var factor = Math.pow(2, Math.min(fails, 4)); // 2,4,8,16,16…
      return Math.min(POLL_MS * factor, MAX_BACKOFF_MS);
    }

    balBtn.addEventListener("click", function () { refresh(true); });

    // Keep the "منذ ..." line fresh even between polls.
    setInterval(showAgo, 15000);

    // When the tab becomes visible again, refresh promptly if the data is stale.
    document.addEventListener("visibilitychange", function () {
      if (document.hidden || !CONFIGURED) return;
      if (hardError || !lastOkAt || (Date.now() - lastOkAt) >= POLL_MS) refresh(false);
    });

    if (CONFIGURED) {
      refresh(false); // initial load — no clicking required
    } else {
      meta("أكمل إعداد TweetSMS لعرض الرصيد ومتابعته تلقائيًا.");
    }
  }
})();
