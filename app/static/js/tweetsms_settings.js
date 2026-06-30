/* TweetSMS settings — reveal a stored secret + check account balance.
   External file because the panel CSP is `script-src 'self'` (inline JS is
   blocked). Route URLs come from the [data-tweetsms-js] element's data-*
   attributes; the CSRF token is read from the page's hidden _csrf_token field. */
(function () {
  "use strict";
  var root = document.querySelector("[data-tweetsms-js]");
  if (!root) return;
  var REVEAL_URL = root.getAttribute("data-reveal-url") || "";
  var BALANCE_URL = root.getAttribute("data-balance-url") || "";

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

  // ── Check account balance ──
  var balBtn = document.getElementById("tss-balance-btn");
  var balOut = document.getElementById("tss-balance-out");
  if (balBtn && balOut && BALANCE_URL) {
    balBtn.addEventListener("click", function () {
      balBtn.disabled = true;
      balOut.textContent = "…";
      post(BALANCE_URL, {}).then(function (res) {
        balBtn.disabled = false;
        var j = res.j;
        if (res.ok && j && j.ok) {
          balOut.style.color = "#15803d";
          balOut.textContent = "الرصيد: " + j.balance;
        } else {
          balOut.style.color = "#b91c1c";
          balOut.textContent = (j && j.message) || ("تعذّر الجلب (رمز " + res.status + ").");
        }
      }).catch(function () {
        balBtn.disabled = false;
        balOut.style.color = "#b91c1c";
        balOut.textContent = "تعذّر الاتصال.";
      });
    });
  }
})();
