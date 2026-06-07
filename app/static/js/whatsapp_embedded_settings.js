/* WhatsApp Embedded Signup settings — reveal the stored App Secret.
   External file because the panel CSP is `script-src 'self'` (inline JS is
   blocked). The reveal route URL comes from the [data-wae-js] element; the
   CSRF token is read from the page's hidden _csrf_token field. */
(function () {
  "use strict";
  var root = document.querySelector("[data-wae-js]");
  if (!root) return;
  var REVEAL_URL = root.getAttribute("data-reveal-url") || "";

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

  // ── Reveal the stored App Secret (super-admin only) ──
  Array.prototype.forEach.call(document.querySelectorAll("[data-wae-reveal]"), function (btn) {
    btn.addEventListener("click", function () {
      var field = btn.getAttribute("data-wae-reveal");
      var out = document.querySelector('[data-wae-secret="' + field + '"]');
      if (!out || !REVEAL_URL) return;
      btn.disabled = true;
      post(REVEAL_URL, { field: field }).then(function (res) {
        btn.disabled = false;
        var j = res.j;
        if (res.ok && j && j.ok) {
          out.textContent = j.value;
          out.hidden = false;
          setTimeout(function () { out.textContent = ""; out.hidden = true; }, 20000);
        } else {
          out.textContent = (j && j.message) || ("تعذّر الإظهار (رمز " + res.status + ").");
          out.hidden = false;
        }
      }).catch(function () {
        btn.disabled = false;
        out.textContent = "تعذّر الاتصال.";
        out.hidden = false;
      });
    });
  });
})();
