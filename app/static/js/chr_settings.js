/* إعدادات CHR — إظهار كلمة المرور المخزّنة مؤقتًا (للمسؤول العام فقط).
   ملف خارجي لأن CSP اللوحة هو `script-src 'self'` (الـJS المضمّن محظور).
   رابط المسار يأتي من data-* في عنصر [data-chr-js]؛ ورمز CSRF من الحقل المخفي. */
(function () {
  "use strict";
  var root = document.querySelector("[data-chr-js]");
  if (!root) return;
  var REVEAL_URL = root.getAttribute("data-reveal-url") || "";

  function csrf() {
    var n = document.querySelector('input[name="_csrf_token"]');
    return n ? n.value : "";
  }

  function post(url) {
    var body = new URLSearchParams();
    body.append("_csrf_token", csrf());
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
        try { j = JSON.parse(t); } catch (e) { /* صفحة خطأ غير JSON */ }
        return { ok: r.ok, status: r.status, j: j };
      });
    });
  }

  var btn = document.querySelector("[data-chr-reveal]");
  var out = document.querySelector("[data-chr-secret]");
  if (btn && out && REVEAL_URL) {
    btn.addEventListener("click", function () {
      btn.disabled = true;
      post(REVEAL_URL).then(function (res) {
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
  }
})();
