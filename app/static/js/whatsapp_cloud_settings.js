/* WhatsApp Cloud API settings — reveal stored secret + discover WABA templates.
   External file because the panel CSP is `script-src 'self'` (inline JS is
   blocked). Route URLs come from the [data-wac-js] element's data-* attributes;
   the CSRF token is read from the page's hidden _csrf_token field. */
(function () {
  "use strict";
  var root = document.querySelector("[data-wac-js]");
  if (!root) return;
  var REVEAL_URL = root.getAttribute("data-reveal-url") || "";
  var TEMPLATES_URL = root.getAttribute("data-templates-url") || "";

  function csrf() {
    var n = document.querySelector('input[name="_csrf_token"]');
    return n ? n.value : "";
  }

  // POST form-encoded with the CSRF token (header + body), then parse the
  // response as text→JSON so a non-JSON error (CSRF 400 / login redirect / 500)
  // surfaces the real HTTP status instead of being swallowed.
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

  // ── Reveal a stored secret (super-admin only) ──
  Array.prototype.forEach.call(document.querySelectorAll("[data-wac-reveal]"), function (btn) {
    btn.addEventListener("click", function () {
      var field = btn.getAttribute("data-wac-reveal");
      var out = document.querySelector('[data-wac-secret="' + field + '"]');
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

  // ── Discover the WABA's templates → clickable chips ──
  var discBtn = document.querySelector("[data-wac-templates]");
  var discOut = document.querySelector("[data-wac-templates-out]");
  var warnEl = document.querySelector("[data-wac-tpl-warn]");

  // Friendly warning when the selected template likely needs variables/media.
  function setWarn(t) {
    if (!warnEl) return;
    if (t && (t.needs_media || t.body_params)) {
      warnEl.textContent = "قد يحتاج هذا القالب إلى متغيرات أو وسائط. جرّب hello_world للاختبار السريع.";
      warnEl.hidden = false;
    } else {
      warnEl.textContent = "";
      warnEl.hidden = true;
    }
  }
  if (discBtn && discOut && TEMPLATES_URL) {
    discBtn.addEventListener("click", function () {
      discBtn.disabled = true;
      discOut.hidden = false;
      discOut.textContent = "";
      var note = document.createElement("span");
      note.className = "wac-tpl-note";
      note.textContent = "جارٍ جلب القوالب…";
      discOut.appendChild(note);

      post(TEMPLATES_URL, {}).then(function (res) {
        discBtn.disabled = false;
        discOut.textContent = "";
        var j = res.j;
        var msg = document.createElement("span");
        msg.className = "wac-tpl-note";

        if (!res.ok || !j || !j.ok) {
          msg.textContent = (j && j.message) ||
            ("تعذّر جلب القوالب (رمز " + res.status + "). تأكّد أن التوكن يملك صلاحية إدارة القوالب وأن Business Account ID صحيح.");
          discOut.appendChild(msg);
          return;
        }
        if (!j.templates || !j.templates.length) {
          msg.textContent = "لا توجد قوالب في هذا الحساب. أنشئ قالبًا في Meta أولًا.";
          discOut.appendChild(msg);
          return;
        }
        msg.textContent = "اختر قالبًا لتعبئة الحقول:";
        discOut.appendChild(msg);

        j.templates.forEach(function (t) {
          var approved = t.status === "APPROVED";
          var chip = document.createElement("button");
          chip.type = "button";
          chip.className = "wac-tpl-chip";

          var sName = document.createElement("span");
          sName.textContent = t.name;
          var sLang = document.createElement("span");
          sLang.className = "lng";
          sLang.textContent = t.language || "";
          var sSt = document.createElement("span");
          sSt.className = "st " + (approved ? "st--ok" : "st--no");
          sSt.textContent = approved ? "معتمد" : (t.status || "");
          chip.appendChild(sName);
          chip.appendChild(sLang);
          chip.appendChild(sSt);

          // Requirement hint: media header / N variables / ready.
          var req = document.createElement("span");
          req.className = "req";
          if (t.needs_media) { req.textContent = "يحتاج وسائط"; req.classList.add("req--warn"); }
          else if (t.body_params) { req.textContent = t.body_params + " متغيّر (تلقائي)"; }
          else { req.textContent = "جاهز"; req.classList.add("req--ok"); }
          chip.appendChild(req);
          if (t.needs_media) chip.classList.add("is-dim");

          // Recommended (preferred name or simple no-variable approved) badge.
          if (t.recommended || t.simple) {
            chip.classList.add("is-rec");
            var rec = document.createElement("span");
            rec.className = "rec";
            rec.textContent = "موصى به";
            chip.appendChild(rec);
          }

          chip.addEventListener("click", function () {
            var n = document.getElementById("wac-tpl-name");
            var l = document.getElementById("wac-tpl-lang");
            if (n) n.value = t.name;
            if (l && t.language) l.value = t.language;
            setWarn(t);
          });
          discOut.appendChild(chip);
        });
      }).catch(function () {
        discBtn.disabled = false;
        discOut.textContent = "";
        var err = document.createElement("span");
        err.className = "wac-tpl-note";
        err.textContent = "تعذّر الاتصال بالخادم.";
        discOut.appendChild(err);
      });
    });
  }
})();
