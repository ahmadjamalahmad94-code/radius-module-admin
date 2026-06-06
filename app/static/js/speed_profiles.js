/* بروفايلات السرعة — إظهار/إخفاء نموذج التعديل المضمّن.
   ملف خارجي لأن CSP اللوحة هو `script-src 'self'`. */
(function () {
  "use strict";
  if (!document.querySelector("[data-speed-profiles-js]")) return;
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-edit-profile]");
    if (!btn) return;
    var id = btn.getAttribute("data-edit-profile");
    var form = document.getElementById("edit-profile-" + id);
    if (form) form.hidden = !form.hidden;
  });
})();
