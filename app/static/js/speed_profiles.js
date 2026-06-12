/* بروفايلات السرعة — JS مساعد للوحة (CSP: script-src 'self').
 *
 * 1. إظهار/إخفاء نموذج التعديل المضمّن (data-edit-profile).
 * 2. سياسة «السرعة المتماثلة»: input واحد ⇒ تنزيل = رفع. زر «متقدّم» يكشف
 *    حقلين منفصلين للحالات النادرة. عند الإرسال نضمن أن download_mbps و
 *    upload_mbps يحملان قيمة معًا (السيرفر يقبل speed_mbps أيضًا، لكن نتعمَّد
 *    إرسال الاثنين كي لا يعتمد التحقق على ترتيب التطبيع).
 */
(function () {
  "use strict";
  if (!document.querySelector("[data-speed-profiles-js]")) return;

  // ── 1) toggle inline edit form ──────────────────────────────────────────
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-edit-profile]");
    if (!btn) return;
    var id = btn.getAttribute("data-edit-profile");
    var form = document.getElementById("edit-profile-" + id);
    if (form) form.hidden = !form.hidden;
  });

  // ── 2) Symmetric speed UX ───────────────────────────────────────────────
  function applySymToForm(form) {
    var symInput = form.querySelector("[data-sym-input]");
    var downInput = form.querySelector("[data-sym-down]");
    var upInput = form.querySelector("[data-sym-up]");
    var advRows = form.querySelectorAll("[data-sym-advanced]");
    var advToggle = form.querySelector("[data-sym-advanced-toggle]");
    if (!symInput || !downInput || !upInput) return;

    function showAdvanced(show) {
      advRows.forEach(function (el) {
        if (show) el.removeAttribute("hidden");
        else el.setAttribute("hidden", "");
      });
      symInput.required = !show;
      downInput.required = show;
      upInput.required = show;
      if (advToggle) {
        advToggle.textContent = show
          ? "سرعة متماثلة (إخفاء المتقدّم)"
          : "سرعة غير متماثلة (متقدّم)";
      }
    }

    function mirror() {
      var v = (symInput.value || "").trim();
      if (!v) return;
      downInput.value = v;
      upInput.value = v;
    }

    symInput.addEventListener("input", mirror);
    if (advToggle) {
      advToggle.addEventListener("click", function (ev) {
        ev.preventDefault();
        var nowHidden = advRows[0] && advRows[0].hasAttribute("hidden");
        showAdvanced(nowHidden);
      });
    }
    form.addEventListener("submit", function () {
      // Before send: if user is in symmetric mode, mirror once more so an
      // initial-value entry that never fired `input` (autofill) is captured.
      if (symInput.required && (symInput.value || "").trim()) {
        mirror();
      }
    });
  }

  document.querySelectorAll("[data-sym-form]").forEach(applySymToForm);
})();
