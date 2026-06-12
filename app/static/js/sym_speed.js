/* سياسة «السرعة المتماثلة» — حقل واحد يُملِئ التنزيل والرفع بالقيمة نفسها.
 *
 * يُحمَّل على كل صفحة admin من base_new.html. يفعّل الحقول الموسومة:
 *
 *   <form data-sym-form>
 *     <input name="speed_mbps" data-sym-input> ← القيمة المتماثلة
 *     <div data-sym-advanced hidden>
 *       <input name="download_mbps" data-sym-down>
 *       <input name="upload_mbps"   data-sym-up>
 *     </div>
 *     <a data-sym-advanced-toggle>سرعة غير متماثلة</a>
 *   </form>
 *
 * بدون النموذج لا يفعل شيئًا (لا يُسبّب أعطالاً على صفحات لا تستعمله).
 * يدعم CSP: script-src 'self'.
 */
(function () {
  "use strict";

  function applyToForm(form) {
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
      if (symInput.required && (symInput.value || "").trim()) mirror();
    });
  }

  function boot() {
    document.querySelectorAll("[data-sym-form]").forEach(applyToForm);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
