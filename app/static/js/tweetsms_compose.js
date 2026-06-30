/* TweetSMS compose — live, Unicode-aware character + segment counter.
   External file because the panel CSP is `script-src 'self'`. Each SMS segment
   costs money, so the counter guides at 60 chars and warns beyond it. Counts
   Unicode code points ([...text].length) to match the server's len(text). */
(function () {
  "use strict";
  var LIMIT = 60;

  function arabicSegments(n) {
    if (n === 1) return "جزء واحد";
    if (n === 2) return "جزآن";
    if (n >= 3 && n <= 10) return n + " أجزاء";
    return n + " جزءًا";
  }

  function update(input, counter) {
    var len = Array.from(input.value || "").length;   // code points
    var segments = len === 0 ? 1 : Math.max(1, Math.ceil(len / LIMIT));
    var over = len > LIMIT;
    counter.textContent = len + " / " + LIMIT + " محرف · " + arabicSegments(segments);
    counter.style.color = over ? "#b91c1c" : "";
    counter.style.fontWeight = over ? "700" : "";
  }

  function wire(input) {
    var form = input.closest("form") || document;
    var counter = form.querySelector("[data-sms-counter]");
    if (!counter) return;
    var run = function () { update(input, counter); };
    input.addEventListener("input", run);
    run();
  }

  // "select all" toggles only the enabled (has-phone) row checkboxes.
  function wireCheckAll() {
    var master = document.querySelector("[data-sms-check-all]");
    if (!master) return;
    master.addEventListener("change", function () {
      Array.prototype.forEach.call(document.querySelectorAll("[data-sms-row]"), function (cb) {
        if (!cb.disabled) cb.checked = master.checked;
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    Array.prototype.forEach.call(document.querySelectorAll("[data-sms-input]"), wire);
    wireCheckAll();
  });
})();
