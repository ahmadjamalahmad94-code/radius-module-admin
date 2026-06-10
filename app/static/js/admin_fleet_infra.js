// Fleet-infrastructure settings page — styled confirm + form interception.
//
// Owner rules:
//   * NO native confirm/alert anywhere. Any form whose submit needs operator
//     confirmation carries `data-confirm="..."`; the fi-confirm modal
//     resolves a Promise<boolean> before allowing the submit through.
//   * CSP-safe external script; no inline handlers.
(function () {
  "use strict";

  const confirmEl    = document.getElementById("fi-confirm");
  const confirmMsg   = document.getElementById("fi-confirm-msg");
  const confirmOk    = document.getElementById("fi-confirm-ok");
  const confirmCanc  = document.getElementById("fi-confirm-cancel");

  function styledConfirm(message) {
    return new Promise(function (resolve) {
      if (!confirmEl) return resolve(true);
      confirmMsg.textContent = message || "هل أنت متأكد؟";
      confirmEl.style.display = "flex";
      function close(r) {
        confirmEl.style.display = "none";
        confirmOk.removeEventListener("click", onOk);
        confirmCanc.removeEventListener("click", onCancel);
        confirmEl.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
        resolve(r);
      }
      function onOk()      { close(true); }
      function onCancel()  { close(false); }
      function onBackdrop(e) { if (e.target === confirmEl) close(false); }
      function onKey(e)    { if (e.key === "Escape") close(false); }
      confirmOk.addEventListener("click", onOk);
      confirmCanc.addEventListener("click", onCancel);
      confirmEl.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);
    });
  }

  // Intercept any submitter (button or input) carrying data-confirm, OR any
  // form whose <form data-confirm> is set. The submitter (the button the
  // operator clicked) is preferred so each button in a form can carry its
  // own confirm text — e.g. «حفظ السر» vs «توليد سرّ قوي».
  document.addEventListener("submit", async function (e) {
    const form = e.target;
    if (!form) return;
    const submitter = e.submitter;
    const msg =
      (submitter && submitter.getAttribute && submitter.getAttribute("data-confirm")) ||
      form.getAttribute("data-confirm");
    if (!msg) return;
    if (form.__fiConfirmed) return;
    e.preventDefault();
    const ok = await styledConfirm(msg);
    if (!ok) return;
    form.__fiConfirmed = true;
    // Re-submit using the original submitter so name/value pairs (e.g.
    // `auto_generate=1`) reach the server.
    if (submitter && typeof form.requestSubmit === "function") {
      form.requestSubmit(submitter);
    } else {
      form.submit();
    }
  }, true);

  // The «توليد مفتاح اللوحة» button is a type=button (intentional — its parent
  // <form> exists only to carry CSRF and the POST action). Hook it manually
  // so clicking it pops the confirm before submitting.
  const genKeyBtn = document.getElementById("fi-gen-panel-key");
  if (genKeyBtn) {
    const form = genKeyBtn.closest("form");
    genKeyBtn.addEventListener("click", async function () {
      const msg = genKeyBtn.getAttribute("data-confirm")
        || "هل تريد توليد مفتاح جديد؟";
      const ok = await styledConfirm(msg);
      if (!ok) return;
      form.submit();
    });
  }
})();
