// Standalone customer-users page: toast-based confirm (replaces native confirm()),
// outside-click dismiss for popovers (password reset).
(function () {
  "use strict";

  var toast = document.getElementById("cu-confirm-toast");
  var toastMsg = document.getElementById("cu-confirm-toast-msg");
  var btnOk = document.getElementById("cu-confirm-toast-ok");
  var btnCancel = document.getElementById("cu-confirm-toast-cancel");
  var pendingForm = null;

  function hideToast() {
    if (!toast) return;
    toast.style.display = "none";
    pendingForm = null;
  }

  function showToast(message, form) {
    if (!toast || !toastMsg) return;
    toastMsg.textContent = message || "هل تريد المتابعة؟";
    pendingForm = form;
    toast.style.display = "block";
  }

  if (btnOk) {
    btnOk.addEventListener("click", function () {
      var f = pendingForm;
      hideToast();
      if (f && typeof f.submit === "function") f.submit();
    });
  }
  if (btnCancel) {
    btnCancel.addEventListener("click", hideToast);
  }
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") hideToast();
  });

  // Intercept any submit that carries data-cu-confirm.
  document.addEventListener(
    "submit",
    function (e) {
      var form = e.target;
      if (!form || !form.querySelector) return;
      var trigger = form.querySelector("[data-cu-confirm]");
      if (!trigger) return;
      if (form.__cuConfirmed) return;
      e.preventDefault();
      showToast(trigger.getAttribute("data-cu-confirm"), form);
      form.__cuConfirmed = true;
      // Reset after a short delay so a cancelled action can be retried.
      setTimeout(function () { form.__cuConfirmed = false; }, 600);
    },
    true
  );

  // Close any open <details class="cu-popover"> when clicking outside it.
  document.addEventListener("click", function (e) {
    var pops = document.querySelectorAll("details.cu-popover[open]");
    for (var i = 0; i < pops.length; i++) {
      if (!pops[i].contains(e.target)) pops[i].removeAttribute("open");
    }
  });
})();
