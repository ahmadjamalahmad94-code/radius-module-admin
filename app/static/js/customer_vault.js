/* Customer Secure Vault — admin UI behavior.
   Tabs · inline form toggles · reveal modal (fetch plaintext on demand, copy,
   never persisted). Secrets are NEVER stored in localStorage/sessionStorage,
   never written into the page before reveal, and cleared on modal close. */
(function () {
  "use strict";
  var CSRF = window.VAULT_CSRF || "";

  // ── Tabs ──
  var tabs = document.querySelectorAll(".vault-tab");
  function showTab(name) {
    tabs.forEach(function (t) { t.classList.toggle("is-active", t.dataset.tab === name); });
    document.querySelectorAll(".vault-panel").forEach(function (p) {
      var on = p.id === "tab-" + name;
      p.classList.toggle("is-active", on);
      p.hidden = !on;
    });
  }
  tabs.forEach(function (t) { t.addEventListener("click", function () { showTab(t.dataset.tab); }); });
  if (location.hash) { var h = location.hash.slice(1); if (document.getElementById("tab-" + h)) showTab(h); }

  // ── Inline form toggles (edit/rotate/metadata) ──
  document.querySelectorAll("[data-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var el = document.getElementById(btn.dataset.toggle);
      if (el) el.hidden = !el.hidden;
    });
  });

  // ── Reveal modal ──
  var modal = document.getElementById("vaultRevealModal");
  if (!modal) return;
  var elLabel = document.getElementById("vaultRevealLabel");
  var elReason = document.getElementById("vaultRevealReason");
  var elValue = document.getElementById("vaultRevealValue");
  var step1 = document.getElementById("vaultRevealStep1");
  var step2 = document.getElementById("vaultRevealStep2");
  var elErr = document.getElementById("vaultRevealError");
  var confirmBtn = document.getElementById("vaultRevealConfirm");
  var copyBtn = document.getElementById("vaultCopyBtn");
  var currentUrl = null;

  function openModal(url, label) {
    currentUrl = url;
    elLabel.textContent = label || "";
    elReason.value = "";
    elValue.value = "";
    step1.hidden = false;
    step2.hidden = true;
    elErr.hidden = true;
    modal.hidden = false;
  }
  function closeModal() {
    // wipe any revealed value from the DOM
    elValue.value = "";
    currentUrl = null;
    modal.hidden = true;
  }

  document.querySelectorAll("[data-reveal]").forEach(function (btn) {
    btn.addEventListener("click", function () { openModal(btn.dataset.url, btn.dataset.label); });
  });
  modal.querySelectorAll("[data-close-modal]").forEach(function (b) {
    b.addEventListener("click", closeModal);
  });
  modal.addEventListener("click", function (e) { if (e.target === modal) closeModal(); });

  confirmBtn.addEventListener("click", function () {
    if (!currentUrl) return;
    confirmBtn.disabled = true;
    var body = new URLSearchParams();
    body.append("_csrf_token", CSRF);
    body.append("reason", elReason.value || "");
    fetch(currentUrl, {
      method: "POST",
      headers: { "X-Requested-With": "XMLHttpRequest", "X-CSRFToken": CSRF,
                 "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      credentials: "same-origin",
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        confirmBtn.disabled = false;
        if (res.ok && res.j && res.j.ok) {
          elValue.value = res.j.secret || "";
          step1.hidden = true;
          step2.hidden = false;
        } else {
          elErr.textContent = (res.j && res.j.message) || "تعذّر عرض السر.";
          elErr.hidden = false;
        }
      }).catch(function () {
        confirmBtn.disabled = false;
        elErr.textContent = "خطأ في الاتصال.";
        elErr.hidden = false;
      });
  });

  copyBtn.addEventListener("click", function () {
    var v = elValue.value;
    if (!v) return;
    var done = function () {
      var t = copyBtn.innerHTML; copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> تم النسخ';
      setTimeout(function () { copyBtn.innerHTML = t; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(v).then(done).catch(function () { elValue.select(); document.execCommand("copy"); done(); });
    } else { elValue.select(); document.execCommand("copy"); done(); }
  });
})();
