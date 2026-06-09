// fleet/ui — onboarding wizard frontend.
//
// Multi-step state machine: 1) provider + name, 2) capacity + network identity,
// 3) bandwidth model, 4) review + submit. POSTs the collected payload to the
// onboarding API URL the server stamped onto the form (data-onboarding-url),
// owned by the sibling agent's fleet.registry.routes_onboarding blueprint.
//
// Constraints from the owner:
//   * NO native alert()/confirm() — toasts + a styled confirm dialog only.
//   * No inline event handlers (CSP: script-src 'self').
//   * All step transitions are JS-driven; the form never submits via Enter.

(function () {
  "use strict";

  const form = document.getElementById("fw-form");
  if (!form) return;

  const onboardingUrl = form.dataset.onboardingUrl || "/admin/fleet/onboarding/jobs";
  const providersUrl = form.dataset.providersUrl || "/admin/fleet/providers";

  const panels = Array.from(form.querySelectorAll(".fw-panel"));
  const stepperItems = Array.from(document.querySelectorAll(".fw-step"));
  const TOTAL_STEPS = panels.length;
  let currentStep = 1;

  // ────────────────────────────────────────────────────────────────────
  // Toast host (info / success / warn / error)
  // ────────────────────────────────────────────────────────────────────
  const toastHost = document.getElementById("fw-toast-host");
  function toast(kind, message, opts) {
    if (!toastHost) return;
    opts = opts || {};
    const node = document.createElement("div");
    node.className = "fw-toast fw-toast--" + (kind || "info");
    const iconClass = {
      info: "fa-circle-info",
      success: "fa-circle-check",
      warn: "fa-triangle-exclamation",
      error: "fa-circle-xmark",
    }[kind || "info"];
    const icon = document.createElement("i");
    icon.className = "fa-solid " + iconClass + " fw-toast-icon";
    const msg = document.createElement("div");
    msg.className = "fw-toast-msg";
    msg.textContent = message || "";
    const closeBtn = document.createElement("button");
    closeBtn.className = "fw-toast-close";
    closeBtn.setAttribute("type", "button");
    closeBtn.setAttribute("aria-label", "إغلاق");
    closeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    closeBtn.addEventListener("click", () => node.remove());
    node.appendChild(icon);
    node.appendChild(msg);
    node.appendChild(closeBtn);
    toastHost.appendChild(node);
    const ttl = opts.ttl != null ? opts.ttl : 4200;
    if (ttl > 0) setTimeout(() => { if (node.parentNode) node.remove(); }, ttl);
  }

  // ────────────────────────────────────────────────────────────────────
  // Confirm dialog (Promise<boolean>); replaces native confirm()
  // ────────────────────────────────────────────────────────────────────
  const confirmEl = document.getElementById("fw-confirm");
  const confirmMsg = document.getElementById("fw-confirm-msg");
  const confirmOk = document.getElementById("fw-confirm-ok");
  const confirmCancel = document.getElementById("fw-confirm-cancel");
  function confirmDialog(message) {
    return new Promise((resolve) => {
      if (!confirmEl) return resolve(true);
      confirmMsg.textContent = message || "هل أنت متأكد؟";
      confirmEl.classList.add("is-open");
      function close(result) {
        confirmEl.classList.remove("is-open");
        confirmOk.removeEventListener("click", onOk);
        confirmCancel.removeEventListener("click", onCancel);
        confirmEl.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
        resolve(result);
      }
      function onOk() { close(true); }
      function onCancel() { close(false); }
      function onBackdrop(e) { if (e.target === confirmEl) close(false); }
      function onKey(e) { if (e.key === "Escape") close(false); }
      confirmOk.addEventListener("click", onOk);
      confirmCancel.addEventListener("click", onCancel);
      confirmEl.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);
    });
  }

  // ────────────────────────────────────────────────────────────────────
  // Step navigation
  // ────────────────────────────────────────────────────────────────────
  function showStep(n) {
    if (n < 1 || n > TOTAL_STEPS) return;
    panels.forEach((p) => p.classList.remove("is-active"));
    const target = form.querySelector('.fw-panel[data-step="' + n + '"]');
    if (target) target.classList.add("is-active");
    stepperItems.forEach((s) => {
      const idx = parseInt(s.dataset.stepTag, 10);
      s.classList.remove("is-current", "is-done");
      if (idx === n) s.classList.add("is-current");
      else if (idx < n) s.classList.add("is-done");
    });
    currentStep = n;
    if (n === TOTAL_STEPS) renderReview();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  form.querySelectorAll("[data-fw-next]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (!validateStep(currentStep)) {
        toast("error", "أكمل الحقول المطلوبة في هذه الخطوة قبل المتابعة.");
        return;
      }
      showStep(currentStep + 1);
    });
  });
  form.querySelectorAll("[data-fw-prev]").forEach((btn) => {
    btn.addEventListener("click", () => showStep(currentStep - 1));
  });

  // Block native form submission on Enter — wizard only submits via the button.
  form.addEventListener("submit", (e) => e.preventDefault());

  // ────────────────────────────────────────────────────────────────────
  // Per-step validation
  // ────────────────────────────────────────────────────────────────────
  function setError(fieldId, hasError) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    const field = input.closest(".fw-field");
    if (!field) return;
    field.classList.toggle("is-error", !!hasError);
  }

  function validateStep(step) {
    if (step === 1) {
      const providerEl = document.getElementById("provider_id");
      const provider = providerEl.value;
      const name = document.getElementById("name").value.trim();
      setError("provider_id", !provider);
      setError("name", !name);
      if (provider === "__new__") {
        toast("warn", "احفظ المزود الجديد أولاً قبل المتابعة.");
        return false;
      }
      return !!provider && !!name;
    }
    if (step === 2) {
      const ms = parseInt(document.getElementById("max_sessions").value, 10);
      const ls = parseInt(document.getElementById("link_speed_mbps").value, 10);
      const ip = document.getElementById("public_ip").value.trim();
      const ipOk = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
      setError("max_sessions", !ms || ms <= 0);
      setError("link_speed_mbps", !ls || ls <= 0);
      setError("public_ip", !ipOk);
      return ms > 0 && ls > 0 && ipOk;
    }
    if (step === 3) {
      const model = (form.querySelector('input[name="cost_model"]:checked') || {}).value;
      if (model === "metered") {
        const cap = parseFloat(document.getElementById("bandwidth_cap_tb").value);
        if (!cap || cap <= 0) {
          toast("error", "النموذج «محدودة» يتطلب سقفاً شهرياً موجباً (TB).");
          return false;
        }
      }
      return true;
    }
    return true;
  }

  // ────────────────────────────────────────────────────────────────────
  // Cost-model radio: highlight selected card, toggle metered fields
  // ────────────────────────────────────────────────────────────────────
  function syncCostModelUI() {
    const selected = (form.querySelector('input[name="cost_model"]:checked') || {}).value;
    form.querySelectorAll(".fw-radio-card").forEach((card) => {
      const inp = card.querySelector('input[name="cost_model"]');
      card.classList.toggle("is-selected", inp && inp.checked);
    });
    const meteredVisible = selected === "metered";
    form.querySelectorAll("[data-fw-metered]").forEach((el) => {
      el.style.opacity = meteredVisible ? "1" : ".55";
      el.style.pointerEvents = meteredVisible ? "auto" : "none";
    });
  }
  form.querySelectorAll('input[name="cost_model"]').forEach((r) => {
    r.addEventListener("change", syncCostModelUI);
  });
  syncCostModelUI();

  // ────────────────────────────────────────────────────────────────────
  // "Add new provider" panel — POSTs to providers API, then auto-selects.
  // ────────────────────────────────────────────────────────────────────
  const providerSelect = document.getElementById("provider_id");
  const newProviderPanel = document.getElementById("fw-new-provider");
  providerSelect.addEventListener("change", () => {
    const isNew = providerSelect.value === "__new__";
    newProviderPanel.style.display = isNew ? "block" : "none";
  });

  document.getElementById("fw-new-provider-save").addEventListener("click", async () => {
    const name = document.getElementById("np_name").value.trim();
    const costModel = document.getElementById("np_cost_model").value;
    const cap = document.getElementById("np_monthly_cap_tb").value;
    const price = document.getElementById("np_price_per_tb").value;
    const overage = document.getElementById("np_overage_allowed").checked;
    if (!name) { toast("error", "اسم المزود مطلوب."); return; }
    if (costModel === "metered" && (!cap || parseFloat(cap) <= 0)) {
      toast("error", "المزود «محدود» يتطلب سقفاً شهرياً موجباً (TB).");
      return;
    }
    try {
      const res = await fetch(providersUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify({
          name: name,
          cost_model: costModel,
          monthly_cap_tb: cap || null,
          price_per_tb: price || null,
          overage_allowed: overage,
        }),
      });
      const body = await safeJson(res);
      if (!res.ok || !body.ok) {
        toast("error", "تعذّر إنشاء المزود: " + (body.detail || body.error || res.status));
        return;
      }
      // Inject the new option, select it, hide the inline panel.
      const opt = document.createElement("option");
      opt.value = String(body.item.id);
      opt.textContent = body.item.name + " (جديد)";
      opt.dataset.costModel = costModel;
      providerSelect.insertBefore(opt, providerSelect.querySelector('option[value="__new__"]'));
      providerSelect.value = String(body.item.id);
      newProviderPanel.style.display = "none";
      toast("success", "تم حفظ المزود وتعيينه.");
    } catch (err) {
      toast("error", "خطأ شبكي عند حفظ المزود.");
    }
  });

  // ────────────────────────────────────────────────────────────────────
  // Review pane
  // ────────────────────────────────────────────────────────────────────
  function renderReview() {
    const review = document.getElementById("fw-review");
    if (!review) return;
    const data = collectPayload();
    const rows = [
      ["المزود", providerLabel(data.provider_id)],
      ["اسم العقدة", data.name],
      ["السعة (جلسات)", data.max_sessions],
      ["سرعة الرابط (Mbps)", data.link_speed_mbps],
      ["IP العام (v4)", data.public_ip],
      ["IP العام (v6)", data.public_ipv6 || "—"],
      ["وزن التفضيل", data.weight || "1.0"],
      ["نموذج التكلفة", costModelLabel(data.cost_model)],
    ];
    if (data.cost_model === "metered") {
      rows.push(["السقف (TB)", data.bandwidth_cap_tb || "—"]);
      rows.push(["سعر / TB ($)", data.price_per_tb || "—"]);
      rows.push(["السماح بالتجاوز المدفوع", data.overage_allowed ? "نعم" : "لا"]);
    }
    review.innerHTML = "";
    rows.forEach(([k, v]) => {
      const row = document.createElement("div");
      row.className = "fw-review-row";
      const key = document.createElement("div");
      key.className = "fw-review-key";
      key.textContent = k;
      const val = document.createElement("div");
      val.className = "fw-review-val";
      val.textContent = (v === null || v === undefined || v === "") ? "—" : String(v);
      row.appendChild(key);
      row.appendChild(val);
      review.appendChild(row);
    });
  }

  function providerLabel(id) {
    const opt = providerSelect.querySelector('option[value="' + id + '"]');
    return opt ? opt.textContent.replace(/\s+\(.*\)$/, "") : ("#" + id);
  }
  function costModelLabel(m) {
    return { inherit: "وراثة من المزود", open: "مفتوحة (open)", metered: "محدودة (metered)" }[m] || m;
  }

  // ────────────────────────────────────────────────────────────────────
  // Payload assembly + submit
  // ────────────────────────────────────────────────────────────────────
  function collectPayload() {
    const fd = new FormData(form);
    const overage = form.querySelector('input[name="overage_allowed"]').checked;
    return {
      provider_id: fd.get("provider_id"),
      name: (fd.get("name") || "").toString().trim(),
      public_ip: (fd.get("public_ip") || "").toString().trim(),
      public_ipv6: (fd.get("public_ipv6") || "").toString().trim() || null,
      max_sessions: parseInt(fd.get("max_sessions"), 10),
      link_speed_mbps: parseInt(fd.get("link_speed_mbps"), 10),
      cost_model: fd.get("cost_model") || "inherit",
      bandwidth_cap_tb: (fd.get("bandwidth_cap_tb") || "").toString().trim() || null,
      price_per_tb: (fd.get("price_per_tb") || "").toString().trim() || null,
      overage_allowed: overage,
      weight: (fd.get("weight") || "").toString().trim() || null,
      bootstrap: {
        endpoint: (fd.get("bootstrap_endpoint") || "").toString().trim(),
        user: (fd.get("bootstrap_user") || "").toString().trim(),
        // password is intentionally NOT echoed back into the review pane.
        // It is sent ONCE to the onboarding endpoint and never logged.
        pass: fd.get("bootstrap_pass") || "",
      },
    };
  }

  document.getElementById("fw-submit").addEventListener("click", async () => {
    if (!validateStep(1) || !validateStep(2) || !validateStep(3)) {
      toast("error", "بعض الحقول المطلوبة فارغة. عد للخطوات السابقة.");
      return;
    }
    const ok = await confirmDialog(
      "سيبدأ المعالج بإنشاء عقدة CHR جديدة وتشغيل آلة الحالة (مفاتيح → سكربت → دفع → تحقق). هل تريد المتابعة؟"
    );
    if (!ok) return;
    const payload = collectPayload();
    const btn = document.getElementById("fw-submit");
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> جارٍ الإرسال…';
    try {
      const res = await fetch(onboardingUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify(payload),
      });
      const body = await safeJson(res);
      if (res.ok && body.ok) {
        toast("success", "تم إنشاء عملية الأنبوردنغ. متابعتها متاحة من لوحة الأسطول.");
        setTimeout(() => { window.location.href = "/admin/fleet/"; }, 1100);
      } else {
        const detail = body.detail || body.error || ("HTTP " + res.status);
        toast("error", "تعذّر إرسال الطلب: " + detail, { ttl: 8000 });
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> إرسال للأنبوردنغ';
      }
    } catch (err) {
      toast("error", "خطأ شبكي — تأكد من اتصالك ثم أعِد المحاولة.", { ttl: 8000 });
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> إرسال للأنبوردنغ';
    }
  });

  // ────────────────────────────────────────────────────────────────────
  // Helpers
  // ────────────────────────────────────────────────────────────────────
  function csrfToken() {
    const el = form.querySelector('input[name="_csrf_token"]');
    return el ? el.value : "";
  }
  async function safeJson(res) {
    try { return await res.json(); } catch (_) { return {}; }
  }
})();
