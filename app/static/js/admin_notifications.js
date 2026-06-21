// Notification bell — poll the unread count and paint the sidebar badge.
// CSP-safe, no inline handlers. Also wires per-row «تعليم كمقروء» buttons
// on the notification-center page (data-notif-read).
(function () {
  "use strict";

  function csrfToken() {
    const el = document.querySelector('input[name="_csrf_token"]');
    return el ? el.value : "";
  }

  // ── Sidebar bell badge ───────────────────────────────────────────────
  const bell = document.querySelector("[data-notif-bell]");
  const badge = document.querySelector("[data-notif-badge]");

  function paintBadge(count) {
    if (!badge) return;
    const n = parseInt(count, 10) || 0;
    if (n > 0) {
      badge.textContent = n > 99 ? "99+" : String(n);
      badge.hidden = false;
    } else {
      badge.hidden = true;
    }
  }

  async function refreshBadge() {
    if (!bell) return;
    const url = bell.getAttribute("data-unread-url");
    if (!url) return;
    try {
      const res = await fetch(url, { headers: { "Accept": "application/json" } });
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.ok) paintBadge(data.count);
    } catch (e) { /* network blip — try again next tick */ }
  }

  if (bell && badge) {
    refreshBadge();
    setInterval(refreshBadge, 30000); // every 30s
  }

  // ── Notification-center: mark-read buttons (AJAX, no full reload) ─────
  document.addEventListener("click", async function (e) {
    const btn = e.target.closest("[data-notif-read]");
    if (!btn) return;
    e.preventDefault();
    const id = btn.getAttribute("data-notif-read");
    try {
      const res = await fetch("/admin/notifications/" + id + "/read", {
        method: "POST",
        headers: {
          "X-Requested-With": "XMLHttpRequest",
          "Accept": "application/json",
          "X-CSRFToken": csrfToken(),
        },
      });
      const data = await res.json().catch(function () { return {}; });
      if (data && data.ok) {
        const row = btn.closest("[data-notif-row]");
        if (row) row.classList.remove("is-unread");
        btn.remove();
        paintBadge(data.unread_count);
      }
    } catch (e2) { /* leave the row as-is on error */ }
  });
})();
