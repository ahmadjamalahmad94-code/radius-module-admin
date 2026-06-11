/*
 * admin_design_sweep.js — DESIGN SYSTEM SWEEP v1
 *
 * Three small, well-contained behaviors:
 *   1. Section tabs  — {% call hub.tab_bar(...) %} ... {% endcall %}
 *      Activates one panel at a time, restores from location.hash, deep
 *      links via hash on click.
 *   2. Styled confirm — any submit button with [data-confirm="..."] is
 *      intercepted; we show the in-page modal from {% call hub.confirm_modal() %}
 *      instead of window.confirm.
 *   3. Toast        — window.showToast(msg, kind) appends to the
 *      hub-toast-root node from {% call hub.toast_root() %}.
 *
 * No external dependencies. Loaded with `defer` from admin/base_new.html.
 */

(function () {
  'use strict';

  // ────────────────────────────────────────────────────────────────────
  // 1. Section tabs
  // ────────────────────────────────────────────────────────────────────
  function activateTab(tabsEl, key) {
    if (!tabsEl || !key) return false;
    var btns   = tabsEl.querySelectorAll('.hub-tab-btn[data-tab]');
    var panels = tabsEl.querySelectorAll('.hub-tab-panel[data-tab-panel]');
    var matched = false;
    btns.forEach(function (b) {
      var k = b.getAttribute('data-tab');
      var on = (k === key);
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      if (on) matched = true;
    });
    panels.forEach(function (p) {
      var k = p.getAttribute('data-tab-panel');
      var on = (k === key);
      p.classList.toggle('is-active', on);
      if (on) { p.removeAttribute('hidden'); } else { p.setAttribute('hidden', ''); }
    });
    return matched;
  }

  function initTabs() {
    var groups = document.querySelectorAll('[data-tabs]');
    if (!groups.length) return;
    groups.forEach(function (g) {
      var fallback = g.getAttribute('data-default-tab') || '';
      var hashKey  = (location.hash || '').replace(/^#/, '');
      // We support either "tab-<key>" or just "<key>" in the URL hash. The
      // tab_bar macro pushes "tab-<key>" for uniqueness across multiple tab
      // groups on a page; we accept both for backwards compatibility.
      var key = '';
      if (hashKey.indexOf('tab-') === 0) {
        key = hashKey.slice(4);
        if (!activateTab(g, key)) key = '';
      }
      if (!key && hashKey) {
        if (activateTab(g, hashKey)) key = hashKey;
      }
      if (!key) activateTab(g, fallback);

      g.addEventListener('click', function (e) {
        var btn = e.target.closest('.hub-tab-btn[data-tab]');
        if (!btn || btn.hasAttribute('disabled')) return;
        var k = btn.getAttribute('data-tab');
        if (!k) return;
        e.preventDefault();
        if (activateTab(g, k)) {
          // Update the URL hash without scrolling.
          try {
            history.replaceState(null, '', '#tab-' + k);
          } catch (_) {}
        }
      });
    });

    // Cross-tab deep-link updates: respond to back/forward.
    window.addEventListener('hashchange', function () {
      var hk = (location.hash || '').replace(/^#/, '');
      if (!hk) return;
      var key = hk.indexOf('tab-') === 0 ? hk.slice(4) : hk;
      groups.forEach(function (g) { activateTab(g, key); });
    });
  }

  // ────────────────────────────────────────────────────────────────────
  // 2. Styled confirm  (replaces window.confirm)
  // ────────────────────────────────────────────────────────────────────
  function initConfirm() {
    var overlay = document.getElementById('hub-confirm-overlay');
    if (!overlay) return;
    var msgEl   = document.getElementById('hub-confirm-message');
    var okBtn   = document.getElementById('hub-confirm-ok');
    var cancel  = document.getElementById('hub-confirm-cancel');
    var pendingForm = null;
    var pendingResolve = null;
    var pendingSubmitter = null;   // the [data-confirm] control that opened us

    function close() {
      overlay.hidden = true;
      pendingForm = null;
      pendingSubmitter = null;
      if (pendingResolve) { try { pendingResolve(false); } catch (_) {} }
      pendingResolve = null;
    }
    function open(msg, form, resolve, submitter) {
      msgEl.textContent = String(msg || 'هل أنت متأكد؟');
      pendingForm = form || null;
      pendingResolve = resolve || null;
      pendingSubmitter = submitter || null;
      overlay.hidden = false;
    }

    // Submit a form, PRESERVING the submitter's name/value when the
    // trigger is a real submit control (e.g. <button name="auto_generate"
    // value="1">). Plain form.submit() drops that pair — which silently
    // broke multi-button forms (the operator clicked «توليد» but the
    // server saw a bare save). requestSubmit(submitter) keeps it. For a
    // type="button" trigger (not a submitter) requestSubmit() would throw,
    // so we fall back to form.submit().
    function submitForm(f, submitter) {
      var isSubmitControl = submitter
        && submitter.type !== 'button'
        && (submitter.tagName === 'BUTTON' || submitter.tagName === 'INPUT');
      if (isSubmitControl && typeof f.requestSubmit === 'function') {
        try { f.requestSubmit(submitter); return; } catch (_) { /* fall through */ }
      }
      f.submit();
    }

    okBtn.addEventListener('click', function () {
      if (pendingForm) {
        var f = pendingForm; var s = pendingSubmitter;
        pendingForm = null; pendingSubmitter = null;
        overlay.hidden = true;
        submitForm(f, s);
      } else if (pendingResolve) {
        var r = pendingResolve; pendingResolve = null;
        overlay.hidden = true;
        try { r(true); } catch (_) {}
      } else {
        overlay.hidden = true;
      }
    });
    cancel.addEventListener('click', close);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', function (e) {
      if (!overlay.hidden && e.key === 'Escape') close();
    });

    // Any [data-confirm] button/link hooks the modal. This is the SINGLE
    // confirm system across the admin app — pages must NOT ship their own
    // [data-confirm] interceptor (two interceptors = two stacked overlays =
    // dead buttons, the fleet-infra «توليد مفتاح اللوحة» incident).
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('button[data-confirm], a[data-confirm]');
      if (!btn) return;
      var msg = btn.getAttribute('data-confirm') || 'هل أنت متأكد؟';
      var form = btn.closest('form');
      if (!form) return;
      e.preventDefault();
      // Stop other delegated handlers (legacy page-local confirm code) from
      // also firing on the same click — defence in depth against a second
      // modal opening behind ours.
      e.stopPropagation();
      open(msg, form, null, btn);
    }, true);

    // Promise-based API (for JS-driven actions):
    window.hubConfirm = function (msg) {
      return new Promise(function (resolve) { open(msg, null, resolve); });
    };
  }

  // ────────────────────────────────────────────────────────────────────
  // 3. Toast  (window.showToast)
  // ────────────────────────────────────────────────────────────────────
  function ensureToastRoot() {
    var node = document.getElementById('hub-toast-root');
    if (!node) {
      node = document.createElement('div');
      node.id = 'hub-toast-root';
      node.className = 'hub-toast';
      node.setAttribute('role', 'status');
      node.setAttribute('aria-live', 'polite');
      node.hidden = true;
      document.body.appendChild(node);
    }
    return node;
  }

  function showToast(msg, kind) {
    var t = ensureToastRoot();
    t.className = 'hub-toast' + (kind ? ' hub-toast--' + kind : '') + ' is-visible';
    t.textContent = String(msg || '');
    t.hidden = false;
    clearTimeout(showToast._t);
    showToast._t = setTimeout(function () {
      t.classList.remove('is-visible');
      setTimeout(function () { t.hidden = true; }, 320);
    }, 2600);
  }
  window.showToast = showToast;

  // Hard-replace native window.alert/confirm with safe toast / styled modal
  // so any third-party legacy code on admin pages still routes through the
  // design system. We keep prompt() as-is (rarely used).
  try {
    var _origAlert = window.alert;
    window.alert = function (msg) { showToast(String(msg || ''), 'warn'); };
    window._nativeAlert = _origAlert;
  } catch (_) {}
  try {
    var _origConfirm = window.confirm;
    window.confirm = function (msg) {
      // Synchronous semantics can't be preserved; we surface a toast that
      // tells the operator to use the in-page action button instead. This
      // is a defensive fallback — every legitimate admin path uses
      // data-confirm or window.hubConfirm(...) explicitly now.
      showToast(String(msg || ''), 'warn');
      return false;
    };
    window._nativeConfirm = _origConfirm;
  } catch (_) {}

  // ────────────────────────────────────────────────────────────────────
  // Boot
  // ────────────────────────────────────────────────────────────────────
  function onReady(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }
  onReady(function () {
    initTabs();
    initConfirm();
    ensureToastRoot();
  });
})();
