/* HoberRadius Admin — vanilla helpers
 * Loaded once from base.html with defer.
 *
 * Provides:
 *   - View switcher (sliding pill, localStorage-persisted)
 *   - Confirm modal (data-confirm-form delegated handler)
 *   - Password reveal toggle (data-pwd-toggle)
 *   - Per-page select autosubmit
 */
(function () {
  'use strict';

  // ────────────────────────────────────────────── View switcher
  function syncSwitcherThumb(switcher) {
    var active = switcher.querySelector('button.active');
    if (!active) {
      var first = switcher.querySelector('button');
      if (first) first.classList.add('active');
      active = first;
    }
    if (!active) return;
    var x = active.offsetLeft;
    var w = active.offsetWidth;
    switcher.style.setProperty('--switch-x', x + 'px');
    switcher.style.setProperty('--switch-w', w + 'px');
  }

  function applyView(targetSel, view) {
    var target = document.querySelector(targetSel);
    if (!target) return;
    target.classList.remove('hub-view--chip', 'hub-view--table');
    target.classList.add('hub-view--' + view);
  }

  function initSwitchers() {
    var switchers = document.querySelectorAll('[data-view-switch]');
    switchers.forEach(function (sw) {
      var key = sw.getAttribute('data-view-switch') || 'default';
      var targetSel = sw.getAttribute('data-view-target') || '#hub-view-target';
      var stored = null;
      try { stored = localStorage.getItem('hub.view.' + key); } catch (e) {}
      if (stored) {
        sw.querySelectorAll('button').forEach(function (b) {
          b.classList.toggle('active', b.getAttribute('data-view') === stored);
        });
        applyView(targetSel, stored);
      } else {
        applyView(targetSel, (sw.querySelector('button.active') || {}).getAttribute && sw.querySelector('button.active').getAttribute('data-view') || 'chip');
      }
      syncSwitcherThumb(sw);

      sw.addEventListener('click', function (e) {
        var btn = e.target.closest('button[data-view]');
        if (!btn) return;
        sw.querySelectorAll('button').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        syncSwitcherThumb(sw);
        var v = btn.getAttribute('data-view');
        applyView(targetSel, v);
        try { localStorage.setItem('hub.view.' + key, v); } catch (e) {}
      });

      window.addEventListener('resize', function () { syncSwitcherThumb(sw); });
    });
  }

  // ────────────────────────────────────────────── Confirm modal
  function initConfirm() {
    var modal = document.getElementById('hub-confirm');
    if (!modal) return;
    var titleEl = modal.querySelector('#hub-confirm-title');
    var msgEl   = modal.querySelector('#hub-confirm-msg');
    var okBtn   = modal.querySelector('#hub-confirm-ok');
    var cancel  = modal.querySelector('#hub-confirm-cancel');
    var pending = null;
    var lastFocus = null; // a11y: العنصر الذي فتح المودال — نعيد التركيز إليه عند الإغلاق

    function open(opts) {
      titleEl.textContent = opts.title || 'تأكيد العملية';
      msgEl.textContent   = opts.msg   || 'هل أنت متأكد من المتابعة؟';
      okBtn.textContent   = opts.ok    || 'تأكيد';
      okBtn.classList.remove('hub-btn--primary', 'hub-btn--danger');
      okBtn.classList.add(opts.variant === 'primary' ? 'hub-btn--primary' : 'hub-btn--danger');
      pending = opts.form;
      lastFocus = document.activeElement;
      modal.classList.add('is-open');
      modal.setAttribute('aria-hidden', 'false');
      cancel.focus();
    }
    function close() {
      modal.classList.remove('is-open');
      modal.setAttribute('aria-hidden', 'true');
      pending = null;
      if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) {} }
      lastFocus = null;
    }

    document.addEventListener('click', function (e) {
      var trigger = e.target.closest('[data-confirm-form]');
      if (trigger) {
        e.preventDefault();
        var formId = trigger.getAttribute('data-confirm-form');
        var form = document.getElementById(formId);
        if (!form) return;
        open({
          form: form,
          title: trigger.getAttribute('data-confirm-title') || '',
          msg:   trigger.getAttribute('data-confirm-msg')   || '',
          ok:    trigger.getAttribute('data-confirm-ok')    || '',
          variant: trigger.getAttribute('data-confirm-variant') || 'danger',
        });
        return;
      }
      if (e.target === modal) close();
    });

    okBtn.addEventListener('click', function () {
      if (pending) pending.submit();
      close();
    });
    cancel.addEventListener('click', close);
    document.addEventListener('keydown', function (e) {
      if (!modal.classList.contains('is-open')) return;
      if (e.key === 'Escape') { close(); return; }
      // a11y: حبس التركيز داخل المودال — Tab يدور بين زرّيه فقط
      if (e.key === 'Tab') {
        var focusables = [cancel, okBtn].filter(function (b) { return b && !b.disabled; });
        if (!focusables.length) return;
        var first = focusables[0], last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        else if (!modal.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
      }
    });
  }

  // ────────────────────────────────────────────── Password reveal
  function initPwdToggle() {
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-pwd-toggle]');
      if (!btn) return;
      e.preventDefault();
      var sel = btn.getAttribute('data-pwd-toggle');
      var input = sel ? document.querySelector(sel) : btn.parentElement.querySelector('input');
      if (!input) return;
      var hidden = input.type === 'password';
      input.type = hidden ? 'text' : 'password';
      var icon = btn.querySelector('i');
      if (icon) {
        icon.classList.toggle('fa-eye', hidden);
        icon.classList.toggle('fa-eye-slash', !hidden);
      }
    });
  }

  // ────────────────────────────────────────────── Pager perpage autosubmit
  function initPagerPerpage() {
    document.addEventListener('change', function (e) {
      var sel = e.target.closest('[data-pager-perpage]');
      if (!sel) return;
      var form = sel.closest('form');
      if (form) form.submit();
    });
  }

  // ────────────────────────────────────────────── Boot
  function boot() {
    initSwitchers();
    initConfirm();
    initPwdToggle();
    initPagerPerpage();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
