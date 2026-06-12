/*
 * admin_polish.js — animation utilities that pair with admin_polish.css.
 *
 *  PURE progressive enhancement: it auto-detects existing markup
 *  (numeric KPI values, hub-progress bars) so no template changes are
 *  required for a page to pick up the polish.  Pages CAN opt in
 *  explicitly via data-attributes when they want to be precise.
 *
 *  Exports nothing on `window`; everything is scoped to one IIFE.
 *
 *  Honours `prefers-reduced-motion`: the count-up snaps to the final
 *  number; the bars set width without transition; reveals are no-ops.
 *
 *  Hooks
 *  =====
 *
 *    data-countup="<number>"              explicit count-up target.
 *    data-countup-duration="<ms>"         override the 900 ms default.
 *    data-countup-decimals="<n>"          how many decimal places to render.
 *
 *    data-bar="<percent 0..100>"          fill bar from 0 to <percent>.
 *      (auto-applied to any .hub-progress with a width:N% inline style.)
 *
 *    .polish-reveal                       fade-up when scrolled into view.
 *
 *    button.is-busy / [data-loading]      shimmer overlay (CSS only — JS
 *                                         only adds the class on click for
 *                                         buttons inside <form>).
 *
 *  Auto-pickups
 *  ============
 *
 *    • Any .hub-kpi-value, .fi-stat-num, .fd-num-emph whose textContent
 *      starts with a number → count-up.
 *    • Any .hub-progress with a child <span style="width:N%"> → bar fill.
 *    • Any form submit button → adds .is-busy on submit (so the shimmer
 *      shows during the request).
 *
 *  All side effects are idempotent: re-running detect() (which we DO call
 *  on hash/route changes) skips elements already tagged data-polished="1".
 */
(function () {
  'use strict';

  var reduced =
    window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ──────────────────────────────────────────────────────────────────────
     1.  COUNT-UP
     ────────────────────────────────────────────────────────────────────── */

  function parseNumericPrefix(raw) {
    if (raw == null) return null;
    var s = String(raw).trim();
    if (!s) return null;
    // Match: optional minus, digits with optional commas/spaces, optional
    // decimal, optional trailing % handled by suffix split below.
    var match = s.match(/^(-?[\d٠-٩,٫٬٬ ]+(?:[.,٫][\d٠-٩]+)?)/);
    if (!match) return null;
    // Strip thousand separators (Arabic + Latin) for parseFloat.
    var num = match[0]
      .replace(/[٠-٩]/g, function (d) { return d.charCodeAt(0) - 0x0660; })
      .replace(/[,٫٬٬ ]/g, '')
      .replace('٫', '.');
    var parsed = parseFloat(num);
    if (!isFinite(parsed)) return null;
    return { value: parsed, raw: match[0], suffix: s.slice(match[0].length) };
  }

  function fmtNumber(value, decimals) {
    if (decimals > 0) {
      return value.toFixed(decimals);
    }
    // Integer values get thousand separators (Arabic locale honours dir).
    try {
      return Math.round(value).toLocaleString('en-US');
    } catch (e) {
      return String(Math.round(value));
    }
  }

  function startCountUp(el, target, suffix, opts) {
    opts = opts || {};
    var duration = +(el.dataset.countupDuration || opts.duration || 900);
    var decimals = +(el.dataset.countupDecimals != null
                       ? el.dataset.countupDecimals
                       : (Number.isInteger(target) ? 0 : 1));
    if (reduced) {
      el.textContent = fmtNumber(target, decimals) + (suffix || '');
      el.dataset.polished = '1';
      return;
    }
    // Wrap digits in a <span class="polish-count-num"> so the suffix
    // doesn't get reflowed every tick.
    el.textContent = '';
    var numSpan = document.createElement('span');
    numSpan.className = 'polish-count-num';
    numSpan.textContent = '0';
    el.appendChild(numSpan);
    if (suffix) {
      el.appendChild(document.createTextNode(suffix));
    }
    var start = null;
    function step(ts) {
      if (start === null) start = ts;
      var t = Math.min(1, (ts - start) / duration);
      // Ease-out cubic so the count slows toward the target.
      var eased = 1 - Math.pow(1 - t, 3);
      var current = target * eased;
      numSpan.textContent = fmtNumber(current, decimals);
      if (t < 1) {
        requestAnimationFrame(step);
      } else {
        numSpan.textContent = fmtNumber(target, decimals);
        el.dataset.polished = '1';
      }
    }
    requestAnimationFrame(step);
  }

  function detectCountUp(root) {
    var nodes = (root || document).querySelectorAll(
      '[data-countup], .hub-kpi-value, .fi-stat-num, .fd-num-emph, .hub-tile-value'
    );
    nodes.forEach(function (el) {
      if (el.dataset.polished) return;
      // Skip if a child element wraps the number (template already
      // structured it); we don't want to break complex layouts.
      if (el.children.length && !el.hasAttribute('data-countup')) {
        // Allow the simple <strong> / <span> case: one direct child.
        if (el.children.length > 1) return;
        var only = el.firstElementChild;
        if (only && only.textContent !== el.textContent) return;
      }
      var explicit = el.dataset.countup;
      var parsed;
      if (explicit != null && explicit !== '') {
        parsed = parseNumericPrefix(explicit);
        if (!parsed) return;
        // Suffix lives on the data attribute (or is appended from text).
        var raw = el.textContent.trim();
        var rawParsed = parseNumericPrefix(raw);
        var suffix = rawParsed ? rawParsed.suffix : '';
        startCountUp(el, parsed.value, suffix);
      } else {
        parsed = parseNumericPrefix(el.textContent);
        if (!parsed) return;
        // Skip if the number is too small to be worth animating (e.g. "0").
        if (parsed.value === 0) {
          el.dataset.polished = '1';
          return;
        }
        startCountUp(el, parsed.value, parsed.suffix);
      }
    });
  }


  /* ──────────────────────────────────────────────────────────────────────
     2.  ANIMATED BARS
     ────────────────────────────────────────────────────────────────────── */

  function detectBars(root) {
    var bars = (root || document).querySelectorAll(
      '[data-bar], .hub-progress, .polish-bar'
    );
    bars.forEach(function (bar) {
      if (bar.dataset.polished) return;
      var target;
      var fill;
      if (bar.classList.contains('polish-bar')) {
        fill = bar.querySelector('.polish-bar-fill') ||
               (function () {
                 var f = document.createElement('span');
                 f.className = 'polish-bar-fill';
                 bar.appendChild(f);
                 return f;
               })();
        target = bar.dataset.bar || fill.style.width || '0%';
      } else if (bar.classList.contains('hub-progress')) {
        fill = bar.querySelector('span');
        if (!fill) return;
        target = fill.style.width || bar.dataset.bar || '';
      } else {
        // bare [data-bar] — wrap in a polish-bar if needed.
        if (!bar.classList.contains('hub-progress') &&
            !bar.querySelector('.polish-bar-fill')) {
          bar.classList.add('polish-bar');
          fill = document.createElement('span');
          fill.className = 'polish-bar-fill';
          bar.appendChild(fill);
        } else {
          fill = bar.querySelector('span.polish-bar-fill') || bar.querySelector('span');
        }
        target = bar.dataset.bar || '0';
      }
      if (!fill) return;
      // Normalise to "N%".
      target = String(target).trim();
      if (!target) return;
      if (!/%$/.test(target)) target = target + '%';
      var n = parseFloat(target);
      if (!isFinite(n)) return;
      n = Math.max(0, Math.min(100, n));
      target = n + '%';
      if (reduced) {
        fill.style.width = target;
        bar.dataset.polished = '1';
        return;
      }
      // Start at 0 then animate.
      fill.style.transition = 'none';
      fill.style.width = '0%';
      // Force layout.
      void fill.offsetWidth;
      fill.style.transition = 'width 900ms cubic-bezier(.22,1,.36,1)';
      // Animate in next frame so the transition picks up.
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          fill.style.width = target;
          bar.dataset.polished = '1';
        });
      });
    });
  }


  /* ──────────────────────────────────────────────────────────────────────
     3.  REVEAL-ON-SCROLL
     ────────────────────────────────────────────────────────────────────── */

  function detectReveals() {
    var nodes = document.querySelectorAll('.polish-reveal:not(.is-revealed)');
    if (!nodes.length) return;
    if (reduced || !('IntersectionObserver' in window)) {
      nodes.forEach(function (n) { n.classList.add('is-revealed'); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-revealed');
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -10% 0px', threshold: 0.1 });
    nodes.forEach(function (n) { io.observe(n); });
  }


  /* ──────────────────────────────────────────────────────────────────────
     4.  BUSY BUTTONS  (shimmer during form submit)
     ────────────────────────────────────────────────────────────────────── */

  function bindBusyButtons() {
    document.addEventListener('submit', function (ev) {
      var form = ev.target;
      if (!form || form.dataset.polishBusyBound === '1') {}
      var submitters = form.querySelectorAll('button[type="submit"], input[type="submit"]');
      submitters.forEach(function (btn) {
        if (btn.dataset.noBusy === '1') return;
        btn.classList.add('is-busy');
        // Re-enable after 8 s as a safety net if the page didn't navigate.
        setTimeout(function () { btn.classList.remove('is-busy'); }, 8000);
      });
    }, { capture: true });
  }


  /* ──────────────────────────────────────────────────────────────────────
     5.  HERO SHEEN — guarantee it runs even after a soft navigation.
     ────────────────────────────────────────────────────────────────────── */

  function refreshHeroSheen() {
    var heroes = document.querySelectorAll(
      '.hub-hero, .sg-hero, .fi-hero, .fd-hero, .p7-hero-card'
    );
    heroes.forEach(function (h) {
      h.classList.remove('polish-sheen');
      // Force reflow to restart the CSS animation.
      void h.offsetWidth;
      h.classList.add('polish-sheen');
    });
  }


  /* ──────────────────────────────────────────────────────────────────────
     6.  COUNT-UP scroll-trigger for off-screen KPIs
     ────────────────────────────────────────────────────────────────────── */

  function scrollTriggeredCountUp() {
    if (reduced || !('IntersectionObserver' in window)) {
      detectCountUp(document);
      return;
    }
    var candidates = document.querySelectorAll(
      '[data-countup], .hub-kpi-value, .fi-stat-num, .fd-num-emph, .hub-tile-value'
    );
    var visible = [];
    var pending = [];
    candidates.forEach(function (el) {
      // Above-the-fold start immediately; below-the-fold wait for IO.
      var rect = el.getBoundingClientRect();
      if (rect.top < window.innerHeight) visible.push(el);
      else pending.push(el);
    });
    detectCountUp({ querySelectorAll: function () { return visible; } });

    if (!pending.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          detectCountUp({ querySelectorAll: function () { return [entry.target]; } });
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -5% 0px', threshold: 0.15 });
    pending.forEach(function (el) { io.observe(el); });
  }


  /* ──────────────────────────────────────────────────────────────────────
     BOOT
     ────────────────────────────────────────────────────────────────────── */

  function boot() {
    try {
      scrollTriggeredCountUp();
      detectBars(document);
      detectReveals();
      bindBusyButtons();
      refreshHeroSheen();
    } catch (e) {
      // Polish must NEVER take a page down.
      if (window.console && console.warn) console.warn('admin_polish:', e);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // Expose a tiny helper so AJAX-driven pages can ask for a re-detect.
  window.AdminPolish = {
    rescan: function () {
      try {
        detectCountUp(document);
        detectBars(document);
        detectReveals();
      } catch (e) { /* noop */ }
    }
  };
})();
