/*
 * portal_sidebar.js — Customer Portal sidebar ↔ in-page-tab bridge.
 *
 * The new portal sidebar (.adm-side in portal_base.html) contains links
 * that switch the dashboard's in-page panes (data-pp-view="services"
 * etc.). Each sidebar link carries data-pp-go="<key>".
 *
 * Behavior:
 *   1. On dashboard page load, read location.hash. If it's "#tab-<key>",
 *      activate that pane. The dashboard's own pp-view-switcher JS sets
 *      up the panes; we only force-activate the right one after DOM ready.
 *   2. When the user clicks a data-pp-go="<key>" sidebar link from
 *      INSIDE the dashboard, switch panes IN-PLACE (no navigation).
 *   3. When the user clicks the same link from another portal page, the
 *      link's href already points at /portal#tab-<key>, so navigation
 *      happens and step 1 picks it up on the next page load.
 *
 * No external deps. Pairs with admin_design_sweep.js (loaded before this)
 * which already provides showToast() + hubConfirm() + data-confirm handling.
 */

(function () {
  'use strict';

  function activatePane(key) {
    // The dashboard's panes follow the pattern
    //   <section class="pp-view" data-pp-pane="<key>">…</section>
    // and the dashboard JS also flips a "is-active" class on its
    // matching pp-nav-link button. We do BOTH so the legacy in-page
    // nav stays in sync if it's still in the DOM.
    var panes = document.querySelectorAll('.pp-view[data-pp-pane]');
    if (!panes.length) return false;
    var matched = false;
    panes.forEach(function (p) {
      var on = (p.getAttribute('data-pp-pane') === key);
      p.classList.toggle('is-active', on);
      if (on) matched = true;
    });
    // Legacy inner nav buttons (now hidden by portal_redesign.css, but if
    // they're still in the DOM and re-shown later we keep them in sync).
    document.querySelectorAll('.pp-nav-link[data-pp-view]').forEach(function (b) {
      b.classList.toggle('is-active', b.getAttribute('data-pp-view') === key);
    });
    // Sidebar links — flip the visual active state on the matching
    // data-pp-go link so the user sees where they are.
    document.querySelectorAll('.adm-side [data-pp-go]').forEach(function (a) {
      var on = (a.getAttribute('data-pp-go') === key);
      // For .adm-link (group children) toggle is-active class directly.
      // For .adm-solo we add the same class so its existing styles activate.
      a.classList.toggle('is-active', on);
    });
    return matched;
  }

  function keyFromHash() {
    var h = (location.hash || '').replace(/^#/, '');
    if (!h) return '';
    if (h.indexOf('tab-') === 0) return h.slice(4);
    return h;
  }

  function isDashboard() {
    // Dashboard is the ONLY page that renders .pp-view panes.
    return document.querySelector('.pp-view[data-pp-pane]') !== null;
  }

  function init() {
    // Step 1: respond to a deep-link on arrival.
    var k = keyFromHash();
    if (k && isDashboard()) {
      activatePane(k);
    }

    // Step 2: intercept sidebar clicks WHEN we're already on the dashboard
    // so we switch panes in-place instead of re-loading.
    document.querySelectorAll('.adm-side [data-pp-go]').forEach(function (a) {
      a.addEventListener('click', function (e) {
        var key = a.getAttribute('data-pp-go');
        if (!key || !isDashboard()) return; // let normal navigation happen
        // Switch in-place.
        e.preventDefault();
        if (activatePane(key)) {
          try { history.replaceState(null, '', '#tab-' + key); } catch (_) {}
          // Scroll the main column to the top so the user always sees the
          // hero of the newly-activated pane.
          var main = document.querySelector('.adm-main');
          if (main) main.scrollTo({ top: 0, behavior: 'smooth' });
        }
      });
    });

    // Step 3: react to back/forward (hashchange).
    window.addEventListener('hashchange', function () {
      if (!isDashboard()) return;
      var nk = keyFromHash();
      if (nk) activatePane(nk);
    });
  }

  function onReady(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }
  onReady(init);

  // Public escape hatch (e.g. for inline scripts in the dashboard).
  window.portalActivatePane = activatePane;
})();
