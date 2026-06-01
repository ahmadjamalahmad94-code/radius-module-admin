/* public_landing.js — HobeRadius landing interactions (no dependencies).
   Mobile menu · smooth anchor scroll · FAQ accordion · scroll-reveal · count-up.
   Scoped to .lp-root. Respects prefers-reduced-motion. */
(function () {
  "use strict";
  document.documentElement.classList.add("lp-js");
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ── Mobile menu ──
  var burger = document.getElementById("lpBurger");
  var nav = document.getElementById("lpNav");
  if (burger && nav) {
    burger.addEventListener("click", function () { nav.classList.toggle("open"); });
    nav.addEventListener("click", function (e) { if (e.target.tagName === "A") nav.classList.remove("open"); });
  }

  // ── Sticky nav shadow on scroll ──
  var topnav = document.querySelector(".lp-nav");
  if (topnav) {
    var onScroll = function () { topnav.classList.toggle("is-scrolled", window.scrollY > 8); };
    window.addEventListener("scroll", onScroll, { passive: true }); onScroll();
  }

  // ── Smooth anchor scrolling ──
  // Reveal the target first so its reveal transform (translateY) can't offset the
  // computed scroll position, then use scrollIntoView (respects CSS scroll-margin-top).
  document.querySelectorAll('.lp-root a[href^="#"]').forEach(function (link) {
    link.addEventListener("click", function (e) {
      var id = link.getAttribute("href");
      if (id === "#" || id.length < 2) return;
      var target = document.querySelector(id);
      if (!target) return;
      e.preventDefault();
      if (nav) nav.classList.remove("open");
      target.classList.add("in");  // clear any pending reveal transform on the target
      target.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    });
  });

  // ── FAQ accordion ──
  document.querySelectorAll(".lp-faq-item .lp-faq-q").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var item = btn.closest(".lp-faq-item");
      var wasOpen = item.classList.contains("open");
      document.querySelectorAll(".lp-faq-item.open").forEach(function (o) { o.classList.remove("open"); });
      if (!wasOpen) item.classList.add("open");
    });
  });

  // ── Count-up for [data-count] ──
  function countUp(el) {
    var target = parseFloat(el.getAttribute("data-count"));
    if (isNaN(target)) return;
    var suffix = el.getAttribute("data-suffix") || "";
    if (reduce) { el.textContent = target.toLocaleString("en-US") + suffix; return; }
    var dur = 1100, start = null;
    function step(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / dur, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.floor(eased * target).toLocaleString("en-US") + suffix;
      if (p < 1) requestAnimationFrame(step);
      else el.textContent = target.toLocaleString("en-US") + suffix;
    }
    requestAnimationFrame(step);
  }

  // ── Scroll-reveal (IntersectionObserver) + trigger count-up ──
  var revealEls = document.querySelectorAll(".lp-reveal");
  if (reduce || !("IntersectionObserver" in window)) {
    revealEls.forEach(function (el) { el.classList.add("in"); });
    document.querySelectorAll("[data-count]").forEach(countUp);
  } else {
    var io = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        en.target.classList.add("in");
        en.target.querySelectorAll && en.target.querySelectorAll("[data-count]").forEach(countUp);
        if (en.target.hasAttribute && en.target.hasAttribute("data-count")) countUp(en.target);
        obs.unobserve(en.target);
      });
    }, { threshold: 0.16, rootMargin: "0px 0px -40px 0px" });
    revealEls.forEach(function (el) { io.observe(el); });
    // observe count elements not wrapped in a reveal
    document.querySelectorAll("[data-count]").forEach(function (el) {
      if (!el.closest(".lp-reveal")) io.observe(el);
    });
  }
})();
