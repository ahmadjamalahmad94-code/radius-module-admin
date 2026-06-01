/* public_landing.js — HobeRadius landing interactions (no dependencies).
   Mobile menu toggle · smooth anchor scroll · FAQ accordion. Scoped to .lp-root. */
(function () {
  "use strict";

  // Mobile menu
  var burger = document.getElementById("lpBurger");
  var nav = document.getElementById("lpNav");
  if (burger && nav) {
    burger.addEventListener("click", function () {
      nav.classList.toggle("open");
    });
    nav.addEventListener("click", function (e) {
      if (e.target.tagName === "A") nav.classList.remove("open");
    });
  }

  // Smooth anchor scrolling with sticky-nav offset
  document.querySelectorAll('.lp-root a[href^="#"]').forEach(function (link) {
    link.addEventListener("click", function (e) {
      var id = link.getAttribute("href");
      if (id === "#" || id.length < 2) return;
      var target = document.querySelector(id);
      if (!target) return;
      e.preventDefault();
      var top = target.getBoundingClientRect().top + window.pageYOffset - 78;
      window.scrollTo({ top: top, behavior: "smooth" });
    });
  });

  // FAQ accordion
  document.querySelectorAll(".lp-faq-item .lp-faq-q").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var item = btn.closest(".lp-faq-item");
      var wasOpen = item.classList.contains("open");
      document.querySelectorAll(".lp-faq-item.open").forEach(function (o) {
        o.classList.remove("open");
      });
      if (!wasOpen) item.classList.add("open");
    });
  });
})();
