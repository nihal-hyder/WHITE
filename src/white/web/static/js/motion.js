// Shared interface motion: custom cursor, magnetic buttons, 3D tilt, scroll reveals,
// sticky-header state and the mobile menu. Everything degrades gracefully: on touch devices
// or with "reduce motion" enabled, only the essentials (menu, reveals shown) remain.
(function () {
  "use strict";
  var root = document.documentElement;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var finePointer = window.matchMedia("(hover: hover) and (pointer: fine)").matches;

  // ---------------------------------------------------------------- mobile menu
  var header = document.querySelector(".topbar");
  var toggle = document.querySelector(".menu-toggle");
  if (header && toggle) {
    toggle.addEventListener("click", function () {
      var open = header.classList.toggle("menu-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    header.addEventListener("click", function (e) {
      if (e.target.closest(".nav a") && header.classList.contains("menu-open")) {
        header.classList.remove("menu-open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && header.classList.contains("menu-open")) {
        header.classList.remove("menu-open");
        toggle.setAttribute("aria-expanded", "false");
        toggle.focus();
      }
    });
  }

  // ---------------------------------------------------------------- header on scroll
  function onScroll() {
    if (header) header.classList.toggle("is-scrolled", window.scrollY > 8);
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // ---------------------------------------------------------------- scroll reveal
  var reveals = document.querySelectorAll(".reveal");
  if (reduce || !("IntersectionObserver" in window)) {
    reveals.forEach(function (el) { el.classList.add("is-visible"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    reveals.forEach(function (el) { io.observe(el); });
  }

  if (reduce || !finePointer) return;

  // ---------------------------------------------------------------- custom cursor
  var dot = document.createElement("div");
  var ring = document.createElement("div");
  dot.className = "cursor-dot";
  ring.className = "cursor-ring";
  ring.innerHTML = '<span class="cursor-label"></span>';
  dot.setAttribute("aria-hidden", "true");
  ring.setAttribute("aria-hidden", "true");
  document.body.appendChild(dot);
  document.body.appendChild(ring);
  var label = ring.firstChild;
  var mx = -100, my = -100, rx = -100, ry = -100, started = false;

  document.addEventListener("mousemove", function (e) {
    mx = e.clientX; my = e.clientY;
    if (!started) { started = true; rx = mx; ry = my; root.classList.add("has-cursor"); }
    dot.style.transform = "translate3d(" + mx + "px," + my + "px,0)";
    var dark = e.target.closest && e.target.closest("[data-dark]");
    root.classList.toggle("on-dark", !!dark);
  }, { passive: true });
  document.addEventListener("mouseleave", function () { root.classList.add("cursor-hidden"); });
  document.addEventListener("mouseenter", function () { root.classList.remove("cursor-hidden"); });
  document.addEventListener("mousedown", function () { root.classList.add("cursor-down"); });
  document.addEventListener("mouseup", function () { root.classList.remove("cursor-down"); });

  var interactive = "a, button, summary, label, select, [data-cursor], .tilt";
  var textual = 'input[type="text"], input[type="email"], input[type="password"], input[type="url"], textarea';
  document.addEventListener("mouseover", function (e) {
    var t = e.target;
    if (t.closest(textual)) { root.classList.add("cursor-hidden"); return; }
    root.classList.remove("cursor-hidden");
    var labelled = t.closest("[data-cursor]");
    if (labelled && labelled.getAttribute("data-cursor")) {
      label.textContent = labelled.getAttribute("data-cursor");
      root.classList.add("cursor-label-on");
      root.classList.remove("cursor-hover");
    } else if (t.closest(interactive)) {
      root.classList.add("cursor-hover");
      root.classList.remove("cursor-label-on");
    } else {
      root.classList.remove("cursor-hover", "cursor-label-on");
    }
  });

  (function follow() {
    rx += (mx - rx) * 0.18;
    ry += (my - ry) * 0.18;
    ring.style.transform = "translate3d(" + rx + "px," + ry + "px,0)";
    requestAnimationFrame(follow);
  })();

  // ---------------------------------------------------------------- magnetic buttons
  document.querySelectorAll(".btn").forEach(function (btn) {
    btn.addEventListener("mousemove", function (e) {
      var r = btn.getBoundingClientRect();
      var x = (e.clientX - r.left - r.width / 2) * 0.18;
      var y = (e.clientY - r.top - r.height / 2) * 0.28;
      btn.style.transform = "translate(" + x + "px," + y + "px)";
    });
    btn.addEventListener("mouseleave", function () { btn.style.transform = ""; });
  });

  // ---------------------------------------------------------------- 3D tilt cards
  document.querySelectorAll(".tilt").forEach(function (card) {
    var max = parseFloat(card.getAttribute("data-tilt") || "7");
    card.addEventListener("mousemove", function (e) {
      var r = card.getBoundingClientRect();
      var px = (e.clientX - r.left) / r.width - 0.5;
      var py = (e.clientY - r.top) / r.height - 0.5;
      card.classList.add("is-tilting");
      card.style.transform = "perspective(900px) rotateX(" + (-py * max) + "deg) rotateY(" + (px * max) + "deg) translateY(-4px)";
      card.style.setProperty("--mx", ((px + 0.5) * 100) + "%");
      card.style.setProperty("--my", ((py + 0.5) * 100) + "%");
    });
    card.addEventListener("mouseleave", function () {
      card.classList.remove("is-tilting");
      card.style.transform = "";
    });
  });
})();
