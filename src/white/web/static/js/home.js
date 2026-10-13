// Homepage motion: intro screen, interactive 3D globe (plain canvas, no library),
// 3D headline tilt and count-up figures. Respects "reduce motion".
(function () {
  "use strict";
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var root = document.documentElement;

  // ---------------------------------------------------------------- intro screen
  var intro = document.getElementById("intro");
  if (intro) {
    root.classList.add("intro-active");
    var bar = intro.querySelector(".intro-line i");
    var minTime = reduce ? 150 : 1700;
    var start = performance.now();
    var steps = 0;
    function advance() {
      steps += 1;
      if (bar) bar.style.transform = "scaleX(" + Math.min(steps / 2, 1) + ")";
    }
    var fontsReady = document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve();
    var loaded = new Promise(function (resolve) {
      if (document.readyState === "complete") resolve();
      else window.addEventListener("load", resolve, { once: true });
    });
    fontsReady.then(advance);
    loaded.then(advance);
    var done = false;
    function finish() {
      if (done) return;
      done = true;
      if (bar) bar.style.transform = "scaleX(1)";
      intro.classList.add("is-done");
      root.classList.remove("intro-active");
      document.body.classList.add("intro-finished");
      // Scrolling is locked during the intro, so honour links like /#faq afterwards.
      if (window.location.hash.length > 1) {
        var target = document.getElementById(decodeURIComponent(window.location.hash.slice(1)));
        if (target) target.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      }
      setTimeout(function () { intro.classList.add("is-gone"); }, reduce ? 50 : 1100);
    }
    Promise.all([fontsReady, loaded]).then(function () {
      setTimeout(finish, Math.max(0, minTime - (performance.now() - start)));
    });
    setTimeout(finish, 4000); // failsafe: never trap the visitor behind the intro
  }

  // ---------------------------------------------------------------- 3D globe
  var canvas = document.getElementById("globe");
  if (canvas && canvas.getContext) {
    var ctx = canvas.getContext("2d");
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var size = 0;
    var points = [];
    var N = 520;
    var golden = Math.PI * (3 - Math.sqrt(5));
    for (var i = 0; i < N; i++) {
      var y = 1 - (i / (N - 1)) * 2;
      var r = Math.sqrt(1 - y * y);
      var t = golden * i;
      points.push([Math.cos(t) * r, y, Math.sin(t) * r]);
    }
    // A handful of "monitored" nodes linked by arcs.
    var nodes = [12, 77, 140, 205, 266, 331, 398, 455, 489, 37, 180, 300];
    var links = [[0, 3], [3, 5], [5, 8], [1, 4], [4, 7], [2, 6], [6, 9], [9, 11], [10, 2], [7, 10]];

    function resize() {
      var rect = canvas.getBoundingClientRect();
      size = Math.max(10, Math.min(rect.width, rect.height));
      canvas.width = size * dpr;
      canvas.height = size * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    resize();
    window.addEventListener("resize", resize);

    var rotY = 0.6, rotX = -0.32, targetX = -0.32, targetY = 0, spin = 0.0025;
    var hero = document.querySelector(".hero");
    if (hero && !reduce) {
      hero.addEventListener("mousemove", function (e) {
        var r = hero.getBoundingClientRect();
        targetX = -0.32 + ((e.clientY - r.top) / r.height - 0.5) * 0.5;
        targetY = ((e.clientX - r.left) / r.width - 0.5) * 0.8;
      });
    }

    function rotate(p) {
      var cy = Math.cos(rotY + targetY), sy = Math.sin(rotY + targetY);
      var cx = Math.cos(rotX), sx = Math.sin(rotX);
      var x = p[0] * cy + p[2] * sy;
      var z = -p[0] * sy + p[2] * cy;
      var y2 = p[1] * cx - z * sx;
      var z2 = p[1] * sx + z * cx;
      return [x, y2, z2];
    }
    function project(p, R, c) {
      var f = 3.2;
      var s = f / (f - p[2]);
      return [c + p[0] * R * s, c + p[1] * R * s, s, p[2]];
    }
    function slerp(a, b, t) {
      var dot = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
      var om = Math.acos(Math.max(-1, Math.min(1, dot)));
      if (om < 1e-4) return a;
      var s1 = Math.sin((1 - t) * om) / Math.sin(om), s2 = Math.sin(t * om) / Math.sin(om);
      var lift = 1 + Math.sin(Math.PI * t) * 0.18;
      return [(a[0] * s1 + b[0] * s2) * lift, (a[1] * s1 + b[1] * s2) * lift, (a[2] * s1 + b[2] * s2) * lift];
    }

    var running = true, frame = 0;
    function draw() {
      frame += 1;
      var c = size / 2, R = size * 0.36;
      ctx.clearRect(0, 0, size, size);
      rotX += (targetX - rotX) * 0.05;
      // orbit ring (behind)
      ctx.save();
      ctx.translate(c, c);
      ctx.rotate(-0.35);
      ctx.strokeStyle = "rgba(20,32,27,0.14)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.ellipse(0, 0, R * 1.32, R * 0.42, 0, 0, Math.PI * 2);
      ctx.stroke();
      var a = frame * 0.012;
      ctx.fillStyle = "#b05a2a";
      ctx.beginPath();
      ctx.arc(Math.cos(a) * R * 1.32, Math.sin(a) * R * 0.42, 4.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      // dots
      for (var i = 0; i < points.length; i++) {
        var p = project(rotate(points[i]), R, c);
        var depth = (p[3] + 1) / 2; // 0 back .. 1 front
        ctx.fillStyle = "rgba(20,32,27," + (0.07 + depth * 0.5).toFixed(3) + ")";
        var rad = (0.6 + depth * 1.35) * p[2];
        ctx.beginPath();
        ctx.arc(p[0], p[1], rad, 0, Math.PI * 2);
        ctx.fill();
      }
      // arcs between monitored nodes
      var dash = (frame * 0.008) % 1;
      for (var k = 0; k < links.length; k++) {
        var A = points[nodes[links[k][0]]], B = points[nodes[links[k][1]]];
        ctx.beginPath();
        var visible = false;
        for (var s = 0; s <= 28; s++) {
          var q = project(rotate(slerp(A, B, s / 28)), R, c);
          if (q[3] > -0.15) visible = true;
          if (s === 0) ctx.moveTo(q[0], q[1]); else ctx.lineTo(q[0], q[1]);
        }
        if (!visible) continue;
        ctx.strokeStyle = "rgba(29,107,78,0.55)";
        ctx.lineWidth = 1.3;
        ctx.stroke();
        // travelling pulse
        var tp = (dash + k * 0.13) % 1;
        var pp = project(rotate(slerp(A, B, tp)), R, c);
        if (pp[3] > -0.1) {
          ctx.fillStyle = "#1d6b4e";
          ctx.beginPath();
          ctx.arc(pp[0], pp[1], 2.6 * pp[2], 0, Math.PI * 2);
          ctx.fill();
        }
      }
      // nodes
      for (var n = 0; n < nodes.length; n++) {
        var np = project(rotate(points[nodes[n]]), R, c);
        if (np[3] < -0.2) continue;
        var pulse = 1 + 0.35 * Math.sin(frame * 0.05 + n);
        ctx.strokeStyle = "rgba(29,107,78,0.35)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(np[0], np[1], 7 * pulse * np[2], 0, Math.PI * 2);
        ctx.stroke();
        ctx.fillStyle = n % 4 === 0 ? "#b05a2a" : "#1d6b4e";
        ctx.beginPath();
        ctx.arc(np[0], np[1], 3.4 * np[2], 0, Math.PI * 2);
        ctx.fill();
      }
      rotY += spin;
      if (running && !reduce) requestAnimationFrame(draw);
    }
    draw();
    if (!reduce && "IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        var vis = entries[0].isIntersecting;
        if (vis && !running) { running = true; requestAnimationFrame(draw); }
        if (!vis) running = false;
      }).observe(canvas);
      document.addEventListener("visibilitychange", function () {
        if (document.hidden) running = false;
        else if (!running) { running = true; requestAnimationFrame(draw); }
      });
    }
  }

  // ---------------------------------------------------------------- 3D headline
  var title = document.querySelector(".hero-title");
  var heroEl = document.querySelector(".hero");
  if (title && heroEl && !reduce && window.matchMedia("(hover: hover)").matches) {
    var lines = title.querySelectorAll(".line");
    var words = title.querySelectorAll(".word");
    heroEl.addEventListener("mousemove", function (e) {
      var r = heroEl.getBoundingClientRect();
      var px = (e.clientX - r.left) / r.width - 0.5;
      var py = (e.clientY - r.top) / r.height - 0.5;
      lines.forEach(function (line, idx) {
        line.style.transform = "rotateX(" + (-py * 10) + "deg) rotateY(" + (px * 14) + "deg) translateZ(" + (idx * 6) + "px)";
      });
      var sx = (-px * 2.4).toFixed(2), sy = (-py * 2.4 + 0.4).toFixed(2);
      words.forEach(function (w) { w.style.setProperty("--sx", sx); w.style.setProperty("--sy", sy); });
    });
    heroEl.addEventListener("mouseleave", function () {
      lines.forEach(function (line) { line.style.transform = ""; });
      words.forEach(function (w) { w.style.setProperty("--sx", 1); w.style.setProperty("--sy", 1); });
    });
  }

  // ---------------------------------------------------------------- count-up figures
  var counters = document.querySelectorAll("[data-count]");
  function setFinal(el) { el.textContent = el.getAttribute("data-count"); }
  if (reduce || !("IntersectionObserver" in window)) {
    counters.forEach(setFinal);
  } else {
    var co = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        co.unobserve(entry.target);
        var el = entry.target, target = parseInt(el.getAttribute("data-count"), 10), t0 = performance.now();
        (function tick(now) {
          var p = Math.min((now - t0) / 1400, 1);
          var eased = 1 - Math.pow(1 - p, 3);
          el.textContent = String(Math.round(target * eased));
          if (p < 1) requestAnimationFrame(tick); else setFinal(el);
        })(t0);
      });
    }, { threshold: 0.4 });
    counters.forEach(function (el) { el.textContent = "0"; co.observe(el); });
  }
})();
