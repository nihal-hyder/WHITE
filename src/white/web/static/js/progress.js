// Animates the scan progress page from the real job status. Every number shown comes from the
// server; the animation only interpolates smoothly between polls.
(function () {
  "use strict";
  var root = document.getElementById("scan-progress");
  if (!root) return;

  var scanId = root.getAttribute("data-scan-id");
  var total = parseInt(root.getAttribute("data-total"), 10) || 0;
  var stageEl = document.getElementById("progress-stage");
  var countsEl = document.getElementById("progress-counts");
  var elapsedEl = document.getElementById("progress-elapsed");
  var stateEl = document.getElementById("progress-state");
  var errorBox = document.getElementById("progress-error");
  var ringFg = document.getElementById("ring-fg");
  var ringPct = document.getElementById("ring-pct");
  var checks = Array.prototype.slice.call(document.querySelectorAll(".scan-check"));
  var CIRC = 2 * Math.PI * 54;
  var FINISHED = ["completed", "completed_with_errors", "failed", "cancelled", "interrupted"];
  var failures = 0;
  var shownPct = 0;

  // Smooth elapsed timer between polls.
  var baseElapsed = parseFloat(elapsedEl.textContent) || 0;
  var baseAt = Date.now();
  var ticking = true;
  setInterval(function () {
    if (!ticking) return;
    elapsedEl.textContent = (baseElapsed + (Date.now() - baseAt) / 1000).toFixed(1);
  }, 100);

  function setRing(pct) {
    ringFg.style.strokeDashoffset = String(CIRC * (1 - pct / 100));
    ringPct.innerHTML = Math.round(pct) + "<small>%</small>";
  }

  function markChecks(completed, running) {
    checks.forEach(function (li, i) {
      var cls = i < completed ? "is-done" : (running && i === completed ? "is-active" : "is-pending");
      if (li.getAttribute("data-state") !== cls) {
        li.setAttribute("data-state", cls);
        li.classList.remove("is-done", "is-active", "is-pending");
        li.classList.add(cls);
      }
    });
  }

  function render(s) {
    stateEl.textContent = s.state.replace(/_/g, " ");
    stateEl.className = "st st-" + s.state;
    if (s.stage && s.stage !== stageEl.textContent) {
      stageEl.style.opacity = "0";
      setTimeout(function () { stageEl.textContent = s.stage; stageEl.style.opacity = "1"; }, 120);
    }

    var done = FINISHED.indexOf(s.state) >= 0;
    var running = s.state === "running" && /check/i.test(s.stage || "");
    var completed = done ? total : Math.min(s.completed_checks || 0, total);
    var pct = done ? 100 : (total ? (completed / total) * 100 : 0);
    if (pct >= shownPct || done) { setRing(pct); shownPct = pct; }

    if (total && !done) {
      countsEl.textContent = completed + " / " + total + " checks";
    } else if (done) {
      countsEl.textContent = s.state === "completed" ? "complete" : s.state.replace(/_/g, " ");
    } else {
      countsEl.textContent = "connecting";
    }
    markChecks(completed, running);

    baseElapsed = s.elapsed_seconds != null ? s.elapsed_seconds : baseElapsed;
    baseAt = Date.now();

    if (s.error) { errorBox.textContent = s.error; errorBox.hidden = false; }

    if (done) {
      ticking = false;
      root.classList.add("is-finished");
      setTimeout(function () { window.location.reload(); }, 750);
    }
  }

  function poll() {
    fetch("/api/scans/" + encodeURIComponent(scanId) + "/status", { credentials: "same-origin" })
      .then(function (r) {
        if (r.status === 401) { window.location.href = "/login?msg=expired"; throw new Error("auth"); }
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (s) {
        failures = 0;
        render(s);
        if (FINISHED.indexOf(s.state) < 0) setTimeout(poll, 1000);
      })
      .catch(function (e) {
        if (e.message === "auth") return;
        failures += 1;
        if (failures >= 5) {
          errorBox.textContent = "Lost contact with the server. Refresh the page to try again.";
          errorBox.hidden = false;
          ticking = false;
        } else {
          setTimeout(poll, 2500);
        }
      });
  }

  // Serverless hosting: the scan runs inside this request; progress is read by polling.
  if (root.getAttribute("data-run") === "yes") {
    var csrf = document.querySelector('meta[name="csrf-token"]').getAttribute("content");
    fetch("/api/scans/" + encodeURIComponent(scanId) + "/run", {
      method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf }
    }).then(function (r) {
      if (r.ok || r.status === 409) return;
      return r.json().then(function (body) {
        errorBox.textContent = body.detail || "The scan could not be started.";
        errorBox.hidden = false;
      });
    }).catch(function () { /* the status poll reports the final state */ });
  }

  poll();
})();
