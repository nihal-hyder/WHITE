// Polls the real job status endpoint. Values shown are exactly what the server reports.
(function () {
  "use strict";
  var root = document.getElementById("scan-progress");
  if (!root) return;
  var scanId = root.getAttribute("data-scan-id");
  var stage = document.getElementById("progress-stage");
  var counts = document.getElementById("progress-counts");
  var elapsed = document.getElementById("progress-elapsed");
  var state = document.getElementById("progress-state");
  var bar = document.getElementById("progress-bar");
  var track = document.getElementById("progress-track");
  var errorBox = document.getElementById("progress-error");
  var finished = ["completed", "completed_with_errors", "failed", "cancelled", "interrupted"];
  var failures = 0;

  function render(s) {
    state.textContent = s.state.replace(/_/g, " ");
    state.className = "st st-" + s.state;
    stage.textContent = s.stage;
    if (s.total_checks > 0) {
      counts.textContent = s.completed_checks + " of " + s.total_checks + " checks completed";
      var pct = Math.round((s.completed_checks / s.total_checks) * 100);
      bar.style.width = pct + "%";
      track.setAttribute("aria-valuenow", String(pct));
    } else {
      counts.textContent = "Waiting for the scan to start";
    }
    elapsed.textContent = (s.elapsed_seconds || 0).toFixed(1) + " seconds";
    if (s.error) {
      errorBox.textContent = s.error;
      errorBox.hidden = false;
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
        if (finished.indexOf(s.state) >= 0) {
          setTimeout(function () { window.location.reload(); }, 600);
        } else {
          setTimeout(poll, 1200);
        }
      })
      .catch(function (e) {
        if (e.message === "auth") return;
        failures += 1;
        if (failures >= 5) {
          errorBox.textContent = "Lost contact with the server. Refresh the page to try again.";
          errorBox.hidden = false;
        } else {
          setTimeout(poll, 2500);
        }
      });
  }
  poll();
})();
