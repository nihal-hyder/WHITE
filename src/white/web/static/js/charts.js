// Renders dashboard and report charts from server-provided JSON. No values are invented here:
// every number comes from #chart-data, which the server computes from stored scan reports.
(function () {
  "use strict";
  var dataEl = document.getElementById("chart-data");
  if (!dataEl || typeof Chart === "undefined") return;
  var data = JSON.parse(dataEl.textContent);

  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  Chart.defaults.font.family = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  Chart.defaults.color = "#4b525b";
  Chart.defaults.borderColor = "#e2e4e6";
  Chart.defaults.animation = reduceMotion ? false : { duration: 300 };
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.boxHeight = 10;
  Chart.defaults.maintainAspectRatio = false;

  var SEVERITY = { CRITICAL: "#b42318", HIGH: "#d9541e", MEDIUM: "#c98500", LOW: "#2a78d6", INFO: "#9ca3af" };
  var COVERAGE = { PASS: "#1f7a4d", FINDING: "#b42318", POTENTIAL: "#c98500", INCONCLUSIVE: "#2a78d6",
                   NOT_APPLICABLE: "#c9cdd1", NOT_TESTED: "#898781", ERROR: "#6d28d9" };
  var TREND = { unresolved: "#2a78d6", "new": "#eb6834", fixed: "#1baf7a", unverified: "#eda100" };

  function sum(values) { return values.reduce(function (a, b) { return a + b; }, 0); }
  function canvas(id) { return document.getElementById(id); }

  function severityChart(id, sev) {
    var el = canvas(id);
    if (!el || !sev || sum(sev.values) === 0) return;
    new Chart(el, {
      type: "doughnut",
      data: {
        labels: sev.labels.map(function (l, i) { return l + " (" + sev.values[i] + ")"; }),
        datasets: [{ data: sev.values, backgroundColor: sev.keys.map(function (k) { return SEVERITY[k]; }),
                     borderColor: "#ffffff", borderWidth: 2 }]
      },
      options: {
        cutout: "62%",
        plugins: {
          legend: { position: "right" },
          tooltip: { callbacks: { label: function (c) { return " " + c.label.replace(/ \(\d+\)$/, "") + ": " + c.parsed + " finding(s)"; } } }
        }
      }
    });
  }

  function barChart(id, series, colors, label) {
    var el = canvas(id);
    if (!el || !series) return;
    new Chart(el, {
      type: "bar",
      data: {
        labels: series.labels,
        datasets: [{ label: label, data: series.values, borderRadius: 4, borderSkipped: "start",
                     maxBarThickness: 22,
                     backgroundColor: colors ? series.keys.map(function (k) { return colors[k]; }) : "#2a78d6" }]
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#eef0f1" } },
          y: { grid: { display: false } }
        }
      }
    });
  }

  function trendChart(id, trend) {
    var el = canvas(id);
    if (!el || !trend || !trend.enough_data) return;
    var points = trend.points;
    var series = [
      ["unresolved", "Still present"], ["new", "Newly detected"], ["fixed", "No longer detected"],
      ["unverified", "Not re-verified"]
    ];
    new Chart(el, {
      type: "line",
      data: {
        labels: points.map(function (p) { return p.label; }),
        datasets: series.map(function (s) {
          return { label: s[1], data: points.map(function (p) { return p[s[0]]; }), borderColor: TREND[s[0]],
                   backgroundColor: TREND[s[0]], borderWidth: 2, pointRadius: 4, pointHoverRadius: 6, tension: 0 };
        })
      },
      options: {
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { position: "bottom" } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#eef0f1" } },
                  x: { grid: { display: false } } }
      }
    });
  }

  severityChart("chart-severity", data.severity);
  barChart("chart-category", data.categories, null, "Findings");
  barChart("chart-coverage", data.coverage, COVERAGE, "Checks");
  trendChart("chart-trend", data.trend);
})();
