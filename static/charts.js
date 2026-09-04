/* ==========================================================================
   SENTINEL AI - analytics charts (Chart.js)
   All charts are simple bar/doughnut charts built from the current
   alert batch returned by /api/process.
   ========================================================================== */
(function () {
  const COLORS = {
    cyan: "#22d3ee", red: "#ff3b5c", orange: "#ffa63d",
    green: "#35e08a", gray: "#5b6672", grid: "rgba(120,160,200,0.08)",
    text: "#8493a6",
  };

  Chart.defaults.color = COLORS.text;
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.font.size = 11;

  let charts = {};

  function makeChart(id, config) {
    const ctx = document.getElementById(id);
    if (!ctx) return null;
    if (charts[id]) charts[id].destroy();
    charts[id] = new Chart(ctx, config);
    return charts[id];
  }

  function countBy(arr, keyFn) {
    const out = {};
    arr.forEach(item => {
      const k = keyFn(item);
      out[k] = (out[k] || 0) + 1;
    });
    return out;
  }

  function update(alerts, stats) {
    // 1. Severity distribution
    const sevCounts = countBy(alerts, a => a.severity);
    const sevLabels = ["Critical", "High", "Medium", "Low"];
    makeChart("chartSeverity", {
      type: "doughnut",
      data: {
        labels: sevLabels,
        datasets: [{
          data: sevLabels.map(s => sevCounts[s] || 0),
          backgroundColor: [COLORS.red, COLORS.orange, COLORS.cyan, COLORS.gray],
          borderWidth: 0,
        }],
      },
      options: { plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 12 } } }, cutout: "62%" },
    });

    // 2. Risk score distribution (bins of 10)
    const bins = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    alerts.forEach(a => {
      const idx = Math.min(9, Math.floor(a.risk_score / 10));
      bins[idx]++;
    });
    makeChart("chartRisk", {
      type: "bar",
      data: {
        labels: bins.map((_, i) => `${i * 10}-${i * 10 + 9}`),
        datasets: [{ data: bins, backgroundColor: COLORS.cyan, borderRadius: 4 }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: COLORS.grid }, beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });

    // 3. False positive reduction: FP vs needs-review
    const fp = alerts.filter(a => a.false_positive).length;
    const real = alerts.length - fp;
    makeChart("chartFP", {
      type: "doughnut",
      data: {
        labels: ["Needs Review", "Auto-Deprioritized (FP)"],
        datasets: [{ data: [real, fp], backgroundColor: [COLORS.cyan, COLORS.gray], borderWidth: 0 }],
      },
      options: { plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 12 } } }, cutout: "62%" },
    });

    // 4. Alerts by department
    const deptCounts = countBy(alerts, a => a.asset_context.department);
    const deptLabels = Object.keys(deptCounts);
    makeChart("chartDept", {
      type: "bar",
      data: {
        labels: deptLabels,
        datasets: [{ data: deptLabels.map(d => deptCounts[d]), backgroundColor: COLORS.orange, borderRadius: 4 }],
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: { x: { grid: { color: COLORS.grid }, beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
      },
    });

    // 5. Average risk by asset criticality
    const critLevels = ["Critical", "High", "Medium", "Low"];
    const critAvg = critLevels.map(level => {
      const group = alerts.filter(a => a.asset_context.criticality === level);
      if (!group.length) return 0;
      return Math.round(group.reduce((s, a) => s + a.risk_score, 0) / group.length);
    });
    makeChart("chartAsset", {
      type: "bar",
      data: {
        labels: critLevels,
        datasets: [{ data: critAvg, backgroundColor: [COLORS.red, COLORS.orange, COLORS.cyan, COLORS.gray], borderRadius: 4 }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: { x: { grid: { display: false } }, y: { grid: { color: COLORS.grid }, beginAtZero: true, max: 100 } },
      },
    });

    // 6. Investigation queue by status
    const statusLabels = ["INVESTIGATE", "REVIEW", "MONITOR", "DEPRIORITIZED"];
    const statusCounts = countBy(alerts, a => a.status);
    makeChart("chartQueue", {
      type: "bar",
      data: {
        labels: statusLabels,
        datasets: [{
          data: statusLabels.map(s => statusCounts[s] || 0),
          backgroundColor: [COLORS.red, COLORS.orange, COLORS.cyan, COLORS.gray],
          borderRadius: 4,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: { x: { grid: { display: false } }, y: { grid: { color: COLORS.grid }, beginAtZero: true, ticks: { precision: 0 } } },
      },
    });
  }

  window.SentinelCharts = { update };
})();
