/* ==========================================================================
   SENTINEL AI - dashboard logic
   Talks to the Flask API (/api/simulate, /api/process, /api/alerts) and
   drives the agent-activity animation + priority queue + modal.
   ========================================================================== */

let CURRENT_ALERTS = [];
let CURRENT_STATS = {};

const AGENT_ORDER = ["intake", "context", "threat", "fp", "rank"];

function agentRow(key) {
  return document.querySelector(`.agent-row[data-agent="${key}"]`);
}

function setAgent(key, status, detail) {
  const row = agentRow(key);
  if (!row) return;
  row.classList.remove("processing", "complete");
  if (status === "PROCESSING") row.classList.add("processing");
  if (status === "COMPLETE") row.classList.add("complete");
  row.querySelector("[data-status]").textContent = status;
  if (detail) row.querySelector("[data-detail]").textContent = detail;
}

function resetAgents() {
  AGENT_ORDER.forEach(k => setAgent(k, "IDLE", "Waiting for alert batch…"));
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* -------------------------------------------------------------------------
   Main pipeline run: calls the backend, then plays a short animation that
   reflects the real results (not fake numbers).
   ------------------------------------------------------------------------- */
async function runFullPipeline({ isDemo = false } = {}) {
  const btnSim = document.getElementById("btnSimulate");
  const btnDemo = document.getElementById("btnDemo");
  btnSim.disabled = true;
  btnDemo.disabled = true;
  resetAgents();

  document.getElementById("queueBody").innerHTML =
    `<tr><td colspan="10" style="text-align:center; color:var(--text-faint); padding:30px;">
      <i class="fa-solid fa-spinner fa-spin"></i> Processing alert batch…
    </td></tr>`;

  // Step 1: generate raw alerts
  const simRes = await fetch("/api/simulate", { method: "POST" }).then(r => r.json());

  // Step 2: run the real agent pipeline on the backend
  const processed = await fetch("/api/process", { method: "POST" }).then(r => r.json());
  CURRENT_ALERTS = processed.alerts;
  CURRENT_STATS = processed.stats;

  // Step 3: animate each agent lighting up in sequence, using real numbers
  setAgent("intake", "PROCESSING", `Normalizing ${simRes.count} raw alerts…`);
  await sleep(500);
  setAgent("intake", "COMPLETE", `${CURRENT_STATS.total} alerts normalized`);

  setAgent("context", "PROCESSING", "Attaching asset & user context…");
  await sleep(550);
  setAgent("context", "COMPLETE", `${CURRENT_STATS.total} alerts enriched with context`);

  setAgent("threat", "PROCESSING", "Checking IPs, domains & hashes against IOC feed…");
  await sleep(550);
  setAgent("threat", "COMPLETE", `${CURRENT_STATS.ioc_matches} IOC matches found`);

  setAgent("fp", "PROCESSING", "Comparing against known benign patterns…");
  await sleep(550);
  setAgent("fp", "COMPLETE", `${CURRENT_STATS.false_positives} benign patterns detected`);

  setAgent("rank", "PROCESSING", "Calculating explainable risk scores…");
  await sleep(600);
  setAgent("rank", "COMPLETE", `${CURRENT_STATS.total} alerts ranked`);

  renderStats(CURRENT_STATS);
  renderComparison(CURRENT_STATS);
  renderQueue(CURRENT_ALERTS, { highlightTop: isDemo });
  if (window.SentinelCharts) window.SentinelCharts.update(CURRENT_ALERTS, CURRENT_STATS);

  btnSim.disabled = false;
  btnDemo.disabled = false;

  if (isDemo) {
    await sleep(600);
    showSummary(CURRENT_STATS, CURRENT_ALERTS[0]);
  }
}

/* -------------------------------------------------------------------------
   Stats + comparison rendering
   ------------------------------------------------------------------------- */
function renderStats(stats) {
  document.getElementById("statTotal").textContent = stats.total;
  document.getElementById("statCritical").textContent = stats.critical;
  document.getElementById("statHigh").textContent = stats.high;
  document.getElementById("statFP").textContent = stats.false_positives;
  document.getElementById("statAvg").textContent = stats.avg_risk;
  const hrs = Math.floor(stats.time_saved_minutes / 60);
  const mins = stats.time_saved_minutes % 60;
  document.getElementById("statSaved").textContent = hrs > 0 ? `${hrs}h ${mins}m` : `${mins}m`;
}

function renderComparison(stats) {
  document.getElementById("cmpWithoutTotal").textContent = stats.total;
  document.getElementById("cmpWithoutManual").textContent = stats.total;
  document.getElementById("cmpWithTotal").textContent = stats.total;
  document.getElementById("cmpWithPriority").textContent = stats.total - stats.false_positives;
  document.getElementById("cmpWithFP").textContent = stats.false_positives;
  document.getElementById("cmpWithReduction").textContent = stats.workload_reduction + "%";
}

/* -------------------------------------------------------------------------
   Priority queue table
   ------------------------------------------------------------------------- */
function severityBadge(sev) {
  const cls = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" }[sev] || "badge-low";
  return `<span class="badge ${cls}">${sev.toUpperCase()}</span>`;
}
function statusBadge(status) {
  const cls = { INVESTIGATE: "badge-investigate", REVIEW: "badge-review", MONITOR: "badge-monitor", DEPRIORITIZED: "badge-deprioritized" }[status];
  return `<span class="badge ${cls}">${status}</span>`;
}
function riskClass(score) {
  if (score >= 70) return "r-crit";
  if (score >= 45) return "r-high";
  if (score >= 25) return "r-med";
  return "r-low";
}

function renderQueue(alerts, opts = {}) {
  const body = document.getElementById("queueBody");
  body.innerHTML = "";
  alerts.forEach(a => {
    const tr = document.createElement("tr");
    if (a.false_positive) tr.classList.add("row-fp");
    if (opts.highlightTop && a.rank <= 3) tr.style.background = "rgba(255,59,92,0.05)";
    tr.innerHTML = `
      <td class="rank-cell">#${a.rank}</td>
      <td><b>${a.type}</b><br><span style="color:var(--text-faint); font-size:11.5px;">${a.id}</span></td>
      <td class="risk-cell ${riskClass(a.risk_score)}">${a.risk_score}</td>
      <td>${severityBadge(a.severity)}</td>
      <td>${a.asset}</td>
      <td>${a.user}</td>
      <td>${a.threat_intel_match ? '<span class="badge badge-match">MATCH</span>' : '<span class="badge badge-nomatch">NO</span>'}</td>
      <td>${a.false_positive ? `${a.false_positive_rate}%` : "None"}</td>
      <td>${a.confidence}%</td>
      <td>${statusBadge(a.status)}</td>
    `;
    tr.addEventListener("click", () => openModal(a.id));
    body.appendChild(tr);
  });
}

/* -------------------------------------------------------------------------
   Alert detail modal ("Why this score?")
   ------------------------------------------------------------------------- */
function openModal(alertId) {
  const a = CURRENT_ALERTS.find(x => x.id === alertId);
  if (!a) return;

  const breakdownRows = Object.entries(a.breakdown).map(([label, val]) => `
    <div class="breakdown-row">
      <span>${label}</span>
      <b class="${val < 0 ? "neg" : "pos"}">${val > 0 ? "+" : ""}${val}</b>
    </div>`).join("");

  const stepsHtml = a.recommended_steps.map(s => `<li>${s}</li>`).join("");

  document.getElementById("modalBody").innerHTML = `
    <div class="modal-head">
      <div>
        <div style="font-family:var(--font-head); font-weight:700; font-size:18px;">${a.type}</div>
        <div style="color:var(--text-faint); font-size:12.5px; margin-top:2px;">${a.id} · Rank #${a.rank} · ${statusBadge(a.status)}</div>
      </div>
      <div class="modal-close" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Alert Details</div>
      <div class="kv-grid">
        <div class="kv"><span>Timestamp</span><span>${a.timestamp}</span></div>
        <div class="kv"><span>Source</span><span>${a.source}</span></div>
        <div class="kv"><span>Source IP</span><span>${a.source_ip || "—"}</span></div>
        <div class="kv"><span>User</span><span>${a.user}</span></div>
        <div class="kv"><span>Asset</span><span>${a.asset}</span></div>
        <div class="kv"><span>Severity</span><span>${a.severity}</span></div>
      </div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Asset & User Context</div>
      <div class="kv-grid">
        <div class="kv"><span>Asset Criticality</span><span>${a.asset_context.criticality}</span></div>
        <div class="kv"><span>Department</span><span>${a.asset_context.department}</span></div>
        <div class="kv"><span>User Role</span><span>${a.user_context.role}</span></div>
        <div class="kv"><span>Privilege</span><span>${a.user_context.privilege}</span></div>
      </div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Threat Intelligence</div>
      <div class="kv-grid">
        <div class="kv"><span>IOC Match</span><span>${a.threat_intel_match ? "Yes" : "No"}</span></div>
        <div class="kv"><span>Confidence</span><span>${a.threat_confidence}%</span></div>
        <div class="kv"><span>Threat Type</span><span>${a.threat_type}</span></div>
      </div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">False Positive Analysis</div>
      <div class="kv-grid">
        <div class="kv"><span>Matches Pattern</span><span>${a.false_positive ? "Yes" : "No"}</span></div>
        <div class="kv"><span>Historical Rate</span><span>${a.false_positive_rate}%</span></div>
      </div>
      <div style="font-size:12.5px; color:var(--text-muted); margin-top:8px;">${a.fp_reason}</div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">AI Priority Reasoning — Why This Score?</div>
      <div style="font-family:var(--font-head); font-size:26px; font-weight:700; margin-bottom:10px;" class="risk-cell ${riskClass(a.risk_score)}">${a.risk_score}/100</div>
      ${breakdownRows}
      <div class="explain-box" style="margin-top:12px;">${a.explanation}</div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Recommended Investigation</div>
      <ul class="steps-list">${stepsHtml}</ul>
    </div>

    <div class="approval-banner"><i class="fa-solid fa-user-shield"></i> HUMAN APPROVAL REQUIRED — Sentinel AI does not auto-remediate.</div>
  `;
  document.getElementById("modalOverlay").classList.add("open");
}
function closeModal() { document.getElementById("modalOverlay").classList.remove("open"); }
document.getElementById("modalOverlay").addEventListener("click", (e) => {
  if (e.target.id === "modalOverlay") closeModal();
});

/* -------------------------------------------------------------------------
   Final demo summary screen
   ------------------------------------------------------------------------- */
function showSummary(stats, topAlert) {
  document.getElementById("summaryCard").innerHTML = `
    <div class="summary-title"><i class="fa-solid fa-circle-check" style="color:var(--green)"></i> SOC Triage Complete</div>
    <div class="summary-grid">
      <div><div class="summary-num cyan" style="color:var(--cyan)">${stats.total}</div><div class="summary-label">ALERTS ANALYZED</div></div>
      <div><div class="summary-num" style="color:var(--red)">${stats.critical}</div><div class="summary-label">CRITICAL PRIORITIES</div></div>
      <div><div class="summary-num" style="color:var(--orange)">${stats.high}</div><div class="summary-label">HIGH PRIORITIES</div></div>
      <div><div class="summary-num" style="color:var(--gray)">${stats.false_positives}</div><div class="summary-label">FALSE POSITIVES DEPRIORITIZED</div></div>
      <div><div class="summary-num" style="color:var(--green)">85%</div><div class="summary-label">AI CONFIDENCE</div></div>
      <div><div class="summary-num" style="color:var(--cyan)">~${stats.workload_reduction}%</div><div class="summary-label">WORKLOAD REDUCTION</div></div>
    </div>
    <div class="summary-reco">
      <b>TOP RECOMMENDATION</b>
      "Investigate ${topAlert.type.toLowerCase()} on ${topAlert.asset} immediately — risk score ${topAlert.risk_score}/100."
    </div>
    <div class="human-approval-badge" style="justify-content:center; margin-bottom:22px;">
      <i class="fa-solid fa-user-shield"></i> AI RECOMMENDS. HUMAN ANALYST APPROVES.
    </div>
    <button class="btn btn-primary" onclick="document.getElementById('summaryOverlay').classList.remove('open')">
      <i class="fa-solid fa-table-list"></i> View Investigation Queue
    </button>
  `;
  document.getElementById("summaryOverlay").classList.add("open");
}

/* -------------------------------------------------------------------------
   Wire up buttons
   ------------------------------------------------------------------------- */
document.getElementById("btnSimulate").addEventListener("click", () => runFullPipeline({ isDemo: false }));
document.getElementById("btnDemo").addEventListener("click", () => runFullPipeline({ isDemo: true }));
