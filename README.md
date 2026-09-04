# SENTINEL AI
### Agentic Intelligence for Security Operations

> AI recommends. Human analyst approves.

## Problem

SOC (Security Operations Center) analysts get flooded with hundreds of alerts a day.
Most are duplicates, routine scans, or known false positives. Real threats get buried
in the noise, and analysts waste hours manually triaging events that don't matter —
this is **alert fatigue**.

## Solution

Sentinel AI is an **agentic triage pipeline**: five small, specialized Python agents
each do one job, and hand the alert to the next agent. By the end, every alert has an
explainable 0-100 risk score and a clear reason for its ranking. The system never
performs remediation on its own — it only recommends what to investigate first.

## Architecture

```
Raw Alerts (SIEM / EDR)
        |
        v
Alert Intake Agent        -> normalizes format, assigns alert IDs
        |
        v
Context Enrichment Agent  -> attaches asset criticality + user privilege
        |
        v
Threat Intelligence Agent -> checks IP / domain / hash vs known IOCs
        |
        v
False Positive Agent      -> flags alerts matching known benign patterns
        |
        v
Priority Ranking Agent    -> explainable weighted risk score (0-100)
        |
        v
Human Analyst Dashboard   -> ranked queue, "why this score?", human approval
```

## The Five Agents

| # | Agent | File | Responsibility |
|---|-------|------|-----------------|
| 1 | Alert Intake | `agents/alert_intake.py` | Normalize raw alerts into one structure, assign IDs |
| 2 | Context Enrichment | `agents/context_agent.py` | Attach asset & user context (criticality, privilege) |
| 3 | Threat Intelligence | `agents/threat_intel_agent.py` | Match IP/domain/hash against mock IOC database |
| 4 | False Positive | `agents/false_positive_agent.py` | Detect known benign patterns using historical rates |
| 5 | Priority Ranking | `agents/ranking_agent.py` | Compute explainable weighted risk score + reasoning |

Each agent is just a small Python function — no ML models, no complicated
infrastructure. This keeps the whole system explainable and easy to demo.

### Risk score formula

```
Risk Score = Severity + Asset Criticality + User Privilege
             + Threat Intel Match + Novelty - False Positive Adjustment
(clamped 0-100)
```

Weights: Severity (Critical=30/High=20/Medium=10/Low=5), Asset Criticality
(Critical=25/High=18/Medium=10/Low=5), Privileged User=15/Normal=5,
Threat Intel Match=+20, Novel Behavior=+10, Known False Positive=-30.

## Technology Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, vanilla JavaScript
- **Data:** JSON mock databases (assets, users, threat intel, false-positive patterns) + in-memory alert store
- **Charts:** Chart.js (CDN)
- **Icons:** Font Awesome (CDN)

No React, no Docker, no databases to configure, no external AI API required.
The whole thing runs with two commands.

## How to Run

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000** in your browser.

## Demo Instructions

1. Open the landing page and click **Launch SOC**.
2. On the dashboard, click **Start Hackathon Demo**.
3. Watch the five agents light up in sequence as the batch of 40 mock alerts
   is normalized, enriched, checked against threat intel, screened for false
   positives, and ranked.
4. The **Priority Investigation Queue** fills in, sorted by risk score.
5. Click any row to open **"Why this score?"** — a full breakdown and a
   plain-language explanation of the ranking.
6. A final summary screen shows: alerts analyzed, critical/high priorities,
   false positives deprioritized, and the top recommendation.

## Example Output

```
Rank 1  Privileged Login              Risk 92   Finance-DB-01   admin01        INVESTIGATE
Rank 2  Multiple Failed Logins        Risk 78   Finance-Server  finance_mgr    INVESTIGATE
Rank 3  PowerShell Execution          Risk 74   Domain-Controller admin01      INVESTIGATE
...
Rank 40 Scheduled Vulnerability Scan  Risk 5    HR-Server       hr_user        DEPRIORITIZED
```

## Safety & Ethics

- This is a **defensive** cybersecurity project using entirely mock data.
- No real attack execution, no malware, no exploitation.
- Sentinel AI **never auto-remediates** — it only ranks and explains.
  A human analyst always makes the final call.

## Future Scope

- Real SIEM/EDR ingestion via API connectors.
- Persistent SQLite storage of historical alerts and analyst decisions.
- Feedback loop: analyst verdicts refine false-positive pattern weights over time.
- Optional LLM-generated natural-language summaries (works fully offline without one).
