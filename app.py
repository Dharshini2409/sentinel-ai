"""
SENTINEL AI - Agentic Intelligence for Security Operations
============================================================
A simple Flask app that demonstrates a 5-agent SOC alert triage pipeline.

Pipeline:
    Raw Alerts -> Alert Intake Agent -> Context Enrichment Agent
    -> Threat Intel Agent -> False Positive Agent -> Priority Ranking Agent
    -> Human Analyst Dashboard

IMPORTANT: This system never auto-remediates. It only ranks and explains.
"AI recommends. Human analyst approves."
"""
import json
import os
import random
from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template, request

from agents import alert_intake, context_agent, threat_intel_agent, false_positive_agent, ranking_agent

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# In-memory "database" of the current alert batch. Simple on purpose so it's
# easy to explain: no ORM, no external DB server, just a Python list.
STATE = {
    "alerts": [],
    "processed": False,
}

ASSETS = list(json.load(open(os.path.join(BASE_DIR, "data", "assets.json"))).keys())
USERS = list(json.load(open(os.path.join(BASE_DIR, "data", "users.json"))).keys())
THREAT_INTEL = json.load(open(os.path.join(BASE_DIR, "data", "threat_intel.json")))

BENIGN_TYPES = [
    # only patterns with a false-positive rate >= 85, so the 22-alert benign
    # block generated below is reliably deprioritized (matches the demo story)
    "Scheduled Vulnerability Scan",
    "EDR Heartbeat",
    "Backup Process",
    "Patch Scanning",
]
FILLER_TYPES = [
    "Port Scan Detected",
    "Unusual Outbound Traffic",
    "New Device Connected",
    "Failed Login Attempt",
    "File Integrity Change",
    "DNS Query to New Domain",
    "Suspicious Email Attachment",
    "Configuration Change Detected",
]


def _ts(minutes_ago):
    return (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")


def generate_mock_alerts(count=40):
    """
    Build a batch of mock alerts for the demo.
    Guarantees:
      - 3 clearly high-risk alerts (the "needle in the haystack" scenario)
      - 22 alerts matching known benign false-positive patterns
      - the remainder are varied low/medium noise alerts
    """
    raw = []

    # --- 3 guaranteed high-risk alerts -------------------------------------
    raw.append({
        "timestamp": _ts(4), "type": "Privileged Login", "source": "EDR",
        "severity": "Critical", "source_ip": THREAT_INTEL["ips"][0]["indicator"],
        "destination": "10.0.4.12", "user": "admin01", "asset": "Finance-DB-01",
        "novel": True,
    })
    raw.append({
        "timestamp": _ts(11), "type": "Multiple Failed Logins", "source": "SIEM",
        "severity": "High", "source_ip": "203.0.113.44",
        "destination": "10.0.4.9", "user": "finance_mgr", "asset": "Finance-Server",
        "novel": True,
    })
    raw.append({
        "timestamp": _ts(19), "type": "PowerShell Execution", "source": "EDR",
        "severity": "High", "source_ip": THREAT_INTEL["ips"][1]["indicator"],
        "destination": "10.0.1.5", "user": "admin01", "asset": "Domain-Controller",
        "novel": False,
    })

    # --- 22 known-benign alerts ---------------------------------------------
    for i in range(22):
        raw.append({
            "timestamp": _ts(random.randint(1, 58)),
            "type": random.choice(BENIGN_TYPES),
            "source": random.choice(["EDR", "SIEM", "Firewall"]),
            "severity": random.choice(["Low", "Medium"]),
            "source_ip": f"10.0.{random.randint(1,9)}.{random.randint(1,254)}",
            "destination": "internal",
            "user": random.choice(USERS),
            "asset": random.choice(ASSETS),
            "novel": False,
        })

    # --- remaining filler alerts (varied noise) -----------------------------
    remaining = count - len(raw)
    for i in range(remaining):
        is_threat_ip = random.random() < 0.15
        raw.append({
            "timestamp": _ts(random.randint(1, 58)),
            "type": random.choice(FILLER_TYPES),
            "source": random.choice(["EDR", "SIEM", "Firewall", "VPN"]),
            "severity": random.choice(["Low", "Medium", "High"]),
            "source_ip": THREAT_INTEL["ips"][2]["indicator"] if is_threat_ip
                         else f"172.16.{random.randint(1,9)}.{random.randint(1,254)}",
            "destination": "internal",
            "user": random.choice(USERS),
            "asset": random.choice(ASSETS),
            "novel": random.random() < 0.2,
        })

    random.shuffle(raw)
    return raw


def run_pipeline(raw_alerts):
    """Run the full 5-agent pipeline over a batch of raw alerts."""
    alerts = alert_intake.normalize_alerts(raw_alerts)
    for a in alerts:
        context_agent.enrich(a)
        threat_intel_agent.check(a)
        false_positive_agent.check(a)
        ranking_agent.rank(a)
    alerts.sort(key=lambda a: a["risk_score"], reverse=True)
    for idx, a in enumerate(alerts, start=1):
        a["rank"] = idx
    return alerts


def compute_stats(alerts):
    total = len(alerts)
    critical = sum(1 for a in alerts if a["severity"] == "Critical" and not a["false_positive"])
    high = sum(1 for a in alerts if a["severity"] == "High" and not a["false_positive"])
    false_positives = sum(1 for a in alerts if a["false_positive"])
    avg_risk = round(sum(a["risk_score"] for a in alerts) / total, 1) if total else 0
    investigate = sum(1 for a in alerts if a["status"] == "INVESTIGATE")
    workload_reduction = round((false_positives / total) * 100) if total else 0
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "false_positives": false_positives,
        "avg_risk": avg_risk,
        "investigate": investigate,
        "ioc_matches": sum(1 for a in alerts if a["threat_intel_match"]),
        "workload_reduction": workload_reduction,
        "time_saved_minutes": false_positives * 8,  # ~8 min saved per FP not manually reviewed
    }


# ---------------------------------------------------------------------------
# PAGES
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/threat-intel")
def threat_intel_page():
    return render_template("threat_intel.html", ti=THREAT_INTEL)


@app.route("/false-positives")
def false_positives_page():
    patterns = json.load(open(os.path.join(BASE_DIR, "data", "false_positive_patterns.json")))
    return render_template("false_positives.html", patterns=patterns)


@app.route("/architecture")
def architecture_page():
    return render_template("architecture.html")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Step 1: generate a fresh batch of 40 raw mock alerts."""
    raw = generate_mock_alerts(40)
    STATE["raw_alerts"] = raw
    STATE["processed"] = False
    return jsonify({"count": len(raw)})


@app.route("/api/process", methods=["POST"])
def api_process():
    """Step 2: run the raw batch through the full 5-agent pipeline."""
    raw = STATE.get("raw_alerts")
    if not raw:
        raw = generate_mock_alerts(40)
        STATE["raw_alerts"] = raw
    alerts = run_pipeline(raw)
    STATE["alerts"] = alerts
    STATE["processed"] = True
    return jsonify({"stats": compute_stats(alerts), "alerts": alerts})


@app.route("/api/alerts")
def api_alerts():
    return jsonify({"alerts": STATE.get("alerts", []), "stats": compute_stats(STATE.get("alerts", []))})


@app.route("/api/alert/<alert_id>")
def api_alert_detail(alert_id):
    for a in STATE.get("alerts", []):
        if a["id"] == alert_id:
            return jsonify(a)
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    app.run(debug=True, port=5000)
