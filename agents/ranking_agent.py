"""
PRIORITY RANKING AGENT
-----------------------
The core "intelligence" of Sentinel AI. Instead of a black-box ML model,
this uses a simple, fully explainable weighted scoring system so every
score can be broken down and justified to a human analyst.

Risk Score = Severity + Asset Criticality + User Privilege
             + Threat Intel + Novelty - False Positive Adjustment
(clamped between 0 and 100)
"""

SEVERITY_SCORE = {"Critical": 30, "High": 20, "Medium": 10, "Low": 5}
ASSET_SCORE = {"Critical": 25, "High": 18, "Medium": 10, "Low": 5}

INVESTIGATION_STEPS = {
    "default": [
        "Verify the user's recent login and activity history.",
        "Review authentication logs for this asset.",
        "Check endpoint process history for anomalies.",
        "Investigate related source IP activity.",
    ],
    "PowerShell": [
        "Review PowerShell command-line history and encoded commands.",
        "Check for parent process anomalies (e.g. Office spawning PowerShell).",
        "Verify if execution was authorized by change management.",
        "Correlate with EDR script-block logging.",
    ],
    "Login": [
        "Confirm login geolocation against the user's normal pattern.",
        "Check for concurrent sessions or impossible travel.",
        "Review MFA status and any recent MFA changes.",
        "Verify with the user directly if activity is unrecognized.",
    ],
}


def _pick_steps(alert_type):
    for key, steps in INVESTIGATION_STEPS.items():
        if key.lower() in alert_type.lower():
            return steps
    return INVESTIGATION_STEPS["default"]


def rank(alert):
    """Compute an explainable risk score and attach reasoning to the alert."""
    breakdown = {}
    breakdown["Severity"] = SEVERITY_SCORE.get(alert["severity"], 5)
    breakdown["Critical Asset"] = ASSET_SCORE.get(alert["asset_context"]["criticality"], 5)
    breakdown["Privileged User"] = 15 if alert["user_context"]["privilege"] == "Privileged" else 5
    breakdown["Threat Intel Match"] = 20 if alert["threat_intel_match"] else 0
    breakdown["Novel Behavior"] = 10 if alert.get("novel") else 0
    breakdown["False Positive"] = -30 if alert["false_positive"] else 0

    raw_score = sum(breakdown.values())
    score = max(0, min(100, raw_score))

    alert["risk_score"] = score
    alert["breakdown"] = breakdown
    alert["confidence"] = max(50, min(99, 55 + breakdown["Threat Intel Match"] + breakdown["Critical Asset"] // 2))

    # --- Natural language explanation, generated from the same factors ---
    reasons = []
    if breakdown["Privileged User"] == 15:
        reasons.append("a privileged account")
    if breakdown["Critical Asset"] >= 18:
        reasons.append(f"a {alert['asset_context']['criticality'].lower()}-criticality asset ({alert['asset']})")
    if breakdown["Novel Behavior"]:
        reasons.append("unusual or new behavior")
    if alert["threat_intel_match"]:
        reasons.append(f"a known threat-intelligence indicator ({alert['threat_type']})")

    if reasons:
        explanation = "Alert ranked highly because it involves " + ", ".join(reasons) + "."
    else:
        explanation = "Alert has no strong risk factors and appears routine."

    if alert["false_positive"]:
        explanation += f" It also matches a known false-positive pattern ({alert['fp_reason']}), which lowered its score."
    else:
        explanation += " No strong historical false-positive pattern was found."

    alert["explanation"] = explanation
    alert["recommended_steps"] = _pick_steps(alert["type"])

    if alert["false_positive"]:
        alert["status"] = "DEPRIORITIZED"
    elif score >= 70:
        alert["status"] = "INVESTIGATE"
    elif score >= 40:
        alert["status"] = "REVIEW"
    else:
        alert["status"] = "MONITOR"

    return alert
