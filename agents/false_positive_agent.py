"""
FALSE POSITIVE AGENT
--------------------
Compares an alert's type against known benign patterns with historical
false-positive rates (data/false_positive_patterns.json). This is what
directly fights alert fatigue: alerts that look like routine noise get
flagged and pushed down the queue instead of wasting analyst time.
"""
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(BASE_DIR, "data", "false_positive_patterns.json")) as f:
    PATTERNS = json.load(f)


def check(alert):
    """Attach false_positive fields to the alert based on known patterns."""
    for pattern in PATTERNS:
        if pattern["pattern"].lower() in alert["type"].lower():
            alert["false_positive"] = pattern["rate"] >= 85
            alert["false_positive_rate"] = pattern["rate"]
            alert["fp_reason"] = f"Matches known benign pattern: {pattern['pattern']}"
            return alert

    alert["false_positive"] = False
    alert["false_positive_rate"] = 0
    alert["fp_reason"] = "No matching historical false-positive pattern"
    return alert
