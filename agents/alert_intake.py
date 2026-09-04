"""
ALERT INTAKE AGENT
------------------
Takes raw alerts (which may come from different tools/formats) and
normalizes them into one common dictionary structure with a unique ID.
"""

REQUIRED_FIELDS = ["type", "severity", "user", "asset"]


def normalize_alerts(raw_alerts):
    """Turn a list of raw alert dicts into normalized, validated alerts."""
    normalized = []
    for i, raw in enumerate(raw_alerts, start=1):
        alert = {
            "id": f"ALT-{i:03d}",
            "timestamp": raw.get("timestamp", ""),
            "type": raw.get("type", "Unknown Alert"),
            "source": raw.get("source", "EDR"),
            "severity": raw.get("severity", "Low"),
            "source_ip": raw.get("source_ip", ""),
            "domain": raw.get("domain", ""),
            "hash": raw.get("hash", ""),
            "destination": raw.get("destination", ""),
            "user": raw.get("user", ""),
            "asset": raw.get("asset", ""),
            "novel": raw.get("novel", False),
        }
        # basic validation: fall back to safe defaults instead of failing
        for field in REQUIRED_FIELDS:
            if not alert.get(field):
                alert[field] = "Unknown"
        normalized.append(alert)
    return normalized
