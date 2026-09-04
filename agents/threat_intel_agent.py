"""
THREAT INTELLIGENCE AGENT
-------------------------
Checks an alert's IP / domain / file hash against a small mock threat
intelligence database (data/threat_intel.json). No real external API needed.
"""
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(BASE_DIR, "data", "threat_intel.json")) as f:
    THREAT_INTEL = json.load(f)


def check(alert):
    """Look for an IOC match and attach threat intel fields to the alert."""
    match = None

    for ioc in THREAT_INTEL["ips"]:
        if alert.get("source_ip") and alert["source_ip"] == ioc["indicator"]:
            match = ioc
            break
    if not match:
        for ioc in THREAT_INTEL["domains"]:
            if alert.get("domain") and alert["domain"] == ioc["indicator"]:
                match = ioc
                break
    if not match:
        for ioc in THREAT_INTEL["hashes"]:
            if alert.get("hash") and alert["hash"] == ioc["indicator"]:
                match = ioc
                break

    if match:
        alert["threat_intel_match"] = True
        alert["threat_confidence"] = match["confidence"]
        alert["threat_type"] = match["threat"]
    else:
        alert["threat_intel_match"] = False
        alert["threat_confidence"] = 0
        alert["threat_type"] = "None"

    return alert
