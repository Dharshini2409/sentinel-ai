"""
CONTEXT ENRICHMENT AGENT
------------------------
Attaches asset context (criticality, department, owner) and user context
(role, privilege level) to each alert, loaded from simple JSON "databases".
"""
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(BASE_DIR, "data", "assets.json")) as f:
    ASSETS = json.load(f)

with open(os.path.join(BASE_DIR, "data", "users.json")) as f:
    USERS = json.load(f)

DEFAULT_ASSET = {"criticality": "Low", "department": "Unknown", "owner": "Unknown",
                  "environment": "Unknown", "internet_facing": False}
DEFAULT_USER = {"role": "Unknown", "privilege": "Normal", "department": "Unknown"}


def enrich(alert):
    """Attach asset_context and user_context to an alert in place."""
    alert["asset_context"] = ASSETS.get(alert["asset"], DEFAULT_ASSET)
    alert["user_context"] = USERS.get(alert["user"], DEFAULT_USER)
    return alert
