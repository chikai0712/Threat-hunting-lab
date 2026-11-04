"""Deterministic demo detections. Sigma conversion/correlation are future integrations."""

RULES = [
    {
        "id": "endpoint-auth-failure",
        "source": "wazuh",
        "technique": "T1110",
        "title": "Wazuh authentication failure alert",
        "severity": "high",
    },
    {
        "id": "network-ids-alert",
        "source": "suricata",
        "technique": None,
        "title": "High-priority network IDS alert",
        "severity": "high",
    },
    {
        "id": "cloud-stop-logging",
        "source": "cloudtrail",
        "technique": "T1562.008",
        "title": "CloudTrail logging disabled",
        "severity": "high",
    },
    {
        "id": "container-shell",
        "source": "falco",
        "technique": "T1059.004",
        "title": "Shell spawned in a container",
        "severity": "medium",
    },
]


def detect(event):
    action = event.action.lower()
    matched = {
        "endpoint-auth-failure": event.severity in ("high", "critical")
        and any(term in action for term in ("authentication fail", "failed password")),
        "network-ids-alert": event.severity in ("high", "critical"),
        "cloud-stop-logging": event.action == "StopLogging" and not event.details.get("errorCode"),
        "container-shell": "shell" in action and "container" in action,
    }
    return [rule for rule in RULES if rule["source"] == event.source and matched[rule["id"]]]
