"""Small, explicit adapters for the documented fixture formats; not full vendor parsers."""

import hashlib
import json

from .models import Event


def normalize(source, payload):
    event_id = hashlib.sha256(
        (source + ":" + json.dumps(payload, sort_keys=True)).encode()
    ).hexdigest()
    base = {"event_id": event_id, "source": source, "details": payload}
    if source == "wazuh":
        rule = payload["rule"]
        level = int(rule["level"])
        return Event(
            **base,
            timestamp=payload["timestamp"],
            host=payload["agent"]["name"],
            action=rule["description"],
            severity="high" if level >= 10 else "low",
        )
    if source == "suricata":
        alert = payload["alert"]
        return Event(
            **base,
            timestamp=payload["timestamp"],
            host=payload.get("src_ip"),
            action=alert["signature"],
            severity="high" if int(alert["severity"]) <= 2 else "low",
        )
    if source == "falco":
        return Event(
            **base,
            timestamp=payload["time"],
            host=payload.get("hostname"),
            action=payload["rule"],
            severity="high"
            if payload["priority"] in ("Emergency", "Alert", "Critical", "Error", "Warning")
            else "low",
        )
    if source == "cloudtrail":
        return Event(
            **base,
            timestamp=payload["eventTime"],
            actor=payload.get("userIdentity", {}).get("arn"),
            action=payload["eventName"],
            severity="info",
        )
    raise ValueError("unsupported source")
