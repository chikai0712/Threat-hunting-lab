"""Versioned, best-effort source mappings into one common schema; raw remains intact."""

import csv
import ipaddress
import re
from datetime import datetime, timezone

from .log_parser import SEVERITIES, timestamp
from .sources import PROFILES


def first(fields, *keys):
    for key in keys:
        value = fields.get(key)
        if value is not None and value != "":
            return value
    return None


def scalar(value):
    return str(value) if isinstance(value, (str, int, float)) else None


def ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def port(value):
    try:
        number = int(value)
        return number if 0 <= number <= 65535 else None
    except (ValueError, TypeError):
        return None


def iso(value):
    try:
        return timestamp(value)
    except (ValueError, TypeError, OverflowError):
        return None


def normalize_source(record, parsed, received_at):
    source = record.source
    profile = PROFILES.get(source)
    fields = parsed.get("fields", {})
    fields = fields.get("payload", fields)
    if not isinstance(fields, dict):
        fields = {}
    result = {
        "schema_version": "1.0",
        "normalizer": f"{source}-v1" if profile else "generic-v1",
        "source": source,
        "vendor": record.vendor or (profile[1] if profile else parsed.get("vendor")),
        "product": record.product or (profile[2] if profile else parsed.get("product")),
        "timestamp": parsed.get("timestamp") or received_at,
        "timestamp_basis": "event" if parsed.get("timestamp") else "received",
        "host": record.host or parsed.get("host") or record.peer,
        "action": parsed.get("message") or "Log received",
        "category": "log",
        "severity": parsed.get("severity", "info"),
        "event_code": None,
        "source_ip": ip(first(fields, "srcip", "src", "source_ip")),
        "destination_ip": ip(first(fields, "dstip", "dst", "destination_ip")),
        "source_port": port(first(fields, "srcport", "spt", "source_port")),
        "destination_port": port(first(fields, "dstport", "dpt", "destination_port")),
        "protocol": scalar(first(fields, "proto", "protocol")),
        "user": scalar(first(fields, "user", "suser", "username")),
        "outcome": None,
        "parser_status": parsed["status"],
    }
    event_time = None
    if source == "fortinet":
        result.update(
            action=scalar(fields.get("action")) or result["action"],
            category=scalar(fields.get("type")) or "network",
            event_code=scalar(fields.get("logid")),
        )
        value = fields.get("eventtime")
        if value is not None:
            try:
                number = int(value)
                seconds = (
                    number / 1_000_000_000
                    if number > 10**16
                    else number / 1000
                    if number > 10**11
                    else number
                )
                event_time = datetime.fromtimestamp(seconds, timezone.utc).isoformat()
            except (ValueError, TypeError, OverflowError, OSError):
                pass
    elif source == "paloalto":
        # Map the documented shared prefix of default Traffic/Threat CSV only.
        # CEF and JSON use named fields above instead of positional guesses.
        payload = parsed.get("message", record.raw)
        try:
            columns = next(csv.reader([payload]))
        except (csv.Error, StopIteration):
            columns = []
        if len(columns) >= 31 and columns[3] in ("TRAFFIC", "THREAT"):
            result.update(
                category=columns[3].lower(),
                action=columns[30],
                source_ip=ip(columns[7]),
                destination_ip=ip(columns[8]),
                source_port=port(columns[24]),
                destination_port=port(columns[25]),
                protocol=columns[29],
                user=columns[12] or None,
            )
        else:
            result["action"] = scalar(first(fields, "act", "action")) or result["action"]
    elif source == "cisco":
        code = re.search(r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):", record.raw)
        if code:
            result.update(
                event_code=code[0].rstrip(":"),
                action=code[3],
                category="network",
                severity=SEVERITIES[int(code[2])],
            )
    elif source == "windows":
        event = fields.get("Event", fields)
        if not isinstance(event, dict):
            event = fields
        system = event.get("System", event)
        data = event.get("EventData", {})
        if not isinstance(system, dict):
            system = event
        if not isinstance(data, dict):
            data = {}
        code = first(system, "EventID", "EventId", "event_id")
        if isinstance(code, dict):
            code = code.get("#text")
        result.update(
            event_code=scalar(code),
            category="windows_event",
            host=scalar(first(system, "Computer", "ComputerName")) or result["host"],
            user=scalar(first(data, "TargetUserName", "SubjectUserName")) or result["user"],
            source_ip=ip(data.get("IpAddress")) or result["source_ip"],
        )
        if str(code) in ("4624", "4625"):
            result.update(
                action="logon",
                category="authentication",
                outcome="success" if str(code) == "4624" else "failure",
            )
        created = system.get("TimeCreated", {})
        event_time = iso(created.get("SystemTime")) if isinstance(created, dict) else None
        event_time = event_time or iso(first(system, "TimeGenerated", "timestamp"))
    elif source == "linux":
        match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)", record.raw
        )
        if match:
            result.update(
                action="logon",
                category="authentication",
                outcome="failure",
                user=match[1],
                source_ip=ip(match[2]),
                source_port=port(match[3]),
            )
    elif source == "aws":
        identity = fields.get("userIdentity", {})
        result.update(
            action=scalar(fields.get("eventName")) or result["action"],
            category="cloud_audit",
            source_ip=ip(fields.get("sourceIPAddress")),
            user=scalar(identity.get("arn")) if isinstance(identity, dict) else None,
            event_code=scalar(fields.get("eventID")),
            outcome="failure"
            if fields.get("errorCode")
            else "success"
            if fields.get("eventName")
            else None,
        )
        event_time = iso(fields.get("eventTime"))
    elif source == "kubernetes":
        metadata = fields.get("kubernetes", {})
        result.update(
            category="container", action=scalar(first(fields, "log", "message")) or result["action"]
        )
        if isinstance(metadata, dict):
            result.update(
                namespace=scalar(metadata.get("namespace_name")),
                pod=scalar(metadata.get("pod_name")),
                container=scalar(metadata.get("container_name")),
            )
    if event_time:
        result.update(timestamp=event_time, timestamp_basis="event")
    return result
