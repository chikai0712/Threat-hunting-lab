"""Best-effort parsing. Original log text is always retained by the storage layer."""

import json
import re
import shlex
from datetime import datetime, timezone

SYSLOG = re.compile(r"^<(?P<priority>\d{1,3})>(?P<body>.*)$", re.S)
RFC3164 = re.compile(
    r"^(?P<time>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<message>.*)$", re.S
)
SEVERITIES = ["critical", "critical", "critical", "high", "medium", "low", "info", "info"]


def timestamp(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp has no timezone")
    return parsed.isoformat()


def parse_syslog(raw):
    match = SYSLOG.match(raw)
    if not match or int(match["priority"]) > 191:
        raise ValueError("invalid syslog priority/header")
    priority = int(match["priority"])
    fields = {"facility": priority // 8, "syslog_severity": priority % 8}
    result = {"fields": fields, "severity": SEVERITIES[priority % 8]}
    body = match["body"]
    if re.match(r"[1-9]\d{0,2} ", body):
        parts = body.split(" ", 6)
        if len(parts) != 7:
            raise ValueError("incomplete RFC5424 header")
        version, time, host, app, procid, msgid, rest = parts
        fields.update(version=version, app=app, procid=procid, msgid=msgid)
        result["host"] = None if host == "-" else host
        if time != "-":
            result["timestamp"] = timestamp(time)
        # Find the end of structured data without treating escaped ] as delimiters.
        if rest.startswith("-"):
            end = 1
        elif rest.startswith("["):
            end = 0
            while end < len(rest) and rest[end] == "[":
                end += 1
                escaped = False
                for pos in range(end, len(rest)):
                    char = rest[pos]
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == "]":
                        end = pos + 1
                        break
                else:
                    raise ValueError("unclosed RFC5424 structured data")
        else:
            raise ValueError("missing RFC5424 structured data")
        if rest[end:] and not rest[end:].startswith(" "):
            raise ValueError("invalid structured data separator")
        fields["structured_data"] = rest[:end]
        result["message"] = rest[end:].lstrip(" ").lstrip("\ufeff")
        result["parser"] = "syslog_rfc5424"
    else:
        legacy = RFC3164.match(body)
        if not legacy:
            if re.match(r"[A-Za-z_][\w.-]*=", body) or body.startswith("CEF:"):
                result.update(message=body, parser="syslog_vendor")
                return result
            raise ValueError("unsupported syslog header")
        fields["original_timestamp"] = legacy["time"]
        fields["timestamp_note"] = "RFC3164 omits year/timezone; using receipt time"
        result.update(host=legacy["host"], message=legacy["message"], parser="syslog_rfc3164")
    return result


def unescape(value):
    return re.sub(r"\\([\\|=nr])", lambda m: {"n": "\n", "r": "\r"}.get(m[1], m[1]), value)


def parse_cef(raw):
    # Seven unescaped separators delimit CEF header fields.
    parts, start, escaped = [], 0, False
    for i, char in enumerate(raw):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            parts.append(unescape(raw[start:i]))
            start = i + 1
            if len(parts) == 7:
                break
    if len(parts) != 7 or parts[0] not in ("CEF:0", "CEF:1"):
        raise ValueError("invalid CEF header")
    extension = raw[start:]
    matches = list(re.finditer(r"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=", extension))
    fields = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
        fields[match[1]] = unescape(extension[match.end() : end].rstrip())
    _, vendor, product, version, signature, name, severity = parts
    fields.update(device_version=version, signature_id=signature, cef_severity=severity)
    mapped = {
        "unknown": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "very-high": "critical",
    }
    if severity.isdigit() and 0 <= int(severity) <= 10:
        number = int(severity)
        level = (
            "critical"
            if number >= 9
            else "high"
            if number >= 7
            else "medium"
            if number >= 4
            else "low"
        )
    elif severity.lower() in mapped:
        level = mapped[severity.lower()]
    else:
        raise ValueError("invalid CEF severity")
    return {
        "parser": "cef",
        "message": name,
        "vendor": vendor,
        "product": product,
        "severity": level,
        "fields": fields,
    }


def parse_payload(raw, format):
    if format == "json" or (format == "auto" and raw.lstrip().startswith("{")):
        fields = json.loads(raw)
        if not isinstance(fields, dict):
            raise ValueError("JSON log must be an object")
        result = {
            "parser": "json",
            "fields": fields,
            "message": str(fields.get("message", fields.get("msg", "JSON event"))),
        }
        host = fields.get("hostname", fields.get("ComputerName", fields.get("host")))
        if isinstance(host, dict):
            host = host.get("name")
        if isinstance(host, str):
            result["host"] = host
        level = str(fields.get("severity", fields.get("level", "info"))).lower()
        result["severity"] = {
            "error": "high",
            "warning": "medium",
            "warn": "medium",
            "fatal": "critical",
            "debug": "info",
        }.get(level, level)
        if result["severity"] not in ("info", "low", "medium", "high", "critical"):
            result["severity"] = "info"
        # Vendor timestamps stay in fields unless explicitly timezone-aware ISO8601.
        value = fields.get("timestamp", fields.get("@timestamp"))
        if value:
            try:
                result["timestamp"] = timestamp(value)
            except (ValueError, TypeError):
                result["timestamp_note"] = "unrecognized timestamp; using receipt time"
        return result
    if format == "cef" or (format == "auto" and raw.startswith("CEF:")):
        return parse_cef(raw)
    if format == "kv" or (format == "auto" and re.match(r"[A-Za-z_][\w.-]*=", raw)):
        fields = {}
        for token in shlex.split(raw):
            key, sep, value = token.partition("=")
            if sep:
                fields[key] = value
        if not fields:
            raise ValueError("no key=value fields")
        return {
            "parser": "kv",
            "fields": fields,
            "host": fields.get("devname", fields.get("hostname")),
            "message": fields.get("msg", fields.get("message", raw)),
        }
    return {"parser": "text", "fields": {}, "message": raw}


def parse_log(raw, format="auto"):
    try:
        if format == "syslog" or (format == "auto" and raw.startswith("<")):
            result = parse_syslog(raw)
            nested = parse_payload(result["message"], "auto")
            if nested["parser"] != "text":
                result["payload_parser"] = nested["parser"]
                result["fields"]["payload"] = nested["fields"]
                for key in ("message", "vendor", "product", "severity", "host"):
                    if nested.get(key) is not None:
                        result[key] = nested[key]
        else:
            result = parse_payload(raw, format)
        result["status"] = "unparsed" if result["parser"] == "text" else "parsed"
        return result
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        # Preserve raw text and mark failure instead of silently losing an event.
        return {
            "parser": format,
            "status": "error",
            "error": type(exc).__name__,
            "fields": {},
            "message": raw,
        }


def received_now():
    return datetime.now(timezone.utc).isoformat()
