# mini-siem/analyzer/parsers/web_parser.py
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from analyzer.engine.normalize import Event

# Example line:
# 2026-02-22T01:20:00Z 203.0.113.10 GET /login 401
WEB_RE = re.compile(
    r"^(?P<ts>\S+)\s+"
    r"(?P<ip>(\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<method>[A-Z]+)\s+"
    r"(?P<path>\S+)\s+"
    r"(?P<status>\d{3})"
    r"(?:\s+(?P<rest>.*))?$"
)


def _parse_ts(ts_str: str) -> Optional[datetime]:
    try:
        # handle "Z"
        if ts_str.endswith("Z"):
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).astimezone(timezone.utc)
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def parse_web_line(line: str) -> Optional[Event]:
    m = WEB_RE.match(line.strip())
    if not m:
        return None

    ts = _parse_ts(m.group("ts"))
    if not ts:
        return None

    ip = m.group("ip")
    method = m.group("method")
    path = m.group("path")
    status = int(m.group("status"))

    # No "user=" or "extra=" fields because your Event() signature doesn't support them.
    # Put additional details into raw (or encode into event_type if you want).
    raw = f"{method} {path} {status}"

    return Event(
        ts=ts,
        source="web",
        event_type="web_request",
        ip=ip,
        raw=raw,
    )