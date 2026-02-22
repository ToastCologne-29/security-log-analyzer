# mini-siem/analyzer/parsers/auth_parser.py
import re
from datetime import datetime, timezone

from analyzer.engine.normalize import Event

IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")


def parse_auth_line(line: str):
    ip_match = IP_RE.search(line)
    ip = ip_match.group(0) if ip_match else None

    ts = datetime.now(timezone.utc)  # <-- timezone-aware

    if "Failed password" in line:
        return Event(
            ts=ts,
            source="auth",
            event_type="login_failed",
            ip=ip,
            raw=line.strip(),
        )

    if "Accepted password" in line:
        return Event(
            ts=ts,
            source="auth",
            event_type="login_success",
            ip=ip,
            raw=line.strip(),
        )

    return None