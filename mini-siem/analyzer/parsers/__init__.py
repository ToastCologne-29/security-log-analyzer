import re
from datetime import datetime

from analyzer.engine.normalize import Event

IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")


def parse_auth_log_line(line: str):
    ip_match = IP_RE.search(line)
    ip = ip_match.group(0) if ip_match else None

    ts = datetime.now()

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

from .auth_parser import parse_auth_line
from .web_parser import parse_web_line

__all__ = ["parse_auth_line", "parse_web_line"]