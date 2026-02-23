from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def ensure_utc(ts: datetime) -> datetime:
    """
    Force a datetime into timezone-aware UTC.
    - If naive: assume UTC.
    - If aware: convert to UTC.
    """
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
