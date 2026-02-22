from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Event:
    ts: datetime
    source: str
    event_type: str
    ip: Optional[str] = None
    raw: str = ""