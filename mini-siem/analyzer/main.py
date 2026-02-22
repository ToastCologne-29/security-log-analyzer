# mini-siem/analyzer/main.py
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict

from analyzer.engine.correlate import CorrelationEngine
from analyzer.output.reporter import build_report, write_report
from analyzer.parsers.auth_parser import parse_auth_line

# Optional: only import if you actually have web_parser.py
try:
    from analyzer.parsers.web_parser import parse_web_line
except Exception:
    parse_web_line = None


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Make sure dt is timezone-aware UTC (so sorting never breaks)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def read_events_from_file(source: str, filepath: str):
    p = Path(filepath)
    if not p.exists():
        return []

    events = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            evt = None

            if source == "auth":
                evt = parse_auth_line(line)
            elif source == "web" and parse_web_line:
                evt = parse_web_line(line)

            if evt:
                evt.ts = ensure_utc(evt.ts)
                events.append(evt)

    return events


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM: Security Event Correlation Engine")
    parser.add_argument("--auth-log", help="Path to auth log file", default=None)
    parser.add_argument("--web-log", help="Path to web log file", default=None)
    parser.add_argument("--out", help="Path to JSON report output", default="output/report.json")
    parser.add_argument("--window", type=int, default=600, help="Correlation window in seconds (reserved)")
    parser.add_argument("--threshold", type=int, default=5, help="Failed login threshold (reserved)")

    args = parser.parse_args()

    if not args.auth_log and not args.web_log:
        raise SystemExit("Provide at least one log source: --auth-log and/or --web-log")

    engine = CorrelationEngine()  # <-- your CorrelationEngine.__init__ takes no args

    started_at = datetime.now(timezone.utc)

    events = []
    inputs: Dict[str, str] = {}

    if args.auth_log:
        inputs["auth_log"] = args.auth_log
        events.extend(read_events_from_file("auth", args.auth_log))

    if args.web_log:
        inputs["web_log"] = args.web_log
        events.extend(read_events_from_file("web", args.web_log))

    # safe sort (all UTC-aware now)
    events.sort(key=lambda e: e.ts or datetime.min.replace(tzinfo=timezone.utc))

    alerts = []
    for evt in events:
        alerts.extend(engine.process(evt))

    ended_at = datetime.now(timezone.utc)

    report = build_report(
        started_at=started_at,
        ended_at=ended_at,
        inputs=inputs,
        total_events=len(events),
        alerts=alerts,
    )
    write_report(args.out, report)

    print(f"Processed events: {len(events)}")
    print(f"Alerts: {len(alerts)}")
    print(f"Saved report to: {args.out}")


if __name__ == "__main__":
    main()