import re

IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

def parse_auth_log_line(line: str):
    """
    Returns a tuple: (event_type, ip) or (None, None)
    event_type: "failed" | "success"
    """
    ip_match = IP_RE.search(line)
    ip = ip_match.group(0) if ip_match else None

    if "Failed password" in line:
        return ("failed", ip)

    if "Accepted password" in line:
        return ("success", ip)

    return (None, None)