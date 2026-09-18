"""
Turn raw log lines (or generator dicts) into structured events.
Also converts a structured event into a feature vector for ML scoring.
"""
import re
from datetime import datetime
from typing import Dict, Optional

# Common combined-log format:
# 127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_line(line: str) -> Optional[Dict]:
    """Parse a single raw log line. Returns None if it doesn't match."""
    m = COMBINED_LOG_RE.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = datetime.strptime(g["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        ts = datetime.utcnow()

    return {
        "timestamp": ts,
        "ip": g["ip"],
        "method": g["method"],
        "path": g["path"],
        "status": int(g["status"]),
        "bytes_sent": int(g["bytes"]) if g["bytes"] != "-" else 0,
        "response_time_ms": 0.0,  # not present in combined format
        "user_agent": g["ua"],
    }


# --- Feature engineering helpers (used by ml/features.py) ---

SUSPICIOUS_PATTERNS = [
    ("'", 1), ("--", 1), ("union", 1), ("select", 1),
    ("<script", 1), ("onerror", 1), ("../", 1), ("..%2f", 1),
    ("/etc/", 1), ("/root", 1),
]

SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "masscan", "curl", "python-requests", "go-http"]


def path_suspicion_score(path: str) -> float:
    """0.0 = clean, higher = more suspicious. Simple, explainable heuristic."""
    p = path.lower()
    score = 0.0
    for token, weight in SUSPICIOUS_PATTERNS:
        if token in p:
            score += weight
    return score


def agent_suspicion_score(ua: str) -> float:
    if not ua:
        return 0.0
    u = ua.lower()
    return 1.0 if any(a in u for a in SUSPICIOUS_AGENTS) else 0.0


def status_bucket(status: int) -> int:
    """0 = 2xx, 1 = 3xx, 2 = 4xx, 3 = 5xx"""
    if 200 <= status < 300:
        return 0
    if 300 <= status < 400:
        return 1
    if 400 <= status < 500:
        return 2
    return 3


if __name__ == "__main__":
    sample = '127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
    print(parse_line(sample))
    print("path suspicion:", path_suspicion_score("/login?id=1' OR '1'='1"))
    print("agent suspicion:", agent_suspicion_score("sqlmap/1.7"))
