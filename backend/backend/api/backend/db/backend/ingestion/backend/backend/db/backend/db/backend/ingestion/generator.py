"""
Synthetic log generator.

Emits realistic web server access log lines in a structured dict.
Supports two modes:
- "normal"  : typical traffic (browsing, API calls, static assets)
- "attack"  : injected anomaly patterns (SQLi, XSS, path traversal, brute force, scraping)

This is what powers the live demo on Render — no real server needed.
"""
import random
from datetime import datetime
from typing import Dict, List

NORMAL_PATHS = [
    "/", "/about", "/projects", "/blog", "/contact",
    "/api/v1/users", "/api/v1/posts", "/api/v1/health",
    "/static/main.css", "/static/app.js", "/favicon.ico",
    "/images/hero.png", "/images/logo.svg",
]

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
]

ATTACK_PATHS = {
    "sqli": ["/login?id=1' OR '1'='1", "/api/users?name=admin'--", "/search?q=1 UNION SELECT * FROM users"],
    "xss": ["/comment?text=<script>alert(1)</script>", "/profile?name=<img src=x onerror=alert(1)>"],
    "traversal": ["/../../etc/passwd", "/static/..%2f..%2fetc%2fshadow", "/files?path=../../../root"],
    "bruteforce": ["/admin/login", "/wp-login.php", "/api/auth/login"],
    "scraping": ["/api/v1/users?page=1", "/api/v1/users?page=2", "/api/v1/users?page=3",
                 "/api/v1/posts?page=1", "/api/v1/posts?page=2"],
}

ATTACK_AGENTS = [
    "sqlmap/1.7", "Nikto/2.5", "python-requests/2.31", "curl/8.4.0",
    "Go-http-client/1.1", "masscan/1.3",
]


def _normal_event() -> Dict:
    path = random.choice(NORMAL_PATHS)
    status = random.choices([200, 200, 200, 301, 404], weights=[80, 8, 5, 4, 3])[0]
    return {
        "timestamp": datetime.utcnow(),
        "ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "method": random.choices(["GET", "POST"], weights=[85, 15])[0],
        "path": path,
        "status": status,
        "bytes_sent": random.randint(200, 20000),
        "response_time_ms": round(random.gauss(80, 30), 2),
        "user_agent": random.choice(NORMAL_AGENTS),
    }


def _attack_event(kind: str) -> Dict:
    path = random.choice(ATTACK_PATHS[kind])
    if kind == "bruteforce":
        status = random.choice([401, 403])
    elif kind == "sqli":
        status = random.choice([500, 200, 403])
    else:
        status = random.choice([400, 403, 404, 500])

    return {
        "timestamp": datetime.utcnow(),
        "ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "method": random.choices(["GET", "POST"], weights=[60, 40])[0],
        "path": path,
        "status": status,
        "bytes_sent": random.randint(0, 500),
        "response_time_ms": round(random.gauss(400, 120), 2),
        "user_agent": random.choice(ATTACK_AGENTS),
    }


def generate_batch(n: int = 20, attack_ratio: float = 0.05) -> List[Dict]:
    """
    Generate a batch of mixed events.
    attack_ratio: fraction of events that are attacks (default 5%).
    """
    events = []
    for _ in range(n):
        if random.random() < attack_ratio:
            kind = random.choice(list(ATTACK_PATHS.keys()))
            events.append(_attack_event(kind))
        else:
            events.append(_normal_event())
    return events


def generate_normal_batch(n: int = 200) -> List[Dict]:
    """Pure normal traffic — for training the model."""
    return [_normal_event() for _ in range(n)]


if __name__ == "__main__":
    # Quick sanity check when run directly
    for e in generate_batch(10, attack_ratio=0.3):
        print(f"{e['timestamp']} {e['ip']} {e['method']} {e['path']} {e['status']}")
