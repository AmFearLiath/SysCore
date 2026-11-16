"""
SysCore Sentinel - Web Exploit Probes Scanner
Analysiert Webserver-Logs (NGINX) in Echtzeit auf verdächtige Angriffsmuster:
- SQL Injections
- Path Traversal
- Ausspähen sensibler Dateien (.env, .git, config)
- Automatisierte Schwachstellen-Scanner (sqlmap, nikto, nmap, etc.)
"""

import os
import re
from datetime import datetime
from typing import Dict, Any, List

SUSPICIOUS_PATTERNS = [
    (re.compile(r"(\.env|wp-login\.php|xmlrpc\.php|phpmyadmin|\.git/config|cgi-bin|eval-stdin)", re.I), "Web-Exploit / Probing"),
    (re.compile(r"(\.\./|etc/passwd|boot\.ini|win\.ini|/proc/self)", re.I), "Path Traversal"),
    (re.compile(r"(UNION\s+SELECT|CONCAT\(|'\s*OR\s*'1'='1|benchmark\(|sleep\()", re.I), "SQL Injection Versuch"),
    (re.compile(r"(<script|alert\(|javascript:|onerror=)", re.I), "Cross-Site Scripting (XSS)"),
    (re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster)", re.I), "Automatisierter Schwachstellen-Scanner")
]

def scan_nginx_exploit_probes(max_lines: int = 1500) -> Dict[str, Any]:
    """Analysiert NGINX Logs nach verdächtigen Exploit- und Scannermustern."""
    log_candidates = [
        "/var/log/nginx/error.log",
        "/var/log/nginx/access.log"
    ]

    probes = []
    ip_counter = {}

    for path in log_candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]

            for line in reversed(lines):
                for pattern, category in SUSPICIOUS_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                        ip = ip_match.group(0) if ip_match else "Unbekannt"

                        ts_match = re.search(r"\[([^\]]+)\]", line)
                        ts = ts_match.group(1) if ts_match else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                        ip_counter[ip] = ip_counter.get(ip, 0) + 1

                        if len(probes) < 50:
                            probes.append({
                                "ip": ip,
                                "category": category,
                                "matched": match.group(0),
                                "raw_line": line[:200],
                                "timestamp": ts
                            })
                        break
        except Exception:
            continue

    top_attackers = sorted(
        [{"ip": ip, "count": count} for ip, count in ip_counter.items() if ip not in ("Unbekannt", "127.0.0.1", "0.0.0.0")],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    return {"recent_probes": probes, "top_attackers": top_attackers}
