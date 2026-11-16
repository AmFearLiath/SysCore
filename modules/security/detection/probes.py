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
from typing import Dict, Any, List, Set, Optional

SUSPICIOUS_PATTERNS = [
    (re.compile(r"(\.env|wp-login\.php|xmlrpc\.php|phpmyadmin|\.git/config|cgi-bin|eval-stdin)", re.I), "Web-Exploit / Probing"),
    (re.compile(r"(\.\./|etc/passwd|boot\.ini|win\.ini|/proc/self)", re.I), "Path Traversal"),
    (re.compile(r"(UNION\s+SELECT|CONCAT\(|'\s*OR\s*'1'='1|benchmark\(|sleep\()", re.I), "SQL Injection Versuch"),
    (re.compile(r"(<script|alert\(|javascript:|onerror=)", re.I), "Cross-Site Scripting (XSS)"),
    (re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster)", re.I), "Automatisierter Schwachstellen-Scanner")
]

def _extract_log_details(line: str) -> Dict[str, Any]:
    """Extrahiert Zeitstempel, IP, HTTP-Methode, URI, Status und User-Agent aus einer NGINX Logzeile."""
    # 1. Timestamp:
    # Access log format: [16/Nov/2026:12:34:56 +0100]
    ts = None
    m_ts = re.search(r"\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)\]", line)
    if m_ts:
        raw_ts = m_ts.group(1).split()[0]
        try:
            dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S")
            ts = dt.strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            ts = raw_ts
    else:
        # Error log format: 2026/11/16 11:45:12 oder 2026-11-16T11:45:12
        m_ts2 = re.search(r"^(\d{4}[/-]\d{2}[/-]\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
        if m_ts2:
            ts = m_ts2.group(1).replace("/", ".")
        else:
            # Syslog format: Nov 16 11:45:12
            m_ts3 = re.search(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
            if m_ts3:
                ts = m_ts3.group(1)
            else:
                ts = datetime.utcnow().strftime("%d.%m.%Y %H:%M:%S")

    # 2. IP-Adresse:
    ip = "Unbekannt"
    # In error.log: client: 198.51.100.23
    m_ip = re.search(r"client:\s*([0-9a-fA-F:.]+)", line)
    if m_ip:
        ip = m_ip.group(1).strip()
    else:
        # In access.log: Zeile beginnt meist mit IP
        m_ip2 = re.search(r"^([0-9a-fA-F:.]+)", line)
        if m_ip2 and not m_ip2.group(1).startswith("20"):
            ip = m_ip2.group(1).strip()
        else:
            m_ip3 = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if m_ip3:
                ip = m_ip3.group(0)

    # 3. HTTP Request & URI:
    method = "-"
    uri = "-"
    m_req = re.search(r'(?:request:\s*)?"([A-Z]{3,7})\s+([^"\s]+)', line)
    if m_req:
        method = m_req.group(1)
        uri = m_req.group(2)
    else:
        m_req2 = re.search(r'"([A-Z]{3,7})\s+([^"]+)"', line)
        if m_req2:
            method = m_req2.group(1)
            uri = m_req2.group(2)

    # 4. Status code:
    status_code = "-"
    m_st = re.search(r'"\s+(\d{3})\s+\d+', line)
    if m_st:
        status_code = m_st.group(1)

    # 5. User-Agent:
    user_agent = "-"
    m_ua = re.search(r'"[^"]*"\s+"([^"]*)"$', line.strip())
    if m_ua:
        user_agent = m_ua.group(1)

    # 6. Host / Server:
    server_host = "-"
    m_host = re.search(r'(?:host|server):\s*"([^"]+)"', line)
    if m_host:
        server_host = m_host.group(1)

    return {
        "timestamp": ts,
        "ip": ip,
        "method": method,
        "uri": uri,
        "status_code": status_code,
        "user_agent": user_agent,
        "server_host": server_host,
        "raw_line": line.strip()
    }

def scan_nginx_exploit_probes(max_lines: int = 1500, banned_ips: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Analysiert NGINX Logs nach verdächtigen Exploit- und Scannermustern."""
    log_candidates = [
        "/var/log/nginx/error.log",
        "/var/log/nginx/access.log"
    ]

    # Falls keine banned_ips übergeben wurden, direkt aus DB nachladen
    if banned_ips is None:
        try:
            import db
            rows = db.query_db("SELECT ip_address FROM security_ip_bans")
            banned_ips = {r["ip_address"] for r in rows} if rows else set()
        except Exception:
            banned_ips = set()

    probes = []
    ip_counter = {}
    probe_id_counter = 1

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
                        details = _extract_log_details(line)
                        ip = details["ip"]
                        ip_counter[ip] = ip_counter.get(ip, 0) + 1

                        if len(probes) < 60:
                            probes.append({
                                "id": probe_id_counter,
                                "ip": ip,
                                "category": category,
                                "matched": match.group(0),
                                "timestamp": details["timestamp"],
                                "method": details["method"],
                                "uri": details["uri"],
                                "status_code": details["status_code"],
                                "user_agent": details["user_agent"],
                                "server_host": details["server_host"],
                                "raw_line": details["raw_line"],
                                "is_banned": ip in banned_ips
                            })
                            probe_id_counter += 1
                        break
        except Exception:
            continue

    # Bereits gesperrte IPs aus der 'Top Angreifer'-Liste herausfiltern
    top_attackers = sorted(
        [
            {"ip": ip, "count": count}
            for ip, count in ip_counter.items()
            if ip not in ("Unbekannt", "127.0.0.1", "0.0.0.0") and ip not in banned_ips
        ],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    return {"recent_probes": probes, "top_attackers": top_attackers}
