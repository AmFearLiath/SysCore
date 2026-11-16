"""
SysCore Sentinel - Risk Engine
Berechnet dynamische Sicherheits- und Risikobewertungen (0 - 100%)
auf Basis von Schwachstellen, offenen Ports, Firewall-Status, SSH-Konfiguration
und Echtzeit-Angriffsvektoren.
"""

from typing import Dict, List, Tuple, Any
import db

DANGER_PORTS = {
    3306: ("MySQL / MariaDB", "Datenbank sollte niemals ungeschützt auf 0.0.0.0 erreichbar sein!", "critical", 15),
    5432: ("PostgreSQL", "Enterprise DB sollte nur lokal (127.0.0.1) lauschen.", "critical", 15),
    6379: ("Redis Cache", "Redis ohne Authentifizierung auf 0.0.0.0 ist ein extremes Sicherheitsrisiko!", "critical", 20),
    27017: ("MongoDB", "NoSQL-Datenbank öffentlich erreichbar.", "critical", 15),
    11211: ("Memcached", "Verstärkungsangriffe / UDP-Exploitgefahr.", "high", 10),
    2375: ("Docker Remote API", "Docker-Socket unverschlüsselt im Netz erlaubt vollständigen Root-Kompromiss!", "critical", 25),
    9000: ("PHP-FPM TCP", "PHP-FPM sollte Unix-Sockets (/run/php/*.sock) statt TCP nutzen.", "medium", 5),
    8080: ("Alternativer Webport", "Unverschlüsselter Port aktiv.", "low", 3)
}

def calculate_system_risk(
    ufw_status: Dict[str, Any],
    f2b_status: Dict[str, Any],
    ssh_audit: Dict[str, Any],
    ports_audit: Dict[str, Any],
    probe_count: int = 0,
    open_findings: List[Dict[str, Any]] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Berechnet den Gesamt-Sicherheitsscore (0 - 100) sowie eine Liste aller Abzüge.
    Gibt (score, deductions) zurück.
    """
    score = 100
    deductions = []

    # 1. Firewall Prüfungen
    if not ufw_status.get("active"):
        score -= 30
        deductions.append({
            "category": "firewall",
            "title": "UFW Firewall ist inaktiv",
            "impact": 30,
            "severity": "critical",
            "recommendation": "Firewall aktivieren und Standardports (SSH, HTTP, HTTPS) freigeben."
        })

    # 2. Intrusion Prevention / Fail2Ban
    if not f2b_status.get("running"):
        score -= 20
        deductions.append({
            "category": "intrusion_prevention",
            "title": "Fail2Ban ist nicht aktiv",
            "impact": 20,
            "severity": "high",
            "recommendation": "Fail2Ban installieren und Schutz-Jails für SSH & Webserver aktivieren."
        })

    # 3. SSH Konfiguration
    if ssh_audit.get("permit_root_login") in ("yes", True):
        score -= 15
        deductions.append({
            "category": "ssh",
            "title": "SSH erlaubt direkten Root-Login",
            "impact": 15,
            "severity": "high",
            "recommendation": "PermitRootLogin auf 'no' oder 'prohibit-password' setzen."
        })

    if ssh_audit.get("password_auth") in ("yes", True) and ssh_audit.get("port") == 22:
        score -= 10
        deductions.append({
            "category": "ssh",
            "title": "SSH nutzt Standardport 22 mit Passwort-Authentifizierung",
            "impact": 10,
            "severity": "medium",
            "recommendation": "SSH-Keys erzwingen (PasswordAuthentication no) oder Port verlegen."
        })

    # 4. Offene Ports & sensible Dienste
    listeners = ports_audit.get("listeners", [])
    for listener in listeners:
        if listener.get("public"):
            p = listener.get("port")
            if p in DANGER_PORTS:
                name, desc, sev, imp = DANGER_PORTS[p]
                score -= imp
                deductions.append({
                    "category": "network",
                    "title": f"Sensibler Dienst {name} auf Port {p} öffentlich exponiert",
                    "impact": imp,
                    "severity": sev,
                    "recommendation": f"Bind-Adresse auf 127.0.0.1 beschränken oder extern via Firewall blockieren. ({desc})"
                })

    # 5. Exploit-Probes & Angriffs-Radar
    if probe_count > 50:
        score -= 10
        deductions.append({
            "category": "threats",
            "title": f"Hohe Anzahl von Angriffs-Probes ({probe_count} in letzter Zeit)",
            "impact": 10,
            "severity": "medium",
            "recommendation": "Aggressive IP-Sperren im Angriffs-Radar aktivieren und WAF-Regeln prüfen."
        })
    elif probe_count > 15:
        score -= 5
        deductions.append({
            "category": "threats",
            "title": f"Scanner-Aktivität festgestellt ({probe_count} Exploit-Versuche)",
            "impact": 5,
            "severity": "low",
            "recommendation": "Top-Angreifer im Radar beobachten und sperren."
        })

    # 6. Registrierte ungelöste Befunde aus der Datenbank
    if open_findings:
        for finding in open_findings:
            sev = finding.get("severity", "medium").lower()
            imp = finding.get("score_impact", 0)
            if not imp:
                imp = 10 if sev == "critical" else (7 if sev == "high" else (4 if sev == "medium" else 2))
            score -= imp
            deductions.append({
                "category": finding.get("finding_type", "audit"),
                "title": finding.get("title", "Ungelöster Sicherheitsbefund"),
                "impact": imp,
                "severity": sev,
                "recommendation": finding.get("recommended_action", "Befund im Security Center prüfen.")
            })

    # Normalisierung auf 0 - 100
    score = max(0, min(100, score))
    return score, deductions
