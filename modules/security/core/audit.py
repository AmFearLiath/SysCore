"""
SysCore Sentinel - Audit & Reporting
Erstellt strukturierte Diagnoseberichte und Prompt-Exporte für externe KI-Agenten
sowie interne Compliance-Prüfungen.
"""

import os
import shutil
import subprocess
import psutil
from datetime import datetime
from typing import Dict, Any, List
import config

def generate_markdown_audit_report(
    score: int,
    deductions: List[Dict[str, Any]],
    ufw: Dict[str, Any],
    f2b: Dict[str, Any],
    ssh: Dict[str, Any],
    ports: Dict[str, Any],
    clamav: Dict[str, Any],
    software_inventory: List[Dict[str, Any]] = None
) -> str:
    """Generiert den vollständigen Markdown-Auditbericht."""
    uname = os.uname() if hasattr(os, "uname") else None
    kernel = uname.release if uname else "Windows/NT"
    uptime_sec = int(psutil.boot_time())

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/") if hasattr(os, "uname") else psutil.disk_usage("C:\\")
    load = psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0.0, 0.0, 0.0)

    # Veraltete Pakete ermitteln
    upgradable_count = 0
    upgradable_pkgs = []
    if shutil.which("apt-get"):
        try:
            res = subprocess.run(["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                if line.startswith("Inst "):
                    upgradable_count += 1
                    if len(upgradable_pkgs) < 15:
                        upgradable_pkgs.append(line.split()[1])
        except Exception:
            pass

    # Formatierte Abzüge
    deduction_lines = []
    for d in deductions:
        if isinstance(d, dict):
            deduction_lines.append(f"- [{d.get('severity', 'WARNUNG').upper()}] {d.get('title')}: {d.get('recommendation')} (-{d.get('impact')}%)")
        else:
            deduction_lines.append(f"- {d}")

    # Software Inventory List
    inv_lines = []
    if software_inventory:
        for sw in software_inventory:
            mode_badge = sw.get("protection_mode", "observe_only").upper()
            inv_lines.append(f"- **{sw.get('name')}** ({sw.get('software_type')}) — Modus: `{mode_badge}` | Status: {sw.get('status')}")

    report = f"""# SysCore Sentinel — System-Audit & Sicherheitsanalyse
**Generiert am:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Hostname:** {config.PANEL_HOST}
**Sicherheits-Score:** {score}/100%

---

## 🤖 PROMPT FÜR KI-AGENTEN (Claude, Gemini, GPT, Ollama)
> Kopiere diesen Block direkt in deinen KI-Agenten, um einen priorisierten Optimierungs- und Härtungsplan zu erhalten:

```text
Du bist ein erfahrener Senior Linux Infrastructure Architect & Cybersecurity Specialist.
Hier ist der vollständige Diagnose- und Sicherheitsbericht meines Servers (SysCore Sentinel Audit).

Bitte erstelle mir auf Basis dieser Daten:
1. Eine priorisierte Risiko- und Schwachstellenanalyse (Kritisch, Hoch, Mittel, Niedrig).
2. Konkrete Maßnahmen zur Leistungsoptimierung (RAM, Swap, NVMe I/O, NGINX Worker, PHP-FPM, MySQL Buffer Pool).
3. Einen schrittweisen, sofort ausführbaren Aktionsplan zur Behebung unter Wahrung der Kompatibilität.
4. Empfehlungen zur weiteren Härtung (SSH, UFW, Fail2Ban/CrowdSec).
```

---

## 1. Sicherheits- & Härtungs-Status
- **Gesamt-Score:** {score} / 100%
- **Identifizierte Abzüge:**
{chr(10).join(deduction_lines) if deduction_lines else '- Keine kritischen Abzüge festgestellt.'}

### UFW Firewall
- **Status:** {'Aktiv' if ufw.get('active') else 'INAKTIV (Sicherheitsrisiko)'}
- **Aktive Regeln:** {len(ufw.get('rules', []))}

### Fail2Ban / Intrusion Prevention
- **Status:** {'Aktiv' if f2b.get('running') else 'INAKTIV'}
- **Aktive Jails:** {', '.join(f2b.get('jails', [])) if f2b.get('jails') else 'Keine'}
- **Aktuell gebannte IPs:** {len(f2b.get('banned_ips', []))}

### SSH-Konfiguration
- **Port:** {ssh.get('port', 22)}
- **PermitRootLogin:** {ssh.get('permit_root_login')}
- **PasswordAuthentication:** {ssh.get('password_auth')}
- **Gehärtet:** {'Ja' if ssh.get('is_hardened') else 'Nein (Empfehlung: Root-Login verbieten und SSH-Keys erzwingen)'}

---

## 2. Hardware- & Ressourcen-Auslastung
- **Kernel:** {kernel}
- **Load Average (1, 5, 15 Min):** {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}
- **CPU Kerne:** {psutil.cpu_count(logical=True)}
- **Arbeitsspeicher (RAM):** {mem.used / (1024**3):.2f} GB / {mem.total / (1024**3):.2f} GB ({mem.percent}% belegt)
- **Swap-Speicher:** {swap.used / (1024**3):.2f} GB / {swap.total / (1024**3):.2f} GB ({swap.percent}% belegt)
- **Hauptspeicher:** {disk.used / (1024**3):.2f} GB / {disk.total / (1024**3):.2f} GB ({disk.percent}% belegt)

---

## 3. Offene Ports & Externe Angriffsflächen
{chr(10).join([f"- Port {p['port']} ({p['process']}) auf {p['ip']} [{'ÖFFENTLICH' if p['public'] else 'LOKAL'}]" for p in ports.get('listeners', [])])}

---

## 4. Erkannte Software & Schutz-Status
{chr(10).join(inv_lines) if inv_lines else '- Keine Software im Inventar erfasst.'}

---

## 5. Paket- & Antiviren-Status
- **Anstehende APT Updates:** {upgradable_count} Pakete
- **Auszug:** {', '.join(upgradable_pkgs) if upgradable_pkgs else 'System ist aktuell'}
- **ClamAV Virenscanner:** {'Installiert & Betriebsbereit' if clamav.get('installed') else 'Nicht installiert'}

---
*Erstellt mit SysCore Sentinel Security Center 2.0.*
"""
    return report
