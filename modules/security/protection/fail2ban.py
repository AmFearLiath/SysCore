"""
SysCore Sentinel - Fail2Ban Protection Module
Interagiert mit fail2ban-client zur Verwaltung von Schutz-Jails,
Konfiguration von Sperrzeiten & Schwellenwerten und IP-Sperren.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from modules.system_agent import run_privileged
from modules.security.core.safe_apply import SafeApply

FAIL2BAN_DROPIN_PATH = "/etc/fail2ban/jail.d/99-syscore.conf"

def get_fail2ban_status() -> Dict[str, Any]:
    """Liest Fail2Ban-Status, aktive Jails und gebannte IPs aus."""
    has_client = shutil.which("fail2ban-client") or os.path.exists("/usr/bin/fail2ban-client")
    if not has_client:
        return {"installed": False, "running": False, "jails": [], "banned_ips": []}

    is_running = False
    # Systemctl Prüfung
    if shutil.which("systemctl"):
        try:
            s_chk = subprocess.run(["systemctl", "is-active", "fail2ban"], capture_output=True, text=True, timeout=3)
            if s_chk.stdout.strip() == "active":
                is_running = True
        except Exception:
            pass

    try:
        # run_privileged nutzen, da fail2ban.sock Root-Rechte erfordert (SEC-001)
        res = run_privileged(["fail2ban-client", "status"], timeout=5)
        if res.returncode == 0:
            is_running = True

        jails = []
        banned = []
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.splitlines():
                if "Jail list:" in line:
                    raw_jails = line.split("Jail list:")[-1].strip().split(",")
                    jails = [j.strip() for j in raw_jails if j.strip()]

            for jail in jails:
                try:
                    j_res = run_privileged(["fail2ban-client", "status", jail], timeout=5)
                    if j_res.returncode == 0 and j_res.stdout:
                        for j_line in j_res.stdout.splitlines():
                            if "Banned IP list:" in j_line:
                                ips = j_line.split("Banned IP list:")[-1].strip().split()
                                for ip in ips:
                                    if ip.strip():
                                        banned.append({"ip": ip.strip(), "jail": jail})
                except Exception:
                    pass

        return {"installed": True, "running": is_running, "jails": jails, "banned_ips": banned}
    except Exception as e:
        return {"installed": True, "running": is_running, "jails": [], "banned_ips": [], "error": str(e)}

def get_fail2ban_config() -> Dict[str, Any]:
    """Liest die Fail2Ban Konfiguration aus dem SysCore Drop-in oder liefert Standards."""
    defaults = {
        "bantime": "3600",       # 1 Stunde Sperre
        "findtime": "600",       # 10 Minuten Zeitfenster
        "maxretry": "5",         # 5 Fehlversuche
        "ignoreip": "127.0.0.1/8 ::1",
        "sshd_enabled": True,
        "nginx_enabled": False,
        "configured": os.path.exists(FAIL2BAN_DROPIN_PATH)
    }

    if os.path.exists(FAIL2BAN_DROPIN_PATH):
        try:
            with open(FAIL2BAN_DROPIN_PATH, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
            m_ban = re.search(r"^\s*bantime\s*=\s*([^\n#]+)", content, re.MULTILINE)
            if m_ban:
                defaults["bantime"] = m_ban.group(1).strip()

            m_find = re.search(r"^\s*findtime\s*=\s*([^\n#]+)", content, re.MULTILINE)
            if m_find:
                defaults["findtime"] = m_find.group(1).strip()

            m_retry = re.search(r"^\s*maxretry\s*=\s*([^\n#]+)", content, re.MULTILINE)
            if m_retry:
                defaults["maxretry"] = m_retry.group(1).strip()

            m_ignore = re.search(r"^\s*ignoreip\s*=\s*([^\n#]+)", content, re.MULTILINE)
            if m_ignore:
                defaults["ignoreip"] = m_ignore.group(1).strip()

            defaults["sshd_enabled"] = bool(re.search(r"\[sshd\][\s\S]*?enabled\s*=\s*true", content, re.IGNORECASE))
            defaults["nginx_enabled"] = bool(re.search(r"\[nginx-http-auth\][\s\S]*?enabled\s*=\s*true", content, re.IGNORECASE))
        except Exception:
            pass

    return defaults

def save_fail2ban_config(
    bantime: str = "3600",
    findtime: str = "600",
    maxretry: str = "5",
    ignoreip: str = "127.0.0.1/8 ::1",
    sshd_enabled: bool = True,
    nginx_enabled: bool = False,
    username: str = "admin"
) -> Tuple[bool, str]:
    """
    Erstellt oder aktualisiert das Fail2Ban Drop-In /etc/fail2ban/jail.d/99-syscore.conf
    ohne bestehende Systemdateien zu überschreiben (SEC-005).
    """
    # Validierung
    bantime_clean = bantime.strip()
    findtime_clean = findtime.strip()
    maxretry_clean = str(maxretry).strip()
    ignoreip_clean = ignoreip.strip()

    if not re.match(r"^\d+[smhd]?$", bantime_clean):
        return False, "Ungültige Sperrdauer (z.B. '3600', '1h', '24h')."
    if not re.match(r"^\d+[smhd]?$", findtime_clean):
        return False, "Ungültiges Zeitfenster (z.B. '600', '10m')."
    if not maxretry_clean.isdigit() or int(maxretry_clean) < 1:
        return False, "Fehlversuche müssen eine positive Zahl sein."

    content = f"""# SysCore Sentinel Fail2ban Configuration Drop-In
# Automatisch verwaltet durch das SysCore Sicherheitscenter

[DEFAULT]
bantime = {bantime_clean}
findtime = {findtime_clean}
maxretry = {maxretry_clean}
ignoreip = {ignoreip_clean}

[sshd]
enabled = {'true' if sshd_enabled else 'false'}
port = ssh

[nginx-http-auth]
enabled = {'true' if nginx_enabled else 'false'}
"""

    # Vorher-Snapshot anlegen
    SafeApply.create_snapshot(
        snapshot_type="fail2ban_config",
        description=f"Fail2Ban Konfigurationsänderung (Bantime: {bantime_clean}, Maxretry: {maxretry_clean})",
        current_state=get_fail2ban_config(),
        created_by=username
    )

    # Zielverzeichnis anlegen
    os.makedirs(os.path.dirname(FAIL2BAN_DROPIN_PATH), exist_ok=True)

    try:
        with open(FAIL2BAN_DROPIN_PATH, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        return False, f"Fehler beim Schreiben von {FAIL2BAN_DROPIN_PATH}: {e}"

    # Fail2Ban neu laden
    if shutil.which("fail2ban-client"):
        try:
            res = run_privileged(["fail2ban-client", "reload"], timeout=10)
            if res.returncode != 0:
                # Versuch über systemctl
                run_privileged(["systemctl", "restart", "fail2ban"], timeout=10)
        except Exception:
            pass

    return True, "Fail2Ban Konfiguration erfolgreich angewendet und neu geladen."

def fail2ban_service_action(action: str) -> Tuple[bool, str]:
    """Startet, stoppt oder startet Fail2ban neu."""
    if action not in ("start", "stop", "restart", "enable", "disable"):
        return False, "Ungültige Aktion."
    try:
        # Sicherstellen dass /var/run/fail2ban existiert (erforderlich für fail2ban.sock)
        if action in ("start", "restart") and hasattr(os, "geteuid"):
            try:
                os.makedirs("/var/run/fail2ban", exist_ok=True)
            except Exception:
                run_privileged(["mkdir", "-p", "/var/run/fail2ban"])

        res = run_privileged(["systemctl", action, "fail2ban"], timeout=15)
        
        # Fallback auf fail2ban-client falls systemctl fehlschlägt
        if res.returncode != 0 and shutil.which("fail2ban-client"):
            if action in ("start", "restart"):
                fb_res = run_privileged(["fail2ban-client", action], timeout=10)
                if fb_res.returncode == 0:
                    return True, f"Fail2Ban erfolgreich {action}ed (via fail2ban-client)."
            elif action == "stop":
                run_privileged(["fail2ban-client", "stop"], timeout=10)
                return True, "Fail2Ban gestoppt."

        # Wenn Start erfolgreich war, Dienst auch automatisch im Boot aktivieren
        if action == "start" and res.returncode == 0:
            run_privileged(["systemctl", "enable", "fail2ban"], timeout=10)

        success = (res.returncode == 0)
        msg = (res.stdout or res.stderr).strip() or (f"Dienstaktion '{action}' erfolgreich" if success else f"Aktion '{action}' fehlgeschlagen")
        return success, msg
    except Exception as e:
        return False, str(e)

def fail2ban_unban(ip_address: str, jail: Optional[str] = None) -> bool:
    """Entfernt eine IP-Adresse aus einem oder allen Fail2Ban Jails."""
    if not shutil.which("fail2ban-client"):
        return False
    try:
        if jail:
            run_privileged(["fail2ban-client", "set", jail, "unbanip", ip_address], timeout=10)
        else:
            run_privileged(["fail2ban-client", "unban", ip_address], timeout=10)
        return True
    except Exception:
        return False
