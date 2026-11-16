"""
SysCore Sentinel - SSH Protection Module
Analysiert und verwaltet OpenSSH-Konfigurationen (/etc/ssh/sshd_config und Drop-Ins).
Bietet sichere Härtung (Root-Login deaktivieren, SSH-Port ändern) mit Schutz vor Aussperrung.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, Any, Tuple, Optional
from modules.system_agent import run_privileged
from modules.security.core.safe_apply import SafeApply
from modules.security.protection.firewall import add_ufw_allow

SSH_DROPIN_PATH = "/etc/ssh/sshd_config.d/99-syscore.conf"

def get_ssh_audit() -> Dict[str, Any]:
    """Prüft die aktuelle OpenSSH-Konfiguration auf Härtungsmerkmale."""
    sshd_config_paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"]
    content = ""
    for p in sshd_config_paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content += f.read() + "\n"
            except Exception:
                pass
        elif os.path.isdir(p):
            try:
                for fname in sorted(os.listdir(p)):
                    if fname.endswith(".conf"):
                        try:
                            with open(os.path.join(p, fname), "r", encoding="utf-8", errors="ignore") as f:
                                content += f.read() + "\n"
                        except Exception:
                            pass
            except Exception:
                pass

    port = 22
    permit_root = "yes"  # OpenSSH default falls nicht explizit gesetzt
    password_auth = "yes"

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        key = parts[0].lower()
        val = parts[1].lower() if len(parts) > 1 else ""

        if key == "port" and val.isdigit():
            port = int(val)
        elif key == "permitrootlogin":
            permit_root = val
        elif key == "passwordauthentication":
            password_auth = val

    is_hardened = (permit_root in ("no", "prohibit-password")) and (password_auth == "no" or port != 22)
    return {
        "port": port,
        "permit_root_login": permit_root,
        "password_auth": password_auth,
        "is_hardened": is_hardened
    }

def harden_ssh_safe(
    permit_root_login: str = "no",
    new_port: Optional[int] = None,
    enforce_keys_only: bool = False,
    username: str = "admin"
) -> Tuple[bool, str]:
    """
    Härtet die SSH-Konfiguration ab ohne Gefahr der Aussperrung:
    1. Vorher-Snapshot anlegen.
    2. Wenn ein neuer Port gewählt wird: Zuerst in UFW-Firewall freigeben!
    3. Drop-In /etc/ssh/sshd_config.d/99-syscore.conf anlegen.
    4. Syntaxprüfung mit sshd -t durchführen.
    5. Bei Fehler: automatischer Rollback!
    6. Bei Erfolg: SSH Service sicher neu laden (reload).
    """
    current_audit = get_ssh_audit()
    target_port = new_port if new_port and 1 <= new_port <= 65535 else current_audit["port"]

    # 1. Aussperr-Schutz: Neuer Port wird VORHER in UFW freigegeben!
    if new_port and new_port != current_audit["port"]:
        if new_port in (80, 443, 8888, 3306, 5432, 6379, 8080, 2022):
            return False, f"Port {new_port} kollidiert mit einem anderen Kern-Dienst (Web/Panel/DB/Wings)!"

        # In Firewall eintragen
        add_ufw_allow(f"{new_port}/tcp")

    # 2. Snapshot anlegen
    snapshot_id = SafeApply.create_snapshot(
        snapshot_type="ssh_hardening",
        description=f"SSH Härtung (Root: {permit_root_login}, Port: {target_port})",
        current_state=current_audit,
        created_by=username
    )

    # 3. Drop-In Konfiguration zusammenstellen
    lines = [
        "# SysCore Sentinel SSH Security Hardening Drop-In",
        "# Automatisch und sicher angewendet durch SysCore SafeApply",
        f"PermitRootLogin {permit_root_login}",
        f"Port {target_port}"
    ]
    if enforce_keys_only:
        lines.append("PasswordAuthentication no")

    content = "\n".join(lines) + "\n"

    # 4. Additive Datei sicher schreiben und Syntax prüfen
    os.makedirs(os.path.dirname(SSH_DROPIN_PATH), exist_ok=True)
    ok, msg = SafeApply.apply_additive_file(SSH_DROPIN_PATH, content, service_to_reload="sshd")
    if not ok:
        return False, f"SSH-Härtung abgebrochen: {msg}"

    # Versuche den ssh Dienst neuzuladen
    for svc in ("ssh", "sshd"):
        try:
            run_privileged(["systemctl", "reload", svc], timeout=10)
            break
        except Exception:
            pass

    return True, f"SSH erfolgreich gehärtet! (PermitRootLogin: {permit_root_login}, Port: {target_port}, Snapshot #{snapshot_id})"
