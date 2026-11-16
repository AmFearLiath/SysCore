"""
SysCore Sentinel - SSH Protection Module
Analysiert und verwaltet OpenSSH-Konfigurationen (/etc/ssh/sshd_config und Drop-Ins).
"""

import os
from typing import Dict, Any

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
