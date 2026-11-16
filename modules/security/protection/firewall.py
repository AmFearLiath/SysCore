"""
SysCore Sentinel - Firewall Protection Module (UFW)
Verwaltet UFW-Status, Portfreigaben, Sperren und Notfall-Watchdogs.
"""

import shutil
import subprocess
from typing import Dict, Any, List
from modules.system_agent import run_privileged

def get_ufw_status() -> Dict[str, Any]:
    """Liest den aktuellen UFW-Firewall-Status aus."""
    if not shutil.which("ufw"):
        return {"installed": False, "active": False, "rules": []}
    try:
        res = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=5)
        out = res.stdout
        is_active = "Status: active" in out
        rules = []
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Status:") and not line.startswith("Logging:") and not line.startswith("Default:") and not line.startswith("New profiles:") and not line.startswith("To") and not line.startswith("--"):
                rules.append(line)
        return {"installed": True, "active": is_active, "rules": rules, "raw": out}
    except Exception as e:
        return {"installed": True, "active": False, "rules": [], "error": str(e)}

def set_ufw_enabled(enabled: bool) -> bool:
    """Aktiviert oder deaktiviert UFW sicher."""
    if not shutil.which("ufw"):
        return False
    cmd = ["ufw", "--force", "enable"] if enabled else ["ufw", "disable"]
    try:
        run_privileged(cmd, timeout=10)
        return True
    except Exception:
        return False

def add_ufw_allow(port_or_service: str, proto: str = "tcp") -> bool:
    """Erlaubt einen Port oder Dienst in UFW."""
    if not shutil.which("ufw"):
        return False
    try:
        rule = f"{port_or_service}/{proto}" if proto else str(port_or_service)
        run_privileged(["ufw", "allow", rule], timeout=10)
        return True
    except Exception:
        return False

def add_ufw_deny(ip_address: str) -> bool:
    """Sperrt eine IP-Adresse in UFW."""
    if not shutil.which("ufw"):
        return False
    try:
        run_privileged(["ufw", "deny", "from", ip_address], timeout=10)
        return True
    except Exception:
        return False

def remove_ufw_deny(ip_address: str) -> bool:
    """Entfernt eine IP-Sperre aus UFW."""
    if not shutil.which("ufw"):
        return False
    try:
        run_privileged(["ufw", "delete", "deny", "from", ip_address], timeout=10)
        return True
    except Exception:
        return False
