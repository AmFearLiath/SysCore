"""
SysCore Sentinel - Fail2Ban Protection Module
Interagiert mit fail2ban-client zur Verwaltung von Schutz-Jails und IP-Sperren.
"""

import shutil
import subprocess
from typing import Dict, Any, List
from modules.system_agent import run_privileged

def get_fail2ban_status() -> Dict[str, Any]:
    """Liest Fail2Ban-Status, aktive Jails und gebannte IPs aus."""
    if not shutil.which("fail2ban-client"):
        return {"installed": False, "running": False, "jails": [], "banned_ips": []}
    try:
        res = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            return {"installed": True, "running": False, "jails": [], "banned_ips": []}

        jails = []
        banned = []
        for line in res.stdout.splitlines():
            if "Jail list:" in line:
                raw_jails = line.split("Jail list:")[-1].strip().split(",")
                jails = [j.strip() for j in raw_jails if j.strip()]

        for jail in jails:
            try:
                j_res = subprocess.run(["fail2ban-client", "status", jail], capture_output=True, text=True, timeout=5)
                for j_line in j_res.stdout.splitlines():
                    if "Banned IP list:" in j_line:
                        ips = j_line.split("Banned IP list:")[-1].strip().split()
                        for ip in ips:
                            if ip.strip():
                                banned.append({"ip": ip.strip(), "jail": jail})
            except Exception:
                pass

        return {"installed": True, "running": True, "jails": jails, "banned_ips": banned}
    except Exception as e:
        return {"installed": True, "running": False, "jails": [], "banned_ips": [], "error": str(e)}

def fail2ban_unban(ip_address: str) -> bool:
    """Entfernt eine IP-Adresse aus allen Fail2Ban Jails."""
    if not shutil.which("fail2ban-client"):
        return False
    try:
        run_privileged(["fail2ban-client", "unban", ip_address], timeout=10)
        return True
    except Exception:
        return False
