"""
SysCore Sentinel - ClamAV Antivirus Module
Führt Malware-Scans durch, überwacht den ClamAV-Daemon und protokolliert Scan-Ergebnisse.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, Any, List
import db
from modules.system_agent import run_privileged

def get_clamav_status() -> Dict[str, Any]:
    """Prüft ClamAV Installation, Daemon-Status und letzte Scans."""
    installed = bool(shutil.which("clamscan"))
    daemon_running = False
    if shutil.which("systemctl"):
        try:
            res = subprocess.run(["systemctl", "is-active", "clamav-daemon"], capture_output=True, text=True, timeout=3)
            daemon_running = (res.stdout.strip() == "active")
        except Exception:
            pass

    recent_scans = db.query_db("SELECT * FROM clamav_scans ORDER BY id DESC LIMIT 10")
    return {
        "installed": installed,
        "daemon_running": daemon_running,
        "recent_scans": [dict(r) for r in recent_scans] if recent_scans else []
    }

def run_clamscan(target_path: str, max_filesize_mb: int = 50) -> Dict[str, Any]:
    """Führt einen Malware-Scan auf dem angegebenen Pfad durch."""
    if not os.path.exists(target_path):
        return {"success": False, "error": f"Pfad '{target_path}' existiert nicht."}

    if not shutil.which("clamscan"):
        # Simulations-Eintrag für Systeme ohne Clamscan
        db.execute_db("""
            INSERT INTO clamav_scans (target_path, scanned_files, infected_files, scan_log, status)
            VALUES (?, 0, 0, ?, 'completed')
        """, (target_path, "[SysCore Info] ClamAV ist nicht installiert. Bitte im Paket-Manager installieren."))
        return {
            "success": False,
            "installed": False,
            "message": "ClamAV (clamscan) ist auf diesem Server nicht installiert."
        }

    try:
        cmd = [
            "clamscan", "-r", "-i",
            f"--max-filesize={max_filesize_mb}M",
            "--max-scansize=100M",
            target_path
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        out = (res.stdout or "") + "\n" + (res.stderr or "")

        scanned_match = re.search(r"Scanned files:\s+(\d+)", out)
        infected_match = re.search(r"Infected files:\s+(\d+)", out)

        scanned = int(scanned_match.group(1)) if scanned_match else 0
        infected = int(infected_match.group(1)) if infected_match else 0
        status = "infected" if infected > 0 else "clean"

        db.execute_db("""
            INSERT INTO clamav_scans (target_path, scanned_files, infected_files, scan_log, status)
            VALUES (?, ?, ?, ?, ?)
        """, (target_path, scanned, infected, out[:4000], status))

        return {
            "success": True,
            "scanned": scanned,
            "infected": infected,
            "status": status,
            "log": out[:2000]
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Scan hat das Zeitlimit von 10 Minuten überschritten."}
    except Exception as e:
        return {"success": False, "error": f"Fehler bei Scan-Ausführung: {e}"}
