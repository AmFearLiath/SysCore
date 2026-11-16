"""
SysCore Sentinel - File Integrity Monitoring (FIM)
Erstellt SHA-256 Prüfsummen-Baselines für Webspaces und Systemkonfigurationen,
erkennt unautorisierte Datei-Drifts und potenzielle Webshell-Injektionen.
"""

import os
import hashlib
import json
from typing import Dict, Any, List
import db
import config

BASELINE_STORAGE_PATH = config.BASE_DIR / "backups" / "fim_baseline.json"

def compute_sha256(filepath: str) -> str:
    """Berechnet den SHA-256 Hash einer Datei."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

class FileIntegrityMonitor:
    """Verwaltet Integritäts-Baselines und Drift-Erkennung."""

    @staticmethod
    def initialize_baseline(target_paths: List[str] = None) -> Dict[str, Any]:
        """Erstellt eine neue Prüfsummen-Baseline."""
        if not target_paths:
            target_paths = [str(config.WEB_ROOT_BASE)]

        baseline = {}
        total_files = 0

        for root_path in target_paths:
            if not os.path.exists(root_path):
                continue

            for root, _, files in os.walk(root_path):
                # Logs, Caches und Upload-Ordner ausschließen
                if any(x in root for x in ("cache", "logs", "tmp", "node_modules")):
                    continue

                for f in files:
                    # Relevante ausführbare oder Skriptdateien
                    if f.endswith((".php", ".py", ".sh", ".js", ".conf", ".env")):
                        fpath = os.path.join(root, f)
                        fhash = compute_sha256(fpath)
                        if fhash:
                            baseline[fpath] = {
                                "hash": fhash,
                                "size": os.path.getsize(fpath),
                                "mtime": os.path.getmtime(fpath)
                            }
                            total_files += 1

        # Baseline sichern
        BASELINE_STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_STORAGE_PATH.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

        return {"status": "success", "total_files": total_files}

    @staticmethod
    def check_drift() -> Dict[str, Any]:
        """Vergleicht das Dateisystem mit der gespeicherten Baseline."""
        if not BASELINE_STORAGE_PATH.exists():
            return {"status": "uninitialized", "modified": [], "deleted": [], "new": []}

        try:
            baseline = json.loads(BASELINE_STORAGE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {"status": "error", "message": "Baseline-Datei beschädigt"}

        modified = []
        deleted = []

        for fpath, data in baseline.items():
            if not os.path.exists(fpath):
                deleted.append(fpath)
            else:
                curr_hash = compute_sha256(fpath)
                if curr_hash and curr_hash != data["hash"]:
                    modified.append(fpath)

        return {
            "status": "clean" if not (modified or deleted) else "drift_detected",
            "modified": modified[:50],
            "deleted": deleted[:50],
            "total_monitored": len(baseline)
        }
