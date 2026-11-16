"""
SysCore Sentinel - Software Discovery Engine
Scannt das System nach installierten Diensten, Webanwendungen, Datenbanken,
Container-Laufzeiten und Hintergrund-Daemons und registriert sie im Software-Inventar.
"""

import os
import json
import shutil
import subprocess
import psutil
from typing import List, Dict, Any
import db
import config
from modules.security.inventory.software_registry import KNOWN_SOFTWARE_RULES

class SoftwareDiscovery:
    """Scannt und synchronisiert installierte Software mit der SysCore-Datenbank."""

    @staticmethod
    def run_discovery() -> List[Dict[str, Any]]:
        """Führt einen vollständigen Systemscan durch und aktualisiert das Inventar."""
        discovered = {}

        # 1. Bekannte Software anhand von Dateien und Services prüfen
        for key, info in KNOWN_SOFTWARE_RULES.items():
            is_present = False
            version = "Unbekannt"
            active_ports = []
            service_found = None

            # Prüfe Konfigurationspfade
            for cpath in info["config_paths"]:
                if os.path.exists(cpath):
                    is_present = True
                    break

            # Prüfe systemd-Dienste
            if shutil.which("systemctl"):
                for sname in info["service_names"]:
                    try:
                        res = subprocess.run(["systemctl", "is-active", sname], capture_output=True, text=True, timeout=2)
                        if res.stdout.strip() in ("active", "activating"):
                            is_present = True
                            service_found = sname
                            break
                        elif res.returncode == 0:
                            is_present = True
                            service_found = sname
                    except Exception:
                        pass

            # Prüfe Ports
            for target_port in info["ports"]:
                try:
                    for conn in psutil.net_connections(kind="inet"):
                        if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == target_port:
                            active_ports.append(target_port)
                            is_present = True
                except Exception:
                    pass

            if is_present:
                discovered[key] = {
                    "name": key,
                    "software_type": info["type"],
                    "protection_mode": info["default_mode"],
                    "version": version,
                    "ports_json": json.dumps(list(set(active_ports))),
                    "config_paths_json": json.dumps(info["config_paths"]),
                    "service_name": service_found or (info["service_names"][0] if info["service_names"] else None),
                    "status": "active" if active_ports or service_found else "installed",
                    "notes": info["notes"]
                }

        # 2. Webanwendungen unter /var/www bzw. WEB_ROOT_BASE prüfen
        web_base = config.WEB_ROOT_BASE
        if os.path.exists(web_base):
            try:
                for item in os.listdir(web_base):
                    p = os.path.join(web_base, item)
                    if not os.path.isdir(p):
                        continue

                    # Spezielle Webanwendungen erkennen
                    if os.path.exists(os.path.join(p, "wp-config.php")):
                        discovered[f"wp-{item}"] = {
                            "name": f"WordPress ({item})",
                            "software_type": "web_cms",
                            "protection_mode": "security_managed",
                            "version": "WordPress Core",
                            "ports_json": json.dumps([80, 443]),
                            "config_paths_json": json.dumps([os.path.join(p, "wp-config.php")]),
                            "service_name": "nginx",
                            "status": "active",
                            "notes": f"WordPress Installation für Domain/Ordner {item}"
                        }
                    elif os.path.exists(os.path.join(p, "artisan")) and "pterodactyl" in item.lower():
                        discovered["pterodactyl-panel"] = {
                            "name": "Pterodactyl Panel",
                            "software_type": "game_panel",
                            "protection_mode": "protected",
                            "version": "Production",
                            "ports_json": json.dumps([80, 443]),
                            "config_paths_json": json.dumps([os.path.join(p, ".env")]),
                            "service_name": "pteroq",
                            "status": "active",
                            "notes": "Pterodactyl Game Server Management Panel"
                        }
            except Exception:
                pass

        # 3. Datenbank synchronisieren (bestehende manuell angepasste protection_modes beibehalten!)
        for key, item in discovered.items():
            existing = db.query_db("SELECT id, protection_mode FROM software_inventory WHERE name = ?", (item["name"],), one=True)
            if existing:
                # Modus nicht überschreiben, nur Ports und Status updaten
                db.execute_db("""
                    UPDATE software_inventory 
                    SET ports_json = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (item["ports_json"], item["status"], existing["id"]))
            else:
                db.execute_db("""
                    INSERT INTO software_inventory 
                    (name, software_type, protection_mode, version, ports_json, config_paths_json, service_name, status, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    item["name"], item["software_type"], item["protection_mode"], item["version"],
                    item["ports_json"], item["config_paths_json"], item["service_name"], item["status"], item["notes"]
                ))

        # Alle Einträge aus DB zurückgeben
        rows = db.query_db("SELECT * FROM software_inventory ORDER BY protection_mode, name")
        return [dict(r) for r in rows] if rows else []
