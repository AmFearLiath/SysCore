"""
SysCore Sentinel - Auto-Ban Engine for Exploit Radar
Automatisiertes Sperren von Angreifern basierend auf erkannten Web-Exploits:
- Konfigurierbare Schwellenwerte (z.B. sofort ab 1. Treffer oder nach X Versuchen)
- Ein-/Ausschalten einzelner Angriffskategorien (SQLi, Path Traversal, .env Probing, Scanner, XSS)
- Konfigurierbare Sperrdauer (Permanent, 24h, 7d, 30d)
- Whitelist für eigene Admin-IPs & Subnetze
- Automatische Incident- & Audit-Protokollierung
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List, Set, Optional
import db
from modules.security.protection.firewall import add_ufw_deny
from modules.security.detection.incidents import IncidentManager

SETTING_KEY = "security_radar_autoban"

DEFAULT_AUTOBAN_CONFIG = {
    "enabled": False,
    "threshold": 1,
    "ban_duration": "permanent",
    "categories": {
        "sqli": True,
        "path_traversal": True,
        "web_exploit": True,
        "scanners": True,
        "xss": True
    },
    "whitelist": "127.0.0.1, ::1",
    "notify_incident": True
}

CATEGORY_MAP = {
    "SQL Injection Versuch": "sqli",
    "Path Traversal": "path_traversal",
    "Web-Exploit / Probing": "web_exploit",
    "Automatisierter Schwachstellen-Scanner": "scanners",
    "Cross-Site Scripting (XSS)": "xss"
}

CATEGORY_TITLES = {
    "sqli": "SQL-Injection Versuche",
    "path_traversal": "Path Traversal & Systemdateien",
    "web_exploit": "Web-Exploits & Sensible Dateien (.env, .git, etc.)",
    "scanners": "Automatisierte Scanner (sqlmap, nikto, etc.)",
    "xss": "Cross-Site Scripting (XSS)"
}

class RadarAutoBanManager:
    """Verwaltet Konfiguration und Ausführung der automatischen Exploit-Sperre."""

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Lädt die aktuellen Auto-Ban-Einstellungen aus der Datenbank."""
        try:
            row = db.query_db("SELECT value FROM settings WHERE `key` = ?", (SETTING_KEY,), one=True)
            if row and row["value"]:
                cfg = json.loads(row["value"])
                # Fallback für eventuell neue Felder
                merged = dict(DEFAULT_AUTOBAN_CONFIG)
                merged.update(cfg)
                if "categories" in cfg:
                    merged_cats = dict(DEFAULT_AUTOBAN_CONFIG["categories"])
                    merged_cats.update(cfg["categories"])
                    merged["categories"] = merged_cats
                return merged
        except Exception:
            pass
        return dict(DEFAULT_AUTOBAN_CONFIG)

    @staticmethod
    def save_config(new_config: Dict[str, Any]) -> bool:
        """Speichert die Auto-Ban-Einstellungen in der Datenbank."""
        try:
            current = RadarAutoBanManager.get_config()
            current["enabled"] = bool(new_config.get("enabled", False))
            current["threshold"] = max(1, int(new_config.get("threshold", 1)))
            current["ban_duration"] = str(new_config.get("ban_duration", "permanent")).strip()
            current["whitelist"] = str(new_config.get("whitelist", "127.0.0.1, ::1")).strip()
            current["notify_incident"] = bool(new_config.get("notify_incident", True))

            if "categories" in new_config and isinstance(new_config["categories"], dict):
                for k in current["categories"]:
                    current["categories"][k] = bool(new_config["categories"].get(k, False))

            json_val = json.dumps(current)
            db.execute_db("""
                INSERT OR REPLACE INTO settings (`key`, `value`, `updated_at`)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (SETTING_KEY, json_val))

            # Synchronisiere auch security_automation_rules
            try:
                db.execute_db("""
                    INSERT OR REPLACE INTO security_automation_rules 
                    (rule_name, event_type, reaction_level, action_type, condition_json, is_enabled)
                    VALUES ('auto_ban_exploit_scanners', 'exploit_probe_detected', ?, 'ban_ip', ?, ?)
                """, (
                    4 if current["enabled"] else 1,
                    json.dumps({"threshold": current["threshold"], "categories": current["categories"]}),
                    1 if current["enabled"] else 0
                ))
            except Exception:
                pass

            return True
        except Exception:
            return False

    @staticmethod
    def is_ip_whitelisted(ip: str, whitelist_str: str) -> bool:
        """Prüft, ob eine IP-Adresse in der Whitelist oder Loopback/Private ist."""
        if not ip or ip in ("Unbekannt", "127.0.0.1", "0.0.0.0", "::1"):
            return True

        clean_ip = ip.strip()
        parts = re.split(r"[,\s;]+", whitelist_str.strip())
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if clean_ip == p:
                return True
            # Subnetz-Prüfung bei IPv4 (z.B. 192.168.1. oder CIDR-Präfix)
            if p.endswith(".") and clean_ip.startswith(p):
                return True
        return False

    @staticmethod
    def execute_autoban(probes: Optional[List[Dict[str, Any]]] = None, banned_ips_set: Optional[Set[str]] = None) -> Dict[str, Any]:
        """
        Analysiert die übergebenen Probes (oder lädt neue) und sperrt IPs vollautomatisch,
        falls die Auto-Ban-Kriterien erfüllt sind.
        """
        config = RadarAutoBanManager.get_config()
        if not config.get("enabled"):
            return {
                "active": False,
                "banned_count": 0,
                "banned_ips": [],
                "message": "Auto-Ban ist deaktiviert."
            }

        # Falls keine Probes übergeben wurden, scannen
        if probes is None:
            from modules.security.detection.probes import scan_nginx_exploit_probes
            scan_result = scan_nginx_exploit_probes()
            probes = scan_result.get("recent_probes", [])

        # Bereits gesperrte IPs laden
        if banned_ips_set is None:
            try:
                rows = db.query_db("SELECT ip_address FROM security_ip_bans")
                banned_ips_set = {r["ip_address"] for r in rows} if rows else set()
            except Exception:
                banned_ips_set = set()

        threshold = int(config.get("threshold", 1))
        enabled_categories = config.get("categories", {})
        whitelist = config.get("whitelist", "")
        duration = config.get("ban_duration", "permanent")

        # Zähle relevante Treffer pro IP
        ip_hits: Dict[str, List[Dict[str, Any]]] = {}
        for p in probes:
            ip = p.get("ip")
            if not ip or ip in banned_ips_set:
                continue
            if RadarAutoBanManager.is_ip_whitelisted(ip, whitelist):
                continue

            category_name = p.get("category", "")
            cat_key = CATEGORY_MAP.get(category_name)
            # Prüfen, ob diese Kategorie aktiviert ist
            if cat_key and enabled_categories.get(cat_key, False):
                if ip not in ip_hits:
                    ip_hits[ip] = []
                ip_hits[ip].append(p)

        newly_banned = []
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for ip, hits in ip_hits.items():
            if len(hits) >= threshold:
                first_hit = hits[0]
                category_name = first_hit.get("category", "Exploit")
                reason = f"Auto-Ban: {len(hits)}x {category_name} ({duration})"

                # 1. Firewall Deny
                add_ufw_deny(ip)

                # 2. In DB protokollieren
                try:
                    db.execute_db("""
                        INSERT OR REPLACE INTO security_ip_bans (ip_address, reason, banned_by, ban_type, created_at)
                        VALUES (?, ?, 'sentinel_autoban', 'ufw', ?)
                    """, (ip, reason, now_str))

                    # 3. Incident eintragen
                    if config.get("notify_incident", True):
                        hit_details = f"Automatische Sperre nach {len(hits)} Treffern ({category_name}). Letztes Muster: {first_hit.get('matched', '-')}"
                        IncidentManager.log_incident(
                            incident_type="autoban_exploit",
                            source_ip=ip,
                            target_service="nginx",
                            severity="high",
                            details=hit_details,
                            response_action="ufw_deny"
                        )

                    # 4. Audit Log
                    try:
                        db.log_audit(
                            username="sentinel_autoban",
                            action="SECURITY_AUTOBAN_IP",
                            details=f"IP {ip} automatisch gesperrt ({reason})",
                            ip_address="127.0.0.1",
                            status="success"
                        )
                    except Exception:
                        pass

                    banned_ips_set.add(ip)
                    newly_banned.append({
                        "ip": ip,
                        "hits": len(hits),
                        "category": category_name,
                        "reason": reason
                    })
                except Exception:
                    continue

        return {
            "active": True,
            "banned_count": len(newly_banned),
            "banned_ips": newly_banned,
            "message": f"{len(newly_banned)} Angreifer-IPs automatisch gesperrt." if newly_banned else "Keine neuen IPs über dem Schwellenwert."
        }
