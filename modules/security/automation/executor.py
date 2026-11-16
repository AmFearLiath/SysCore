"""
SysCore Sentinel - Automation Action Executor
Führt automatisierte Reaktionen gemäß definierter Reaktionsstufen sicher aus.
"""

from typing import Dict, Any
import db
from modules.security.protection.firewall import add_ufw_deny
from modules.security.detection.incidents import IncidentManager

class ActionExecutor:
    """Führt automatisierte Sicherheitsaktionen aus."""

    @staticmethod
    def handle_event(event_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Prüft und triggert Aktionen für ein Ereignis."""
        row = db.query_db("SELECT * FROM security_automation_rules WHERE event_type = ? AND is_enabled = 1", (event_type,), one=True)
        if not row:
            return {"action": "none", "reason": "Keine aktive Regel für diesen Event-Typ."}

        level = row["reaction_level"]
        action_type = row["action_type"]

        # Level 4: Automatische Sofortaktion
        if level == 4 and action_type == "ban_ip":
            ip = context.get("ip")
            if ip and ip not in ("127.0.0.1", "0.0.0.0"):
                add_ufw_deny(ip)
                db.execute_db("""
                    INSERT OR REPLACE INTO security_ip_bans (ip_address, reason, banned_by, ban_type)
                    VALUES (?, 'Automatische Sperre durch Sentinel Automation (Level 4)', 'sentinel_auto', 'ufw')
                """, (ip,))
                IncidentManager.log_incident("auto_ban", ip, "system", "high", f"IP {ip} automatisch gesperrt", "banned")
                return {"action": "banned", "ip": ip, "level": 4}

        # Level 1-3: Protokollieren und Melden
        IncidentManager.log_incident(event_type, context.get("ip", "unknown"), "sentinel", "medium", str(context), f"level_{level}")
        return {"action": "notified", "level": level}
