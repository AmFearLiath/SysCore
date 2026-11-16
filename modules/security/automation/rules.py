"""
SysCore Sentinel - Automation Engine
Verwaltet automatisierte Reaktionsregeln mit 5 Reaktionsstufen (0 - 4):
- Level 0: Log Only
- Level 1: Notify (Dashboard / E-Mail)
- Level 2: Recommend (Sentinel schlägt Maßnahme vor)
- Level 3: Confirm (Erfordert 1-Klick Bestätigung im Panel)
- Level 4: Automatic (Vollautomatische sofortige Schutzreaktion, z.B. IP-Sperre)
"""

from typing import Dict, Any, List
import db
import json

REACTION_LEVELS = {
    0: ("Log Only", "Nur protokollieren, keine aktive Benachrichtigung."),
    1: ("Notify", "Admin per Dashboard & Benachrichtigung informieren."),
    2: ("Recommend", "Sentinel schlägt konkrete Gegenmaßnahmen vor."),
    3: ("Confirm", "Vollständige Vorbereitung der Abwehraktion, erfordert 1-Klick Bestätigung."),
    4: ("Automatic", "Sofortige, ununterbrochene automatisierte Abwehr.")
}

class AutomationRulesManager:
    """Verwaltet Automatisierungsregeln in der Datenbank."""

    @staticmethod
    def get_rules() -> List[Dict[str, Any]]:
        rows = db.query_db("SELECT * FROM security_automation_rules ORDER BY reaction_level DESC, id ASC")
        return [dict(r) for r in rows] if rows else []

    @staticmethod
    def update_rule_level(rule_id: int, new_level: int, is_enabled: bool = True) -> bool:
        if new_level not in REACTION_LEVELS:
            return False
        db.execute_db("""
            UPDATE security_automation_rules 
            SET reaction_level = ?, is_enabled = ? 
            WHERE id = ?
        """, (new_level, 1 if is_enabled else 0, rule_id))
        return True
