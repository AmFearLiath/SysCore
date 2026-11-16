"""
SysCore Sentinel - Incident Management Module
Protokolliert und korreliert sicherheitsrelevante Ereignisse in der Vorfalls-Timeline.
"""

from typing import Dict, Any, List
import db

class IncidentManager:
    """Verwaltet Sicherheitsvorfälle und Angriffs-Ereignisse."""

    @staticmethod
    def log_incident(
        incident_type: str,
        source_ip: str,
        target_service: str,
        severity: str = "high",
        details: str = "",
        response_action: str = "logged"
    ) -> int:
        """Erfasst einen neuen Sicherheitsvorfall in der Datenbank."""
        return db.execute_db("""
            INSERT INTO security_incidents (incident_type, source_ip, target_service, severity, details, response_action)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (incident_type, source_ip, target_service, severity, details, response_action))

    @staticmethod
    def get_recent_incidents(limit: int = 50) -> List[Dict[str, Any]]:
        """Liest die neuesten Sicherheitsvorfälle aus."""
        rows = db.query_db("SELECT * FROM security_incidents ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows] if rows else []
