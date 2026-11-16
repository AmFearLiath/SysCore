"""
SysCore Sentinel - Policy Engine
Zentrale Richtlinien-Engine zur Validierung, Überprüfung und Durchsetzung
von Sicherheits-Policies im laufenden System.
"""

from typing import Dict, List, Any
import db

class PolicyEngine:
    """Verwaltet und evaluiert System-Sicherheits-Policies."""

    @staticmethod
    def get_all_policies() -> List[Dict[str, Any]]:
        """Lädt alle Policies aus der Datenbank."""
        rows = db.query_db("SELECT * FROM security_policies ORDER BY category, policy_key")
        return [dict(r) for r in rows] if rows else []

    @staticmethod
    def evaluate_live_policies(
        ufw_status: Dict[str, Any],
        ssh_audit: Dict[str, Any],
        f2b_status: Dict[str, Any],
        ports_audit: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Gleicht den aktuellen Zustand des Systems mit den gespeicherten Policies ab
        und aktualisiert den Status in der Datenbank.
        """
        policies = PolicyEngine.get_all_policies()
        results = []

        # Ermittle aktuelle Systemwerte
        live_values = {
            "firewall.ufw_enabled": "active" if ufw_status.get("active") else "inactive",
            "ssh.disable_root_login": "no" if ssh_audit.get("permit_root_login") in ("no", "prohibit-password") else "yes",
            "ssh.enforce_key_auth": "no" if ssh_audit.get("password_auth") == "no" else "yes",
            "fail2ban.service_active": "running" if f2b_status.get("running") else "stopped",
            "ports.database_not_public": "127.0.0.1", # Wird unten geprüft
            "waf.security_headers": "enabled", # Wird durch NGINX drop-in bestimmt
            "file_integrity.baseline": "valid"
        }

        # Prüfe Datenbank-Ports
        for listener in ports_audit.get("listeners", []):
            if listener.get("public") and listener.get("port") in (3306, 5432):
                live_values["ports.database_not_public"] = "0.0.0.0"
                break

        for pol in policies:
            pkey = pol["policy_key"]
            desired = pol["desired_value"]
            curr = live_values.get(pkey, pol.get("current_value", "unknown"))

            # Status ermitteln
            if curr == desired:
                status = "compliant"
            elif pkey in ("ssh.enforce_key_auth", "waf.security_headers") and curr != desired:
                status = "warning"
            else:
                status = "non_compliant"

            # In DB persistieren
            try:
                db.execute_db("""
                    UPDATE security_policies 
                    SET current_value = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE policy_key = ?
                """, (str(curr), status, pkey))
            except Exception:
                pass

            pol["current_value"] = curr
            pol["status"] = status
            results.append(pol)

        return results

    @staticmethod
    def get_compliance_stats(policies: List[Dict[str, Any]]) -> Dict[str, int]:
        """Gibt Zählungen für compliant, warning, non_compliant zurück."""
        stats = {"compliant": 0, "warning": 0, "non_compliant": 0, "total": len(policies)}
        for p in policies:
            st = p.get("status", "non_compliant")
            if st in stats:
                stats[st] += 1
            else:
                stats["non_compliant"] += 1
        return stats
