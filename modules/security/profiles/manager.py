"""
SysCore Sentinel - Profile Manager
Verwaltet die 5 Sicherheits-Profile (Basic, Standard, Hardened, Maximum, Custom),
generiert transparente Change Plans (Diffs) und wendet Profilwechsel transaktional an.
"""

import json
from typing import Dict, Any, List, Tuple
import db
from modules.security.core.safe_apply import SafeApply
from modules.security.compatibility.engine import CompatibilityEngine

# Spezifikation der 5 Profile nach security-center.md Kapitel 4
PROFILES_SPEC = {
    "basic": {
        "name": "basic",
        "display_name": "Basic Protection",
        "badge_color": "blue",
        "target_score": 60,
        "description": "Grundlegender Basisschutz für Entwicklungs- und Testserver. Keine harten Einschränkungen.",
        "settings": {
            "firewall_active": True,
            "firewall_default_incoming": "deny",
            "ssh_root_login": "yes",
            "ssh_password_auth": "yes",
            "fail2ban_active": False,
            "waf_level": "off",
            "clamav_active": False,
            "fim_active": False
        }
    },
    "standard": {
        "name": "standard",
        "display_name": "Standard Server (Empfohlen)",
        "badge_color": "emerald",
        "target_score": 80,
        "description": "Ausgewogener Schutz für produktive Web- und App-Server. UFW aktiv, Fail2Ban aktiv, Passwort-SSH erlaubt.",
        "settings": {
            "firewall_active": True,
            "firewall_default_incoming": "deny",
            "ssh_root_login": "no",
            "ssh_password_auth": "yes",
            "fail2ban_active": True,
            "waf_level": "standard",
            "clamav_active": True,
            "fim_active": False
        }
    },
    "hardened": {
        "name": "hardened",
        "display_name": "Hardened Production",
        "badge_color": "amber",
        "target_score": 90,
        "description": "Erhöhte Sicherheit für exponierte Server. SSH nur via Key (kein Passwort, kein Root), NGINX WAF aktiv.",
        "settings": {
            "firewall_active": True,
            "firewall_default_incoming": "deny",
            "ssh_root_login": "no",
            "ssh_password_auth": "no",
            "fail2ban_active": True,
            "waf_level": "strict",
            "clamav_active": True,
            "fim_active": True
        }
    },
    "maximum": {
        "name": "maximum",
        "display_name": "Maximum Lockdown",
        "badge_color": "rose",
        "target_score": 98,
        "description": "Höchste Schutzstufe für sicherheitskritische Infrastruktur. Aggressives Fail2Ban, Strict Rate-Limiting, FIM Überwachung.",
        "settings": {
            "firewall_active": True,
            "firewall_default_incoming": "deny",
            "ssh_root_login": "no",
            "ssh_password_auth": "no",
            "fail2ban_active": True,
            "waf_level": "maximum",
            "clamav_active": True,
            "fim_active": True
        }
    },
    "custom": {
        "name": "custom",
        "display_name": "Benutzerdefiniert",
        "badge_color": "purple",
        "target_score": 0,
        "description": "Individuelle Konfiguration durch den Administrator ohne festes Schema.",
        "settings": {}
    }
}

class ProfileManager:
    """Verwaltet Profile und Profilwechsel."""

    @staticmethod
    def get_all_profiles() -> List[Dict[str, Any]]:
        """Gibt alle Profile mit aktuellem Status zurück."""
        db_profiles = {r["name"]: dict(r) for r in db.query_db("SELECT * FROM security_profiles")}
        result = []
        for key, spec in PROFILES_SPEC.items():
            item = dict(spec)
            if key in db_profiles:
                item["is_active"] = db_profiles[key]["is_active"] == 1
                item["id"] = db_profiles[key]["id"]
            else:
                item["is_active"] = (key == "standard")
            result.append(item)
        return result

    @staticmethod
    def get_active_profile() -> Dict[str, Any]:
        """Ermittelt das aktuell aktive Profil."""
        row = db.query_db("SELECT * FROM security_profiles WHERE is_active = 1", one=True)
        if row:
            p_name = row["name"]
            spec = PROFILES_SPEC.get(p_name, PROFILES_SPEC["standard"])
            res = dict(spec)
            res["is_active"] = True
            return res
        return PROFILES_SPEC["standard"]

    @staticmethod
    def generate_change_plan(target_profile_name: str) -> Dict[str, Any]:
        """Erzeugt einen transparenten Change Plan mit Diffs vor der Anwendung."""
        target = PROFILES_SPEC.get(target_profile_name)
        if not target:
            raise ValueError(f"Profil '{target_profile_name}' existiert nicht.")

        current = ProfileManager.get_active_profile()
        diffs = []
        files_to_write = {}

        t_set = target.get("settings", {})
        c_set = current.get("settings", {})

        # Vergleiche Einstellungen
        for key, target_val in t_set.items():
            curr_val = c_set.get(key)
            if curr_val != target_val:
                diffs.append({
                    "setting": key,
                    "old_value": curr_val,
                    "new_value": target_val,
                    "description": f"Änderung von '{key}': {curr_val} ➜ {target_val}"
                })

        # Drop-Ins vorbereiten (Additive Konfiguration)
        if "ssh_root_login" in t_set or "ssh_password_auth" in t_set:
            ssh_dropin = f"""# SysCore Sentinel Profile: {target['display_name']}
# Automatisch generiert durch Safe-Apply
PermitRootLogin {t_set.get('ssh_root_login', 'no')}
PasswordAuthentication {t_set.get('ssh_password_auth', 'yes')}
"""
            files_to_write["/etc/ssh/sshd_config.d/99-syscore.conf"] = ssh_dropin

        if t_set.get("waf_level") in ("strict", "maximum"):
            waf_dropin = f"""# SysCore Sentinel WAF Drop-In
# Profil: {target['display_name']}
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"""
            files_to_write["/etc/nginx/conf.d/99-syscore-waf.conf"] = waf_dropin

        return {
            "target_profile": target_profile_name,
            "target_display_name": target["display_name"],
            "target_score": target["target_score"],
            "diffs": diffs,
            "files_write": files_to_write,
            "packages_remove": [],
            "ports_block": []
        }

    @staticmethod
    def apply_profile(target_profile_name: str, username: str = "admin") -> Tuple[bool, str]:
        """Wendet das Zielprofil mit Safe-Apply und Kompatibilitätsprüfung an."""
        change_plan = ProfileManager.generate_change_plan(target_profile_name)

        # 1. Kompatibilitätsprüfung
        is_compat, errors = CompatibilityEngine.validate_change_plan(change_plan)
        if not is_compat:
            return False, f"Kompatibilitätsfehler: {', '.join(errors)}"

        # 2. Vorher-Snapshot anlegen
        current = ProfileManager.get_active_profile()
        snapshot_id = SafeApply.create_snapshot(
            snapshot_type="pre_profile_switch",
            description=f"Automatischer Snapshot vor Profilwechsel zu '{target_profile_name}'",
            current_state={
                "profile": current["name"],
                "settings": current.get("settings", {}),
                "files": {}
            },
            created_by=username
        )

        # 3. Additive Dateien anwenden
        files = change_plan.get("files_write", {})
        for path, content in files.items():
            service = "nginx" if "nginx" in path else ("sshd" if "ssh" in path else None)
            ok, msg = SafeApply.apply_additive_file(path, content, service_to_reload=service)
            if not ok:
                # Rollback!
                SafeApply.rollback_snapshot(snapshot_id)
                return False, f"Fehler bei Safe-Apply ({path}): {msg}. Automatischer Rollback durchgeführt."

        # 4. Profilstatus in DB aktualisieren
        db.execute_db("UPDATE security_profiles SET is_active = 0")
        db.execute_db("UPDATE security_profiles SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE name = ?", (target_profile_name,))

        return True, f"Sicherheitsprofil '{change_plan['target_display_name']}' erfolgreich mit Safe-Apply aktiviert (Snapshot #{snapshot_id})."
