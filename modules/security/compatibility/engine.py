"""
SysCore Sentinel - Compatibility Engine
Führt umfassende Kompatibilitäts- und Kollisionsprüfungen durch,
bevor Sicherheitsmaßnahmen oder Profilwechsel ausgeführt werden.
"""

from typing import Dict, Any, List, Tuple
from modules.security.compatibility.package_guard import PackageGuard
from modules.security.compatibility.config_guard import ConfigGuard
from modules.security.inventory.software_registry import SoftwareRegistry

class CompatibilityEngine:
    """Zentrale Validierungsinstanz für geplante System- und Sicherheitsoperationen."""

    @staticmethod
    def validate_change_plan(change_plan: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validiert einen vollständigen Change Plan.
        Gibt (is_valid, errors) zurück.
        """
        errors = []

        # 1. Paketoperationen validieren
        packages_to_remove = change_plan.get("packages_remove", [])
        if packages_to_remove:
            ok, msg = PackageGuard.validate_package_action("remove", packages_to_remove)
            if not ok:
                errors.append(msg)

        # 2. Dateisystem-Schreiboperationen validieren
        files_to_write = change_plan.get("files_write", {})
        for path, content in files_to_write.items():
            ok, msg = ConfigGuard.validate_file_write(path, is_drop_in=True)
            if not ok:
                errors.append(msg)

        # 3. Port-Sperren auf Konflikte prüfen
        ports_to_block = change_plan.get("ports_block", [])
        for port in ports_to_block:
            # Pterodactyl Ports schützen
            if port in (8080, 2022) and SoftwareRegistry.is_protected("pterodactyl-wings"):
                errors.append(f"Port {port} darf nicht gesperrt werden, da er für Pterodactyl Wings erforderlich ist!")

            # SSH Port schützen
            if port == 22:
                errors.append("Port 22 (SSH) darf niemals komplett gesperrt werden, um Aussperrung zu verhindern!")

        # 4. Prüfen ob Pterodactyl aktiv ist und NGINX WAF zu strikt werden könnte
        if SoftwareRegistry.is_protected("pterodactyl-panel") and change_plan.get("waf_block_websocket"):
            errors.append("Pterodactyl benötigt WebSocket-Verbindungen für die Server-Konsole. WebSocket-Blockade verhindert!")

        return (len(errors) == 0), errors
