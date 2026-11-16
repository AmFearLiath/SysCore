"""
SysCore Sentinel - Config Guard
Erzwingt additive Konfigurationsänderungen (SEC-005):
- Verbietet das Überschreiben monolithischer Basiskonfigurationen (/etc/nginx/nginx.conf, /etc/ssh/sshd_config).
- Erzwingt die Verwendung isolierter SysCore Drop-Ins (/etc/nginx/conf.d/99-syscore.conf, /etc/ssh/sshd_config.d/99-syscore.conf).
- Schützt geschützte Drittanbieter-Dateien (z.B. Pterodactyl config.yml, Docker daemon.json).
"""

import os
from typing import Tuple

PROTECTED_CONFIG_FILES = {
    "/etc/pterodactyl/config.yml",
    "/etc/nginx/nginx.conf",
    "/etc/ssh/sshd_config",
    "/etc/docker/daemon.json",
    "/etc/mysql/my.cnf",
    "/etc/fstab",
    "/etc/passwd",
    "/etc/shadow"
}

ALLOWED_DROP_IN_PREFIXES = [
    "/etc/nginx/conf.d/",
    "/etc/ssh/sshd_config.d/",
    "/etc/systemd/system/",
    "/etc/sysctl.d/",
    "/etc/fail2ban/jail.d/"
]

class ConfigGuard:
    """Verhindert destruktive Änderungen an System- und Fremdkonfigurationen."""

    @staticmethod
    def validate_file_write(target_path: str, is_drop_in: bool = False) -> Tuple[bool, str]:
        """Prüft, ob eine Schreiboperation auf den Pfad zulässig und additiv ist."""
        norm_path = os.path.normpath(target_path).replace("\\", "/")

        # 1. Streng verbotene monolithische Dateien
        if norm_path in PROTECTED_CONFIG_FILES and not is_drop_in:
            return False, f"Config Guard Blockade: '{norm_path}' ist eine geschützte Basiskonfiguration. Änderungen müssen über ein Drop-In (z.B. in conf.d/) erfolgen!"

        # 2. Prüfe ob Pfad in erlaubten Drop-In Ordnern liegt, falls es eine System-Konfiguration ist
        if norm_path.startswith("/etc/"):
            # Pterodactyl-Dateien niemals antasten
            if "/pterodactyl/" in norm_path:
                return False, f"Config Guard Blockade: '{norm_path}' gehört zu einer geschützten Pterodactyl-Instanz und darf nicht verändert werden!"

            # Erlaube Drop-Ins
            allowed = any(norm_path.startswith(prefix) for prefix in ALLOWED_DROP_IN_PREFIXES)
            if not allowed and not norm_path.startswith("/etc/nginx/sites-available/"):
                return False, f"Config Guard Blockade: Direkte Modifikation von '{norm_path}' abgelehnt. Verwende einen Drop-In Ordner."

        return True, "Konfigurationsänderung ist additiv und zulässig."
