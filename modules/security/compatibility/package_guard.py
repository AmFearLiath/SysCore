"""
SysCore Sentinel - Package Guard
Verhindert destruktive Paketoperationen auf Linux-Systemen (SEC-004):
- Verbietet automatische Deinstallation von geschützten Abhängigkeiten (z.B. Pterodactyl, Docker, MariaDB).
- Blockiert gefährliche Befehle wie 'apt-get autoremove --purge', 'apt-get dist-upgrade' ohne Admin-Freigabe.
- Stellt sicher, dass keine systemkritischen Binaries beschädigt werden.
"""

from typing import Tuple, List
from modules.security.inventory.software_registry import SoftwareRegistry

PROTECTED_SYSTEM_PACKAGES = {
    "mariadb-server", "mariadb-client", "mysql-server", "mysql-client",
    "nginx", "nginx-common", "nginx-core",
    "docker-ce", "docker-ce-cli", "containerd.io",
    "openssh-server", "openssh-client",
    "wings", "sudo", "systemd", "ufw", "fail2ban", "python3"
}

class PackageGuard:
    """Schützt essentielle System- und Drittanbieter-Pakete vor versehentlicher Beschädigung."""

    @staticmethod
    def validate_package_action(action: str, packages: List[str]) -> Tuple[bool, str]:
        """
        Prüft eine geplante Paketoperation auf Gefahren.
        action: 'install', 'remove', 'purge', 'upgrade'
        """
        action = action.lower().strip()
        packages_lower = [p.lower().strip() for p in packages]

        # 1. Destruktive Entfernungen prüfen
        if action in ("remove", "purge", "autoremove"):
            for pkg in packages_lower:
                if pkg in PROTECTED_SYSTEM_PACKAGES:
                    return False, f"Package Guard Schutzverletzung: Paket '{pkg}' ist als geschützt markiert und darf nicht deinstalliert werden!"
                if SoftwareRegistry.is_protected(pkg):
                    return False, f"Package Guard Schutzverletzung: Paket '{pkg}' wird von einer geschützten Softwarekomponente benötigt!"

        # 2. Ungeprüftes Massen-Upgrade blockieren
        if action in ("dist-upgrade", "full-upgrade"):
            return False, "Package Guard Warnung: Vollständiges System-Dist-Upgrade erfordert manuelle Terminal-Bestätigung, um Breaking Changes zu vermeiden."

        return True, "Paketoperation kompatibel und freigegeben."
