"""
SysCore Sentinel - Software Protection Registry
Klassifiziert und schützt installierte Software und Dienste:
- observe_only: Nur Beobachtung, keine Konfigurationsänderungen (z.B. externe Docker-Container)
- security_managed: Durch SysCore verwaltete Komponenten (z.B. NGINX VHosts, PHP-FPM)
- protected: Streng geschützte Drittanbieter- oder Systemsoftware (z.B. Pterodactyl Wings, MariaDB, SSH).
             Keine destruktiven Paket-Aktionen, keine Monolith-Überschreibungen.
"""

from typing import Dict, Any, List
import db

# Vordefinierte Erkennungsregeln und Schutzklassen
KNOWN_SOFTWARE_RULES = {
    "pterodactyl-wings": {
        "display_name": "Pterodactyl Wings (Game Server Daemon)",
        "type": "game_panel",
        "default_mode": "protected",
        "service_names": ["wings"],
        "ports": [8080, 2022],
        "config_paths": ["/etc/pterodactyl/config.yml"],
        "notes": "Geschützte Game-Server-Steuerung. Darf niemals durch SysCore deinstalliert oder rekonfiguriert werden!"
    },
    "pterodactyl-panel": {
        "display_name": "Pterodactyl Web Panel",
        "type": "game_panel",
        "default_mode": "protected",
        "service_names": ["pteroq"],
        "ports": [80, 443],
        "config_paths": ["/var/www/pterodactyl/.env"],
        "notes": "Pterodactyl Webinterface. Datenbank und Crons sind geschützt."
    },
    "nginx": {
        "display_name": "NGINX Reverse Proxy & Webserver",
        "type": "webserver",
        "default_mode": "security_managed",
        "service_names": ["nginx"],
        "ports": [80, 443],
        "config_paths": ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/"],
        "notes": "Webserver-Verwaltung erfolgt ausschließlich additiv über Drop-Ins (/etc/nginx/conf.d/)."
    },
    "mariadb": {
        "display_name": "MariaDB / MySQL Server",
        "type": "database",
        "default_mode": "protected",
        "service_names": ["mariadb", "mysql"],
        "ports": [3306],
        "config_paths": ["/etc/mysql/my.cnf", "/etc/mysql/mariadb.conf.d/"],
        "notes": "Kern-Datenbank. Muss vor unberechtigtem externen Zugriff isoliert bleiben."
    },
    "docker": {
        "display_name": "Docker Engine & Container Runtime",
        "type": "container_runtime",
        "default_mode": "observe_only",
        "service_names": ["docker", "containerd"],
        "ports": [2375, 2376],
        "config_paths": ["/etc/docker/daemon.json"],
        "notes": "Container-Netzwerke werden nur beobachtet; keine automatischen Port-Sperren auf Docker-Bridges."
    },
    "openssh-server": {
        "display_name": "OpenSSH Daemon",
        "type": "system_service",
        "default_mode": "protected",
        "service_names": ["ssh", "sshd"],
        "ports": [22],
        "config_paths": ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"],
        "notes": "System-Fernzugriff. Änderungen erfolgen über Drop-Ins mit Safe-Apply Watchdog."
    },
    "php-fpm": {
        "display_name": "PHP FastCGI Process Manager",
        "type": "language_runtime",
        "default_mode": "security_managed",
        "service_names": ["php8.0-fpm", "php8.1-fpm", "php8.2-fpm", "php8.3-fpm", "php8.4-fpm"],
        "ports": [9000],
        "config_paths": ["/etc/php/"],
        "notes": "SysCore verwaltet einzelne PHP-FPM Pools pro Domain."
    },
    "phpmyadmin": {
        "display_name": "phpMyAdmin Database Manager",
        "type": "database_tool",
        "default_mode": "security_managed",
        "service_names": [],
        "ports": [],
        "config_paths": ["/etc/phpmyadmin/config.inc.php"],
        "notes": "Webbasierte Datenbankverwaltung."
    },
    "nextcloud": {
        "display_name": "Nextcloud Hub",
        "type": "cloud_storage",
        "default_mode": "security_managed",
        "service_names": [],
        "ports": [],
        "config_paths": ["/var/www/nextcloud/config/config.php"],
        "notes": "Private Cloud Lösung."
    }
}

class SoftwareRegistry:
    """Verwaltet registrierte Software und deren Schutzstufen."""

    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        rows = db.query_db("SELECT * FROM software_inventory ORDER BY protection_mode, name")
        return [dict(r) for r in rows] if rows else []

    @staticmethod
    def is_protected(software_name: str) -> bool:
        """Prüft, ob ein Software-Paket oder Dienst unter 'protected' fällt."""
        row = db.query_db("SELECT protection_mode FROM software_inventory WHERE name = ?", (software_name,), one=True)
        if row and row["protection_mode"] == "protected":
            return True
        rule = KNOWN_SOFTWARE_RULES.get(software_name)
        if rule and rule["default_mode"] == "protected":
            return True
        return False

    @staticmethod
    def set_protection_mode(software_id: int, mode: str) -> bool:
        """Ändert den Schutzmodus (observe_only, security_managed, protected)."""
        if mode not in ("observe_only", "security_managed", "protected"):
            return False
        db.execute_db("UPDATE software_inventory SET protection_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (mode, software_id))
        return True
