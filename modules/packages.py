"""
SysCore Package Manager - Unified Package, Application & Stack Engine
Version 0.9.0.0
Verwaltet Systempakete, Webanwendungen, Stacks, Container und Repositories
vollständig integriert mit dem Sentinel Software Inventory & UFW Port-Schutz.
"""

import os
import re
import json
import time
import shutil
import secrets
import threading
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify, session, send_file
from modules.auth_users import login_required, role_required, log_audit
from db import query_db, execute_db
from config import WEB_ROOT_BASE, NGINX_AVAILABLE, NGINX_ENABLED, CERTBOT_EMAIL
from modules.webserver import build_nginx_config, reload_nginx, find_ssl_cert_for_domain, issue_and_apply_ssl, detect_php_versions
from modules.system_agent import run_privileged, build_privileged_cmd

# Import der gehärteten App-Importer Funktionen für vollständige Menü-Konsolidierung
from modules.apps import (
    safe_extract_zip, resolve_manifest_path, validate_manifest,
    create_app_database, ACTION_REGISTRY, SAMPLE_MANIFEST
)

packages_bp = Blueprint("packages", __name__, url_prefix="/packages")

# -----------------------------------------------------------------------------
# 1. Einheitliche Paket-, Stack- & Service-Registry
# -----------------------------------------------------------------------------

PACKAGES_REGISTRY = {
    # --- Runtimes ---
    "php8.2": {
        "name": "PHP 8.2 & Extensions",
        "category": "Runtimes",
        "type": "runtime",
        "service_name": "php8.2-fpm",
        "desc": "PHP 8.2 FPM inkl. curl, mbstring, xml, zip, gd, mysql, intl, bcmath",
        "check_cmd": ["php8.2", "-v"],
        "check_paths": ["/etc/php/8.2"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y php8.2 php8.2-fpm php8.2-mysql php8.2-mbstring php8.2-xml php8.2-curl php8.2-zip php8.2-gd php8.2-intl php8.2-bcmath",
            "systemctl enable --now php8.2-fpm"
        ]
    },
    "php8.3": {
        "name": "PHP 8.3 & Extensions",
        "category": "Runtimes",
        "type": "runtime",
        "service_name": "php8.3-fpm",
        "desc": "PHP 8.3 FPM inkl. curl, mbstring, xml, zip, gd, mysql, intl, bcmath",
        "check_cmd": ["php8.3", "-v"],
        "check_paths": ["/etc/php/8.3"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y php8.3 php8.3-fpm php8.3-mysql php8.3-mbstring php8.3-xml php8.3-curl php8.3-zip php8.3-gd php8.3-intl php8.3-bcmath",
            "systemctl enable --now php8.3-fpm"
        ]
    },
    "php8.4": {
        "name": "PHP 8.4 & Extensions",
        "category": "Runtimes",
        "type": "runtime",
        "service_name": "php8.4-fpm",
        "desc": "PHP 8.4 FPM (neueste Version) inkl. moderner Web-Extensions",
        "check_cmd": ["php8.4", "-v"],
        "check_paths": ["/etc/php/8.4"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y php8.4 php8.4-fpm php8.4-mysql php8.4-mbstring php8.4-xml php8.4-curl php8.4-zip php8.4-gd php8.4-intl php8.4-bcmath",
            "systemctl enable --now php8.4-fpm"
        ]
    },
    "composer": {
        "name": "Composer (PHP Manager)",
        "category": "Runtimes",
        "type": "tool",
        "desc": "Global installierter PHP Composer für Laravel, Symfony & WordPress",
        "check_cmd": ["composer", "--version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y curl php-cli unzip",
            "curl -sS https://getcomposer.org/installer -o /tmp/composer-setup.php",
            "php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer",
            "rm -f /tmp/composer-setup.php"
        ]
    },
    "nodejs": {
        "name": "Node.js 20 LTS & PM2",
        "category": "Runtimes",
        "type": "runtime",
        "desc": "Node.js 20 LTS (NodeSource) + globaler PM2 Process Manager",
        "check_cmd": ["node", "-v"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y ca-certificates curl gnupg",
            "mkdir -p /etc/apt/keyrings",
            "curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg --yes",
            "echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main' > /etc/apt/sources.list.d/nodesource.list",
            "apt-get update",
            "apt-get install -y nodejs",
            "npm install -g pm2"
        ]
    },

    # --- Webserver & Proxies ---
    "nginx": {
        "name": "NGINX Reverse Proxy & Webserver",
        "category": "Webserver",
        "type": "service",
        "service_name": "nginx",
        "desc": "Hochperformanter Reverse Proxy, Static File Server und SSL-Terminator",
        "check_cmd": ["nginx", "-v"],
        "check_paths": ["/etc/nginx/nginx.conf"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y nginx",
            "systemctl enable --now nginx"
        ]
    },
    "apache2": {
        "name": "Apache2 HTTP Server",
        "category": "Webserver",
        "type": "service",
        "service_name": "apache2",
        "desc": "Traditioneller, modularer Webserver mit .htaccess-Unterstützung",
        "check_cmd": ["apache2", "-v"],
        "check_paths": ["/etc/apache2/apache2.conf"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y apache2",
            "systemctl enable --now apache2"
        ]
    },

    # --- Datenbanken & Cache ---
    "mariadb": {
        "name": "MariaDB Relational Database Server",
        "category": "Databases",
        "type": "database",
        "service_name": "mariadb",
        "desc": "Robuste relationale SQL-Datenbank (MySQL-kompatibler Open-Source Standard)",
        "check_cmd": ["mariadb", "--version"],
        "check_paths": ["/etc/mysql/my.cnf", "/var/lib/mysql"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y mariadb-server mariadb-client",
            "systemctl enable --now mariadb"
        ]
    },
    "redis": {
        "name": "Redis In-Memory Server",
        "category": "Databases",
        "type": "cache",
        "service_name": "redis-server",
        "desc": "Hochperformanter In-Memory Cache & Key-Value Store für Sessions, Queues und Caching",
        "check_cmd": ["redis-server", "-v"],
        "check_paths": ["/etc/redis/redis.conf"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y redis-server",
            "systemctl enable --now redis-server"
        ]
    },
    "postgresql": {
        "name": "PostgreSQL Database Server",
        "category": "Databases",
        "type": "database",
        "service_name": "postgresql",
        "desc": "Enterprise-Grade relationale Open-Source Datenbank mit JSONB-Unterstützung",
        "check_cmd": ["psql", "--version"],
        "check_paths": ["/etc/postgresql"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y postgresql postgresql-contrib",
            "systemctl enable --now postgresql"
        ]
    },

    # --- Pterodactyl Game Server Stack (Vollintegration) ---
    "pterodactyl-panel": {
        "name": "Pterodactyl Web Panel",
        "category": "Game Server",
        "type": "application",
        "service_name": "pteroq",
        "desc": "Zentrales Web-Management-Interface für Nodes, Game-Server, Backups und Benutzer",
        "check_cmd": ["test", "-d", "/var/www/pterodactyl"],
        "check_paths": ["/var/www/pterodactyl/.env", "/var/www/pterodactyl/artisan"],
        "web_configurable": True,
        "doc_root": "/var/www/pterodactyl/public",
        "requires_php": True,
        "default_subdomain_prefix": "panel",
        "install_cmds": [
            "echo 'Pterodactyl Panel Stack-Installation über SysCore Stack Manager verfügbar.'"
        ]
    },
    "pterodactyl-wings": {
        "name": "Pterodactyl Wings (Node Daemon)",
        "category": "Game Server",
        "type": "service",
        "service_name": "wings",
        "desc": "High-Performance Go-Daemon zur Container- und Gameserver-Orchestrierung auf Port 8080 & 2022",
        "check_cmd": ["wings", "--version"],
        "check_paths": ["/etc/pterodactyl/config.yml", "/usr/local/bin/wings"],
        "port": 8080,
        "protected_ports": [8080, 2022],
        "install_cmds": [
            "echo 'Wings Daemon Konfiguration erfordert Node-Token aus dem Pterodactyl Panel.'"
        ]
    },

    # --- Monitoring & Analyse ---
    "uptime_kuma": {
        "name": "Uptime Kuma",
        "category": "Monitoring",
        "type": "tool",
        "desc": "Modernes Monitoring-Tool mit Statusseiten und Alarmierung auf Port 3001",
        "check_cmd": ["test", "-d", "/opt/uptime-kuma"],
        "check_paths": ["/opt/uptime-kuma"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y git curl",
            "mkdir -p /opt",
            "if [ ! -d /opt/uptime-kuma ]; then git clone https://github.com/louislam/uptime-kuma.git /opt/uptime-kuma; fi",
            "cd /opt/uptime-kuma && npm run setup",
            "pm2 start /opt/uptime-kuma/server/server.js --name uptime-kuma",
            "pm2 save"
        ],
        "port": 3001,
        "web_configurable": True,
        "proxy_port": 3001,
        "default_subdomain_prefix": "status"
    },
    "goaccess": {
        "name": "GoAccess (Log-Analyzer)",
        "category": "Monitoring",
        "type": "tool",
        "desc": "Visueller NGINX Realtime Log-Analyzer für Besucher-, Traffic- und Bot-Statistiken",
        "check_cmd": ["goaccess", "--version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y goaccess"
        ]
    },

    # --- Web-GUIs & Tools ---
    "phpmyadmin": {
        "name": "phpMyAdmin (Web Database GUI)",
        "category": "Tools",
        "type": "tool",
        "desc": "Vollwertige phpMyAdmin Web-Oberfläche für MySQL/MariaDB unter /var/www/phpmyadmin",
        "check_cmd": ["test", "-d", "/var/www/phpmyadmin"],
        "check_paths": ["/var/www/phpmyadmin/config.inc.php"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y wget unzip",
            "mkdir -p /var/www/phpmyadmin",
            "wget -q https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz -O /tmp/pma.tar.gz",
            "tar -xzf /tmp/pma.tar.gz -C /var/www/phpmyadmin --strip-components=1",
            "rm -f /tmp/pma.tar.gz",
            "cp /var/www/phpmyadmin/config.sample.inc.php /var/www/phpmyadmin/config.inc.php",
            "RANDOM_BLOWFISH=$(python3 -c \"import secrets; print(secrets.token_hex(16))\")",
            "sed -i \"s/\\$cfg\\['blowfish_secret'\\] = '';/\\$cfg\\['blowfish_secret'\\] = '$RANDOM_BLOWFISH';/\" /var/www/phpmyadmin/config.inc.php",
            "chown -R www-data:www-data /var/www/phpmyadmin"
        ],
        "web_configurable": True,
        "doc_root": "/var/www/phpmyadmin",
        "requires_php": True,
        "default_subdomain_prefix": "phpmyadmin"
    },
    "adminer": {
        "name": "Adminer (Lightweight DB GUI)",
        "category": "Tools",
        "type": "tool",
        "desc": "1-Datei-Alternative zu phpMyAdmin für MySQL, PostgreSQL und SQLite unter /var/www/adminer",
        "check_cmd": ["test", "-f", "/var/www/adminer/index.php"],
        "check_paths": ["/var/www/adminer/index.php"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "mkdir -p /var/www/adminer",
            "wget -q https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php -O /var/www/adminer/index.php",
            "chown -R www-data:www-data /var/www/adminer"
        ],
        "web_configurable": True,
        "doc_root": "/var/www/adminer",
        "requires_php": True,
        "default_subdomain_prefix": "adminer"
    },

    # --- Sicherheit & Netzwerk ---
    "fail2ban": {
        "name": "Fail2Ban Brute-Force Schutz",
        "category": "Security",
        "type": "service",
        "service_name": "fail2ban",
        "desc": "Schützt SSH, NGINX und Web-Ports vor Brute-Force-Angriffen durch automatische IP-Bans",
        "check_cmd": ["fail2ban-client", "version"],
        "check_paths": ["/etc/fail2ban/jail.conf"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y fail2ban",
            "systemctl enable --now fail2ban"
        ]
    },
    "crowdsec": {
        "name": "CrowdSec & Firewall Bouncer",
        "category": "Security",
        "type": "service",
        "service_name": "crowdsec",
        "desc": "Moderner Fail2Ban-Nachfolger mit Community-Threat-Intelligence und Verhaltensanalyse",
        "check_cmd": ["crowdsec", "-version"],
        "check_paths": ["/etc/crowdsec/config.yaml"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash",
            "apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables",
            "systemctl enable --now crowdsec"
        ]
    },
    "wireguard": {
        "name": "WireGuard VPN",
        "category": "Security",
        "type": "service",
        "service_name": "wireguard",
        "desc": "Ultraschnelles, modernes VPN-Protokoll zur sicheren Fernverwaltung interner Dienste",
        "check_cmd": ["which", "wg"],
        "check_paths": ["/etc/wireguard"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y wireguard wireguard-tools"
        ]
    },
    "certbot": {
        "name": "Certbot & NGINX Plugin",
        "category": "Security",
        "type": "tool",
        "desc": "Offizielles Let's Encrypt Tool für automatische SSL/TLS-Zertifikate",
        "check_cmd": ["certbot", "--version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y certbot python3-certbot-nginx"
        ]
    },

    # --- DevOps & Container ---
    "docker": {
        "name": "Docker & Compose v2",
        "category": "DevOps",
        "type": "service",
        "service_name": "docker",
        "desc": "Führende Container-Engine zur isolierten Ausführung von Web-Apps, Gameservern und Microservices",
        "check_cmd": ["docker", "--version"],
        "check_paths": ["/etc/docker/daemon.json", "/var/run/docker.sock"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y docker.io docker-compose-v2",
            "systemctl enable --now docker"
        ]
    },
    "gitea": {
        "name": "Gitea (Self-Hosted Git)",
        "category": "DevOps",
        "type": "tool",
        "service_name": "gitea",
        "desc": "Leichtgewichtige, private GitHub-Alternative in Go (<40 MB RAM) für eigene Repositories auf Port 3000",
        "check_cmd": ["test", "-f", "/usr/local/bin/gitea"],
        "check_paths": ["/usr/local/bin/gitea", "/etc/gitea/app.ini"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "wget -q -O /usr/local/bin/gitea https://dl.gitea.com/gitea/1.22.0/gitea-1.22.0-linux-amd64",
            "chmod +x /usr/local/bin/gitea"
        ],
        "port": 3000,
        "web_configurable": True,
        "proxy_port": 3000,
        "default_subdomain_prefix": "git"
    }
}

# -----------------------------------------------------------------------------
# 2. Status-Erkennung & Verknüpfung mit Software Inventory
# -----------------------------------------------------------------------------

def get_systemd_status(service_name: Optional[str]) -> str:
    """Ermittelt den Systemd-Dienststatus (active, inactive, failed, unmanaged)."""
    if not service_name or not shutil.which("systemctl"):
        return "unmanaged"
    try:
        res = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True, timeout=2)
        out = res.stdout.strip()
        if out in ("active", "activating"):
            return "active"
        elif out in ("inactive", "deactivating"):
            return "inactive"
        elif out in ("failed",):
            return "failed"
        return "stopped"
    except Exception:
        return "unmanaged"

def check_installed(pkg_key: str) -> Tuple[bool, str, str]:
    """
    Erkennt zuverlässig, ob ein Paket installiert ist:
    1. Prüft check_paths (Konfigurations- oder Binary-Pfade)
    2. Prüft check_cmd
    3. Prüft Software-Inventar der Sentinel Security Engine
    Gibt (is_installed, version_info, service_status) zurück.
    """
    cfg = PACKAGES_REGISTRY.get(pkg_key)
    if not cfg:
        return False, "Unbekannt", "unmanaged"

    # 1. Dateipfade prüfen
    for p in cfg.get("check_paths", []):
        if os.path.exists(p):
            svc_status = get_systemd_status(cfg.get("service_name"))
            return True, "Installiert (Pfad erkannt)", svc_status

    # 2. check_cmd prüfen
    cmd = cfg.get("check_cmd")
    if cmd:
        if cmd[0] == "test":
            flag = cmd[1]
            path = cmd[2]
            if flag == "-d" and os.path.isdir(path):
                return True, "Bereit im Web-Root", get_systemd_status(cfg.get("service_name"))
            elif flag == "-f" and os.path.isfile(path):
                return True, "Installiert & Bereit", get_systemd_status(cfg.get("service_name"))
        elif shutil.which(cmd[0]):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    first_line = res.stdout.strip().splitlines()[0] if res.stdout else "Aktiv"
                    return True, first_line[:36], get_systemd_status(cfg.get("service_name"))
            except Exception:
                pass

    # 3. Sentinel software_inventory Datenbank abgleichen
    try:
        inv = query_db("SELECT status, version FROM software_inventory WHERE name LIKE ? OR service_name = ?", 
                       (f"%{pkg_key}%", cfg.get("service_name")), one=True)
        if inv:
            svc_status = get_systemd_status(cfg.get("service_name"))
            return True, inv["version"] or "Erkannt über Sentinel", svc_status
    except Exception:
        pass

    return False, "Nicht installiert", "unmanaged"

# -----------------------------------------------------------------------------
# 3. Asynchrone Background Job Engine
# -----------------------------------------------------------------------------

ACTIVE_JOBS: Dict[int, Dict[str, Any]] = {}

def _run_package_job(job_id: int, pkg_key: str, commands: List[str]):
    """Arbeitet einen Installations-/Update-Job im Hintergrund ab und protokolliert in DB."""
    cfg = PACKAGES_REGISTRY.get(pkg_key, {})
    pkg_name = cfg.get("name", pkg_key)

    execute_db("UPDATE package_jobs SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = ?", (job_id,))
    total_cmds = len(commands)
    logs = [f"[{datetime.now().strftime('%H:%M:%S')}] === Start: Job #{job_id} ({pkg_name}) ==="]

    has_error = False
    err_msg = ""

    for idx, cmd in enumerate(commands):
        progress = int(((idx) / max(total_cmds, 1)) * 95)
        step_log = f"[{datetime.now().strftime('%H:%M:%S')}] [Schritt {idx+1}/{total_cmds}] {cmd}"
        logs.append(step_log)

        # In-Memory Cache und DB aktualisieren
        execute_db("UPDATE package_jobs SET progress = ?, logs = ? WHERE id = ?", (progress, "\n".join(logs), job_id))

        exec_cmd = cmd
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
            if not cmd.startswith("export") and not cmd.startswith("sudo"):
                exec_cmd = f"sudo -n {cmd}"

        try:
            proc = subprocess.Popen(
                exec_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in proc.stdout:
                line_clean = line.strip()
                if line_clean:
                    logs.append(f"  > {line_clean}")
                    # Regelmäßig Logs persistieren
                    if len(logs) % 5 == 0:
                        execute_db("UPDATE package_jobs SET logs = ? WHERE id = ?", ("\n".join(logs), job_id))

            proc.wait()
            if proc.returncode != 0:
                has_error = True
                err_msg = f"Befehl '{cmd[:40]}' mit Returncode {proc.returncode} fehlgeschlagen."
                logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [FEHLER] {err_msg}")
                break
        except Exception as e:
            has_error = True
            err_msg = f"Ausnahme bei Befehlsausführung: {str(e)}"
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] [AUSNAHME] {err_msg}")
            break

    if has_error:
        execute_db("""
            UPDATE package_jobs 
            SET status = 'failed', progress = 100, error_message = ?, logs = ?, completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (err_msg, "\n".join(logs), job_id))
    else:
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] === Erfolgreich abgeschlossen: {pkg_name} ===")
        execute_db("""
            UPDATE package_jobs 
            SET status = 'completed', progress = 100, logs = ?, completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, ("\n".join(logs), job_id))

# -----------------------------------------------------------------------------
# 4. Pterodactyl Game-Ports & UFW Schutz-Helper
# -----------------------------------------------------------------------------

def get_pterodactyl_port_status() -> Dict[str, Any]:
    """
    Ermittelt alle Ports des Pterodactyl Stacks (Wings API 8080, SFTP 2022 sowie
    aktive Docker Gameserver-Ports wie 25565, 27015 etc.) und prüft deren UFW-Freigabe.
    """
    from modules.security.protection.firewall import get_ufw_status

    detected_ports = []
    
    # 1. Wings Kern-Ports
    wings_cfg = "/etc/pterodactyl/config.yml"
    api_port = 8080
    sftp_port = 2022
    if os.path.exists(wings_cfg):
        try:
            with open(wings_cfg, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                m_api = re.search(r"api:\s*[^:]*port:\s*(\d+)", content, re.DOTALL)
                if m_api:
                    api_port = int(m_api.group(1))
                m_sftp = re.search(r"bind_port:\s*(\d+)", content)
                if m_sftp:
                    sftp_port = int(m_sftp.group(1))
        except Exception:
            pass

    detected_ports.append({"port": api_port, "proto": "tcp", "service": "Wings Node API", "type": "core"})
    detected_ports.append({"port": sftp_port, "proto": "tcp", "service": "Wings SFTP Server", "type": "core"})

    # 2. Docker Container Game-Ports
    if shutil.which("docker"):
        try:
            res = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                capture_output=True, text=True, timeout=4
            )
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    if "\t" not in line:
                        continue
                    c_name, ports_str = line.split("\t", 1)
                    matches = re.findall(r"(?:0\.0\.0\.0|:::|\[::\]):(\d+)->\d+/(tcp|udp)", ports_str)
                    for p_num, proto in matches:
                        p_int = int(p_num)
                        if p_int not in [80, 443, 8888, 3306, 5432, 6379, 22]:
                            detected_ports.append({
                                "port": p_int,
                                "proto": proto.lower(),
                                "service": f"Gameserver ({c_name[:16]})",
                                "type": "game"
                            })
        except Exception:
            pass

    # 3. Mit UFW Regeln abgleichen
    ufw = get_ufw_status()
    active_ufw_rules = " ".join(ufw.get("rules", []))
    
    missing_ports = []
    for dp in detected_ports:
        rule_needle = f"{dp['port']}/{dp['proto']}"
        dp["is_allowed"] = (rule_needle in active_ufw_rules) or (str(dp["port"]) in active_ufw_rules)
        if not dp["is_allowed"]:
            missing_ports.append(dp)

    return {
        "ufw_active": ufw.get("active", False),
        "detected_ports": detected_ports,
        "missing_ports": missing_ports,
        "is_safe": len(missing_ports) == 0 or not ufw.get("active", False)
    }

# -----------------------------------------------------------------------------
# 5. Routen: Package Manager Dashboard & Navigation
# -----------------------------------------------------------------------------

@packages_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    tab = request.args.get("tab", "overview").lower()
    
    # 1. Konfigurierte Subdomains laden
    configured_domains = {}
    try:
        rows = query_db("SELECT * FROM package_configs")
        for r in rows:
            configured_domains[r["package_key"]] = dict(r)
    except Exception:
        pass

    # 2. Verfügbare Domains für Alias-Routing
    available_domains = []
    if os.path.exists(NGINX_AVAILABLE):
        for f in os.listdir(NGINX_AVAILABLE):
            if f.endswith(".panel.conf"):
                available_domains.append(f.replace(".panel.conf", ""))

    php_versions = detect_php_versions()

    # 3. Katalog & Status aller Pakete aufbauen
    packages_status = []
    installed_count = 0
    services_active_count = 0

    for key, data in PACKAGES_REGISTRY.items():
        installed, version_info, svc_status = check_installed(key)
        pkg_cfg = configured_domains.get(key)
        
        target_url = None
        if pkg_cfg and pkg_cfg.get("domain"):
            proto = "https" if pkg_cfg.get("ssl_enabled") else "http"
            target_url = f"{proto}://{pkg_cfg['domain']}"
        elif data.get("port"):
            target_url = f"http://{request.host.split(':')[0]}:{data['port']}"

        if installed:
            installed_count += 1
        if svc_status == "active":
            services_active_count += 1

        packages_status.append({
            "key": key,
            "name": data["name"],
            "category": data["category"],
            "type": data.get("type", "package"),
            "service_name": data.get("service_name"),
            "desc": data["desc"],
            "installed": installed,
            "version": version_info,
            "service_status": svc_status,
            "port": data.get("port"),
            "web_configurable": data.get("web_configurable", False),
            "doc_root": data.get("doc_root"),
            "requires_php": data.get("requires_php", False),
            "default_subdomain_prefix": data.get("default_subdomain_prefix"),
            "configured_domain": pkg_cfg.get("domain") if pkg_cfg else None,
            "ssl_enabled": pkg_cfg.get("ssl_enabled", 1) if pkg_cfg else 1,
            "target_url": target_url
        })

    # 4. Stacks laden & Status ermitteln
    stacks = []
    try:
        stk_rows = query_db("SELECT * FROM package_stacks ORDER BY id")
        for sr in stk_rows:
            stk = dict(sr)
            comps = json.loads(stk.get("components_json") or "[]")
            comp_statuses = []
            all_ready = True
            for ckey in comps:
                c_inst, _, c_svc = check_installed(ckey)
                comp_statuses.append({"key": ckey, "installed": c_inst, "service_status": c_svc})
                if not c_inst:
                    all_ready = False
            stk["components_detail"] = comp_statuses
            stk["is_fully_installed"] = all_ready
            stacks.append(stk)
    except Exception:
        pass

    # 5. Pterodactyl Firewall Status
    ptero_ports = get_pterodactyl_port_status()

    # 6. Repositories
    repositories = []
    try:
        repos_rows = query_db("SELECT * FROM package_repositories ORDER BY trust_level, id")
        repositories = [dict(r) for r in repos_rows]
    except Exception:
        pass

    # 7. Neueste Jobs / Aktivitäten
    recent_jobs = []
    try:
        job_rows = query_db("SELECT * FROM package_jobs ORDER BY id DESC LIMIT 20")
        recent_jobs = [dict(r) for r in job_rows]
    except Exception:
        pass

    # 8. Integrierte App-Deployments (aus modules/apps.py)
    app_deployments = []
    try:
        app_rows = query_db("SELECT * FROM app_deployments ORDER BY deployed_at DESC")
        app_deployments = [dict(r) for r in app_rows]
    except Exception:
        pass

    return render_template(
        "packages.html",
        active_tab=tab,
        packages=packages_status,
        stacks=stacks,
        repositories=repositories,
        recent_jobs=recent_jobs,
        app_deployments=app_deployments,
        sample_manifest_json=json.dumps(SAMPLE_MANIFEST, indent=2),
        ptero_ports=ptero_ports,
        installed_count=installed_count,
        services_active_count=services_active_count,
        total_packages_count=len(PACKAGES_REGISTRY),
        available_domains=available_domains,
        php_versions=php_versions
    )

# -----------------------------------------------------------------------------
# 6. Routen: Service-Steuerung (Start, Stop, Restart, Status)
# -----------------------------------------------------------------------------

@packages_bp.route("/service/<pkg_key>/<action>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def control_service(pkg_key: str, action: str):
    """Startet, stoppt oder startet einen Dienst über systemctl sicher neu."""
    cfg = PACKAGES_REGISTRY.get(pkg_key)
    if not cfg:
        return jsonify({"success": False, "error": "Paket nicht gefunden"}), 404

    service_name = cfg.get("service_name")
    if not service_name:
        return jsonify({"success": False, "error": f"{cfg['name']} ist kein systemd-Dienst."}), 400

    if action not in ("start", "stop", "restart", "status"):
        return jsonify({"success": False, "error": "Ungültige Service-Aktion"}), 400

    cmd = ["systemctl", action, service_name]
    try:
        res = run_privileged(cmd, timeout=10)
        new_status = get_systemd_status(service_name)
        log_audit(session.get("username"), f"SERVICE_{action.upper()}", f"Dienst '{service_name}' ({cfg['name']}): {action}", request.remote_addr, "success" if res.returncode == 0 else "error")
        return jsonify({
            "success": res.returncode == 0,
            "message": f"Dienst '{service_name}' wurde ausgeführt ({action}).",
            "service_status": new_status,
            "output": res.stdout or res.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# -----------------------------------------------------------------------------
# 7. Routen: Pterodactyl Firewall Quick-Whitelist
# -----------------------------------------------------------------------------

@packages_bp.route("/pterodactyl/whitelist-ports", methods=["POST"])
@login_required
@role_required(["root_admin"])
def whitelist_ptero_ports():
    """Schaltet alle erkannten, fehlenden Pterodactyl- & Gameserver-Ports in UFW frei."""
    from modules.security.protection.firewall import add_ufw_allow
    
    ptero_status = get_pterodactyl_port_status()
    missing = ptero_status.get("missing_ports", [])
    
    if not missing:
        flash("Alle Pterodactyl- und Gameserver-Ports sind in der Firewall bereits freigegeben!", "info")
        return redirect(url_for("packages.index", tab="stacks"))

    success_count = 0
    for p in missing:
        ok = add_ufw_allow(str(p["port"]), proto=p["proto"])
        if ok:
            success_count += 1

    log_audit(session.get("username"), "PTERO_FIREWALL_WHITELIST", f"{success_count} Pterodactyl Gameserver-Ports in UFW freigegeben", request.remote_addr, "success")
    flash(f"Erfolg: {success_count} Pterodactyl- & Gameserver-Ports wurden sicher in der UFW-Firewall freigegeben!", "success")
    return redirect(url_for("packages.index", tab="stacks"))

# -----------------------------------------------------------------------------
# 8. Routen: Asynchrone Job-Ausführung & Realtime Logs
# -----------------------------------------------------------------------------

@packages_bp.route("/install/<pkg_key>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def start_installation_job(pkg_key: str):
    """Startet die asynchrone Installation eines Pakets mit Job-Tracking."""
    cfg = PACKAGES_REGISTRY.get(pkg_key)
    if not cfg:
        return jsonify({"error": "Paket nicht gefunden"}), 404

    title = f"Installation von {cfg['name']}"
    cmds = cfg.get("install_cmds", [])

    execute_db("""
        INSERT INTO package_jobs (job_type, package_key, title, status, progress, logs, started_by)
        VALUES ('install', ?, ?, 'pending', 0, 'Job initialisiert...', ?)
    """, (pkg_key, title, session.get("username") or "admin"))

    row = query_db("SELECT id FROM package_jobs WHERE package_key = ? ORDER BY id DESC LIMIT 1", (pkg_key,), one=True)
    job_id = row["id"]

    # Hintergrund-Thread starten
    worker = threading.Thread(target=_run_package_job, args=(job_id, pkg_key, cmds), daemon=True)
    worker.start()

    log_audit(session.get("username"), "PACKAGE_INSTALL_START", f"Job #{job_id}: {title} gestartet", request.remote_addr)

    # Wenn AJAX Request: JSON zurückgeben, sonst SSE Stream
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"success": True, "job_id": job_id, "title": title})

    return redirect(url_for("packages.index", tab="activities"))

@packages_bp.route("/api/jobs/<int:job_id>")
@login_required
def get_job_status(job_id: int):
    """Gibt den aktuellen Status und die Logs eines Installationsjobs zurück."""
    job = query_db("SELECT * FROM package_jobs WHERE id = ?", (job_id,), one=True)
    if not job:
        return jsonify({"error": "Job nicht gefunden"}), 404
    return jsonify(dict(job))

@packages_bp.route("/api/jobs/stream/<int:job_id>")
@login_required
def stream_job_logs(job_id: int):
    """Server-Sent Events Stream für Live-Konsolen-Logs eines Jobs."""
    def generate():
        last_log_len = 0
        while True:
            job = query_db("SELECT status, logs, progress FROM package_jobs WHERE id = ?", (job_id,), one=True)
            if not job:
                yield "data: [FEHLER] Job existiert nicht mehr.\n\n"
                break

            current_logs = job["logs"] or ""
            if len(current_logs) > last_log_len:
                new_chunk = current_logs[last_log_len:]
                last_log_len = len(current_logs)
                for line in new_chunk.splitlines():
                    if line.strip():
                        yield f"data: {line}\n\n"

            if job["status"] in ("completed", "failed", "cancelled"):
                yield f"data: [STATUS] {job['status'].upper()}\n\n"
                break

            time.sleep(1.0)

    return Response(generate(), mimetype="text/event-stream")

# -----------------------------------------------------------------------------
# 9. Routen: Web-Konfiguration & phpMyAdmin Superuser
# -----------------------------------------------------------------------------

def create_mysql_admin_user(username, password):
    """Erstellt einen MySQL/MariaDB Administrator mit Superuser-Rechten."""
    from modules.database import run_mysql

    username = username.strip()
    if not re.match(r"^[a-zA-Z0-9_]{2,32}$", username):
        return False, "Der Benutzername darf nur aus 2-32 alphanumerischen Zeichen und Unterstrichen bestehen."
    if len(password) < 6 or "'" in password or "\\" in password:
        return False, "Das Passwort muss mindestens 6 Zeichen lang sein und darf keine Anführungszeichen enthalten."

    sql = (
        f"CREATE USER IF NOT EXISTS '{username}'@'localhost' IDENTIFIED BY '{password}'; "
        f"ALTER USER '{username}'@'localhost' IDENTIFIED BY '{password}'; "
        f"GRANT ALL PRIVILEGES ON *.* TO '{username}'@'localhost'; "
        f"CREATE USER IF NOT EXISTS '{username}'@'127.0.0.1' IDENTIFIED BY '{password}'; "
        f"ALTER USER '{username}'@'127.0.0.1' IDENTIFIED BY '{password}'; "
        f"GRANT ALL PRIVILEGES ON *.* TO '{username}'@'127.0.0.1'; "
        f"FLUSH PRIVILEGES;"
    )
    ok, out, err = run_mysql(sql)
    if not ok:
        return False, f"MySQL Fehler: {err or out}"
    return True, f"MySQL Administrator '{username}' erfolgreich eingerichtet."

@packages_bp.route("/configure/<pkg_key>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def configure_package(pkg_key):
    """Richtet eine Subdomain oder VHost für ein Web-Paket ein."""
    pkg_data = PACKAGES_REGISTRY.get(pkg_key)
    if not pkg_data or not pkg_data.get("web_configurable"):
        flash("Dieses Paket unterstützt keine automatische Web-Routing-Konfiguration.", "error")
        return redirect(url_for("packages.index"))

    domain = request.form.get("domain", "").strip().lower()
    php_version = request.form.get("php_version", "8.2").strip()
    auto_ssl = 1 if request.form.get("auto_ssl") == "1" else 0

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Bitte einen gültigen Domain- oder Subdomainnamen angeben.", "error")
        return redirect(url_for("packages.index"))

    os.makedirs(NGINX_AVAILABLE, exist_ok=True)
    os.makedirs(NGINX_ENABLED, exist_ok=True)

    conf_name = f"{domain}.panel.conf"
    avail_path = os.path.join(NGINX_AVAILABLE, conf_name)
    enabled_path = os.path.join(NGINX_ENABLED, conf_name)

    if pkg_data.get("doc_root"):
        mode = "webspace"
        target_path = pkg_data["doc_root"]
        proxy_port = ""
    else:
        mode = "proxy"
        target_path = ""
        proxy_port = str(pkg_data.get("proxy_port", 3000))

    cert_info = find_ssl_cert_for_domain(domain)
    ssl_active = (cert_info is not None)

    vhost_content = build_nginx_config(
        domain=domain,
        mode=mode,
        target_path=target_path,
        proxy_port=proxy_port,
        php_version=php_version,
        ssl_enabled=ssl_active,
        cert_path=cert_info["cert_path"] if cert_info else None,
        key_path=cert_info["key_path"] if cert_info else None
    )

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(vhost_content)

    try:
        if os.path.exists(enabled_path):
            os.remove(enabled_path)
        os.symlink(avail_path, enabled_path)
    except OSError:
        pass

    ok, msg = reload_nginx()
    if not ok:
        flash(f"NGINX-Konfiguration fehlgeschlagen: {msg}", "error")
        return redirect(url_for("packages.index"))

    if auto_ssl and not ssl_active:
        ssl_ok, ssl_msg = issue_and_apply_ssl(domain)
        if not ssl_ok:
            flash(f"VHost wurde angelegt, aber SSL-Zertifikat konnte nicht ausgestellt werden ({ssl_msg}).", "warning")

    existing = query_db("SELECT id FROM package_configs WHERE package_key = ?", (pkg_key,), one=True)
    if existing:
        execute_db("""
        UPDATE package_configs 
        SET domain = ?, mode = ?, port = ?, ssl_enabled = ?, php_version = ?, updated_at = CURRENT_TIMESTAMP
        WHERE package_key = ?
        """, (domain, mode, int(proxy_port) if proxy_port else None, auto_ssl, php_version, pkg_key))
    else:
        execute_db("""
        INSERT INTO package_configs (package_key, domain, mode, port, ssl_enabled, php_version)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (pkg_key, domain, mode, int(proxy_port) if proxy_port else None, auto_ssl, php_version))

    log_audit(session.get("username"), "PACKAGE_CONFIGURE", f"{pkg_data['name']} an Subdomain '{domain}' angebunden", request.remote_addr, "success")
    flash(f"{pkg_data['name']} wurde erfolgreich unter https://{domain} bereitgestellt!", "success")

    # Optionaler PMA Admin
    if pkg_key == "phpmyadmin" and request.form.get("create_pma_admin") == "1":
        pma_user = request.form.get("pma_admin_user", "pma_admin").strip()
        pma_pass = request.form.get("pma_admin_pass", "").strip()
        if pma_user and pma_pass:
            admin_ok, admin_msg = create_mysql_admin_user(pma_user, pma_pass)
            if admin_ok:
                flash(f"phpMyAdmin Admin-Benutzer '{pma_user}' eingerichtet!", "success")

    return redirect(url_for("packages.index", tab="installed"))

@packages_bp.route("/phpmyadmin/create-admin-user", methods=["POST"])
@login_required
@role_required(["root_admin"])
def create_pma_admin_standalone():
    """Erstellt einen MySQL Superuser für phpMyAdmin."""
    username = request.form.get("username", "pma_admin").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        flash("Benutzername und Passwort sind erforderlich.", "error")
        return redirect(url_for("packages.index"))

    ok, msg = create_mysql_admin_user(username, password)
    if ok:
        log_audit(session.get("username"), "PMA_ADMIN_CREATE", f"MySQL Admin '{username}' angelegt", request.remote_addr, "success")
        flash(f"{msg} Du kannst dich nun in phpMyAdmin anmelden.", "success")
    else:
        log_audit(session.get("username"), "PMA_ADMIN_FAIL", msg, request.remote_addr, "error")
        flash(f"Fehler: {msg}", "error")

    return redirect(url_for("packages.index"))

# -----------------------------------------------------------------------------
# 10. Routen: Konsolidierter App-Importer & SCP-Pakete
# -----------------------------------------------------------------------------

@packages_bp.route("/apps/deploy", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def deploy_app():
    """Konsolidiertes Deployment von Webanwendungen via ZIP und Manifest."""
    from modules.apps import deploy as apps_deploy_func
    # Führt das gehärtete Deployment aus apps.py aus
    return apps_deploy_func()

@packages_bp.route("/starter-template")
@login_required
def download_starter_template():
    """Lädt das deklarative SysCore Starter Template herunter."""
    from modules.apps import download_starter_template as apps_template_func
    return apps_template_func()

# -----------------------------------------------------------------------------
# 11. Routen: Repository Management
# -----------------------------------------------------------------------------

@packages_bp.route("/repositories/toggle/<int:repo_id>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def toggle_repository(repo_id: int):
    """Aktiviert oder deaktiviert eine Paketquelle."""
    repo = query_db("SELECT * FROM package_repositories WHERE id = ?", (repo_id,), one=True)
    if not repo:
        flash("Repository nicht gefunden.", "error")
        return redirect(url_for("packages.index", tab="repositories"))

    new_state = 0 if repo["is_enabled"] else 1
    execute_db("UPDATE package_repositories SET is_enabled = ? WHERE id = ?", (new_state, repo_id))
    state_str = "aktiviert" if new_state else "deaktiviert"
    log_audit(session.get("username"), "REPO_TOGGLE", f"Repository '{repo['name']}' {state_str}", request.remote_addr)
    flash(f"Repository '{repo['name']}' wurde {state_str}.", "success")
    return redirect(url_for("packages.index", tab="repositories"))
