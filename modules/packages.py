import os
import re
import shutil
import secrets
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify, session
from modules.auth_users import login_required, role_required, log_audit
from db import query_db, execute_db
from config import WEB_ROOT_BASE, NGINX_AVAILABLE, NGINX_ENABLED, CERTBOT_EMAIL
from modules.webserver import build_nginx_config, reload_nginx, find_ssl_cert_for_domain, enable_ssl, repair_domain_ssl, detect_php_versions

packages_bp = Blueprint("packages", __name__, url_prefix="/packages")

# Umfassende Paket-Definitionen & Installations-Rezepte mit Web-Konfiguration
PACKAGES_REGISTRY = {
    # --- Runtimes ---
    "php8.2": {
        "name": "PHP 8.2 & Extensions",
        "category": "Runtimes",
        "desc": "PHP 8.2 FPM inkl. curl, mbstring, xml, zip, gd, mysql, intl, bcmath",
        "check_cmd": ["php8.2", "-v"],
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
        "desc": "PHP 8.3 FPM inkl. curl, mbstring, xml, zip, gd, mysql, intl, bcmath",
        "check_cmd": ["php8.3", "-v"],
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
        "desc": "PHP 8.4 FPM (neueste Version) inkl. moderner Web-Extensions",
        "check_cmd": ["php8.4", "-v"],
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

    # --- Monitoring & Analyse ---
    "goaccess": {
        "name": "GoAccess (Log-Analyzer)",
        "category": "Monitoring",
        "desc": "Visueller NGINX Realtime Log-Analyzer für Besucher-, Traffic- und Bot-Statistiken",
        "check_cmd": ["goaccess", "--version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y goaccess"
        ]
    },
    "uptime_kuma": {
        "name": "Uptime Kuma",
        "category": "Monitoring",
        "desc": "Modernes Monitoring-Tool mit Statusseiten und Alarmierung auf Port 3001",
        "check_cmd": ["test", "-d", "/opt/uptime-kuma"],
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

    # --- Datenbanken & Cache ---
    "redis": {
        "name": "Redis In-Memory Server",
        "category": "Databases",
        "desc": "Hochperformanter In-Memory Cache & Key-Value Store für Sessions und Caching",
        "check_cmd": ["redis-server", "-v"],
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
        "desc": "Die führende relationale Open-Source Enterprise-Datenbank neben MySQL/MariaDB",
        "check_cmd": ["psql", "--version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y postgresql postgresql-contrib",
            "systemctl enable --now postgresql"
        ]
    },

    # --- Web-GUIs & Tools ---
    "phpmyadmin": {
        "name": "phpMyAdmin (Web Database GUI)",
        "category": "Tools",
        "desc": "Vollwertige phpMyAdmin Web-Oberfläche für MySQL/MariaDB unter /var/www/phpmyadmin",
        "check_cmd": ["test", "-d", "/var/www/phpmyadmin"],
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
        "desc": "1-Datei-Alternative zu phpMyAdmin für MySQL, PostgreSQL und SQLite unter /var/www/adminer",
        "check_cmd": ["test", "-f", "/var/www/adminer/index.php"],
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
    "crowdsec": {
        "name": "CrowdSec & Firewall Bouncer",
        "category": "Security",
        "desc": "Moderner Fail2Ban-Nachfolger mit Community-Threat-Intelligence und Verhaltensanalyse",
        "check_cmd": ["crowdsec", "-version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash",
            "apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables",
            "systemctl enable --now crowdsec"
        ]
    },
    "fail2ban": {
        "name": "Fail2Ban Brute-Force Schutz",
        "category": "Security",
        "desc": "Schützt SSH, NGINX und Web-Ports vor Brute-Force-Angriffen durch automatische IP-Bans",
        "check_cmd": ["fail2ban-client", "version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y fail2ban",
            "systemctl enable --now fail2ban"
        ]
    },
    "wireguard": {
        "name": "WireGuard VPN",
        "category": "Security",
        "desc": "Ultraschnelles, modernes VPN-Protokoll zur sicheren Fernverwaltung interner Dienste",
        "check_cmd": ["which", "wg"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y wireguard wireguard-tools"
        ]
    },
    "certbot": {
        "name": "Certbot & NGINX Plugin",
        "category": "Security",
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
        "desc": "Führende Container-Engine zur isolierten Ausführung von Web-Apps und Microservices",
        "check_cmd": ["docker", "--version"],
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
        "desc": "Leichtgewichtige, private GitHub-Alternative in Go (<40 MB RAM) für eigene Repositories auf Port 3000",
        "check_cmd": ["test", "-f", "/usr/local/bin/gitea"],
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

def check_installed(pkg_key):
    cfg = PACKAGES_REGISTRY.get(pkg_key)
    if not cfg:
        return False, "Unbekannt"

    cmd = cfg["check_cmd"]
    if cmd[0] == "test":
        flag = cmd[1]
        path = cmd[2]
        if flag == "-d" and os.path.isdir(path):
            return True, "Installiert & Bereit"
        elif flag == "-f" and os.path.isfile(path):
            return True, "Installiert & Bereit"
        return False, "Nicht installiert"

    if not shutil.which(cmd[0]):
        return False, "Nicht installiert"

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            first_line = res.stdout.strip().splitlines()[0] if res.stdout else "Aktiv"
            return True, first_line[:36]
    except Exception:
        pass

    return False, "Nicht installiert"

@packages_bp.route("/")
@login_required
@role_required(["root_admin"])
def index():
    packages_status = []
    
    # Bereits konfigurierte Subdomains aus DB laden
    configured_domains = {}
    try:
        rows = query_db("SELECT * FROM package_configs")
        for r in rows:
            configured_domains[r["package_key"]] = dict(r)
    except Exception:
        pass

    # Vorhandene Domains für Alias-Vorschläge
    available_domains = []
    if os.path.exists(NGINX_AVAILABLE):
        for f in os.listdir(NGINX_AVAILABLE):
            if f.endswith(".panel.conf"):
                available_domains.append(f.replace(".panel.conf", ""))

    php_versions = detect_php_versions()

    for key, data in PACKAGES_REGISTRY.items():
        installed, version_info = check_installed(key)
        pkg_cfg = configured_domains.get(key)
        
        target_url = None
        if pkg_cfg and pkg_cfg.get("domain"):
            proto = "https" if pkg_cfg.get("ssl_enabled") else "http"
            target_url = f"{proto}://{pkg_cfg['domain']}"
        elif data.get("port"):
            target_url = f"http://{request.host.split(':')[0]}:{data['port']}"

        packages_status.append({
            "key": key,
            "name": data["name"],
            "category": data["category"],
            "desc": data["desc"],
            "installed": installed,
            "version": version_info,
            "port": data.get("port"),
            "web_configurable": data.get("web_configurable", False),
            "doc_root": data.get("doc_root"),
            "requires_php": data.get("requires_php", False),
            "default_subdomain_prefix": data.get("default_subdomain_prefix"),
            "configured_domain": pkg_cfg.get("domain") if pkg_cfg else None,
            "ssl_enabled": pkg_cfg.get("ssl_enabled") if pkg_cfg else 1,
            "target_url": target_url
        })

    return render_template(
        "packages.html",
        packages=packages_status,
        available_domains=available_domains,
        php_versions=php_versions
    )

@packages_bp.route("/configure/<pkg_key>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def configure_package(pkg_key):
    """Richtet eine Subdomain oder VHost für ein Web-Paket (phpMyAdmin, Adminer, Uptime Kuma etc.) ein"""
    pkg_data = PACKAGES_REGISTRY.get(pkg_key)
    if not pkg_data or not pkg_data.get("web_configurable"):
        flash("Dieses Paket unterstützt keine automatische Web-Routing-Konfiguration.", "error")
        return redirect(url_for("packages.index"))

    domain = request.form.get("domain", "").strip().lower()
    php_version = request.form.get("php_version", "8.2").strip()
    auto_ssl = 1 if request.form.get("auto_ssl") == "1" else 0

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Bitte einen gültigen Domain- oder Subdomainnamen angeben (z. B. phpmyadmin.amfearliath.de).", "error")
        return redirect(url_for("packages.index"))

    os.makedirs(NGINX_AVAILABLE, exist_ok=True)
    os.makedirs(NGINX_ENABLED, exist_ok=True)

    conf_name = f"{domain}.panel.conf"
    avail_path = os.path.join(NGINX_AVAILABLE, conf_name)
    enabled_path = os.path.join(NGINX_ENABLED, conf_name)

    # 1. Modus und Zielpfad bestimmen
    if pkg_data.get("doc_root"):
        mode = "webspace"
        target_path = pkg_data["doc_root"]
        proxy_port = ""
    else:
        mode = "proxy"
        target_path = ""
        proxy_port = str(pkg_data.get("proxy_port", 3000))

    # Prüfen ob bereits ein SSL-Zertifikat existiert
    cert_info = find_ssl_cert_for_domain(domain)
    ssl_active = (cert_info is not None)

    # 2. VHost erzeugen
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

    # 3. Falls SSL gewünscht ist, aber noch kein Zertifikat existierte: Sofort anfordern
    if auto_ssl and not ssl_active:
        enable_ssl(domain)
        # Erneut prüfen ob Zertifikat nun da ist
        cert_info = find_ssl_cert_for_domain(domain)
        if cert_info:
            repair_domain_ssl(domain)

    # 4. In package_configs Tabelle speichern
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

    log_audit(session.get("username"), "PACKAGE_CONFIGURE", f"{pkg_data['name']} erfolgreich an Subdomain '{domain}' angebunden", request.remote_addr, "success")
    flash(f"{pkg_data['name']} wurde erfolgreich unter https://{domain} bereitgestellt!", "success")
    return redirect(url_for("packages.index"))

@packages_bp.route("/install/<pkg_key>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def install_stream(pkg_key):
    cfg = PACKAGES_REGISTRY.get(pkg_key)
    if not cfg:
        return jsonify({"error": "Paket nicht gefunden"}), 404

    log_audit(session.get("username"), "PACKAGE_INSTALL_START", f"Installation von '{cfg['name']}' gestartet", request.remote_addr)

    def generate():
        yield f"data: === SysCore Paket-Installation: {cfg['name']} ===\n\n"
        for cmd in cfg["install_cmds"]:
            yield f"data: [Befehl] {cmd}\n\n"
            try:
                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                for line in proc.stdout:
                    yield f"data: {line.strip()}\n\n"
                proc.wait()
                if proc.returncode != 0:
                    yield f"data: [FEHLER] Befehl mit Code {proc.returncode} beendet.\n\n"
                    return
            except Exception as e:
                yield f"data: [AUSNAHME] {str(e)}\n\n"
                return

        yield f"data: [ERFOLG] {cfg['name']} wurde erfolgreich installiert!\n\n"
        log_audit(session.get("username"), "PACKAGE_INSTALL_FINISH", f"Installation von '{cfg['name']}' abgeschlossen", request.remote_addr)

    return Response(generate(), mimetype="text/event-stream")
