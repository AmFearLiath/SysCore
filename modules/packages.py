import os
import shutil
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify, session
from modules.auth_users import login_required, role_required
from db import log_audit

packages_bp = Blueprint("packages", __name__, url_prefix="/packages")

# Paket-Definitionen & Installations-Rezepte
PACKAGES_REGISTRY = {
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
        "name": "Composer (PHP Dependency Manager)",
        "category": "Tools",
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
        "name": "Node.js LTS & PM2",
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
    "redis": {
        "name": "Redis In-Memory Database",
        "category": "Databases",
        "desc": "Hochperformanter Redis Cache & Key-Value Server",
        "check_cmd": ["redis-server", "-v"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y redis-server",
            "systemctl enable --now redis-server"
        ]
    },
    "phpmyadmin": {
        "name": "phpMyAdmin (Web Database GUI)",
        "category": "Tools",
        "desc": "phpMyAdmin automatisch unter /var/www/phpmyadmin installiert und bereitgestellt",
        "check_cmd": ["test", "-d", "/var/www/phpmyadmin"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update && apt-get install -y wget unzip",
            "mkdir -p /var/www/phpmyadmin",
            "wget -q https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz -O /tmp/pma.tar.gz",
            "tar -xzf /tmp/pma.tar.gz -C /var/www/phpmyadmin --strip-components=1",
            "rm -f /tmp/pma.tar.gz",
            "cp /var/www/phpmyadmin/config.sample.inc.php /var/www/phpmyadmin/config.inc.php",
            "chown -R www-data:www-data /var/www/phpmyadmin"
        ]
    },
    "fail2ban": {
        "name": "Fail2Ban Brute-Force Schutz",
        "category": "Security",
        "desc": "Schützt SSH, NGINX und Web-Ports vor Brute-Force-Angriffen",
        "check_cmd": ["fail2ban-client", "version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y fail2ban",
            "systemctl enable --now fail2ban"
        ]
    },
    "certbot": {
        "name": "Certbot & NGINX Plugin",
        "category": "Security",
        "desc": "Offizielles Let's Encrypt Tool für automatische SSL-Zertifikate",
        "check_cmd": ["certbot", "--version"],
        "install_cmds": [
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get update",
            "apt-get install -y certbot python3-certbot-nginx"
        ]
    }
}

def check_installed(pkg_key):
    cfg = PACKAGES_REGISTRY.get(pkg_key)
    if not cfg:
        return False, "Unbekannt"

    cmd = cfg["check_cmd"]
    if not shutil.which(cmd[0]):
        # Prüfen ob zweites Token ein Pfad ist (z.B. test -d)
        if cmd[0] == "test" and os.path.exists(cmd[2]):
            return True, "Installiert"
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
    for key, data in PACKAGES_REGISTRY.items():
        installed, version_info = check_installed(key)
        packages_status.append({
            "key": key,
            "name": data["name"],
            "category": data["category"],
            "desc": data["desc"],
            "installed": installed,
            "version": version_info
        })

    return render_template("packages.html", packages=packages_status)

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
