import os
import re
import glob
import shutil
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from config import WEB_ROOT_BASE, NGINX_AVAILABLE, NGINX_ENABLED, APACHE_PORTS_CONF, CERTBOT_EMAIL
from modules.auth_users import login_required, role_required
from db import log_audit

webserver_bp = Blueprint("webserver", __name__, url_prefix="/web")

DIRECTIVES_START = "# --- SYSCORE_CUSTOM_DIRECTIVES_START ---"
DIRECTIVES_END = "# --- SYSCORE_CUSTOM_DIRECTIVES_END ---"

def detect_php_versions():
    sockets = glob.glob("/run/php/php*-fpm.sock")
    versions = []
    for s in sockets:
        m = re.search(r"php(\d+\.\d+)-fpm\.sock", s)
        if m:
            versions.append(m.group(1))
    # Fallback gängige Versionen
    if not versions:
        return ["8.2", "8.3", "8.4"]
    return sorted(list(set(versions)))

def check_webserver_health():
    apache_conflict = False
    if os.path.exists(APACHE_PORTS_CONF):
        try:
            with open(APACHE_PORTS_CONF, "r", encoding="utf-8") as f:
                content = f.read()
                if re.search(r"^\s*Listen\s+80\b", content, re.MULTILINE):
                    apache_conflict = True
        except Exception:
            pass

    default_site_enabled = os.path.exists(os.path.join(NGINX_ENABLED, "default"))
    try:
        os.makedirs(WEB_ROOT_BASE, exist_ok=True)
    except Exception:
        pass

    return {
        "apache_conflict": apache_conflict,
        "default_site_enabled": default_site_enabled,
        "php_versions": detect_php_versions()
    }

def reload_nginx():
    if not shutil.which("nginx"):
        return True, "Entwicklungsumgebung: NGINX-Prüfung übersprungen."
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        return False, test.stderr
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "reload", "nginx"], check=False)
    return True, "NGINX erfolgreich neu geladen."

def validate_web_path(custom_path, fallback_domain):
    base = os.path.realpath(WEB_ROOT_BASE)
    if not custom_path:
        return os.path.join(base, fallback_domain, "public")
    norm = os.path.realpath(os.path.normpath(custom_path.strip()))
    if not norm.startswith(base):
        return None
    return norm

def get_ssl_cert_info(domain):
    cert_path = f"/etc/letsencrypt/live/{domain}/cert.pem"
    if not os.path.exists(cert_path):
        return {"active": False, "expires": None, "days_left": None}
    
    try:
        res = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", cert_path], capture_output=True, text=True)
        if res.returncode == 0 and "notAfter=" in res.stdout:
            date_str = res.stdout.strip().replace("notAfter=", "")
            # Format: 'Feb 14 12:00:00 2027 GMT'
            exp_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
            return {
                "active": True,
                "expires": exp_date.strftime("%d.%m.%Y"),
                "days_left": days_left
            }
    except Exception:
        pass

    return {"active": True, "expires": "Unbekannt", "days_left": 90}

def build_nginx_config(domain, mode, target_path, proxy_port, php_version, custom_directives=""):
    directives_block = f"""    {DIRECTIVES_START}
{custom_directives.strip() if custom_directives.strip() else '    # Keine benutzerdefinierten Direktiven aktiv'}
    {DIRECTIVES_END}"""

    log_dir = "/var/log/nginx"

    if mode == "proxy":
        return f"""server {{
    listen 80;
    server_name {domain};

    access_log {log_dir}/{domain}.access.log;
    error_log {log_dir}/{domain}.error.log;

{directives_block}

    location / {{
        proxy_pass http://127.0.0.1:{proxy_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
    return f"""server {{
    listen 80;
    server_name {domain};
    root {target_path};
    index index.php index.html index.htm;

    access_log {log_dir}/{domain}.access.log;
    error_log {log_dir}/{domain}.error.log;

{directives_block}

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php{php_version}-fpm.sock;
    }}

    location ~ /\\.ht {{
        deny all;
    }}
}}
"""

def parse_domain_config(domain_name, content):
    ssl_active = ("listen 443 ssl" in content) or ("ssl_certificate" in content)
    is_proxy = "proxy_pass" in content
    mode = "proxy" if is_proxy else "webspace"

    proxy_match = re.search(r"proxy_pass\s+http://127\.0\.0\.1:(\d+);", content)
    root_match = re.search(r"^\s*root\s+([^;]+);", content, re.MULTILINE)
    php_match = re.search(r"php(\d+\.\d+)-fpm\.sock", content)

    proxy_port = proxy_match.group(1) if proxy_match else ""
    root_path = root_match.group(1).strip() if root_match else os.path.join(WEB_ROOT_BASE, domain_name, "public")
    php_version = php_match.group(1) if php_match else "8.2"

    # Custom Direktiven extrahieren
    directives = ""
    if DIRECTIVES_START in content and DIRECTIVES_END in content:
        try:
            directives = content.split(DIRECTIVES_START)[1].split(DIRECTIVES_END)[0].strip()
            if directives == "# Keine benutzerdefinierten Direktiven aktiv":
                directives = ""
        except Exception:
            pass

    ssl_info = get_ssl_cert_info(domain_name)
    if ssl_active and not ssl_info["active"]:
        ssl_info["active"] = True

    return {
        "name": domain_name,
        "ssl": ssl_info["active"],
        "ssl_info": ssl_info,
        "mode": mode,
        "mode_label": "Reverse Proxy" if is_proxy else f"Webspace (PHP {php_version})",
        "target": f"Port {proxy_port}" if is_proxy else root_path,
        "root_path": root_path,
        "proxy_port": proxy_port,
        "php_version": php_version,
        "custom_directives": directives
    }

@webserver_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    health = check_webserver_health()
    domains = []
    if os.path.exists(NGINX_AVAILABLE):
        for filename in sorted(os.listdir(NGINX_AVAILABLE)):
            if not filename.endswith(".panel.conf"):
                continue
            domain_name = filename.replace(".panel.conf", "")
            try:
                with open(os.path.join(NGINX_AVAILABLE, filename), "r", encoding="utf-8") as f:
                    content = f.read()
                domains.append(parse_domain_config(domain_name, content))
            except Exception:
                continue

    return render_template("webserver.html", health=health, domains=domains, web_root_base=WEB_ROOT_BASE)

@webserver_bp.route("/fix-apache-port", methods=["POST"])
@login_required
@role_required(["root_admin"])
def fix_apache_port():
    if os.path.exists(APACHE_PORTS_CONF):
        try:
            with open(APACHE_PORTS_CONF, "r", encoding="utf-8") as f:
                content = f.read()
            content = re.sub(r"^\s*Listen\s+80\b", "Listen 8080", content, flags=re.MULTILINE)
            with open(APACHE_PORTS_CONF, "w", encoding="utf-8") as f:
                f.write(content)

            default_vhost = "/etc/apache2/sites-available/000-default.conf"
            if os.path.exists(default_vhost):
                with open(default_vhost, "r", encoding="utf-8") as f:
                    vcontent = f.read()
                vcontent = vcontent.replace("<VirtualHost *:80>", "<VirtualHost *:8080>")
                with open(default_vhost, "w", encoding="utf-8") as f:
                    f.write(vcontent)

            if shutil.which("systemctl"):
                subprocess.run(["systemctl", "restart", "apache2"], check=False)
                subprocess.run(["systemctl", "restart", "nginx"], check=False)

            log_audit(session.get("username"), "APACHE_PORT_FIX", "Apache auf Port 8080 verschoben", request.remote_addr)
            flash("Apache auf Port 8080 verschoben und NGINX auf Port 80 aktiviert.", "success")
        except Exception as e:
            flash(f"Fehler beim Anpassen der Apache-Ports: {e}", "error")
    return redirect(url_for("webserver.index"))

@webserver_bp.route("/disable-default", methods=["POST"])
@login_required
@role_required(["root_admin"])
def disable_default():
    default_path = os.path.join(NGINX_ENABLED, "default")
    if os.path.exists(default_path):
        os.remove(default_path)
        reload_nginx()
        log_audit(session.get("username"), "NGINX_DISABLE_DEFAULT", "NGINX Standard-Seite deaktiviert", request.remote_addr)
        flash("NGINX Standard-Seite ('default') deaktiviert.", "success")
    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/add", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def add_domain():
    domain = request.form.get("domain", "").strip().lower()
    mode = request.form.get("mode", "webspace")
    proxy_port = request.form.get("proxy_port", "").strip()
    php_version = request.form.get("php_version", "8.2").strip()
    custom_root = request.form.get("root_path", "").strip()

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültiges Domain-Format.", "error")
        return redirect(url_for("webserver.index"))

    os.makedirs(NGINX_AVAILABLE, exist_ok=True)
    os.makedirs(NGINX_ENABLED, exist_ok=True)

    conf_name = f"{domain}.panel.conf"
    avail_path = os.path.join(NGINX_AVAILABLE, conf_name)
    enabled_path = os.path.join(NGINX_ENABLED, conf_name)

    if os.path.exists(avail_path):
        flash(f"Domain '{domain}' existiert bereits.", "error")
        return redirect(url_for("webserver.index"))

    target_path = None
    if mode == "proxy":
        if not proxy_port.isdigit() or not (1 <= int(proxy_port) <= 65535):
            flash("Bitte einen gültigen Ziel-Port (1-65535) angeben.", "error")
            return redirect(url_for("webserver.index"))
    else:
        target_path = validate_web_path(custom_root, domain)
        if not target_path:
            flash(f"Zielpfad muss innerhalb von {WEB_ROOT_BASE}/ liegen.", "error")
            return redirect(url_for("webserver.index"))

        try:
            os.makedirs(target_path, exist_ok=True)
            index_file = os.path.join(target_path, "index.php")
            if not os.path.exists(index_file) and not os.path.exists(os.path.join(target_path, "index.html")):
                with open(index_file, "w", encoding="utf-8") as f:
                    f.write(f"""<!DOCTYPE html>
<html>
<head><title>{domain}</title></head>
<body style="font-family: sans-serif; background: #090d16; color: #fff; padding: 40px; text-align: center;">
    <h1 style="color: #10b981;">{domain} ist online!</h1>
    <p>Verwaltet mit <strong>SysCore Server Manager</strong></p>
    <p style="color: #64748b;">PHP-Version: <?php echo phpversion(); ?></p>
</body>
</html>""")
            if shutil.which("chown"):
                subprocess.run(["chown", "-R", "www-data:www-data", target_path])
        except Exception as e:
            flash(f"Webspace-Verzeichnis konnte nicht vorbereitet werden: {e}", "error")
            return redirect(url_for("webserver.index"))

    nginx_conf = build_nginx_config(domain, mode, target_path, proxy_port, php_version)
    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(nginx_conf)

    # Symlink in sites-enabled erstellen
    try:
        if os.path.exists(enabled_path):
            os.remove(enabled_path)
        os.symlink(avail_path, enabled_path)
    except OSError:
        pass

    ok, msg = reload_nginx()
    if not ok:
        if os.path.exists(enabled_path):
            os.remove(enabled_path)
        if os.path.exists(avail_path):
            os.remove(avail_path)
        flash(f"NGINX Syntax-Fehler: {msg}", "error")
    else:
        log_audit(session.get("username"), "DOMAIN_CREATE", f"Domain '{domain}' ({mode}) angelegt", request.remote_addr)
        flash(f"Domain '{domain}' erfolgreich eingerichtet.", "success")

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/directives/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def edit_directives(domain):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültige Domain.", "error")
        return redirect(url_for("webserver.index"))

    conf_name = f"{domain}.panel.conf"
    avail_path = os.path.join(NGINX_AVAILABLE, conf_name)
    if not os.path.exists(avail_path):
        flash("VHost Konfiguration nicht gefunden.", "error")
        return redirect(url_for("webserver.index"))

    custom_directives = request.form.get("custom_directives", "").strip()

    with open(avail_path, "r", encoding="utf-8") as f:
        old_content = f.read()

    # Ersetze existierenden Direktiven-Block oder baue ihn ein
    new_block = f"""    {DIRECTIVES_START}\n{custom_directives if custom_directives else '    # Keine benutzerdefinierten Direktiven aktiv'}\n    {DIRECTIVES_END}"""
    
    if DIRECTIVES_START in old_content and DIRECTIVES_END in old_content:
        pattern = re.compile(rf"\s*{re.escape(DIRECTIVES_START)}.*?{re.escape(DIRECTIVES_END)}", re.DOTALL)
        new_content = pattern.sub(f"\n{new_block}\n", old_content)
    else:
        # Nach server_name einfügen
        new_content = re.sub(r"(server_name\s+[^;]+;)", rf"\1\n\n{new_block}\n", old_content, count=1)

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    ok, msg = reload_nginx()
    if not ok:
        # Rollback bei Syntax-Fehler
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(old_content)
        flash(f"Direktiven abgelehnt (NGINX Syntaxfehler): {msg}", "error")
    else:
        log_audit(session.get("username"), "DOMAIN_DIRECTIVES_UPDATE", f"Custom Direktiven für '{domain}' aktualisiert", request.remote_addr)
        flash(f"Custom Direktiven für {domain} erfolgreich angewendet.", "success")

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/ssl/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def enable_ssl(domain):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültige Domain.", "error")
        return redirect(url_for("webserver.index"))

    if not shutil.which("certbot"):
        flash("Certbot ist auf diesem Server nicht installiert. Bitte im Paket-Manager installieren.", "error")
        return redirect(url_for("webserver.index"))

    email_arg = ["--email", CERTBOT_EMAIL] if CERTBOT_EMAIL and "@" in CERTBOT_EMAIL else ["--register-unsafely-without-email"]
    cmd = ["certbot", "--nginx", "-d", domain, "--non-interactive", "--agree-tos", "--redirect"] + email_arg

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        log_audit(session.get("username"), "SSL_ENABLE", f"Let's Encrypt SSL für '{domain}' aktiviert", request.remote_addr)
        flash(f"Let's Encrypt SSL Zertifikat für {domain} erfolgreich aktiviert!", "success")
    else:
        log_audit(session.get("username"), "SSL_FAIL", f"SSL Fehler für '{domain}': {res.stderr}", request.remote_addr, "warning")
        flash(f"Certbot Fehler: {res.stderr[:300]}", "error")

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/logs/<domain>/<log_type>")
@login_required
@role_required(["root_admin", "web_admin"])
def domain_logs(domain, log_type):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain) or log_type not in ["access", "error"]:
        return jsonify({"lines": ["Ungültige Anfrage"]}), 400

    log_file = f"/var/log/nginx/{domain}.{log_type}.log"
    if not os.path.exists(log_file):
        # Fallback auf allgemeine NGINX Logs
        log_file = f"/var/log/nginx/{log_type}.log"

    lines = []
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
                lines = [l.strip() for l in all_lines[-60:]]
        except Exception as e:
            lines = [f"Fehler beim Lesen des Logfiles: {e}"]
    else:
        lines = [f"Log-Datei {log_file} existiert noch nicht."]

    return jsonify({"domain": domain, "type": log_type, "lines": lines})

@webserver_bp.route("/domain/traffic/<domain>")
@login_required
@role_required(["root_admin", "web_admin"])
def domain_traffic_report(domain):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültige Domain.", "error")
        return redirect(url_for("webserver.index"))

    log_file = f"/var/log/nginx/{domain}.access.log"
    if not os.path.exists(log_file):
        log_file = "/var/log/nginx/access.log"

    if shutil.which("goaccess") and os.path.exists(log_file):
        report_file = f"/tmp/goaccess_{domain}.html"
        subprocess.run(["goaccess", log_file, "-o", report_file, "--log-format=COMBINED"], capture_output=True)
        if os.path.exists(report_file):
            return send_file(report_file)

    # Fallback / Info View
    return render_template(
        "traffic_report.html",
        domain=domain,
        goaccess_installed=shutil.which("goaccess") is not None
    )

@webserver_bp.route("/domain/delete/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def delete_domain(domain):
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        conf_name = f"{domain}.panel.conf"
        for folder in [NGINX_ENABLED, NGINX_AVAILABLE]:
            p = os.path.join(folder, conf_name)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        reload_nginx()
        log_audit(session.get("username"), "DOMAIN_DELETE", f"VHost für '{domain}' entfernt", request.remote_addr, "warning")
        flash(f"VHost für {domain} entfernt.", "success")
    return redirect(url_for("webserver.index"))
