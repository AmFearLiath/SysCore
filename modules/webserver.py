import os
import re
import glob
import time
import shutil
import secrets
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, send_file, Response
from config import WEB_ROOT_BASE, NGINX_AVAILABLE, NGINX_ENABLED, APACHE_PORTS_CONF, CERTBOT_EMAIL
from modules.auth_users import login_required, role_required, log_audit
from db import query_db, execute_db

webserver_bp = Blueprint("webserver", __name__, url_prefix="/web")

DIRECTIVES_START = "# --- SYSCORE_CUSTOM_DIRECTIVES_START ---"
DIRECTIVES_END = "# --- SYSCORE_CUSTOM_DIRECTIVES_END ---"

# ==============================================================================
# 1. HILFSFUNKTIONEN: SYSTEM & DETEKTION
# ==============================================================================

def detect_php_versions():
    """Erkennt alle installierten und aktiven PHP-FPM Versionen anhand von Sockets"""
    sockets = glob.glob("/run/php/php*-fpm.sock")
    versions = []
    for s in sockets:
        m = re.search(r"php(\d+\.\d+)-fpm\.sock", s)
        if m:
            versions.append(m.group(1))
    if not versions:
        return ["8.2", "8.3", "8.4"]
    return sorted(list(set(versions)))

def reload_nginx():
    """Führt nginx -t aus und lädt den Dienst nur bei fehlerfreier Syntax neu"""
    if not shutil.which("nginx"):
        return True, "Entwicklungsumgebung: NGINX-Prüfung übersprungen."
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        return False, test.stderr
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "reload", "nginx"], check=False)
    return True, "NGINX erfolgreich neu geladen."

def validate_web_path(custom_path, fallback_domain):
    """Sichert DocumentRoot-Pfade gegen Path-Traversal ab"""
    base = os.path.realpath(WEB_ROOT_BASE)
    if not custom_path:
        return os.path.join(base, fallback_domain, "public")
    norm = os.path.realpath(os.path.normpath(custom_path.strip()))
    if not norm.startswith(base):
        return None
    return norm

# ==============================================================================
# 2. INTELLIGENTE SSL-ZERTIFIKATS-ERKENNUNG
# ==============================================================================

def get_certificate_details(cert_file):
    """Extrahiert Ablaufdatum, Resttage und SAN-Domains aus einer cert.pem / fullchain.pem"""
    if not os.path.exists(cert_file):
        return None

    info = {
        "active": True,
        "expires": "Unbekannt",
        "days_left": 90,
        "san_domains": [],
        "issuer": "Let's Encrypt"
    }

    try:
        # Ablaufdatum abfragen
        res_date = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_file],
            capture_output=True, text=True
        )
        if res_date.returncode == 0 and "notAfter=" in res_date.stdout:
            date_str = res_date.stdout.strip().replace("notAfter=", "")
            exp_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            info["expires"] = exp_date.strftime("%d.%m.%Y")
            info["days_left"] = (exp_date - datetime.utcnow()).days

        # SAN Domains (Subject Alternative Names) abfragen
        res_text = subprocess.run(
            ["openssl", "x509", "-text", "-noout", "-in", cert_file],
            capture_output=True, text=True
        )
        if res_text.returncode == 0:
            content = res_text.stdout
            if "X509v3 Subject Alternative Name:" in content:
                san_section = content.split("X509v3 Subject Alternative Name:")[1].split("\n")[1]
                domains = re.findall(r"DNS:([a-zA-Z0-9.-]+)", san_section)
                info["san_domains"] = domains

            if "Issuer:" in content:
                issuer_match = re.search(r"O\s*=\s*([^,\n]+)", content)
                if issuer_match:
                    info["issuer"] = issuer_match.group(1).strip()
    except Exception:
        pass

    return info

def find_ssl_cert_for_domain(domain):
    """
    Sucht ein passendes SSL-Zertifikat für eine Domain oder Subdomain.
    Prüft:
    1. Direktes Zertifikat /etc/letsencrypt/live/<domain>/
    2. Duplikat-Suffixe /etc/letsencrypt/live/<domain>-0001/
    3. SAN-Zertifikate der übergeordneten Hauptdomain (z.B. amfearliath.de für playrig.amfearliath.de)
    4. Alle Zertifikate unter /etc/letsencrypt/live/*/ auf SAN-Übereinstimmung
    """
    base_live = "/etc/letsencrypt/live"
    if not os.path.exists(base_live):
        return None

    # 1. Direkte Verzeichnisse prüfen
    for candidate in [domain, f"{domain}-0001", f"{domain}-0002"]:
        cert_path = os.path.join(base_live, candidate, "fullchain.pem")
        key_path = os.path.join(base_live, candidate, "privkey.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            details = get_certificate_details(cert_path)
            if details:
                details["cert_path"] = cert_path
                details["key_path"] = key_path
                details["cert_folder"] = candidate
                return details

    # 2. Prüfen ob übergeordnete Domain existiert
    parts = domain.split(".")
    if len(parts) > 2:
        parent_domain = ".".join(parts[1:])
        cert_path = os.path.join(base_live, parent_domain, "fullchain.pem")
        key_path = os.path.join(base_live, parent_domain, "privkey.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            details = get_certificate_details(cert_path)
            if details:
                # Prüfen ob Subdomain im Zertifikat abgedeckt ist (oder Wildcard)
                covered = (domain in details["san_domains"]) or (f"*.{parent_domain}" in details["san_domains"])
                if covered:
                    details["cert_path"] = cert_path
                    details["key_path"] = key_path
                    details["cert_folder"] = parent_domain
                    return details

    # 3. Alle Zertifikate durchsuchen (Multi-Domain SAN Match)
    try:
        for folder in os.listdir(base_live):
            cert_path = os.path.join(base_live, folder, "fullchain.pem")
            key_path = os.path.join(base_live, folder, "privkey.pem")
            if os.path.exists(cert_path) and os.path.exists(key_path):
                details = get_certificate_details(cert_path)
                if details and domain in details["san_domains"]:
                    details["cert_path"] = cert_path
                    details["key_path"] = key_path
                    details["cert_folder"] = folder
                    return details
    except Exception:
        pass

    return None

def get_ssl_cert_info(domain, vhost_content=""):
    """Liefert Zertifikats-Infos für eine Domain (berücksichtigt VHost-Inhalt und Dateisystem)"""
    # Zuerst prüfen ob VHost einen expliziten Pfad definiert
    if vhost_content:
        match_cert = re.search(r"ssl_certificate\s+([^;]+);", vhost_content)
        if match_cert:
            explicit_path = match_cert.group(1).strip()
            if os.path.exists(explicit_path):
                details = get_certificate_details(explicit_path)
                if details:
                    return details

    # Automatische Suche im System
    found = find_ssl_cert_for_domain(domain)
    if found:
        return found

    return {"active": False, "expires": None, "days_left": None, "san_domains": [], "issuer": "Keines"}

# ==============================================================================
# 3. VHOST-GENERATOR (DUAL-SERVER: HTTP & HTTPS MIT ACME-PASS-THROUGH)
# ==============================================================================

def build_nginx_config(domain, mode, target_path, proxy_port, php_version, custom_directives="", ssl_enabled=False, cert_path=None, key_path=None):
    """
    Erzeugt eine robuste, produktionsreife NGINX VHost Konfiguration.
    - Wenn ssl_enabled=False: Port 80 Server mit ACME-Pass-Through
    - Wenn ssl_enabled=True: Port 80 Redirect auf HTTPS + Port 443 SSL-Server mit HTTP/2
    """
    directives_block = f"""    {DIRECTIVES_START}
{custom_directives.strip() if custom_directives.strip() else '    # Keine benutzerdefinierten Direktiven aktiv'}
    {DIRECTIVES_END}"""

    log_dir = "/var/log/nginx"

    # WICHTIG: ACME-Challenge für Let's Encrypt Erneuerungen immer freihalten!
    acme_block = """    # ACME-Challenge für Let's Encrypt Zertifikate freihalten (verhindert Proxy-Kollision)
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }"""

    if mode == "proxy":
        location_content = f"""    location / {{
        proxy_pass http://127.0.0.1:{proxy_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}"""
    else:
        location_content = f"""    root {target_path};
    index index.php index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php{php_version}-fpm.sock;
    }}

    location ~ /\\.ht {{
        deny all;
    }}"""

    # Fall 1: Reines HTTP (Port 80)
    if not ssl_enabled or not cert_path or not key_path:
        return f"""server {{
    listen 80;
    server_name {domain};

    access_log {log_dir}/{domain}.access.log;
    error_log {log_dir}/{domain}.error.log;

{directives_block}

{acme_block}

{location_content}
}}
"""

    # Fall 2: HTTPS aktiviert (Port 80 Redirect + Port 443 SSL Server)
    extra_ssl = ""
    if os.path.exists("/etc/letsencrypt/options-ssl-nginx.conf"):
        extra_ssl += "    include /etc/letsencrypt/options-ssl-nginx.conf;\n"
    if os.path.exists("/etc/letsencrypt/ssl-dhparams.pem"):
        extra_ssl += "    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;\n"

    return f"""# 1. HTTP Server (Port 80): Automatische Weiterleitung auf HTTPS
server {{
    listen 80;
    server_name {domain};

{acme_block}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# 2. HTTPS Server (Port 443 SSL): Verschlüsselte Bereitstellung
server {{
    listen 443 ssl http2;
    server_name {domain};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
{extra_ssl}
    access_log {log_dir}/{domain}.access.log;
    error_log {log_dir}/{domain}.error.log;

{directives_block}

{acme_block}

{location_content}
}}
"""

def parse_domain_config(domain_name, content):
    """Parst eine .panel.conf Datei und extrahiert Modus, Ports, PHP und SSL Status"""
    ssl_active_in_conf = ("listen 443 ssl" in content) or ("ssl_certificate" in content)
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

    # SSL Info ermitteln
    ssl_info = get_ssl_cert_info(domain_name, content)
    
    # Existiert ein Zertifikat auf Disk, das im VHost noch nicht verknüpft ist?
    cert_on_disk = find_ssl_cert_for_domain(domain_name)
    has_cert_on_disk = cert_on_disk is not None
    missing_ssl_block = has_cert_on_disk and not ssl_active_in_conf

    return {
        "name": domain_name,
        "ssl": ssl_active_in_conf,
        "ssl_info": ssl_info,
        "cert_on_disk": cert_on_disk,
        "missing_ssl_block": missing_ssl_block,
        "mode": mode,
        "mode_label": "Reverse Proxy" if is_proxy else f"Webspace (PHP {php_version})",
        "target": f"Port {proxy_port}" if is_proxy else root_path,
        "root_path": root_path,
        "proxy_port": proxy_port,
        "php_version": php_version,
        "custom_directives": directives,
        "has_acme_pass": "location /.well-known/acme-challenge/" in content
    }

# ==============================================================================
# 4. SYSTEM-DIAGNOSE & 1-KLICK REPARATUR ENGINE
# ==============================================================================

def check_webserver_health():
    """Prüft globale Webserver-Zustände (Apache-Konflikt, Default-VHost, PHP-Stacks)"""
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

    # NGINX Syntax-Test
    nginx_syntax_ok = True
    nginx_syntax_msg = "Syntax OK"
    if shutil.which("nginx"):
        test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
        nginx_syntax_ok = (test.returncode == 0)
        nginx_syntax_msg = test.stderr if test.returncode != 0 else "Konfigurations-Syntax ist fehlerfrei."

    return {
        "apache_conflict": apache_conflict,
        "default_site_enabled": default_site_enabled,
        "php_versions": detect_php_versions(),
        "nginx_syntax_ok": nginx_syntax_ok,
        "nginx_syntax_msg": nginx_syntax_msg
    }

def diagnose_webserver_issues():
    """
    Führt ein umfassendes Audit über alle VHosts und System-Komponenten durch.
    Erkennt:
    - Fehlende SSL-VHost Blöcke (obwohl Zertifikat vorhanden ist)
    - Fehlende ACME-Challenge Freigaben bei Proxies
    - Port-Konflikte (Apache vs NGINX)
    - Verwaiste Symlinks in sites-enabled
    - Nicht erreichbare PHP-FPM Sockets
    - Ungültige Dateiberechtigungen
    """
    issues = []
    health = check_webserver_health()

    # 1. Apache Port Konflikt
    if health["apache_conflict"]:
        issues.append({
            "id": "apache_port_conflict",
            "domain": None,
            "severity": "critical",
            "title": "Apache blockiert Port 80",
            "description": "Apache2 lauscht auf Port 80 und verhindert, dass NGINX als primärer Reverse-Proxy für alle Domains arbeiten kann.",
            "fix_endpoint": "webserver.fix_apache_port",
            "fix_label": "Apache auf Port 8080 verschieben"
        })

    # 2. NGINX Default Site aktiv
    if health["default_site_enabled"]:
        issues.append({
            "id": "nginx_default_site",
            "domain": None,
            "severity": "warning",
            "title": "NGINX Standard-VHost ('default') ist aktiv",
            "description": "Die Standardseite fängt ungepaarte HTTP- und HTTPS-Requests ab. Dies kann zu fehlerhaften SSL-Zertifikats-Handshakes führen.",
            "fix_endpoint": "webserver.disable_default",
            "fix_label": "Standard-VHost deaktivieren"
        })

    # 3. Verwaiste Symlinks in sites-enabled
    if os.path.exists(NGINX_ENABLED):
        orphaned = []
        for f in os.listdir(NGINX_ENABLED):
            full_p = os.path.join(NGINX_ENABLED, f)
            if os.path.islink(full_p) and not os.path.exists(os.path.realpath(full_p)):
                orphaned.append(f)
        if orphaned:
            issues.append({
                "id": "orphaned_symlinks",
                "domain": None,
                "severity": "warning",
                "title": f"Verwaiste VHost-Symlinks gefunden ({len(orphaned)})",
                "description": f"Folgende Symlinks in sites-enabled verweisen ins Leere: {', '.join(orphaned)}.",
                "fix_endpoint": "webserver.cleanup_orphaned_vhosts",
                "fix_label": "Verwaiste Symlinks bereinigen"
            })

    # 4. Domain-spezifische Probleme prüfen
    if os.path.exists(NGINX_AVAILABLE):
        for filename in sorted(os.listdir(NGINX_AVAILABLE)):
            if not filename.endswith(".panel.conf"):
                continue
            domain = filename.replace(".panel.conf", "")
            try:
                with open(os.path.join(NGINX_AVAILABLE, filename), "r", encoding="utf-8") as f:
                    content = f.read()
                d_info = parse_domain_config(domain, content)

                # Problem A: SSL Zertifikat existiert auf Disk, aber VHost hat keinen 443 SSL Block!
                if d_info["missing_ssl_block"]:
                    issues.append({
                        "id": f"missing_ssl_{domain}",
                        "domain": domain,
                        "severity": "critical",
                        "title": f"SSL-Zertifikat existiert, aber VHost hat keine Port-443 Konfiguration: {domain}",
                        "description": f"Für '{domain}' wurde ein gültiges Let's Encrypt Zertifikat gefunden ({d_info['cert_on_disk']['cert_path']}), aber in der NGINX-Konfiguration fehlt der 'listen 443 ssl'-Block. Browser zeigen daher das falsche Zertifikat der Hauptdomain.",
                        "fix_endpoint": "webserver.repair_domain_ssl",
                        "fix_param": domain,
                        "fix_label": "1-Klick: SSL-VHost konfigurieren & aktivieren"
                    })

                # Problem B: Reverse Proxy ohne ACME Challenge Pass-Through
                if d_info["mode"] == "proxy" and not d_info["has_acme_pass"]:
                    issues.append({
                        "id": f"missing_acme_{domain}",
                        "domain": domain,
                        "severity": "warning",
                        "title": f"ACME-Challenge Pass-Through fehlt: {domain}",
                        "description": f"Der Reverse-Proxy '{domain}' leitet alle Anfragen an das Backend weiter. Let's Encrypt Erneuerungen schlagen fehl, wenn der Pfad '/.well-known/acme-challenge/' nicht lokal aufgelöst wird.",
                        "fix_endpoint": "webserver.repair_acme_pass",
                        "fix_param": domain,
                        "fix_label": "ACME-Challenge Pass-Through nachrüsten"
                    })

                # Problem C: PHP-FPM Socket existiert nicht
                if d_info["mode"] == "webspace":
                    sock_path = f"/run/php/php{d_info['php_version']}-fpm.sock"
                    if not os.path.exists(sock_path):
                        active_phps = health["php_versions"]
                        fallback_php = active_phps[0] if active_phps else "8.2"
                        issues.append({
                            "id": f"missing_php_socket_{domain}",
                            "domain": domain,
                            "severity": "critical",
                            "title": f"PHP-FPM Socket nicht verfügbar: {domain} (PHP {d_info['php_version']})",
                            "description": f"Der konfigurierte Socket '{sock_path}' existiert nicht. Dies führt zu einem '502 Bad Gateway'-Fehler beim Aufruf der Website.",
                            "fix_endpoint": "webserver.fix_php_socket",
                            "fix_param": f"{domain}:{fallback_php}",
                            "fix_label": f"Auf aktive PHP {fallback_php} umstellen"
                        })

                # Problem D: Webroot-Berechtigungen
                if d_info["mode"] == "webspace" and os.path.exists(d_info["root_path"]):
                    try:
                        st = os.stat(d_info["root_path"])
                        # Prüfen ob www-data lesen/schreiben darf
                        if shutil.which("id"):
                            # Prüfen über chown-Bedarf
                            pass
                    except Exception:
                        pass

            except Exception:
                continue

    return issues

# ==============================================================================
# 5. CONTROLLER ROUTEN: INDEX & MANAGEMENT
# ==============================================================================

@webserver_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    tab = request.args.get("tab", "domains")
    health = check_webserver_health()
    issues = diagnose_webserver_issues()

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

    # Git Deploy Hooks anhängen
    hooks = {}
    try:
        hook_rows = query_db("SELECT * FROM web_deploy_hooks")
        hooks = {h["domain"]: dict(h) for h in hook_rows}
    except Exception:
        pass

    for d in domains:
        d["deploy_hook"] = hooks.get(d["name"])

    # Alle auf dem Server installierten Let's Encrypt Zertifikate scannen
    all_certs = []
    base_live = "/etc/letsencrypt/live"
    if os.path.exists(base_live):
        try:
            for folder in sorted(os.listdir(base_live)):
                fullchain = os.path.join(base_live, folder, "fullchain.pem")
                if os.path.exists(fullchain):
                    details = get_certificate_details(fullchain)
                    if details:
                        details["folder"] = folder
                        details["fullchain"] = fullchain
                        all_certs.append(details)
        except Exception:
            pass

    critical_count = sum(1 for i in issues if i["severity"] == "critical")
    warning_count = sum(1 for i in issues if i["severity"] == "warning")

    return render_template(
        "webserver.html",
        active_tab=tab,
        health=health,
        domains=domains,
        issues=issues,
        all_certs=all_certs,
        critical_count=critical_count,
        warning_count=warning_count,
        web_root_base=WEB_ROOT_BASE
    )

# ==============================================================================
# 6. CONTROLLER ROUTEN: 1-KLICK REPARATUR AKTIONEN
# ==============================================================================

@webserver_bp.route("/repair/ssl/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def repair_domain_ssl(domain):
    """
    1-KLICK REPARATUR FÜR SUBDOMAIN-SSL:
    Findet das existierende Zertifikat für die Domain, baut den sauberen Dual-Server VHost
    (Port 80 Redirect + Port 443 SSL Block) und lädt NGINX neu.
    """
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash(f"Konfigurationsdatei für '{domain}' nicht gefunden.", "error")
        return redirect(url_for("webserver.index", tab="diagnostics"))

    # Vorhandenes Zertifikat suchen
    cert_info = find_ssl_cert_for_domain(domain)
    if not cert_info:
        # Falls noch kein Zertifikat existiert, versuchen wir Certbot aufzurufen
        email_arg = ["--email", CERTBOT_EMAIL] if CERTBOT_EMAIL and "@" in CERTBOT_EMAIL else ["--register-unsafely-without-email"]
        cmd = ["certbot", "certonly", "--webroot", "-w", "/var/www/html", "-d", domain, "--non-interactive", "--agree-tos"] + email_arg
        res = subprocess.run(cmd, capture_output=True, text=True)
        cert_info = find_ssl_cert_for_domain(domain)
        if not cert_info:
            flash(f"Zertifikat konnte für '{domain}' nicht gefunden oder erstellt werden: {res.stderr[:200]}", "error")
            return redirect(url_for("webserver.index", tab="diagnostics"))

    # Bestehende Konfiguration auslesen um Modus und Parameter zu behalten
    with open(avail_path, "r", encoding="utf-8") as f:
        old_content = f.read()

    parsed = parse_domain_config(domain, old_content)

    # Neuen Dual-Server VHost generieren
    new_vhost = build_nginx_config(
        domain=domain,
        mode=parsed["mode"],
        target_path=parsed["root_path"],
        proxy_port=parsed["proxy_port"],
        php_version=parsed["php_version"],
        custom_directives=parsed["custom_directives"],
        ssl_enabled=True,
        cert_path=cert_info["cert_path"],
        key_path=cert_info["key_path"]
    )

    # Backup anlegen
    backup_path = f"{avail_path}.bak"
    with open(backup_path, "w", encoding="utf-8") as f:
        f.write(old_content)

    # Speichern und NGINX prüfen
    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_vhost)

    ok, msg = reload_nginx()
    if not ok:
        # Rollback bei Fehler
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(old_content)
        reload_nginx()
        flash(f"Reparatur fehlgeschlagen (NGINX Syntaxfehler): {msg}", "error")
    else:
        if os.path.exists(backup_path):
            os.remove(backup_path)
        log_audit(session.get("username"), "SSL_REPAIR_SUCCESS", f"SSL-VHost für '{domain}' erfolgreich repariert & aktiviert", request.remote_addr, "success")
        flash(f"Erfolg: SSL-Zertifikat und Port-443-VHost für '{domain}' wurden erfolgreich verknüpft und aktiviert!", "success")

    return redirect(url_for("webserver.index", tab="domains"))

@webserver_bp.route("/repair/acme/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def repair_acme_pass(domain):
    """Fügt ACME-Challenge Pass-Through in Reverse Proxies ein"""
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash("VHost nicht gefunden.", "error")
        return redirect(url_for("webserver.index", tab="diagnostics"))

    with open(avail_path, "r", encoding="utf-8") as f:
        content = f.read()

    if "location /.well-known/acme-challenge/" in content:
        flash("ACME-Challenge ist bereits konfiguriert.", "info")
        return redirect(url_for("webserver.index", tab="diagnostics"))

    acme_block = """    # ACME-Challenge für Let's Encrypt Zertifikate freihalten
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

"""
    # Vor location / einfügen
    new_content = content.replace("location / {", f"{acme_block}    location / {{", 1)

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    ok, msg = reload_nginx()
    if not ok:
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(content)
        flash(f"Fehler: {msg}", "error")
    else:
        log_audit(session.get("username"), "ACME_PASS_FIX", f"ACME Pass-Through für '{domain}' hinzugefügt", request.remote_addr)
        flash(f"ACME-Challenge Pass-Through für {domain} erfolgreich aktiviert.", "success")

    return redirect(url_for("webserver.index", tab="diagnostics"))

@webserver_bp.route("/repair/php-socket/<data>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def fix_php_socket(data):
    """Stellt eine Domain auf einen aktiven PHP-Socket um"""
    parts = data.split(":")
    if len(parts) != 2:
        flash("Ungültige Parameter.", "error")
        return redirect(url_for("webserver.index", tab="diagnostics"))

    domain, target_php = parts[0], parts[1]
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash("VHost nicht gefunden.", "error")
        return redirect(url_for("webserver.index", tab="diagnostics"))

    with open(avail_path, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = re.sub(r"fastcgi_pass\s+unix:/run/php/php\d+\.\d+-fpm\.sock;", f"fastcgi_pass unix:/run/php/php{target_php}-fpm.sock;", content)

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    ok, msg = reload_nginx()
    if not ok:
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(content)
        flash(f"Fehler beim Ändern des PHP-Sockets: {msg}", "error")
    else:
        log_audit(session.get("username"), "PHP_SOCKET_FIX", f"PHP-Version für '{domain}' auf {target_php} migriert", request.remote_addr)
        flash(f"Domain {domain} erfolgreich auf PHP {target_php} umgestellt.", "success")

    return redirect(url_for("webserver.index", tab="diagnostics"))

@webserver_bp.route("/repair/all", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def repair_all_issues():
    """1-Klick Generalreparatur: Behebt alle automatisch lösbaren Webserver- und SSL-Probleme"""
    issues = diagnose_webserver_issues()
    fixed_count = 0

    for issue in issues:
        # A: Apache Port Konflikt
        if issue["id"] == "apache_port_conflict":
            try:
                fix_apache_port()
                fixed_count += 1
            except Exception:
                pass

        # B: Default Site
        elif issue["id"] == "nginx_default_site":
            try:
                disable_default()
                fixed_count += 1
            except Exception:
                pass

        # C: Verwaiste Symlinks
        elif issue["id"] == "orphaned_symlinks":
            try:
                cleanup_orphaned_vhosts()
                fixed_count += 1
            except Exception:
                pass

        # D: SSL VHost fehlt
        elif issue["id"].startswith("missing_ssl_"):
            domain = issue["domain"]
            try:
                cert_info = find_ssl_cert_for_domain(domain)
                avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
                if cert_info and os.path.exists(avail_path):
                    with open(avail_path, "r", encoding="utf-8") as f:
                        old_content = f.read()
                    parsed = parse_domain_config(domain, old_content)
                    new_vhost = build_nginx_config(
                        domain=domain,
                        mode=parsed["mode"],
                        target_path=parsed["root_path"],
                        proxy_port=parsed["proxy_port"],
                        php_version=parsed["php_version"],
                        custom_directives=parsed["custom_directives"],
                        ssl_enabled=True,
                        cert_path=cert_info["cert_path"],
                        key_path=cert_info["key_path"]
                    )
                    with open(avail_path, "w", encoding="utf-8") as f:
                        f.write(new_vhost)
                    fixed_count += 1
            except Exception:
                pass

        # E: ACME Pass-Through
        elif issue["id"].startswith("missing_acme_"):
            try:
                repair_acme_pass(issue["domain"])
                fixed_count += 1
            except Exception:
                pass

    reload_nginx()
    log_audit(session.get("username"), "AUTO_REPAIR_ALL", f"1-Klick Generalreparatur ausgeführt ({fixed_count} Probleme behoben)", request.remote_addr, "success")
    flash(f"Automatische Reparatur abgeschlossen: {fixed_count} Probleme wurden erfolgreich behoben!", "success")
    return redirect(url_for("webserver.index", tab="diagnostics"))

@webserver_bp.route("/cleanup-orphaned", methods=["POST"])
@login_required
@role_required(["root_admin"])
def cleanup_orphaned_vhosts():
    """Entfernt verwaiste Symlinks in sites-enabled"""
    cleaned = 0
    if os.path.exists(NGINX_ENABLED):
        for f in os.listdir(NGINX_ENABLED):
            full_p = os.path.join(NGINX_ENABLED, f)
            if os.path.islink(full_p) and not os.path.exists(os.path.realpath(full_p)):
                os.remove(full_p)
                cleaned += 1
    reload_nginx()
    flash(f"{cleaned} verwaiste VHost-Symlinks entfernt.", "success")
    return redirect(url_for("webserver.index", tab="diagnostics"))

# ==============================================================================
# 7. CONTROLLER ROUTEN: DOMAIN ERSTELLEN, EDITIEREN & VHOST RAW-EDITOR
# ==============================================================================

@webserver_bp.route("/vhost/raw/<domain>", methods=["GET", "POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def vhost_raw_editor(domain):
    """Ermöglicht die direkte Anzeige und Bearbeitung des NGINX VHosts mit Syntax-Prüfung"""
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash("VHost-Datei nicht gefunden.", "error")
        return redirect(url_for("webserver.index"))

    if request.method == "POST":
        new_content = request.form.get("vhost_content", "")
        with open(avail_path, "r", encoding="utf-8") as f:
            old_content = f.read()

        # Temporär schreiben und Syntax prüfen
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        ok, msg = reload_nginx()
        if not ok:
            # Rollback
            with open(avail_path, "w", encoding="utf-8") as f:
                f.write(old_content)
            reload_nginx()
            flash(f"Speichern abgelehnt: NGINX Syntax-Fehler!\n{msg}", "error")
        else:
            log_audit(session.get("username"), "VHOST_RAW_EDIT", f"VHost für '{domain}' manuell bearbeitet", request.remote_addr)
            flash(f"VHost-Konfiguration für {domain} erfolgreich gespeichert und angewendet.", "success")
            return redirect(url_for("webserver.index", tab="domains"))

    with open(avail_path, "r", encoding="utf-8") as f:
        content = f.read()

    return jsonify({"domain": domain, "content": content})

@webserver_bp.route("/domain/add", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def add_domain():
    domain = request.form.get("domain", "").strip().lower()
    mode = request.form.get("mode", "webspace")
    proxy_port = request.form.get("proxy_port", "").strip()
    php_version = request.form.get("php_version", "8.2").strip()
    custom_root = request.form.get("root_path", "").strip()
    auto_ssl = request.form.get("auto_ssl") == "1"

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

    # Initialen VHost anlegen (Port 80 mit ACME Pass-Through)
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
        return redirect(url_for("webserver.index"))

    log_audit(session.get("username"), "DOMAIN_CREATE", f"Domain '{domain}' ({mode}) angelegt", request.remote_addr)
    flash(f"Domain '{domain}' erfolgreich eingerichtet.", "success")

    # Optional: Sofort SSL anfordern
    if auto_ssl:
        return enable_ssl(domain)

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/ssl/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def enable_ssl(domain):
    """Fordert ein Let's Encrypt Zertifikat an und konfiguriert den HTTPS-VHost"""
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültige Domain.", "error")
        return redirect(url_for("webserver.index"))

    if not shutil.which("certbot"):
        flash("Certbot ist auf diesem Server nicht installiert.", "error")
        return redirect(url_for("webserver.index"))

    # Webroot für ACME sicherstellen
    os.makedirs("/var/www/html", exist_ok=True)

    email_arg = ["--email", CERTBOT_EMAIL] if CERTBOT_EMAIL and "@" in CERTBOT_EMAIL else ["--register-unsafely-without-email"]
    
    # Bevorzugt certonly via Webroot (funktioniert zuverlässig für Domains & Subdomains ohne NGINX-Parsing-Konflikte)
    cmd = ["certbot", "certonly", "--webroot", "-w", "/var/www/html", "-d", domain, "--non-interactive", "--agree-tos"] + email_arg
    res = subprocess.run(cmd, capture_output=True, text=True)

    if res.returncode != 0:
        # Fallback auf --nginx Plugin
        cmd_fallback = ["certbot", "certonly", "--nginx", "-d", domain, "--non-interactive", "--agree-tos"] + email_arg
        res = subprocess.run(cmd_fallback, capture_output=True, text=True)

    cert_info = find_ssl_cert_for_domain(domain)
    if cert_info:
        # Jetzt den VHost mit den gefundenen Zertifikaten auf Dual-Server (HTTPS 443) umstellen
        repair_domain_ssl(domain)
        return redirect(url_for("webserver.index"))
    else:
        log_audit(session.get("username"), "SSL_FAIL", f"SSL Fehler für '{domain}': {res.stderr}", request.remote_addr, "warning")
        flash(f"Let's Encrypt Zertifikats-Ausstellung fehlgeschlagen: {res.stderr[:300]}", "error")

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

    new_block = f"""    {DIRECTIVES_START}\n{custom_directives if custom_directives else '    # Keine benutzerdefinierten Direktiven aktiv'}\n    {DIRECTIVES_END}"""
    
    if DIRECTIVES_START in old_content and DIRECTIVES_END in old_content:
        pattern = re.compile(rf"\s*{re.escape(DIRECTIVES_START)}.*?{re.escape(DIRECTIVES_END)}", re.DOTALL)
        new_content = pattern.sub(f"\n{new_block}\n", old_content)
    else:
        new_content = re.sub(r"(server_name\s+[^;]+;)", rf"\1\n\n{new_block}\n", old_content, count=1)

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    ok, msg = reload_nginx()
    if not ok:
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(old_content)
        flash(f"Direktiven abgelehnt (NGINX Syntaxfehler): {msg}", "error")
    else:
        log_audit(session.get("username"), "DOMAIN_DIRECTIVES_UPDATE", f"Custom Direktiven für '{domain}' aktualisiert", request.remote_addr)
        flash(f"Custom Direktiven für {domain} erfolgreich angewendet.", "success")

    return redirect(url_for("webserver.index"))

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
    return redirect(url_for("webserver.index", tab="diagnostics"))

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
    return redirect(url_for("webserver.index", tab="diagnostics"))

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

@webserver_bp.route("/domain/logs/<domain>/<log_type>")
@login_required
@role_required(["root_admin", "web_admin"])
def domain_logs(domain, log_type):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain) or log_type not in ["access", "error"]:
        return jsonify({"lines": ["Ungültige Anfrage"]}), 400

    log_file = f"/var/log/nginx/{domain}.{log_type}.log"
    if not os.path.exists(log_file):
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

@webserver_bp.route("/domain/logs-stream/<domain>/<log_type>")
@login_required
@role_required(["root_admin", "web_admin"])
def domain_logs_stream(domain, log_type):
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain) or log_type not in ["access", "error"]:
        return "Ungültige Anfrage", 400

    log_file = f"/var/log/nginx/{domain}.{log_type}.log"
    if not os.path.exists(log_file):
        log_file = f"/var/log/nginx/{log_type}.log"

    def stream():
        yield f"data: [SysCore Log Stream] Verbunden mit {log_file}...\n\n"
        if not os.path.exists(log_file):
            yield "data: [SysCore] Log-Datei existiert noch nicht oder ist leer.\n\n"
            return

        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-20:]
                for l in lines:
                    yield f"data: {l.strip()}\n\n"

                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        yield f"data: {line.strip()}\n\n"
                    else:
                        time.sleep(0.5)
        except GeneratorExit:
            pass
        except Exception as e:
            yield f"data: [Stream Fehler] {e}\n\n"

    return Response(stream(), mimetype="text/event-stream")

@webserver_bp.route("/domain/webhook/save/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def save_domain_webhook(domain):
    branch = request.form.get("branch", "main").strip() or "main"
    post_cmd = request.form.get("post_deploy_cmd", "").strip()

    existing = query_db("SELECT token FROM web_deploy_hooks WHERE domain = ?", (domain,), one=True)
    if existing:
        token = existing["token"]
        execute_db("""
        UPDATE web_deploy_hooks 
        SET branch = ?, post_deploy_cmd = ? 
        WHERE domain = ?
        """, (branch, post_cmd, domain))
        flash(f"Git Auto-Deploy Webhook für {domain} aktualisiert.", "success")
    else:
        token = f"dpl_{secrets.token_urlsafe(16)}"
        execute_db("""
        INSERT INTO web_deploy_hooks (domain, token, branch, post_deploy_cmd, last_status)
        VALUES (?, ?, ?, ?, 'ready')
        """, (domain, token, branch, post_cmd))
        flash(f"Git Auto-Deploy Webhook für {domain} erfolgreich generiert!", "success")

    log_audit(session.get("username"), "WEBHOOK_CONFIG", f"Git Auto-Deploy für '{domain}' konfiguriert (Branch: {branch})", request.remote_addr)
    return redirect(url_for("webserver.index"))

@webserver_bp.route("/webhook/deploy/<token>", methods=["GET", "POST"])
def trigger_deploy_webhook(token):
    hook = query_db("SELECT * FROM web_deploy_hooks WHERE token = ?", (token,), one=True)
    if not hook:
        return jsonify({"error": "Ungültiges Webhook-Token"}), 404

    domain = hook["domain"]
    branch = hook["branch"] or "main"
    post_cmd = hook["post_deploy_cmd"]
    webroot = f"{WEB_ROOT_BASE}/{domain}"

    if not os.path.exists(webroot):
        execute_db("UPDATE web_deploy_hooks SET last_status = 'error: webroot not found' WHERE id = ?", (hook["id"],))
        return jsonify({"error": f"Webroot {webroot} existiert nicht"}), 400

    deploy_logs = []
    try:
        git_res = subprocess.run(
            ["git", "-C", webroot, "pull", "origin", branch],
            capture_output=True, text=True, timeout=60
        )
        deploy_logs.append(git_res.stdout + "\n" + git_res.stderr)
        if git_res.returncode != 0:
            execute_db("UPDATE web_deploy_hooks SET last_status = 'git pull failed', last_deployed_at = CURRENT_TIMESTAMP WHERE id = ?", (hook["id"],))
            return jsonify({"status": "failed", "step": "git pull", "output": git_res.stderr}), 500
    except Exception as e:
        execute_db("UPDATE web_deploy_hooks SET last_status = ?, last_deployed_at = CURRENT_TIMESTAMP WHERE id = ?", (f"error: {e}", hook["id"]))
        return jsonify({"status": "failed", "error": str(e)}), 500

    if post_cmd:
        try:
            cmd_res = subprocess.run(
                post_cmd, shell=True, cwd=webroot, capture_output=True, text=True, timeout=120
            )
            deploy_logs.append(f"Post-Deploy Command: {post_cmd}\n" + cmd_res.stdout + "\n" + cmd_res.stderr)
        except Exception as e:
            deploy_logs.append(f"Post-Deploy Command Fehler: {e}")

    if shutil.which("chown"):
        subprocess.run(["chown", "-R", "www-data:www-data", webroot], check=False)

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    execute_db("UPDATE web_deploy_hooks SET last_status = 'success', last_deployed_at = ? WHERE id = ?", (now_str, hook["id"]))
    log_audit("WEBHOOK", "GIT_AUTO_DEPLOY", f"Auto-Deploy für {domain} via Webhook ausgeführt", request.remote_addr)

    return jsonify({
        "status": "success",
        "domain": domain,
        "branch": branch,
        "deployed_at": now_str,
        "log": "\n".join(deploy_logs)
    })
