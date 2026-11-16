import os
import re
import glob
import time
import shutil
import secrets
import shlex
import hmac
import hashlib
import base64
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, send_file, Response
from config import WEB_ROOT_BASE, NGINX_AVAILABLE, NGINX_ENABLED, APACHE_PORTS_CONF, CERTBOT_EMAIL
from modules.auth_users import login_required, role_required, log_audit
from modules.system_agent import nginx_reload, run_privileged, manage_service
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
    """Führt nginx -t aus und lädt den Dienst nur bei fehlerfreier Syntax neu (SEC-001)"""
    if not shutil.which("nginx"):
        return True, "Entwicklungsumgebung: NGINX-Prüfung übersprungen."
    res = nginx_reload()
    if res.returncode != 0:
        return False, res.stderr
    return True, "NGINX erfolgreich neu geladen."

def validate_web_path(custom_path, fallback_domain):
    """
    Sichert DocumentRoot-Pfade gegen Path-Traversal ab (SEC-005):
    - Kanonische Prüfung gegen WEB_ROOT_BASE mit os.path.commonpath
    - Ablehnung von Symlinks, die aus dem Webroot ausbrechen
    """
    base = os.path.realpath(WEB_ROOT_BASE)
    if not custom_path:
        return os.path.join(base, fallback_domain, "public")

    clean_path = custom_path.strip()
    norm = os.path.realpath(os.path.normpath(clean_path))

    # Strikte Prüfung mit commonpath statt anfälligem startswith
    if os.path.commonpath([base, norm]) != base:
        return None

    # Falls Pfad ein Symlink ist, Ziel zusätzlich prüfen
    if os.path.islink(norm):
        link_target = os.path.realpath(norm)
        if os.path.commonpath([base, link_target]) != base:
            return None

    return norm

# ==============================================================================
# 2. INTELLIGENTE SSL-ZERTIFIKATS-ERKENNUNG
# ==============================================================================

def domain_matches_cert_domains(target_domain, cert_domains):
    """
    Prüft ob eine Domain (z.B. phpmyadmin.amfearliath.de) von einer Liste von
    Zertifikats-Domains (z.B. ['amfearliath.de', '*.amfearliath.de']) abgedeckt ist.
    Unterstützt exakte Übereinstimmungen und Wildcards.
    """
    target = target_domain.lower().strip()
    # 1. Exakter Match
    for d in cert_domains:
        if d.lower().strip() == target:
            return True
    # 2. Wildcard Match (*.domain.tld)
    for d in cert_domains:
        d = d.lower().strip()
        if d.startswith("*."):
            base = d[2:]
            if target.endswith("." + base):
                return True
    return False

def parse_certbot_certificates_output(output_text):
    """Parst die CLI-Ausgabe von 'certbot certificates' für präzise Discovery"""
    certs = []
    current_cert = None
    for line in output_text.splitlines():
        line_s = line.strip()
        if line_s.startswith("Certificate Name:"):
            if current_cert and current_cert.get("cert_path"):
                certs.append(current_cert)
            name = line_s.split("Certificate Name:")[1].strip()
            current_cert = {
                "name": name,
                "domains": [],
                "cert_path": None,
                "key_path": None,
                "days_left": 90
            }
        elif current_cert:
            if line_s.startswith("Domains:"):
                doms = line_s.split("Domains:")[1].strip().split()
                current_cert["domains"] = [d.strip() for d in doms if d.strip()]
            elif line_s.startswith("Certificate Path:"):
                current_cert["cert_path"] = line_s.split("Certificate Path:")[1].strip()
            elif line_s.startswith("Private Key Path:"):
                current_cert["key_path"] = line_s.split("Private Key Path:")[1].strip()
            elif line_s.startswith("Expiry Date:"):
                exp_str = line_s.split("Expiry Date:")[1].strip()
                m_days = re.search(r"\(VALID:\s*(\d+)\s*days\)", exp_str)
                if m_days:
                    current_cert["days_left"] = int(m_days.group(1))
    if current_cert and current_cert.get("cert_path"):
        certs.append(current_cert)
    return certs

def get_certificate_details(cert_file):
    """Extrahiert Ablaufdatum, Resttage, CN und alle SAN-Domains aus einer cert.pem / fullchain.pem"""
    if not os.path.exists(cert_file):
        return None

    info = {
        "active": True,
        "expires": "Unbekannt",
        "days_left": 90,
        "san_domains": [],
        "issuer": "Let's Encrypt",
        "cn": None
    }

    try:
        # Ablaufdatum abfragen
        res_date = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_file],
            capture_output=True, text=True
        )
        if res_date.returncode == 0 and "notAfter=" in res_date.stdout:
            date_str = res_date.stdout.strip().replace("notAfter=", "")
            try:
                exp_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                info["expires"] = exp_date.strftime("%d.%m.%Y")
                info["days_left"] = (exp_date - datetime.utcnow()).days
            except Exception:
                pass

        # Text-Dump für CN, Issuer und SANs abfragen
        res_text = subprocess.run(
            ["openssl", "x509", "-text", "-noout", "-in", cert_file],
            capture_output=True, text=True
        )
        if res_text.returncode == 0:
            content = res_text.stdout

            # CN (Common Name)
            cn_match = re.search(r"Subject:.*?CN\s*=\s*([^,\n/]+)", content)
            if cn_match:
                info["cn"] = cn_match.group(1).strip()
                info["san_domains"].append(info["cn"])

            # SAN Domains über alle Zeilen hinweg erfassen (inklusive Wildcards '*')
            if "X509v3 Subject Alternative Name:" in content:
                san_part = content.split("X509v3 Subject Alternative Name:")[1]
                san_lines = []
                for line in san_part.splitlines()[1:]:
                    if "X509v3" in line or (line and not line.startswith(" ")):
                        break
                    san_lines.append(line)
                san_text = " ".join(san_lines)
                sans = re.findall(r"DNS:([a-zA-Z0-9*.-]+)", san_text)
                info["san_domains"].extend(sans)

            if "Issuer:" in content:
                issuer_match = re.search(r"O\s*=\s*([^,\n]+)", content)
                if issuer_match:
                    info["issuer"] = issuer_match.group(1).strip()

        # Duplikate entfernen und bereinigen
        clean_domains = []
        for d in info["san_domains"]:
            d_clean = d.strip()
            if d_clean and d_clean not in clean_domains:
                clean_domains.append(d_clean)
        info["san_domains"] = clean_domains
    except Exception:
        pass

    return info

# In-Memory Cache für Zertifikate (drastische Beschleunigung der Ladezeiten)
_SSL_CERTS_CACHE = {"timestamp": 0, "certs": []}
_SSL_CACHE_TTL = 45  # 45 Sekunden TTL

def clear_ssl_cache():
    """Invalidiert den systemweiten SSL-Zertifikats-Cache"""
    global _SSL_CERTS_CACHE
    _SSL_CERTS_CACHE["timestamp"] = 0
    _SSL_CERTS_CACHE["certs"] = []

def scan_all_system_certificates(force_refresh=False):
    """
    Sucht auf dem gesamten System gründlich nach allen vorhandenen Zertifikaten:
    1. Certbot-Registry via 'certbot certificates'
    2. /etc/letsencrypt/live/*/fullchain.pem
    3. /etc/letsencrypt/archive/*/ (letzte Version)
    4. /etc/ssl/certs/ und /etc/ssl/private/
    5. /etc/nginx/ssl/
    6. In bestehenden NGINX-VHosts referenzierte Pfade
    """
    global _SSL_CERTS_CACHE
    now = time.time()
    if not force_refresh and _SSL_CERTS_CACHE["certs"] and (now - _SSL_CERTS_CACHE["timestamp"] < _SSL_CACHE_TTL):
        return _SSL_CERTS_CACHE["certs"]

    found_certs = []
    seen_paths = set()

    # 1. Certbot Registry (am zuverlässigsten für Let's Encrypt)
    if shutil.which("certbot"):
        try:
            res_cb = subprocess.run(["certbot", "certificates"], capture_output=True, text=True, timeout=10)
            if res_cb.returncode == 0:
                parsed_cb = parse_certbot_certificates_output(res_cb.stdout)
                for cb in parsed_cb:
                    cp = cb.get("cert_path")
                    kp = cb.get("key_path")
                    if cp and kp and os.path.exists(cp) and os.path.exists(kp):
                        details = get_certificate_details(cp)
                        if details:
                            details["cert_path"] = cp
                            details["key_path"] = kp
                            details["folder"] = cb["name"]
                            details["domains"] = list(set(cb["domains"] + details["san_domains"]))
                            details["source"] = "Certbot Registry"
                            found_certs.append(details)
                            seen_paths.add(os.path.realpath(cp))
        except Exception:
            pass

    # 2. /etc/letsencrypt/live/*/
    base_live = "/etc/letsencrypt/live"
    if os.path.exists(base_live):
        try:
            for folder in sorted(os.listdir(base_live)):
                fullchain = os.path.join(base_live, folder, "fullchain.pem")
                privkey = os.path.join(base_live, folder, "privkey.pem")
                if os.path.exists(fullchain) and os.path.exists(privkey):
                    real_p = os.path.realpath(fullchain)
                    if real_p not in seen_paths:
                        details = get_certificate_details(fullchain)
                        if details:
                            details["cert_path"] = fullchain
                            details["key_path"] = privkey
                            details["folder"] = folder
                            details["domains"] = details["san_domains"]
                            details["source"] = "Let's Encrypt Live"
                            found_certs.append(details)
                            seen_paths.add(real_p)
        except Exception:
            pass

    # 3. /etc/letsencrypt/archive/*/
    base_archive = "/etc/letsencrypt/archive"
    if os.path.exists(base_archive):
        try:
            for folder in sorted(os.listdir(base_archive)):
                arch_dir = os.path.join(base_archive, folder)
                if not os.path.isdir(arch_dir):
                    continue
                chains = sorted(glob.glob(os.path.join(arch_dir, "fullchain*.pem")))
                keys = sorted(glob.glob(os.path.join(arch_dir, "privkey*.pem")))
                if chains and keys:
                    latest_chain = chains[-1]
                    latest_key = keys[-1]
                    real_p = os.path.realpath(latest_chain)
                    if real_p not in seen_paths:
                        details = get_certificate_details(latest_chain)
                        if details:
                            details["cert_path"] = latest_chain
                            details["key_path"] = latest_key
                            details["folder"] = f"{folder} (Archiv)"
                            details["domains"] = details["san_domains"]
                            details["source"] = "Let's Encrypt Archive"
                            found_certs.append(details)
                            seen_paths.add(real_p)
        except Exception:
            pass

    # 4. Standard Linux SSL Verzeichnisse (/etc/ssl/certs, /etc/nginx/ssl)
    for extra_dir in ["/etc/ssl/certs", "/etc/nginx/ssl", "/var/www/ssl"]:
        if os.path.exists(extra_dir):
            try:
                for f in os.listdir(extra_dir):
                    if f.endswith((".crt", ".pem")):
                        cert_f = os.path.join(extra_dir, f)
                        base_name = f.rsplit(".", 1)[0]
                        key_candidates = [
                            os.path.join(extra_dir, f"{base_name}.key"),
                            os.path.join("/etc/ssl/private", f"{base_name}.key"),
                            os.path.join(extra_dir, "privkey.pem")
                        ]
                        key_f = next((k for k in key_candidates if os.path.exists(k)), None)
                        if key_f:
                            real_p = os.path.realpath(cert_f)
                            if real_p not in seen_paths:
                                details = get_certificate_details(cert_f)
                                if details:
                                    details["cert_path"] = cert_f
                                    details["key_path"] = key_f
                                    details["folder"] = f
                                    details["domains"] = details["san_domains"]
                                    details["source"] = "Custom / System SSL"
                                    found_certs.append(details)
                                    seen_paths.add(real_p)
            except Exception:
                pass

    _SSL_CERTS_CACHE["certs"] = found_certs
    _SSL_CERTS_CACHE["timestamp"] = now
    return found_certs

def find_ssl_cert_for_domain(domain, system_certs=None):
    """
    Sucht das bestmögliche, gültige SSL-Zertifikat für eine Domain oder Subdomain.
    Prüft exakte Übereinstimmungen und Wildcards (*.domain.tld) systemweit.
    """
    if not domain:
        return None
    domain = domain.lower().strip()
    all_certs = system_certs if system_certs is not None else scan_all_system_certificates()

    # 1. Prio: Exakte Domain-Übereinstimmung
    for cert in all_certs:
        doms = [d.lower().strip() for d in cert.get("domains", [])]
        if domain in doms:
            return cert

    # 2. Prio: Wildcard-Übereinstimmung (z.B. *.amfearliath.de für phpmyadmin.amfearliath.de)
    for cert in all_certs:
        doms = [d.lower().strip() for d in cert.get("domains", [])]
        if domain_matches_cert_domains(domain, doms):
            return cert

    # 3. Fallback: Direkte Verzeichnisse prüfen
    base_live = "/etc/letsencrypt/live"
    if os.path.exists(base_live):
        for candidate in [domain, f"{domain}-0001", f"{domain}-0002"]:
            cert_path = os.path.join(base_live, candidate, "fullchain.pem")
            key_path = os.path.join(base_live, candidate, "privkey.pem")
            if os.path.exists(cert_path) and os.path.exists(key_path):
                details = get_certificate_details(cert_path)
                if details:
                    details["cert_path"] = cert_path
                    details["key_path"] = key_path
                    details["folder"] = candidate
                    return details

    return None

def get_ssl_cert_info(domain, vhost_content="", system_certs=None):
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
    found = find_ssl_cert_for_domain(domain, system_certs=system_certs)
    if found:
        return found

    return {"active": False, "expires": None, "days_left": None, "san_domains": [], "issuer": "Keines"}

# ==============================================================================
# 3. VHOST-GENERATOR (DUAL-SERVER: HTTP & HTTPS MIT ACME-PASS-THROUGH)
# ==============================================================================

def get_directory_size_formatted(path):
    """Ermittelt schnell die belegte Speicherplatzgröße eines Domain-Verzeichnisses (Plesk-Metrik)"""
    if not path or not os.path.exists(path):
        return "0 B"
    total_size = 0
    try:
        count = 0
        for root, dirs, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                if not os.path.islink(fp):
                    try:
                        total_size += os.path.getsize(fp)
                    except Exception:
                        pass
                    count += 1
                if count > 2500:
                    break
            if count > 2500:
                break
    except Exception:
        pass

    if total_size < 1024:
        return f"{total_size} B"
    elif total_size < 1024 * 1024:
        return f"{total_size / 1024:.1f} KB"
    elif total_size < 1024 * 1024 * 1024:
        return f"{total_size / (1024 * 1024):.1f} MB"
    else:
        return f"{total_size / (1024 * 1024 * 1024):.2f} GB"

def build_nginx_config(
    domain,
    mode,
    target_path,
    proxy_port,
    php_version,
    custom_directives="",
    ssl_enabled=False,
    cert_path=None,
    key_path=None,
    aliases=None,
    maintenance=False,
    htpasswd_enabled=False,
    hsts=False,
    gzip=True,
    force_https=True
):
    """
    Erzeugt eine robuste, produktionsreife NGINX VHost Konfiguration im Plesk-Standard.
    Unterstützt Aliase, SSL Dual-Server, Wartungsmodus, .htpasswd, HSTS und Gzip.
    """
    server_names = [domain]
    if aliases:
        if isinstance(aliases, str):
            aliases = [a.strip() for a in aliases.split() if a.strip()]
        for a in aliases:
            if a != domain and a not in server_names:
                server_names.append(a)
    server_name_str = " ".join(server_names)

    directives_block = f"""    {DIRECTIVES_START}
{custom_directives.strip() if custom_directives.strip() else '    # Keine benutzerdefinierten Direktiven aktiv'}
    {DIRECTIVES_END}"""

    log_dir = "/var/log/nginx"

    acme_block = """    # ACME-Challenge für Let's Encrypt Zertifikate freihalten (verhindert Proxy-Kollision)
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }"""

    # Sicherheits- & Performance-Header
    extra_headers = ""
    if hsts and ssl_enabled:
        extra_headers += '    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
    if gzip:
        extra_headers += '    gzip on;\n    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;\n'

    # Passwortschutz (.htpasswd)
    htpasswd_block = ""
    if htpasswd_enabled:
        htpasswd_block = f"""    # SYSCORE_HTPASSWD_ACTIVE
    auth_basic "Geschützter Bereich // SysCore";
    auth_basic_user_file /etc/nginx/.htpasswd_{domain};
"""

    # Wartungsmodus Block (HTTP 503)
    if maintenance:
        maintenance_html = f"""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <title>Wartungsarbeiten // {domain}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ background: #090d16; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; text-align: center; }}
        .card {{ background: #111827; border: 1px solid #374151; border-radius: 18px; padding: 40px 32px; max-width: 480px; width: 100%; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }}
        .icon {{ width: 56px; height: 56px; border-radius: 16px; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.3); display: inline-flex; align-items: center; justify-content: center; color: #fbbf24; font-size: 26px; margin-bottom: 20px; }}
        h1 {{ font-size: 20px; font-weight: 800; margin: 0 0 10px 0; color: #fff; }}
        p {{ font-size: 13px; color: #9ca3af; line-height: 1.6; margin: 0 0 24px 0; }}
        .footer {{ font-size: 11px; font-family: monospace; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🚧</div>
        <h1>Wartungsarbeiten</h1>
        <p>Die Website <strong>{domain}</strong> befindet sich derzeit in planm&auml;&szlig;igen Wartungsarbeiten.<br>Wir sind in K&uuml;rze wieder f&uuml;r Sie erreichbar.</p>
        <div class="footer">Status: HTTP 503 Service Unavailable &bull; SysCore Host</div>
    </div>
</body>
</html>"""
        escaped_html = maintenance_html.replace("'", "'\\''")
        location_content = f"""    # SYSCORE_MAINTENANCE_MODE_ACTIVE
    error_page 503 @maintenance;
    location @maintenance {{
        default_type text/html;
        return 503 '{escaped_html}';
    }}
    return 503;
"""
    elif mode == "proxy":
        location_content = f"""{htpasswd_block}    location / {{
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
        location_content = f"""{htpasswd_block}    root {target_path};
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
    server_name {server_name_str};

    access_log {log_dir}/{domain}.access.log;
    error_log {log_dir}/{domain}.error.log;

{extra_headers}{directives_block}

{acme_block}

{location_content}
}}
"""

    # Fall 2: HTTPS aktiviert (Port 80 + Port 443 SSL Server)
    extra_ssl = ""
    if os.path.exists("/etc/letsencrypt/options-ssl-nginx.conf"):
        extra_ssl += "    include /etc/letsencrypt/options-ssl-nginx.conf;\n"
    if os.path.exists("/etc/letsencrypt/ssl-dhparams.pem"):
        extra_ssl += "    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;\n"

    port_80_action = """    location / {
        return 301 https://$host$request_uri;
    }""" if force_https else location_content

    return f"""# 1. HTTP Server (Port 80)
server {{
    listen 80;
    server_name {server_name_str};

{acme_block}

{port_80_action}
}}

# 2. HTTPS Server (Port 443 SSL)
server {{
    listen 443 ssl http2;
    server_name {server_name_str};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
{extra_ssl}
    access_log {log_dir}/{domain}.access.log;
    error_log {log_dir}/{domain}.error.log;

{extra_headers}{directives_block}

{acme_block}

{location_content}
}}
"""

def parse_domain_config(domain_name, content, system_certs=None):
    """Parst eine .panel.conf Datei und extrahiert Modus, Ports, PHP, SSL Status und Plesk-Metriken"""
    ssl_active_in_conf = ("listen 443 ssl" in content) or ("ssl_certificate" in content)
    is_proxy = "proxy_pass" in content
    mode = "proxy" if is_proxy else "webspace"

    proxy_match = re.search(r"proxy_pass\s+http://127\.0\.0\.1:(\d+);", content)
    root_match = re.search(r"^\s*root\s+([^;]+);", content, re.MULTILINE)
    php_match = re.search(r"php(\d+\.\d+)-fpm\.sock", content)

    # Server Name & Aliases extrahieren
    server_name_match = re.search(r"server_name\s+([^;]+);", content)
    raw_server_names = server_name_match.group(1).split() if server_name_match else [domain_name]
    aliases = [s.strip() for s in raw_server_names if s.strip() != domain_name]

    proxy_port = proxy_match.group(1) if proxy_match else ""
    root_path = root_match.group(1).strip() if root_match else os.path.join(WEB_ROOT_BASE, domain_name, "public")
    php_version = php_match.group(1) if php_match else "8.2"

    # Status-Flags
    is_maintenance = "SYSCORE_MAINTENANCE_MODE_ACTIVE" in content
    has_htpasswd = "SYSCORE_HTPASSWD_ACTIVE" in content or "auth_basic_user_file" in content
    has_hsts = "Strict-Transport-Security" in content
    has_gzip = "gzip on;" in content
    has_ssl_redirect = "return 301 https://" in content

    # Disk Usage für diese Domain ermitteln
    domain_dir = os.path.join(WEB_ROOT_BASE, domain_name)
    disk_usage = get_directory_size_formatted(domain_dir)
    has_git = os.path.exists(os.path.join(domain_dir, ".git"))

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
    ssl_info = get_ssl_cert_info(domain_name, content, system_certs=system_certs)
    
    if ssl_info.get("active") and not ssl_active_in_conf:
        cert_on_disk = ssl_info
    else:
        cert_on_disk = find_ssl_cert_for_domain(domain_name, system_certs=system_certs)
    has_cert_on_disk = cert_on_disk is not None and cert_on_disk.get("active", False)
    missing_ssl_block = has_cert_on_disk and not ssl_active_in_conf

    # Deploy Hook auslesen falls vorhanden
    deploy_hook = None
    try:
        deploy_hook = query_db("SELECT * FROM web_deploy_hooks WHERE domain = ?", (domain_name,), one=True)
    except Exception:
        pass

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
        "aliases": aliases,
        "aliases_str": " ".join(aliases),
        "is_maintenance": is_maintenance,
        "has_htpasswd": has_htpasswd,
        "has_hsts": has_hsts,
        "has_gzip": has_gzip,
        "has_ssl_redirect": has_ssl_redirect,
        "disk_usage": disk_usage,
        "has_git": has_git,
        "deploy_hook": deploy_hook,
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

    cb_ok, cb_msg, cb_status = check_certbot_status()

    return {
        "apache_conflict": apache_conflict,
        "default_site_enabled": default_site_enabled,
        "php_versions": detect_php_versions(),
        "nginx_syntax_ok": nginx_syntax_ok,
        "nginx_syntax_msg": nginx_syntax_msg,
        "certbot_ok": cb_ok,
        "certbot_msg": cb_msg,
        "certbot_status": cb_status
    }

def check_certbot_status():
    """Prüft ob Certbot funktionsfähig ist oder ein Python pyOpenSSL/cryptography Versionskonflikt vorliegt"""
    if not shutil.which("certbot"):
        return False, "Certbot ist auf diesem System nicht installiert", "missing"

    try:
        res = subprocess.run(["certbot", "--version"], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            err = (res.stderr or res.stdout).strip()
            if "GEN_EMAIL" in err or "AttributeError" in err or "OpenSSL" in err:
                return False, f"Python pyOpenSSL/cryptography Bibliothekskonflikt: {err}", "conflict"
            return False, f"Certbot-Fehler: {err}", "broken"
        return True, res.stdout.strip(), "ok"
    except Exception as e:
        return False, str(e), "error"

def fix_certbot_conflict_core():
    """
    Behebt die bekannte Debian/pip Kollision zwischen pyOpenSSL und cryptography.
    1. Aktualisiert pyOpenSSL via pip3, damit es mit dem neueren cryptography kompatibel ist
    2. Falls nötig: Bereinigt /usr/local/lib/python3*/dist-packages und reinstalliert APT-Pakete
    """
    if os.name == "nt":
        return True, "Windows: Prüfung übersprungen"

    # Saubere APT-Paketreparatur ohne globale pip-Kollisionen (SEC-019)
    try:
        sh_cmd = """
        rm -rf /usr/local/lib/python3*/dist-packages/cryptography* 2>/dev/null
        rm -rf /usr/local/lib/python3*/dist-packages/OpenSSL* 2>/dev/null
        rm -rf /usr/local/lib/python3*/dist-packages/pyOpenSSL* 2>/dev/null
        apt-get update -y 2>/dev/null
        apt-get install --reinstall -y python3-cryptography python3-openssl certbot python3-certbot-nginx 2>/dev/null
        """
        subprocess.run(["sh", "-c", sh_cmd], capture_output=True, text=True, timeout=90)
    except Exception:
        pass
    except Exception:
        pass

    ok, msg, _ = check_certbot_status()
    if ok:
        return True, "Python-Systembibliotheken erfolgreich bereinigt. Certbot ist wieder einsatzbereit."
    return False, f"Reparatur versucht, aber Certbot meldet weiterhin: {msg}"

def diagnose_webserver_issues(system_certs=None):
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
    if system_certs is None:
        system_certs = scan_all_system_certificates()

    issues = []
    health = check_webserver_health()

    # 0. Certbot Python pyOpenSSL / cryptography Konflikt
    if health.get("certbot_status") == "conflict":
        issues.append({
            "id": "certbot_pyopenssl_conflict",
            "domain": None,
            "severity": "critical",
            "title": "Certbot blockiert: Python pyOpenSSL/cryptography Bibliothekskonflikt",
            "description": f"Certbot stürzt ab: {health.get('certbot_msg')[:150]}. Ursache ist eine Inkompatibilität zwischen neuerer globaler cryptography und Debian pyOpenSSL (AttributeError: 'lib' has no attribute 'GEN_EMAIL').",
            "fix_endpoint": "webserver.fix_certbot_conflict",
            "fix_label": "1-Klick: Certbot-Umgebung reparieren (pyOpenSSL aktualisieren)"
        })
    elif health.get("certbot_status") == "broken":
        issues.append({
            "id": "certbot_broken",
            "domain": None,
            "severity": "critical",
            "title": "Certbot meldet Systemfehler",
            "description": f"Certbot ist fehlerhaft: {health.get('certbot_msg')[:150]}.",
            "fix_endpoint": "webserver.fix_certbot_conflict",
            "fix_label": "1-Klick: Certbot reparieren"
        })

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

    # 4. ACME-Challenge Verzeichnis prüfen
    acme_dir = "/var/www/html/.well-known/acme-challenge"
    if not os.path.exists(acme_dir):
        issues.append({
            "id": "acme_webroot_missing",
            "domain": None,
            "severity": "warning",
            "title": "ACME-Challenge Verzeichnis (/var/www/html) fehlt",
            "description": "Das Verzeichnis '/var/www/html/.well-known/acme-challenge/' ist für Let's Encrypt HTTP-01 Validierungen zwingend erforderlich. Fehlt es, scheitert das Ausstellen neuer Zertifikate.",
            "fix_endpoint": "webserver.fix_acme_webroot",
            "fix_label": "ACME-Verzeichnis anlegen & berechtigen"
        })

    # 5. Domain-spezifische Probleme & SSL-Audits prüfen
    if os.path.exists(NGINX_AVAILABLE):
        for filename in sorted(os.listdir(NGINX_AVAILABLE)):
            if not filename.endswith(".panel.conf"):
                continue
            domain = filename.replace(".panel.conf", "")
            try:
                with open(os.path.join(NGINX_AVAILABLE, filename), "r", encoding="utf-8") as f:
                    content = f.read()
                d_info = parse_domain_config(domain, content, system_certs=system_certs)

                # Problem A: SSL im VHost aktiv, aber Zertifikatsdatei fehlt auf der Festplatte
                if d_info["ssl"]:
                    cert_match = re.search(r"ssl_certificate\s+([^;]+);", content)
                    if cert_match:
                        configured_cert_file = cert_match.group(1).strip()
                        if not os.path.exists(configured_cert_file):
                            issues.append({
                                "id": f"broken_cert_{domain}",
                                "domain": domain,
                                "severity": "critical",
                                "title": f"Zertifikatsdatei nicht gefunden: {domain}",
                                "description": f"Der VHost verweist auf '{configured_cert_file}', diese Datei existiert jedoch nicht mehr. NGINX kann dadurch nicht neu geladen werden.",
                                "fix_endpoint": "webserver.repair_domain_ssl",
                                "fix_param": domain,
                                "fix_label": "1-Klick: Zertifikat reparieren / neu verknüpfen"
                            })

                # Problem B: Kein SSL im VHost, aber passendes Zertifikat liegt auf dem Server
                elif not d_info["ssl"]:
                    cert_found = d_info.get("cert_on_disk") or find_ssl_cert_for_domain(domain, system_certs=system_certs)
                    if cert_found and cert_found.get("active"):
                        issues.append({
                            "id": f"unlinked_cert_{domain}",
                            "domain": domain,
                            "severity": "critical",
                            "title": f"Vorhandenes SSL-Zertifikat verfügbar: {domain}",
                            "description": f"Auf dem Server wurde das Zertifikat '{cert_found.get('folder')}' ({cert_found.get('cert_path')}) gefunden, das '{domain}' abdeckt. Die NGINX-Konfiguration nutzt bisher aber nur unverschlüsseltes HTTP.",
                            "fix_endpoint": "webserver.repair_domain_ssl",
                            "fix_param": domain,
                            "fix_label": "1-Klick: Gefundenes Zertifikat verbinden & HTTPS aktivieren"
                        })
                    else:
                        issues.append({
                            "id": f"no_ssl_{domain}",
                            "domain": domain,
                            "severity": "warning",
                            "title": f"Kein SSL-Zertifikat aktiv: {domain}",
                            "description": f"Für '{domain}' ist noch kein SSL-Zertifikat vorhanden oder eingerichtet. Ein Let's Encrypt Zertifikat kann per 1-Klick angefordert werden.",
                            "fix_endpoint": "webserver.repair_domain_ssl",
                            "fix_param": domain,
                            "fix_label": "1-Klick: Let's Encrypt Zertifikat anfordern"
                        })

                # Problem C: Reverse Proxy ohne ACME Challenge Pass-Through
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

                # Problem D: PHP-FPM Socket existiert nicht
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
    all_certs = scan_all_system_certificates()
    issues = diagnose_webserver_issues(system_certs=all_certs)

    domains = []
    if os.path.exists(NGINX_AVAILABLE):
        for filename in sorted(os.listdir(NGINX_AVAILABLE)):
            if not filename.endswith(".panel.conf"):
                continue
            domain_name = filename.replace(".panel.conf", "")
            try:
                with open(os.path.join(NGINX_AVAILABLE, filename), "r", encoding="utf-8") as f:
                    content = f.read()
                domains.append(parse_domain_config(domain_name, content, system_certs=all_certs))
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
# 6. CONTROLLER ROUTEN: 1-KLICK REPARATUR AKTIONEN & HELPER
# ==============================================================================

def repair_domain_ssl_core(domain):
    """
    Kernfunktion für SSL-Reparatur & Aktivierung im VHost:
    Findet das existierende Zertifikat für die Domain (oder fordert eines via Certbot an),
    baut den sauberen Dual-Server VHost (Port 80 Redirect + Port 443 SSL Block) und lädt NGINX neu.
    Gibt (success: bool, message: str) zurück.
    """
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        return False, f"Konfigurationsdatei für '{domain}' nicht gefunden."

    # 1. Zuerst systemweit prüfen ob bereits ein passendes Zertifikat existiert (inkl. Wildcards & SANs)
    cert_info = find_ssl_cert_for_domain(domain)

    # 2. Falls noch kein Zertifikat existiert: Certbot mit Vorbereitungen & Fallbacks aufrufen
    if not cert_info:
        if not shutil.which("certbot"):
            return False, "Certbot ist auf diesem Server nicht installiert."

        # A: ACME Verzeichnis und Rechte sicherstellen
        acme_dir = "/var/www/html/.well-known/acme-challenge"
        os.makedirs(acme_dir, exist_ok=True)
        try:
            os.chmod(acme_dir, 0o755)
            if shutil.which("chown"):
                subprocess.run(["chown", "-R", "www-data:www-data", "/var/www/html"], check=False)
        except Exception:
            pass

        # B: Apache Konflikt prüfen & temporär lösen falls aktiv
        if os.path.exists(APACHE_PORTS_CONF):
            try:
                with open(APACHE_PORTS_CONF, "r", encoding="utf-8") as f:
                    ap_content = f.read()
                if re.search(r"^\s*Listen\s+80\b", ap_content, re.MULTILINE):
                    if shutil.which("systemctl"):
                        subprocess.run(["systemctl", "stop", "apache2"], check=False)
            except Exception:
                pass

        # C: NGINX Syntax vorab testen und Port-80 VHost aktivieren
        reload_nginx()

        email_arg = ["--email", CERTBOT_EMAIL] if CERTBOT_EMAIL and "@" in CERTBOT_EMAIL else ["--register-unsafely-without-email"]
        last_error = ""

        # Versuch 1: Webroot /var/www/html
        cmd1 = ["certbot", "certonly", "--webroot", "-w", "/var/www/html", "-d", domain, "--non-interactive", "--agree-tos"] + email_arg
        res1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=90)
        if res1.returncode != 0:
            last_error = (res1.stderr or res1.stdout).strip()

        clear_ssl_cache()
        cert_info = find_ssl_cert_for_domain(domain)

        # Versuch 2: Falls VHost ein eigenes Webroot hat (z.B. /var/www/phpmyadmin)
        if not cert_info:
            with open(avail_path, "r", encoding="utf-8") as f:
                c_content = f.read()
            parsed_temp = parse_domain_config(domain, c_content)
            doc_root = parsed_temp.get("root_path")
            if doc_root and os.path.exists(doc_root):
                os.makedirs(os.path.join(doc_root, ".well-known", "acme-challenge"), exist_ok=True)
                cmd2 = ["certbot", "certonly", "--webroot", "-w", doc_root, "-d", domain, "--non-interactive", "--agree-tos"] + email_arg
                res2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=90)
                if res2.returncode != 0 and not last_error:
                    last_error = (res2.stderr or res2.stdout).strip()
                clear_ssl_cache()
                cert_info = find_ssl_cert_for_domain(domain)

        # Versuch 3: NGINX Plugin Fallback
        if not cert_info:
            cmd3 = ["certbot", "certonly", "--nginx", "-d", domain, "--non-interactive", "--agree-tos"] + email_arg
            res3 = subprocess.run(cmd3, capture_output=True, text=True, timeout=90)
            if res3.returncode != 0 and not last_error:
                last_error = (res3.stderr or res3.stdout).strip()
            clear_ssl_cache()
            cert_info = find_ssl_cert_for_domain(domain)

        # Versuch 4: Automatische Selbstheilung bei pyOpenSSL / GEN_EMAIL Kollision!
        if not cert_info and ("GEN_EMAIL" in last_error or "AttributeError" in last_error or "OpenSSL" in last_error):
            fix_certbot_conflict_core()
            # Erneut versuchen mit Webroot
            res_heal = subprocess.run(cmd1, capture_output=True, text=True, timeout=90)
            if res_heal.returncode != 0:
                last_error = (res_heal.stderr or res_heal.stdout).strip()
            clear_ssl_cache()
            cert_info = find_ssl_cert_for_domain(domain)

        if not cert_info:
            # Letzte aussagekräftige Fehlerzeilen extrahieren
            err_lines = [l.strip() for l in last_error.splitlines() if l.strip() and not l.startswith("Saving debug log")]
            summary = " | ".join(err_lines[-3:]) if err_lines else "Unbekannter Certbot-Fehler"
            return False, f"Zertifikats-Ausstellung fehlgeschlagen: {summary}"

    # 3. Bestehende Konfiguration auslesen um Modus und Parameter zu behalten
    with open(avail_path, "r", encoding="utf-8") as f:
        old_content = f.read()

    parsed = parse_domain_config(domain, old_content)

    # 4. Neuen Dual-Server VHost generieren
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
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(old_content)
        reload_nginx()
        return False, f"NGINX Syntaxfehler nach SSL-Einbindung: {msg}"

    if os.path.exists(backup_path):
        os.remove(backup_path)

    return True, f"SSL-Zertifikat ({cert_info.get('folder', 'Aktiv')}) erfolgreich mit '{domain}' verknüpft und Port 443 aktiviert."

def issue_and_apply_ssl(domain):
    """Programmatisches Ausstellen & Einbinden eines SSL-Zertifikats für eine Domain/Subdomain"""
    return repair_domain_ssl_core(domain)

@webserver_bp.route("/fix/acme-webroot", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def fix_acme_webroot():
    """Richtet das Verzeichnis /var/www/html/.well-known/acme-challenge mit korrekten Rechten ein"""
    try:
        path = "/var/www/html/.well-known/acme-challenge"
        os.makedirs(path, exist_ok=True)
        try:
            os.chmod(path, 0o755)
            if shutil.which("chown"):
                subprocess.run(["chown", "-R", "www-data:www-data", "/var/www/html"], check=False)
        except Exception:
            pass
        log_audit(session.get("username"), "ACME_WEBROOT_FIX", "ACME Challenge Verzeichnis repariert", request.remote_addr, "success")
        flash("ACME Challenge Verzeichnis (/var/www/html/.well-known/acme-challenge) erfolgreich eingerichtet und berechtigt!", "success")
    except Exception as e:
        flash(f"Fehler beim Einrichten des ACME-Verzeichnisses: {e}", "error")
    return redirect(url_for("webserver.index", tab="diagnostics"))

@webserver_bp.route("/fix/certbot", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def fix_certbot_conflict():
    """1-Klick Reparatur für den Certbot pyOpenSSL/cryptography Versionskonflikt"""
    ok, msg = fix_certbot_conflict_core()
    if ok:
        log_audit(session.get("username"), "CERTBOT_FIX_SUCCESS", msg, request.remote_addr, "success")
        flash(f"Erfolg: {msg}", "success")
    else:
        log_audit(session.get("username"), "CERTBOT_FIX_FAIL", msg, request.remote_addr, "error")
        flash(f"Reparatur fehlgeschlagen: {msg}", "error")
    return redirect(url_for("webserver.index", tab="diagnostics"))

@webserver_bp.route("/cert/assign", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def assign_custom_or_existing_cert():
    """Weist einer Domain ein bestimmtes, auf dem Server existierendes oder manuell eingegebenes Zertifikat zu"""
    domain = request.form.get("domain", "").strip().lower()
    cert_source = request.form.get("cert_source", "existing")

    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash(f"VHost für '{domain}' nicht gefunden.", "error")
        return redirect(url_for("webserver.index", tab="ssl"))

    cert_path = None
    key_path = None

    if cert_source == "existing":
        selected_cert_path = request.form.get("selected_cert_path", "").strip()
        selected_key_path = request.form.get("selected_key_path", "").strip()
        if not os.path.exists(selected_cert_path) or not os.path.exists(selected_key_path):
            flash("Die ausgewählten Zertifikatsdateien existieren nicht auf dem Server.", "error")
            return redirect(url_for("webserver.index", tab="ssl"))
        cert_path = selected_cert_path
        key_path = selected_key_path
    elif cert_source == "custom":
        cert_data = request.form.get("cert_pem", "").strip()
        key_data = request.form.get("key_pem", "").strip()
        if not cert_data or not key_data or "BEGIN CERTIFICATE" not in cert_data:
            flash("Bitte ein gültiges PEM-Zertifikat und den zugehörigen Private Key angeben.", "error")
            return redirect(url_for("webserver.index", tab="ssl"))

        target_dir_cert = "/etc/ssl/certs"
        target_dir_key = "/etc/ssl/private"
        os.makedirs(target_dir_cert, exist_ok=True)
        os.makedirs(target_dir_key, exist_ok=True)

        cert_path = os.path.join(target_dir_cert, f"{domain}.crt")
        key_path = os.path.join(target_dir_key, f"{domain}.key")

        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(cert_data)
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(key_data)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass

    # VHost aktualisieren
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
        cert_path=cert_path,
        key_path=key_path
    )

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_vhost)

    ok, msg = reload_nginx()
    if not ok:
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(old_content)
        reload_nginx()
        flash(f"Zuweisung fehlgeschlagen (NGINX Syntaxfehler): {msg}", "error")
    else:
        clear_ssl_cache()
        log_audit(session.get("username"), "SSL_ASSIGN_SUCCESS", f"Zertifikat ({cert_path}) erfolgreich für '{domain}' verknüpft", request.remote_addr, "success")
        flash(f"Zertifikat erfolgreich für '{domain}' aktiviert und NGINX neu geladen!", "success")

    return redirect(url_for("webserver.index", tab="domains"))

@webserver_bp.route("/repair/ssl/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def repair_domain_ssl(domain):
    """
    1-KLICK REPARATUR FÜR SUBDOMAIN-SSL:
    Findet das existierende Zertifikat für die Domain, baut den sauberen Dual-Server VHost
    (Port 80 Redirect + Port 443 SSL Block) und lädt NGINX neu.
    """
    ok, msg = repair_domain_ssl_core(domain)
    if not ok:
        flash(f"Reparatur fehlgeschlagen: {msg}", "error")
        return redirect(url_for("webserver.index", tab="diagnostics"))

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
        # 0: Certbot Konflikt
        if issue["id"] in ("certbot_pyopenssl_conflict", "certbot_broken"):
            try:
                ok, _ = fix_certbot_conflict_core()
                if ok:
                    fixed_count += 1
            except Exception:
                pass

        # A: Apache Port Konflikt
        elif issue["id"] == "apache_port_conflict":
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

        # D: ACME Webroot fehlt
        elif issue["id"] == "acme_webroot_missing":
            try:
                fix_acme_webroot()
                fixed_count += 1
            except Exception:
                pass

        # E: SSL VHost fehlt oder Zertifikat verfügbar
        elif issue["id"].startswith(("missing_ssl_", "unlinked_cert_", "broken_cert_")):
            domain = issue["domain"]
            try:
                ok, _ = repair_domain_ssl_core(domain)
                if ok:
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

    clear_ssl_cache()
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
    ok, msg = repair_domain_ssl_core(domain)
    if ok:
        log_audit(session.get("username"), "SSL_ENABLE_SUCCESS", f"SSL für '{domain}' erfolgreich aktiviert", request.remote_addr, "success")
        flash(f"SSL-Zertifikat für '{domain}' erfolgreich aktiviert!", "success")
    else:
        log_audit(session.get("username"), "SSL_ENABLE_FAIL", f"SSL für '{domain}' fehlgeschlagen: {msg}", request.remote_addr, "warning")
        flash(f"Let's Encrypt Zertifikats-Ausstellung fehlgeschlagen: {msg}", "error")

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
        clear_ssl_cache()
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

ALLOWED_DEPLOY_BINARIES = {
    "composer", "npm", "yarn", "pnpm", "php", "python", "python3", "pip", "artisan", "wp"
}

def validate_post_deploy_cmd(cmd_str):
    """Prüft Post-Deploy-Befehle gegen Whitelist und verbietet Shell-Pipes/Chaining (SEC-015)"""
    if not cmd_str:
        return True, ""
    forbidden_chars = [";", "&&", "||", "|", "`", "$", "\n", "\r", "<", ">"]
    for ch in forbidden_chars:
        if ch in cmd_str:
            return False, f"Zeichen '{ch}' im Post-Deploy-Befehl aus Sicherheitsgründen nicht erlaubt."
    try:
        parts = shlex.split(cmd_str)
    except Exception as e:
        return False, f"Befehlssyntax ungültig: {e}"
    if not parts:
        return True, ""
    binary = os.path.basename(parts[0]).lower()
    if binary not in ALLOWED_DEPLOY_BINARIES:
        return False, f"Befehl '{binary}' nicht in der Whitelist erlaubt. Zulässige Build-Tools: {', '.join(sorted(ALLOWED_DEPLOY_BINARIES))}"
    return True, ""

@webserver_bp.route("/domain/webhook/save/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def save_domain_webhook(domain):
    branch = request.form.get("branch", "main").strip() or "main"
    post_cmd = request.form.get("post_deploy_cmd", "").strip()

    is_valid_cmd, cmd_err = validate_post_deploy_cmd(post_cmd)
    if not is_valid_cmd:
        flash(f"Webhook-Konfiguration abgelehnt: {cmd_err}", "error")
        return redirect(url_for("webserver.index"))

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

@webserver_bp.route("/webhook/deploy/<token>", methods=["POST"])
def trigger_deploy_webhook(token):
    # Nur POST-Anfragen sind für Deploy-Hooks zulässig (SEC-015)
    hook = query_db("SELECT * FROM web_deploy_hooks WHERE token = ?", (token,), one=True)
    if not hook:
        return jsonify({"error": "Ungültiges Webhook-Token"}), 404

    # 1. Signaturprüfung für GitHub/GitLab (SEC-015)
    gh_signature = request.headers.get("X-Hub-Signature-256")
    if gh_signature:
        expected_sig = "sha256=" + hmac.new(token.encode("utf-8"), request.get_data(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, gh_signature):
            log_audit("WEBHOOK", "DEPLOY_REJECTED", f"Ungültige GitHub HMAC-Signatur für {hook['domain']}", request.remote_addr, "warning")
            return jsonify({"error": "Ungültige HMAC-Signatur"}), 403

    gl_token = request.headers.get("X-Gitlab-Token")
    if gl_token and not hmac.compare_digest(gl_token, token):
        log_audit("WEBHOOK", "DEPLOY_REJECTED", f"Ungültiger GitLab Token für {hook['domain']}", request.remote_addr, "warning")
        return jsonify({"error": "Ungültiger GitLab Token"}), 403

    # 2. Replay- & DoS-Schutz: Rate-Limiting (mindestens 15 Sekunden Abstand, SEC-015)
    if hook["last_deployed_at"]:
        try:
            last_dt = datetime.strptime(str(hook["last_deployed_at"])[:19], "%Y-%m-%d %H:%M:%S")
            delta = (datetime.utcnow() - last_dt).total_seconds()
            if delta < 15:
                return jsonify({
                    "error": "Rate-Limit aktiv: Bitte warte mindestens 15 Sekunden zwischen Auto-Deploys.",
                    "retry_after_seconds": int(15 - delta)
                }), 429
        except Exception:
            pass

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

    # 3. Sichere Post-Deploy-Ausführung ohne shell=True (SEC-015)
    if post_cmd:
        is_safe, err_msg = validate_post_deploy_cmd(post_cmd)
        if not is_safe:
            deploy_logs.append(f"Post-Deploy Command Sicherheitsfehler: {err_msg}")
        else:
            try:
                cmd_parts = shlex.split(post_cmd)
                cmd_res = subprocess.run(
                    cmd_parts, shell=False, cwd=webroot, capture_output=True, text=True, timeout=120
                )
                deploy_logs.append(f"Post-Deploy Command: {post_cmd}\n" + cmd_res.stdout + "\n" + cmd_res.stderr)
            except Exception as e:
                deploy_logs.append(f"Post-Deploy Command Fehler: {e}")

    if shutil.which("chown"):
        subprocess.run(["chown", "-R", "www-data:www-data", webroot], check=False)

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    execute_db("UPDATE web_deploy_hooks SET last_status = 'success', last_deployed_at = ? WHERE id = ?", (now_str, hook["id"]))
    log_audit("WEBHOOK", "GIT_AUTO_DEPLOY", f"Auto-Deploy für {domain} via Webhook ausgeführt", request.remote_addr, "success")

    return jsonify({
        "status": "success",
        "domain": domain,
        "branch": branch,
        "deployed_at": now_str,
        "log": "\n".join(deploy_logs)
    })

def make_htpasswd_line(username, password):
    """Erzeugt eine NGINX-kompatible {SHA} htpasswd-Zeile ohne externe Abhängigkeiten"""
    sha1_hash = base64.b64encode(hashlib.sha1(password.encode("utf-8")).digest()).decode("ascii")
    return f"{username}:{{SHA}}{sha1_hash}\n"

@webserver_bp.route("/domain/edit/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def edit_domain(domain):
    """Umfangreiche Anpassung und optionales Umbenennen einer Domain (Plesk-Standard)"""
    new_domain = request.form.get("new_domain", domain).strip().lower()
    mode = request.form.get("mode", "webspace")
    proxy_port = request.form.get("proxy_port", "").strip()
    php_version = request.form.get("php_version", "8.2").strip()
    custom_root = request.form.get("root_path", "").strip()
    aliases_raw = request.form.get("aliases", "").strip()
    force_https = request.form.get("force_https") == "1"
    hsts = request.form.get("hsts") == "1"
    gzip = request.form.get("gzip") == "1"

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", new_domain):
        flash("Ungültiges Domain-Format für die Ziel-Domain.", "error")
        return redirect(url_for("webserver.index"))

    old_conf_name = f"{domain}.panel.conf"
    old_avail_path = os.path.join(NGINX_AVAILABLE, old_conf_name)
    if not os.path.exists(old_avail_path):
        flash(f"Domain '{domain}' nicht gefunden.", "error")
        return redirect(url_for("webserver.index"))

    with open(old_avail_path, "r", encoding="utf-8") as f:
        old_content = f.read()
    old_parsed = parse_domain_config(domain, old_content)

    # 1. Fall Umbenennen: Prüfen ob Ziel-Domain bereits existiert
    if new_domain != domain:
        new_avail_path = os.path.join(NGINX_AVAILABLE, f"{new_domain}.panel.conf")
        if os.path.exists(new_avail_path):
            flash(f"Die Ziel-Domain '{new_domain}' existiert bereits.", "error")
            return redirect(url_for("webserver.index"))

    # 2. Zielpfad ermitteln
    if mode == "proxy":
        if not proxy_port.isdigit() or not (1 <= int(proxy_port) <= 65535):
            flash("Bitte einen gültigen Ziel-Port (1-65535) angeben.", "error")
            return redirect(url_for("webserver.index"))
        target_path = ""
    else:
        target_path = validate_web_path(custom_root, new_domain)
        if not target_path:
            flash(f"Ungültiger DocumentRoot. Muss innerhalb von {WEB_ROOT_BASE}/ liegen.", "error")
            return redirect(url_for("webserver.index"))
        try:
            os.makedirs(target_path, exist_ok=True)
            if shutil.which("chown"):
                run_privileged(["chown", "-R", "www-data:www-data", target_path])
        except Exception:
            pass

    # Aliase parsen
    aliases_list = [a.strip().lower() for a in re.split(r"[\s,;]+", aliases_raw) if a.strip()]

    # SSL Info vom bestehenden VHost übernehmen
    cert_path = old_parsed["ssl_info"].get("cert_path")
    key_path = old_parsed["ssl_info"].get("key_path")
    ssl_enabled = old_parsed["ssl"]

    # Neuen VHost generieren
    new_vhost = build_nginx_config(
        domain=new_domain,
        mode=mode,
        target_path=target_path,
        proxy_port=proxy_port,
        php_version=php_version,
        custom_directives=old_parsed["custom_directives"],
        ssl_enabled=ssl_enabled,
        cert_path=cert_path,
        key_path=key_path,
        aliases=aliases_list,
        maintenance=old_parsed["is_maintenance"],
        htpasswd_enabled=old_parsed["has_htpasswd"],
        hsts=hsts,
        gzip=gzip,
        force_https=force_https
    )

    # Bei Umbenennung: Neue Konfigurationspfade vorbereiten
    target_avail_path = os.path.join(NGINX_AVAILABLE, f"{new_domain}.panel.conf")
    target_enabled_path = os.path.join(NGINX_ENABLED, f"{new_domain}.panel.conf")

    with open(target_avail_path, "w", encoding="utf-8") as f:
        f.write(new_vhost)

    try:
        if os.path.exists(target_enabled_path):
            os.remove(target_enabled_path)
        os.symlink(target_avail_path, target_enabled_path)
    except OSError:
        pass

    ok, msg = reload_nginx()
    if not ok:
        # Rollback
        if os.path.exists(target_enabled_path) and new_domain != domain:
            os.remove(target_enabled_path)
        if os.path.exists(target_avail_path) and new_domain != domain:
            os.remove(target_avail_path)
        if new_domain == domain:
            with open(old_avail_path, "w", encoding="utf-8") as f:
                f.write(old_content)
            reload_nginx()
        flash(f"Änderung abgelehnt (NGINX Syntaxfehler): {msg}", "error")
        return redirect(url_for("webserver.index"))

    # Falls erfolgreich umbenannt: Alte VHost-Dateien aufräumen und DB-Einträge migrieren
    if new_domain != domain:
        old_enabled_path = os.path.join(NGINX_ENABLED, old_conf_name)
        if os.path.exists(old_enabled_path):
            try: os.remove(old_enabled_path)
            except Exception: pass
        if os.path.exists(old_avail_path):
            try: os.remove(old_avail_path)
            except Exception: pass

        # Webhook migrieren
        execute_db("UPDATE web_deploy_hooks SET domain = ? WHERE domain = ?", (new_domain, domain))
        # .htpasswd umbenennen falls vorhanden
        old_ht = f"/etc/nginx/.htpasswd_{domain}"
        new_ht = f"/etc/nginx/.htpasswd_{new_domain}"
        if os.path.exists(old_ht):
            try: os.rename(old_ht, new_ht)
            except Exception: pass

        log_audit(session.get("username"), "DOMAIN_RENAME", f"Domain '{domain}' erfolgreich umbenannt in '{new_domain}'", request.remote_addr, "success")
        flash(f"Domain '{domain}' wurde erfolgreich in '{new_domain}' umbenannt und alle Einstellungen übernommen!", "success")
    else:
        log_audit(session.get("username"), "DOMAIN_UPDATE", f"Einstellungen für '{domain}' aktualisiert", request.remote_addr, "success")
        flash(f"Einstellungen für '{domain}' erfolgreich gespeichert und NGINX neu geladen.", "success")

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/maintenance/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def toggle_maintenance(domain):
    """1-Klick Wartungsmodus für eine Domain ein- oder ausschalten (Plesk-Feature)"""
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash("VHost nicht gefunden.", "error")
        return redirect(url_for("webserver.index"))

    with open(avail_path, "r", encoding="utf-8") as f:
        content = f.read()
    parsed = parse_domain_config(domain, content)

    new_maint_state = not parsed["is_maintenance"]

    new_vhost = build_nginx_config(
        domain=domain,
        mode=parsed["mode"],
        target_path=parsed["root_path"],
        proxy_port=parsed["proxy_port"],
        php_version=parsed["php_version"],
        custom_directives=parsed["custom_directives"],
        ssl_enabled=parsed["ssl"],
        cert_path=parsed["ssl_info"].get("cert_path"),
        key_path=parsed["ssl_info"].get("key_path"),
        aliases=parsed["aliases"],
        maintenance=new_maint_state,
        htpasswd_enabled=parsed["has_htpasswd"],
        hsts=parsed["has_hsts"],
        gzip=parsed["has_gzip"],
        force_https=parsed["has_ssl_redirect"]
    )

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_vhost)

    ok, msg = reload_nginx()
    if not ok:
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(content)
        reload_nginx()
        flash(f"Wartungsmodus konnte nicht umgeschaltet werden: {msg}", "error")
    else:
        status_txt = "aktiviert" if new_maint_state else "deaktiviert"
        log_audit(session.get("username"), "MAINTENANCE_TOGGLE", f"Wartungsmodus für '{domain}' {status_txt}", request.remote_addr, "warning" if new_maint_state else "success")
        flash(f"Wartungsmodus für '{domain}' wurde erfolgreich {status_txt}!", "success")

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/htpasswd/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def toggle_htpasswd(domain):
    """1-Klick Verzeichnisschutz (.htpasswd) aktivieren oder deaktivieren"""
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash("VHost nicht gefunden.", "error")
        return redirect(url_for("webserver.index"))

    enabled = request.form.get("enabled") == "1"
    username = request.form.get("htpasswd_user", "").strip()
    password = request.form.get("htpasswd_pass", "").strip()

    htpasswd_file = f"/etc/nginx/.htpasswd_{domain}"

    if enabled:
        if not username or not password:
            flash("Benutzername und Passwort für den Verzeichnisschutz dürfen nicht leer sein.", "error")
            return redirect(url_for("webserver.index"))
        try:
            line = make_htpasswd_line(username, password)
            with open(htpasswd_file, "w", encoding="utf-8") as f:
                f.write(line)
            try:
                os.chmod(htpasswd_file, 0o640)
                if shutil.which("chown"):
                    run_privileged(["chown", "root:www-data", htpasswd_file])
            except Exception:
                pass
        except Exception as e:
            flash(f"Fehler beim Erstellen der .htpasswd: {e}", "error")
            return redirect(url_for("webserver.index"))

    with open(avail_path, "r", encoding="utf-8") as f:
        content = f.read()
    parsed = parse_domain_config(domain, content)

    new_vhost = build_nginx_config(
        domain=domain,
        mode=parsed["mode"],
        target_path=parsed["root_path"],
        proxy_port=parsed["proxy_port"],
        php_version=parsed["php_version"],
        custom_directives=parsed["custom_directives"],
        ssl_enabled=parsed["ssl"],
        cert_path=parsed["ssl_info"].get("cert_path"),
        key_path=parsed["ssl_info"].get("key_path"),
        aliases=parsed["aliases"],
        maintenance=parsed["is_maintenance"],
        htpasswd_enabled=enabled,
        hsts=parsed["has_hsts"],
        gzip=parsed["has_gzip"],
        force_https=parsed["has_ssl_redirect"]
    )

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_vhost)

    ok, msg = reload_nginx()
    if not ok:
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(content)
        reload_nginx()
        flash(f"Verzeichnisschutz konnte nicht angewendet werden: {msg}", "error")
    else:
        status_txt = f"aktiviert (Benutzer: '{username}')" if enabled else "deaktiviert"
        log_audit(session.get("username"), "HTPASSWD_TOGGLE", f"Passwortschutz für '{domain}' {status_txt}", request.remote_addr, "success")
        flash(f"Passwortschutz für '{domain}' wurde erfolgreich {status_txt}!", "success")

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/php-version/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def switch_php_version_direct(domain):
    """1-Klick Schnellumschalter für PHP-Version (8.0 - 8.4) direkt aus der Kachel"""
    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    if not os.path.exists(avail_path):
        flash("VHost nicht gefunden.", "error")
        return redirect(url_for("webserver.index"))

    target_php = request.form.get("php_version", "").strip()
    if target_php not in ["8.0", "8.1", "8.2", "8.3", "8.4"]:
        flash("Ungültige PHP-Version.", "error")
        return redirect(url_for("webserver.index"))

    with open(avail_path, "r", encoding="utf-8") as f:
        content = f.read()
    parsed = parse_domain_config(domain, content)

    new_vhost = build_nginx_config(
        domain=domain,
        mode=parsed["mode"],
        target_path=parsed["root_path"],
        proxy_port=parsed["proxy_port"],
        php_version=target_php,
        custom_directives=parsed["custom_directives"],
        ssl_enabled=parsed["ssl"],
        cert_path=parsed["ssl_info"].get("cert_path"),
        key_path=parsed["ssl_info"].get("key_path"),
        aliases=parsed["aliases"],
        maintenance=parsed["is_maintenance"],
        htpasswd_enabled=parsed["has_htpasswd"],
        hsts=parsed["has_hsts"],
        gzip=parsed["has_gzip"],
        force_https=parsed["has_ssl_redirect"]
    )

    with open(avail_path, "w", encoding="utf-8") as f:
        f.write(new_vhost)

    ok, msg = reload_nginx()
    if not ok:
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(content)
        reload_nginx()
        flash(f"PHP-Umschaltung fehlgeschlagen: {msg}", "error")
    else:
        log_audit(session.get("username"), "PHP_SWITCH_DIRECT", f"Domain '{domain}' auf PHP {target_php} umgestellt", request.remote_addr, "success")
        flash(f"Domain '{domain}' läuft ab sofort mit PHP {target_php}!", "success")

    return redirect(url_for("webserver.index"))

@webserver_bp.route("/domain/clone/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def clone_domain(domain):
    """Plesk-Style Website Klonen: Kopiert Dateien und legt neuen VHost an"""
    target_domain = request.form.get("target_domain", "").strip().lower()

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", target_domain):
        flash("Bitte einen gültigen Zieldomain-Namen angeben.", "error")
        return redirect(url_for("webserver.index"))

    avail_path = os.path.join(NGINX_AVAILABLE, f"{domain}.panel.conf")
    new_avail_path = os.path.join(NGINX_AVAILABLE, f"{target_domain}.panel.conf")
    new_enabled_path = os.path.join(NGINX_ENABLED, f"{target_domain}.panel.conf")

    if not os.path.exists(avail_path):
        flash("Quelldomain nicht gefunden.", "error")
        return redirect(url_for("webserver.index"))

    if os.path.exists(new_avail_path):
        flash(f"Zieldomain '{target_domain}' existiert bereits.", "error")
        return redirect(url_for("webserver.index"))

    with open(avail_path, "r", encoding="utf-8") as f:
        content = f.read()
    parsed = parse_domain_config(domain, content)

    # Webroot kopieren
    src_root = os.path.join(WEB_ROOT_BASE, domain)
    dst_root = os.path.join(WEB_ROOT_BASE, target_domain)

    if os.path.exists(src_root):
        try:
            shutil.copytree(src_root, dst_root, ignore=shutil.ignore_patterns(".git", "*.bak", "tmp", "logs"))
            if shutil.which("chown"):
                run_privileged(["chown", "-R", "www-data:www-data", dst_root])
        except Exception as e:
            flash(f"Fehler beim Kopieren der Webspace-Dateien: {e}", "error")
            return redirect(url_for("webserver.index"))

    # Neuen VHost erstellen
    new_target_path = parsed["root_path"].replace(f"/{domain}/", f"/{target_domain}/")
    new_vhost = build_nginx_config(
        domain=target_domain,
        mode=parsed["mode"],
        target_path=new_target_path,
        proxy_port=parsed["proxy_port"],
        php_version=parsed["php_version"],
        custom_directives=parsed["custom_directives"],
        ssl_enabled=False,
        aliases=None,
        maintenance=False,
        htpasswd_enabled=False,
        hsts=False,
        gzip=parsed["has_gzip"]
    )

    with open(new_avail_path, "w", encoding="utf-8") as f:
        f.write(new_vhost)

    try:
        os.symlink(new_avail_path, new_enabled_path)
    except OSError:
        pass

    ok, msg = reload_nginx()
    if not ok:
        if os.path.exists(new_enabled_path): os.remove(new_enabled_path)
        if os.path.exists(new_avail_path): os.remove(new_avail_path)
        flash(f"Klonen abgebrochen (NGINX Syntaxfehler): {msg}", "error")
    else:
        log_audit(session.get("username"), "DOMAIN_CLONE", f"Website '{domain}' nach '{target_domain}' geklont", request.remote_addr, "success")
        flash(f"Website '{domain}' wurde erfolgreich nach '{target_domain}' dupliziert!", "success")

    return redirect(url_for("webserver.index"))
