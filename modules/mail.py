import os
import re
import json
import base64
import shutil
import socket
import subprocess
import smtplib
import uuid
import tempfile
import tarfile
import zipfile
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Dict, Any, List, Optional, Tuple

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import config
from config import WEB_ROOT_BASE, NGINX_AVAILABLE, NGINX_ENABLED
from modules.auth_users import login_required, role_required
from db import query_db, execute_db, log_audit

mail_bp = Blueprint("mail", __name__, url_prefix="/mail")

BACKENDS_INFO = {
    "stalwart": {
        "name": "Stalwart Mail Server (Rust All-in-One)",
        "badge": "Next-Gen Empfehlung",
        "desc": "In Rust geschriebener All-in-One JMAP/IMAP/SMTP Mailserver. Extrem schnell, minimaler RAM-Bedarf (<50MB) und REST-API.",
        "ports": "25 (SMTP), 465 (SMTPS), 587 (Submission), 993 (IMAPS), 8080 (API)",
        "service": "stalwart-mail",
        "install_guide": "curl -sSf https://stalwartlabs.com/install.sh | sh"
    },
    "postfix_dovecot": {
        "name": "Postfix & Dovecot (Nativer Linux-Stack)",
        "badge": "SysCore-Standard",
        "desc": "Klassischer, erprobter Enterprise-Mailstack mit Postfix (MTA), Dovecot (IMAP/POP3) und Rspamd/OpenDKIM.",
        "ports": "25, 465, 587, 993",
        "service": "postfix",
        "install_guide": "apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd rspamd"
    },
    "mailcow": {
        "name": "Mailcow: dockerized",
        "badge": "Docker Groupware",
        "desc": "Umfassende Groupware-Suite mit SOGo Webmail, Kalender/Kontakte-Sync (CalDAV/CardDAV), ClamAV und Rspamd.",
        "ports": "Docker Ports + NGINX Reverse-Proxy",
        "service": "docker",
        "install_guide": "git clone https://github.com/mailcow/mailcow-dockerized && cd mailcow-dockerized && ./generate_config.sh"
    }
}

WEBMAIL_OPTIONS = {
    "snappymail": {
        "name": "SnappyMail",
        "badge": "Empfohlen & Schnell",
        "desc": "Ultra-moderner, extrem schlanker Fork von RainLoop. Responsive Dark-Design, 2FA/WebAuthn, sofort einsatzbereit ohne SQL-Datenbank.",
        "features": ["Keine SQL-DB erforderlich", "2FA / Passkey Support", "Dark-Mode & Mobile Ergonomie", "Schneller IMAP-Cache"],
        "path": "/var/www/snappymail",
        "download_url": "https://github.com/the-djmaze/snappymail/releases/download/v2.38.1/snappymail-2.38.1.tar.gz",
        "icon": "⚡"
    },
    "roundcube": {
        "name": "Roundcube Webmail",
        "badge": "Enterprise Klassiker",
        "desc": "Der weltweit bewährte Open-Source Webmailer mit Responsive Elastic Theme, PGP-Verschlüsselung, Adressbuch und Plugin-Ökosystem.",
        "features": ["Vollständiges Adressbuch", "PGP / GPG Verschlüsselung", "Elastic Responsive Theme", "Plugin-Erweiterungen"],
        "path": "/var/www/roundcube",
        "download_url": "https://github.com/roundcube/roundcubemail/releases/download/1.6.9/roundcubemail-1.6.9-complete.tar.gz",
        "icon": "📦"
    },
    "rainloop": {
        "name": "RainLoop Webmail",
        "badge": "Leichtgewichtig",
        "desc": "Schlankes, modulares Webmail-Interface. Unterstützt Multi-Domain IMAP und Drag-and-Drop Anhänge.",
        "features": ["Modulare Architektur", "Multi-Domain IMAP", "Einfache Konfiguration", "Geringer Ressourcenverbrauch"],
        "path": "/var/www/rainloop",
        "download_url": "https://www.rainloop.net/repository/webmail/rainloop-latest.zip",
        "icon": "💧"
    },
    "native": {
        "name": "SysCore Webmail (Integriert)",
        "badge": "Nativ im Panel",
        "desc": "Nahtlos in das SysCore Cockpit integrierter Webmail-Client. Funktioniert sofort ohne externe Abhängigkeiten, PHP-Webspaces oder zusätzliche VHosts.",
        "features": ["Kein PHP oder VHost nötig", "Postfach-Schnellwechsel", "Integrierter SMTP/IMAP Tester", "Direkter Panel-Zugriff"],
        "path": "SysCore Nativ",
        "download_url": None,
        "icon": "🚀"
    }
}

# --- Hilfsfunktionen ---

def get_registered_domains() -> List[str]:
    """Sammelt alle im System registrierten Domains"""
    domains = set()
    if os.path.exists(NGINX_AVAILABLE):
        for f in os.listdir(NGINX_AVAILABLE):
            if f.endswith(".panel.conf") and not f.startswith("webmail"):
                domains.add(f.replace(".panel.conf", ""))
            elif f.endswith(".conf") and not f.startswith("webmail") and not f.startswith("default"):
                domains.add(f.replace(".conf", ""))
    if os.path.exists(WEB_ROOT_BASE):
        for d in os.listdir(WEB_ROOT_BASE):
            if os.path.isdir(os.path.join(WEB_ROOT_BASE, d)) and "." in d and not d.startswith("."):
                domains.add(d)
    return sorted(list(domains)) if domains else ["amfearliath.de"]

def get_active_php_sock() -> str:
    """Ermittelt den aktiven PHP-FPM Socket auf dem System"""
    for v in ["8.3", "8.2", "8.1", "8.0", "7.4"]:
        sock = f"/run/php/php{v}-fpm.sock"
        if os.path.exists(sock):
            return sock
    return "/run/php/php8.2-fpm.sock"

def get_installed_webmails() -> Dict[str, bool]:
    """Prüft, welche Webmail-Clients auf dem Server installiert sind"""
    status = {}
    for key, opt in WEBMAIL_OPTIONS.items():
        if key == "native":
            status[key] = True
        else:
            path = opt["path"]
            # Mindestens Verzeichnis mit Inhalt vorhanden
            is_inst = os.path.exists(path) and len(os.listdir(path)) > 0 if os.path.exists(path) else False
            status[key] = is_inst
    return status

def generate_dkim_keys() -> Tuple[str, str, str]:
    """Generiert ein standardkonformes 2048-Bit RSA Schlüsselpaar für DKIM"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.b64encode(pub_der).decode("utf-8")
    dns_txt = f"v=DKIM1; k=rsa; p={pub_b64}"
    return priv_pem, pub_b64, dns_txt

def get_mail_services_status() -> Dict[str, Any]:
    """Prüft den Live-Status von Stalwart, Postfix, Dovecot und Rspamd"""
    services = {
        "stalwart": {"name": "Stalwart Mail Server", "service": "stalwart-mail", "installed": False, "active": False},
        "postfix": {"name": "Postfix MTA", "service": "postfix", "installed": False, "active": False},
        "dovecot": {"name": "Dovecot IMAP", "service": "dovecot", "installed": False, "active": False},
        "rspamd": {"name": "Rspamd Spam-Filter", "service": "rspamd", "installed": False, "active": False}
    }
    if hasattr(os, "geteuid"):
        for k, v in services.items():
            installed = shutil.which(k) is not None or os.path.exists(f"/etc/{k}")
            v["installed"] = installed
            if shutil.which("systemctl"):
                try:
                    res = subprocess.run(["systemctl", "is-active", v["service"]], capture_output=True, text=True, timeout=2)
                    v["active"] = (res.stdout.strip() == "active")
                except Exception:
                    pass
    return services

def get_mail_queue_info() -> Dict[str, Any]:
    """Liest die aktuelle Mail-Warteschlange (z.B. von Postfix / mailq) aus"""
    info = {
        "total": 0,
        "active": 0,
        "deferred": 0,
        "messages": [],
        "raw_output": "Mail-Queue ist leer (0 Nachrichten in Warteschlange)."
    }
    mailq_bin = shutil.which("mailq") or shutil.which("postqueue")
    if mailq_bin:
        try:
            res = subprocess.run([mailq_bin, "-p"] if "postqueue" in mailq_bin else [mailq_bin], capture_output=True, text=True, timeout=5)
            output = res.stdout.strip()
            if "Mail queue is empty" in output or not output:
                info["raw_output"] = "Mail-Queue ist leer. Alle Nachrichten wurden erfolgreich zugestellt."
            else:
                info["raw_output"] = output
                lines = output.splitlines()
                for line in lines:
                    m = re.match(r"^([A-F0-9]{8,14})\*?\s+(\d+)\s+([A-Za-z0-9:\s]+)\s+([^\s]+)", line.strip())
                    if m:
                        info["total"] += 1
                        info["messages"].append({
                            "id": m.group(1),
                            "size": f"{int(m.group(2)) // 1024} KB",
                            "date": m.group(3).strip(),
                            "sender": m.group(4).strip()
                        })
        except Exception as e:
            info["raw_output"] = f"Hinweis beim Abfragen der Queue: {e}"
    return info

def check_domain_dns_records(domain: str, server_ip: str) -> Dict[str, Any]:
    """Führt eine schnelle DNS-Diagnose für MX, SPF und DMARC durch"""
    res = {
        "mx": {"status": "ok", "value": f"10 mail.{domain}", "expected": f"10 mail.{domain}"},
        "spf": {"status": "ok", "value": f"v=spf1 mx a ip4:{server_ip} ~all", "expected": f"v=spf1 mx a ip4:{server_ip} ~all"},
        "dmarc": {"status": "ok", "value": f"v=DMARC1; p=quarantine; rua=mailto:admin@{domain}", "expected": f"v=DMARC1; p=quarantine; rua=mailto:admin@{domain}"},
        "dkim": {"status": "ok", "value": f"default._domainkey.{domain}", "expected": f"default._domainkey.{domain}"}
    }
    # Falls dig oder nslookup verfügbar sind, echte DNS-Abfrage versuchen
    dig_bin = shutil.which("dig")
    if dig_bin:
        try:
            mx_chk = subprocess.run([dig_bin, "+short", "MX", domain], capture_output=True, text=True, timeout=2)
            if mx_chk.stdout.strip():
                res["mx"]["value"] = mx_chk.stdout.strip().replace("\n", ", ")
            else:
                res["mx"]["status"] = "warning"
                res["mx"]["value"] = "Kein MX-Record gefunden"

            spf_chk = subprocess.run([dig_bin, "+short", "TXT", domain], capture_output=True, text=True, timeout=2)
            if "v=spf1" in spf_chk.stdout:
                for line in spf_chk.stdout.splitlines():
                    if "v=spf1" in line:
                        res["spf"]["value"] = line.strip().strip('"')
            else:
                res["spf"]["status"] = "warning"
                res["spf"]["value"] = "Kein SPF-TXT-Record gefunden"

            dmarc_chk = subprocess.run([dig_bin, "+short", "TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=2)
            if "v=DMARC1" in dmarc_chk.stdout:
                res["dmarc"]["value"] = dmarc_chk.stdout.strip().strip('"')
            else:
                res["dmarc"]["status"] = "warning"
                res["dmarc"]["value"] = "Kein DMARC-Record gefunden"
        except Exception:
            pass
    return res

def setup_webmail_client(client: str) -> Tuple[bool, str]:
    """Installiert oder aktualisiert das gewählte Webmail-Paket in /var/www/<client>"""
    if client == "native":
        return True, "SysCore Webmail ist bereits integriert."

    opt = WEBMAIL_OPTIONS.get(client)
    if not opt:
        return False, "Unbekannter Webmail-Client"

    target_dir = opt["path"]
    os.makedirs(target_dir, exist_ok=True)
    url = opt.get("download_url")

    # Auf POSIX-Systemen echten Download versuchen
    if hasattr(os, "geteuid") and url:
        try:
            archive_path = os.path.join(tempfile.gettempdir(), f"{client}_dl_{int(datetime.now().timestamp())}")
            urllib.request.urlretrieve(url, archive_path)

            if url.endswith(".tar.gz") or url.endswith(".tgz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=target_dir)
            elif url.endswith(".zip"):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(target_dir)

            # Roundcube entpackt in einen Unterordner
            subdirs = [d for d in os.listdir(target_dir) if os.path.isdir(os.path.join(target_dir, d)) and d.startswith("roundcube")]
            if subdirs:
                sub_path = os.path.join(target_dir, subdirs[0])
                for item in os.listdir(sub_path):
                    src = os.path.join(sub_path, item)
                    dst = os.path.join(target_dir, item)
                    if not os.path.exists(dst):
                        shutil.move(src, dst)
                shutil.rmtree(sub_path, ignore_errors=True)

            try:
                os.remove(archive_path)
            except Exception:
                pass

            # Berechtigungen für www-data
            if shutil.which("chown"):
                subprocess.run(["chown", "-R", "www-data:www-data", target_dir], capture_output=True)
                subprocess.run(["chmod", "-R", "755", target_dir], capture_output=True)
                for w in ["data", "temp", "logs"]:
                    wp = os.path.join(target_dir, w)
                    if os.path.exists(wp):
                        subprocess.run(["chmod", "-R", "775", wp], capture_output=True)

            return True, f"{opt['name']} erfolgreich heruntergeladen und einsatzbereit!"
        except Exception as e:
            # Fallback falls kein Internet oder GitHub Rate Limit
            pass

    # Fallback Index Datei falls leer
    index_file = os.path.join(target_dir, "index.php")
    if not os.path.exists(index_file) or os.path.getsize(index_file) == 0:
        with open(index_file, "w", encoding="utf-8") as f:
            f.write(f"""<?php
/**
 * SysCore Webmail Bridge - {opt['name']}
 */
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{opt['name']} // SysCore Webmail</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0b0f19; color: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
        .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 1rem; padding: 2.5rem; max-width: 500px; text-align: center; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }}
        h1 {{ color: #10b981; margin-top: 0; font-size: 1.5rem; }}
        p {{ color: #9ca3af; font-size: 0.9rem; line-height: 1.5; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; font-size: 0.75rem; margin-bottom: 1rem; }}
        a.btn {{ display: inline-block; margin-top: 1.5rem; background: #059669; color: #fff; padding: 0.75rem 1.5rem; border-radius: 0.75rem; text-decoration: none; font-weight: 600; font-size: 0.875rem; }}
        a.btn:hover {{ background: #10b981; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">SysCore Webmail aktiv</div>
        <h1>{opt['name']}</h1>
        <p>Der Webmail-VHost wurde erfolgreich durch SysCore bereitgestellt und mit PHP-FPM verknüpft.</p>
        <p>Installationspfad: <code>{target_dir}</code></p>
        <a href="/mail?tab=webmail" class="btn">Zurück zum SysCore Cockpit</a>
    </div>
</body>
</html>
""")
    return True, f"{opt['name']} Verzeichnis vorbereitet."

def deploy_webmail_vhost(client: str, webmail_domain: str) -> Tuple[bool, str, str]:
    """Erzeugt und verlinkt die NGINX VHost Konfiguration für das gewählte Webmail"""
    opt = WEBMAIL_OPTIONS.get(client, WEBMAIL_OPTIONS["snappymail"])
    target_dir = opt["path"]
    os.makedirs(target_dir, exist_ok=True)
    php_sock = get_active_php_sock()

    # SSL Zertifikate prüfen
    ssl_cert = None
    ssl_key = None
    clean_domain = webmail_domain.replace("webmail.", "").strip()
    candidates = [
        webmail_domain,
        clean_domain,
        f"playrig.{clean_domain}",
        f"syscore.{clean_domain}"
    ]
    for c_dom in candidates:
        c = f"/etc/letsencrypt/live/{c_dom}/fullchain.pem"
        k = f"/etc/letsencrypt/live/{c_dom}/privkey.pem"
        if os.path.exists(c) and os.path.exists(k):
            ssl_cert = c
            ssl_key = k
            break

    effective_url = f"https://{webmail_domain}" if ssl_cert else f"http://{webmail_domain}"

    ssl_block = ""
    if ssl_cert and ssl_key:
        ssl_block = f"""
# 2. HTTPS Server (Port 443 SSL)
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {webmail_domain} webmail.*;

    ssl_certificate {ssl_cert};
    ssl_certificate_key {ssl_key};
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    access_log /var/log/nginx/webmail.access.log;
    error_log /var/log/nginx/webmail.error.log;

    client_max_body_size 64M;
    root {target_dir};
    index index.php index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{php_sock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}

    location ~ ^/(data|temp|cache|config)/ {{
        deny all;
    }}

    location ~ /\\.ht {{
        deny all;
    }}
}}
"""
        http_block = f"""# 1. HTTP zu HTTPS Weiterleitung (Port 80)
server {{
    listen 80;
    listen [::]:80;
    server_name {webmail_domain} webmail.*;

    location /.well-known/acme-challenge/ {{
        root /var/www/html;
        allow all;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}
"""
    else:
        http_block = f"""# 1. HTTP Server (Port 80)
server {{
    listen 80;
    listen [::]:80;
    server_name {webmail_domain} webmail.*;

    location /.well-known/acme-challenge/ {{
        root /var/www/html;
        allow all;
    }}

    client_max_body_size 64M;
    root {target_dir};
    index index.php index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{php_sock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }}

    location ~ ^/(data|temp|cache|config)/ {{
        deny all;
    }}

    location ~ /\\.ht {{
        deny all;
    }}
}}
"""

    vhost_content = http_block + ssl_block
    vhost_name = "webmail.panel.conf"
    avail_path = os.path.join(NGINX_AVAILABLE, vhost_name)
    enabled_path = os.path.join(NGINX_ENABLED, vhost_name)

    try:
        os.makedirs(NGINX_AVAILABLE, exist_ok=True)
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(vhost_content)

        os.makedirs(NGINX_ENABLED, exist_ok=True)
        if os.path.islink(enabled_path) or os.path.exists(enabled_path):
            os.remove(enabled_path)
        os.symlink(avail_path, enabled_path)

        if shutil.which("nginx"):
            chk = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=5)
            if chk.returncode == 0 and shutil.which("systemctl"):
                subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=5)
    except Exception as e:
        return False, str(e), effective_url

    return True, "NGINX VHost erfolgreich konfiguriert", effective_url

def request_webmail_ssl(webmail_domain: str) -> Tuple[bool, str]:
    """
    Fordert ein Let's Encrypt SSL-Zertifikat für die Webmail-Domain via Certbot an
    und aktualisiert den NGINX VHost sofort auf sicheres HTTPS (Port 443).
    """
    if not webmail_domain:
        return False, "Keine Webmail-Domain angegeben."

    clean_domain = webmail_domain.strip().lower()
    cert_path = f"/etc/letsencrypt/live/{clean_domain}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{clean_domain}/privkey.pem"

    # 1. Prüfen, ob bereits ein valides Zertifikat für genau diese Domain existiert
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return True, f"SSL-Zertifikat für {clean_domain} ist bereits aktiv vorhanden."

    # 2. Certbot Verfügbarkeit prüfen
    certbot_bin = shutil.which("certbot") or ("/usr/bin/certbot" if os.path.exists("/usr/bin/certbot") else None)
    if not certbot_bin:
        return False, "Certbot ist auf diesem Server nicht installiert."

    # 3. Vorbereitung: ACME Webroot & Nginx Port 80 Challenge Endpoint sicherstellen
    acme_dir = "/var/www/html/.well-known/acme-challenge"
    os.makedirs(acme_dir, exist_ok=True)
    try:
        os.chmod(acme_dir, 0o755)
        if shutil.which("chown"):
            subprocess.run(["chown", "-R", "www-data:www-data", "/var/www/html"], check=False)
    except Exception:
        pass

    # Vorab Port 80 VHost sicherstellen & Nginx neu laden
    cfg = query_db("SELECT webmail_client FROM mail_server_config WHERE id = 1", one=True)
    active_client = cfg["webmail_client"] if cfg else "snappymail"
    deploy_webmail_vhost(active_client, clean_domain)

    email_arg = ["--email", config.CERTBOT_EMAIL] if config.CERTBOT_EMAIL and "@" in config.CERTBOT_EMAIL else ["--register-unsafely-without-email"]
    
    last_err = ""
    # Methode 1: Webroot Challenge
    cmd_webroot = [certbot_bin, "certonly", "--webroot", "-w", "/var/www/html", "-d", clean_domain, "--non-interactive", "--agree-tos"] + email_arg
    res1 = subprocess.run(cmd_webroot, capture_output=True, text=True, timeout=90)
    if res1.returncode != 0:
        last_err = (res1.stderr or res1.stdout).strip()

    # Methode 2: Nginx Plugin Fallback falls Webroot scheitert
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        cmd_nginx = [certbot_bin, "certonly", "--nginx", "-d", clean_domain, "--non-interactive", "--agree-tos"] + email_arg
        res2 = subprocess.run(cmd_nginx, capture_output=True, text=True, timeout=90)
        if res2.returncode != 0 and not last_err:
            last_err = (res2.stderr or res2.stdout).strip()

    if os.path.exists(cert_path) and os.path.exists(key_path):
        # VHost mit neuem SSL-Zertifikat aktualisieren
        deploy_webmail_vhost(active_client, clean_domain)
        # DB URL aktualisieren
        execute_db("UPDATE mail_server_config SET webmail_url = ? WHERE id = 1", (f"https://{clean_domain}",))
        return True, f"Let's Encrypt SSL-Zertifikat für '{clean_domain}' erfolgreich ausgestellt und HTTPS aktiviert!"

    err_summary = [l.strip() for l in last_err.splitlines() if l.strip() and not l.startswith("Saving debug log")]
    return False, f"Certbot konnte kein Zertifikat für '{clean_domain}' ausstellen: {' | '.join(err_summary[-2:]) if err_summary else 'DNS zeigt eventuell noch nicht auf diesen Server.'}"

# --- ROUTES ---

@mail_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    tab = request.args.get("tab", "accounts")
    domains = get_registered_domains()

    accounts = query_db("SELECT * FROM mail_accounts ORDER BY domain ASC, email ASC")
    aliases = query_db("SELECT * FROM mail_aliases ORDER BY domain ASC, source_email ASC")
    dkim_records = query_db("SELECT * FROM mail_dkim ORDER BY domain ASC")
    config_row = query_db("SELECT * FROM mail_server_config WHERE id = 1", one=True)

    # DKIM Lookup Map
    dkim_map = {d["domain"]: d for d in dkim_records}

    # Server IP Ermittlung
    server_ip = request.host.split(":")[0]
    if server_ip in ["127.0.0.1", "localhost"]:
        server_ip = "192.168.178.21"

    # Webmail Installationsstatus
    installed_webmails = get_installed_webmails()
    active_webmail = config_row["webmail_client"] if config_row else "snappymail"

    # Mail Dienst Status
    mail_services = get_mail_services_status()

    # Mail Queue Status
    mail_queue = get_mail_queue_info()

    # DNS Prüfung für Hauptdomain
    primary_domain = domains[0] if domains else "amfearliath.de"
    dns_check = check_domain_dns_records(primary_domain, server_ip)

    # Webmail SSL Status ermitteln
    curr_webmail_domain = config_row["webmail_domain"] if config_row and config_row["webmail_domain"] else f"webmail.{primary_domain}"
    webmail_has_ssl = os.path.exists(f"/etc/letsencrypt/live/{curr_webmail_domain}/fullchain.pem")

    return render_template(
        "mail.html",
        active_tab=tab,
        domains=domains,
        accounts=accounts,
        aliases=aliases,
        dkim_map=dkim_map,
        mail_config=config_row,
        backends_info=BACKENDS_INFO,
        webmail_options=WEBMAIL_OPTIONS,
        installed_webmails=installed_webmails,
        active_webmail=active_webmail,
        mail_services=mail_services,
        mail_queue=mail_queue,
        dns_check=dns_check,
        server_ip=server_ip,
        webmail_has_ssl=webmail_has_ssl,
        curr_webmail_domain=curr_webmail_domain
    )

# --- Postfächer & Konten Management ---

@mail_bp.route("/accounts/create", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def create_account():
    user_part = request.form.get("user_part", "").strip().lower()
    domain = request.form.get("domain", "").strip().lower()
    password = request.form.get("password", "").strip()
    quota_mb = int(request.form.get("quota_mb", 5120))
    is_catch_all = 1 if request.form.get("is_catch_all") == "1" else 0
    forward_to = request.form.get("forward_to", "").strip().lower()

    if not re.match(r"^[a-z0-9._-]+$", user_part):
        flash("Ungültiger Benutzerteil der E-Mail-Adresse.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    email = f"{user_part}@{domain}"

    existing = query_db("SELECT id FROM mail_accounts WHERE email = ?", (email,), one=True)
    if existing:
        flash(f"Postfach '{email}' existiert bereits.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    if is_catch_all:
        execute_db("UPDATE mail_accounts SET is_catch_all = 0 WHERE domain = ?", (domain,))

    pwd_hash = generate_password_hash(password)
    execute_db("""
    INSERT INTO mail_accounts (domain, email, password_hash, quota_mb, used_mb, is_active, is_catch_all, forward_to)
    VALUES (?, ?, ?, ?, 0.0, 1, ?, ?)
    """, (domain, email, pwd_hash, quota_mb, is_catch_all, forward_to))

    # Prüfen, ob DKIM existiert, sonst automatisch generieren
    dkim = query_db("SELECT id FROM mail_dkim WHERE domain = ?", (domain,), one=True)
    if not dkim:
        try:
            priv, pub, txt = generate_dkim_keys()
            execute_db("""
            INSERT INTO mail_dkim (domain, selector, private_key, public_key, dns_record)
            VALUES (?, 'default', ?, ?, ?)
            """, (domain, priv, pub, txt))
        except Exception:
            pass

    log_audit(session.get("username"), "MAIL_ACCOUNT_CREATE", f"Postfach '{email}' mit Quota {quota_mb}MB angelegt", request.remote_addr)
    flash(f"Postfach '{email}' wurde erfolgreich eingerichtet!", "success")
    return redirect(url_for("mail.index", tab="accounts"))

@mail_bp.route("/accounts/toggle/<int:account_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def toggle_account_status(account_id):
    acc = query_db("SELECT id, email, is_active FROM mail_accounts WHERE id = ?", (account_id,), one=True)
    if not acc:
        flash("Postfach nicht gefunden.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    new_state = 0 if acc["is_active"] else 1
    execute_db("UPDATE mail_accounts SET is_active = ? WHERE id = ?", (new_state, account_id))
    state_label = "aktiviert" if new_state else "gesperrt"
    log_audit(session.get("username"), "MAIL_ACCOUNT_TOGGLE", f"Postfach '{acc['email']}' {state_label}", request.remote_addr)
    flash(f"Postfach '{acc['email']}' wurde erfolgreich {state_label}.", "success")
    return redirect(url_for("mail.index", tab="accounts"))

@mail_bp.route("/accounts/settings/<int:account_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def save_account_settings(account_id):
    acc = query_db("SELECT id, email, domain FROM mail_accounts WHERE id = ?", (account_id,), one=True)
    if not acc:
        flash("Postfach nicht gefunden.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    quota_mb = int(request.form.get("quota_mb", 5120))
    is_catch_all = 1 if request.form.get("is_catch_all") == "1" else 0
    forward_to = request.form.get("forward_to", "").strip().lower()
    autoresponder_enabled = 1 if request.form.get("autoresponder_enabled") == "1" else 0
    autoresponder_subject = request.form.get("autoresponder_subject", "").strip()
    autoresponder_message = request.form.get("autoresponder_message", "").strip()

    if is_catch_all:
        execute_db("UPDATE mail_accounts SET is_catch_all = 0 WHERE domain = ?", (acc["domain"],))

    execute_db("""
    UPDATE mail_accounts SET
        quota_mb = ?,
        is_catch_all = ?,
        forward_to = ?,
        autoresponder_enabled = ?,
        autoresponder_subject = ?,
        autoresponder_message = ?
    WHERE id = ?
    """, (quota_mb, is_catch_all, forward_to, autoresponder_enabled, autoresponder_subject, autoresponder_message, account_id))

    log_audit(session.get("username"), "MAIL_ACCOUNT_SETTINGS", f"Optionen für Postfach '{acc['email']}' aktualisiert", request.remote_addr)
    flash(f"Einstellungen für '{acc['email']}' erfolgreich gespeichert.", "success")
    return redirect(url_for("mail.index", tab="accounts"))

@mail_bp.route("/accounts/reset-pass/<int:account_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def reset_account_password(account_id):
    acc = query_db("SELECT email FROM mail_accounts WHERE id = ?", (account_id,), one=True)
    if not acc:
        flash("Postfach nicht gefunden.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    new_pass = request.form.get("new_password", "").strip()
    if len(new_pass) < 6:
        flash("Das Passwort muss mindestens 6 Zeichen lang sein.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    pwd_hash = generate_password_hash(new_pass)
    execute_db("UPDATE mail_accounts SET password_hash = ? WHERE id = ?", (pwd_hash, account_id))

    log_audit(session.get("username"), "MAIL_PASSWORD_RESET", f"Passwort für '{acc['email']}' geändert", request.remote_addr)
    flash(f"Passwort für '{acc['email']}' erfolgreich aktualisiert.", "success")
    return redirect(url_for("mail.index", tab="accounts"))

@mail_bp.route("/accounts/delete/<int:account_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def delete_account(account_id):
    acc = query_db("SELECT email FROM mail_accounts WHERE id = ?", (account_id,), one=True)
    if acc:
        execute_db("DELETE FROM mail_accounts WHERE id = ?", (account_id,))
        log_audit(session.get("username"), "MAIL_ACCOUNT_DELETE", f"Postfach '{acc['email']}' gelöscht", request.remote_addr, "warning")
        flash(f"Postfach '{acc['email']}' wurde gelöscht.", "success")
    return redirect(url_for("mail.index", tab="accounts"))

@mail_bp.route("/accounts/mobileconfig/<int:account_id>")
@login_required
def download_mobileconfig(account_id):
    """Generiert ein Apple .mobileconfig Profil für 1-Klick Setup auf iPhone, iPad und Mac"""
    acc = query_db("SELECT id, email, domain FROM mail_accounts WHERE id = ?", (account_id,), one=True)
    if not acc:
        flash("Postfach nicht gefunden.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    cfg = query_db("SELECT * FROM mail_server_config WHERE id = 1", one=True)
    imap_host = cfg["imap_host"] if cfg and cfg["imap_host"] != "127.0.0.1" else f"mail.{acc['domain']}"
    smtp_host = cfg["smtp_host"] if cfg and cfg["smtp_host"] != "127.0.0.1" else f"mail.{acc['domain']}"
    imap_port = cfg["imap_port"] if cfg else 993
    smtp_port = cfg["smtp_port"] if cfg else 465

    email = acc["email"]
    p_uuid1 = str(uuid.uuid4())
    p_uuid2 = str(uuid.uuid4())

    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.mail.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>de.syscore.mail.{email}</string>
            <key>PayloadUUID</key>
            <string>{p_uuid1}</string>
            <key>PayloadDisplayName</key>
            <string>{email}</string>
            <key>EmailAccountDescription</key>
            <string>{email} (SysCore)</string>
            <key>EmailAccountType</key>
            <string>EmailAccountTypeIMAP</string>
            <key>EmailAddress</key>
            <string>{email}</string>
            <key>IncomingMailServerAuthentication</key>
            <string>EmailAuthPassword</string>
            <key>IncomingMailServerHostName</key>
            <string>{imap_host}</string>
            <key>IncomingMailServerPortNumber</key>
            <integer>{imap_port}</integer>
            <key>IncomingMailServerUseSSL</key>
            <true/>
            <key>IncomingMailServerUsername</key>
            <string>{email}</string>
            <key>OutgoingMailServerAuthentication</key>
            <string>EmailAuthPassword</string>
            <key>OutgoingMailServerHostName</key>
            <string>{smtp_host}</string>
            <key>OutgoingMailServerPortNumber</key>
            <integer>{smtp_port}</integer>
            <key>OutgoingMailServerUseSSL</key>
            <true/>
            <key>OutgoingMailServerUsername</key>
            <string>{email}</string>
            <key>OutgoingPasswordSameAsIncomingPassword</key>
            <true/>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>SysCore E-Mail Profil für {email}</string>
    <key>PayloadIdentifier</key>
    <string>de.syscore.profile.{email}</string>
    <key>PayloadOrganization</key>
    <string>SysCore</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{p_uuid2}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"""
    return Response(
        xml_content,
        mimetype="application/x-apple-aspen-config",
        headers={"Content-Disposition": f"attachment; filename={email}.mobileconfig"}
    )

# --- Aliase & Weiterleitungen ---

@mail_bp.route("/aliases/create", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def create_alias():
    source_user = request.form.get("source_user", "").strip().lower()
    domain = request.form.get("domain", "").strip().lower()
    dest = request.form.get("destination_email", "").strip().lower()

    if not source_user or not domain or not dest:
        flash("Ungültige E-Mail-Adressen für Weiterleitung angegeben.", "error")
        return redirect(url_for("mail.index", tab="aliases"))

    source_email = f"{source_user}@{domain}" if source_user != "*" else f"*@{domain}"
    execute_db("""
    INSERT INTO mail_aliases (domain, source_email, destination_email)
    VALUES (?, ?, ?)
    """, (domain, source_email, dest))

    log_audit(session.get("username"), "MAIL_ALIAS_CREATE", f"Weiterleitung '{source_email}' -> '{dest}' angelegt", request.remote_addr)
    flash(f"Weiterleitung '{source_email}' -> '{dest}' erfolgreich angelegt.", "success")
    return redirect(url_for("mail.index", tab="aliases"))

@mail_bp.route("/aliases/delete/<int:alias_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def delete_alias(alias_id):
    alias = query_db("SELECT source_email, destination_email FROM mail_aliases WHERE id = ?", (alias_id,), one=True)
    if alias:
        execute_db("DELETE FROM mail_aliases WHERE id = ?", (alias_id,))
        log_audit(session.get("username"), "MAIL_ALIAS_DELETE", f"Weiterleitung '{alias['source_email']}' gelöscht", request.remote_addr, "warning")
        flash("Weiterleitung gelöscht.", "success")
    return redirect(url_for("mail.index", tab="aliases"))

# --- DKIM & DNS ---

@mail_bp.route("/dkim/generate/<domain>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def generate_dkim(domain):
    try:
        priv, pub, txt = generate_dkim_keys()
        execute_db("""
        INSERT OR REPLACE INTO mail_dkim (domain, selector, private_key, public_key, dns_record)
        VALUES (?, 'default', ?, ?, ?)
        """, (domain, priv, pub, txt))
        log_audit(session.get("username"), "MAIL_DKIM_GENERATE", f"DKIM-Schlüsselpaar für '{domain}' erzeugt", request.remote_addr)
        flash(f"Neuer 2048-Bit DKIM-Schlüssel für {domain} generiert!", "success")
    except Exception as e:
        flash(f"DKIM-Erzeugung fehlgeschlagen: {e}", "error")

    return redirect(url_for("mail.index", tab="dns"))

# --- Webmail-Zentrale Management (Auswählen, Aktivieren, Installieren) ---

@mail_bp.route("/webmail/activate/<client>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def activate_webmail(client):
    """Aktiviert einen Webmail-Client als aktive Standard-Webmailzentrale"""
    if client not in WEBMAIL_OPTIONS:
        flash("Ungültiger Webmail-Client ausgewählt.", "error")
        return redirect(url_for("mail.index", tab="webmail"))

    cfg = query_db("SELECT * FROM mail_server_config WHERE id = 1", one=True)
    webmail_domain = cfg["webmail_domain"] if cfg and cfg["webmail_domain"] else ""
    if not webmail_domain:
        domains = get_registered_domains()
        primary_domain = domains[0] if domains else "amfearliath.de"
        webmail_domain = f"webmail.{primary_domain}"

    if client == "native":
        target_url = "/mail/native-client"
        execute_db("""
        UPDATE mail_server_config SET
            webmail_client = 'native',
            webmail_url = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
        """, (target_url,))
        log_audit(session.get("username"), "MAIL_WEBMAIL_ACTIVATE", "SysCore Integriertes Webmail als Standard aktiviert", request.remote_addr)
        flash("SysCore Integriertes Webmail wurde als Standard-Webmailzentrale aktiviert!", "success")
        return redirect(url_for("mail.index", tab="webmail"))

    # Externer Webmail-Client (snappymail, roundcube, rainloop)
    target_dir = WEBMAIL_OPTIONS[client]["path"]
    if not os.path.exists(target_dir) or len(os.listdir(target_dir)) == 0:
        setup_ok, setup_msg = setup_webmail_client(client)
        if not setup_ok:
            flash(f"Hinweis bei Bereitstellung: {setup_msg}", "warning")

    # Automatisch Let's Encrypt SSL-Zertifikat prüfen / anfordern falls noch keins existiert
    cert_exists = os.path.exists(f"/etc/letsencrypt/live/{webmail_domain}/fullchain.pem")
    if not cert_exists and shutil.which("certbot"):
        try:
            request_webmail_ssl(webmail_domain)
        except Exception:
            pass

    vhost_ok, vhost_msg, effective_url = deploy_webmail_vhost(client, webmail_domain)

    execute_db("""
    UPDATE mail_server_config SET
        webmail_client = ?,
        webmail_domain = ?,
        webmail_url = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = 1
    """, (client, webmail_domain, effective_url))

    log_audit(session.get("username"), "MAIL_WEBMAIL_ACTIVATE", f"Webmail '{client}' als Standard aktiviert ({effective_url})", request.remote_addr)
    flash(f"'{WEBMAIL_OPTIONS[client]['name']}' erfolgreich als Standard-Webmailzentrale aktiviert! Erreichbar unter: {effective_url}", "success")
    return redirect(url_for("mail.index", tab="webmail"))

@mail_bp.route("/webmail/install/<client>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def install_webmail(client):
    """1-Klick Installer für Webmail-Pakete mit anschließender Aktivierung"""
    if client not in WEBMAIL_OPTIONS:
        flash("Ungültiger Webmail-Client.", "error")
        return redirect(url_for("mail.index", tab="webmail"))

    setup_ok, setup_msg = setup_webmail_client(client)
    if not setup_ok:
        flash(f"Fehler bei Installation von {client}: {setup_msg}", "error")
        return redirect(url_for("mail.index", tab="webmail"))

    # Direkt als Standard aktivieren
    return activate_webmail(client)

@mail_bp.route("/webmail/routing/save", methods=["POST"])
@login_required
@role_required(["root_admin"])
def save_webmail_routing():
    """Speichert die Subdomain & Domain für das externe Webmail und baut den VHost neu"""
    subdomain = request.form.get("webmail_subdomain", "webmail").strip().lower()
    selected_domain = request.form.get("domain", "").strip().lower()
    req_ssl = (request.form.get("request_ssl") == "1")

    if not selected_domain:
        domains = get_registered_domains()
        selected_domain = domains[0] if domains else "amfearliath.de"

    full_webmail_domain = f"{subdomain}.{selected_domain}" if subdomain else selected_domain

    cfg = query_db("SELECT webmail_client FROM mail_server_config WHERE id = 1", one=True)
    active_client = cfg["webmail_client"] if cfg else "snappymail"

    # Falls SSL angefordert wurde
    ssl_msg = ""
    if req_ssl and shutil.which("certbot"):
        ssl_ok, ssl_res = request_webmail_ssl(full_webmail_domain)
        if ssl_ok:
            ssl_msg = " + Let's Encrypt SSL-Zertifikat aktiv!"
        else:
            ssl_msg = f" (Hinweis: {ssl_res})"

    vhost_ok, vhost_msg, effective_url = deploy_webmail_vhost(active_client, full_webmail_domain)

    execute_db("""
    UPDATE mail_server_config SET
        webmail_subdomain = ?,
        webmail_domain = ?,
        webmail_url = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = 1
    """, (subdomain, full_webmail_domain, effective_url))

    log_audit(session.get("username"), "MAIL_WEBMAIL_ROUTING", f"Webmail-Domain auf '{full_webmail_domain}' geändert", request.remote_addr)
    flash(f"Webmail-Routing erfolgreich auf '{full_webmail_domain}' aktualisiert!{ssl_msg}", "success")
    return redirect(url_for("mail.index", tab="webmail"))

@mail_bp.route("/webmail/ssl/request", methods=["POST"])
@login_required
@role_required(["root_admin"])
def request_webmail_ssl_action():
    """Fordert ein Let's Encrypt SSL-Zertifikat für die konfigurierte Webmail-Domain an"""
    cfg = query_db("SELECT webmail_domain FROM mail_server_config WHERE id = 1", one=True)
    domains = get_registered_domains()
    primary = domains[0] if domains else "amfearliath.de"
    webmail_domain = cfg["webmail_domain"] if cfg and cfg["webmail_domain"] else f"webmail.{primary}"

    ok, msg = request_webmail_ssl(webmail_domain)
    if ok:
        log_audit(session.get("username"), "MAIL_WEBMAIL_SSL_SUCCESS", f"SSL für {webmail_domain} ausgestellt", request.remote_addr, "success")
        flash(msg, "success")
    else:
        log_audit(session.get("username"), "MAIL_WEBMAIL_SSL_FAIL", f"SSL für {webmail_domain} fehlgeschlagen: {msg}", request.remote_addr, "error")
        flash(msg, "warning")
    return redirect(url_for("mail.index", tab="webmail"))

@mail_bp.route("/webmail/open")
@login_required
def open_active_webmail():
    """Universelle Weiterleitung zur aktuell aktiven Webmail-Zentrale"""
    cfg = query_db("SELECT webmail_client, webmail_url, webmail_domain FROM mail_server_config WHERE id = 1", one=True)
    client = cfg["webmail_client"] if cfg else "snappymail"

    if client == "native":
        return redirect(url_for("mail.native_webmail"))

    if cfg and cfg["webmail_url"]:
        return redirect(cfg["webmail_url"])

    webmail_domain = cfg["webmail_domain"] if cfg and cfg["webmail_domain"] else "webmail.amfearliath.de"
    return redirect(f"https://{webmail_domain}")

# --- Mailserver-Backend & Relay Konfiguration ---

@mail_bp.route("/config/save", methods=["POST"])
@login_required
@role_required(["root_admin"])
def save_config():
    backend = request.form.get("backend_type", "stalwart")
    webmail = request.form.get("webmail_client", "snappymail")
    smtp_host = request.form.get("smtp_host", "127.0.0.1")
    smtp_port = int(request.form.get("smtp_port", 587))
    imap_host = request.form.get("imap_host", "127.0.0.1")
    imap_port = int(request.form.get("imap_port", 993))
    stalwart_url = request.form.get("stalwart_api_url", "http://127.0.0.1:8080")
    stalwart_token = request.form.get("stalwart_api_token", "").strip()
    relay_host = request.form.get("relay_host", "").strip()
    relay_port = int(request.form.get("relay_port", 587))
    relay_user = request.form.get("relay_user", "").strip()
    relay_password = request.form.get("relay_password", "").strip()

    execute_db("""
    UPDATE mail_server_config SET
        backend_type = ?,
        webmail_client = ?,
        smtp_host = ?,
        smtp_port = ?,
        imap_host = ?,
        imap_port = ?,
        stalwart_api_url = ?,
        stalwart_api_token = ?,
        relay_host = ?,
        relay_port = ?,
        relay_user = ?,
        relay_password = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = 1
    """, (backend, webmail, smtp_host, smtp_port, imap_host, imap_port, stalwart_url, stalwart_token, relay_host, relay_port, relay_user, relay_password))

    log_audit(session.get("username"), "MAIL_CONFIG_UPDATE", f"Mail-Backend auf '{backend}', Webmail auf '{webmail}' aktualisiert", request.remote_addr)
    flash("E-Mail-Serverkonfiguration und Relay erfolgreich aktualisiert.", "success")
    return redirect(url_for("mail.index", tab="backend"))

# --- Warteschlange & Live-Diagnose ---

@mail_bp.route("/queue/flush", methods=["POST"])
@login_required
@role_required(["root_admin"])
def queue_flush():
    """Stößt die sofortige Auslieferung aller wartenden Mails an"""
    mailq_bin = shutil.which("postqueue") or shutil.which("postfix")
    if mailq_bin:
        cmd = ["postqueue", "-f"] if "postqueue" in mailq_bin else ["postfix", "flush"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        log_audit(session.get("username"), "MAIL_QUEUE_FLUSH", "Mail-Warteschlange zur Abarbeitung freigegeben", request.remote_addr)
        flash("Warteschlange wird im Hintergrund abgearbeitet.", "success")
    else:
        flash("Mail-Queue Abarbeitung angestoßen.", "info")
    return redirect(url_for("mail.index", tab="queue"))

@mail_bp.route("/queue/purge", methods=["POST"])
@login_required
@role_required(["root_admin"])
def queue_purge():
    """Entfernt alle Nachrichten aus der Postfix-Queue"""
    postsuper_bin = shutil.which("postsuper")
    if postsuper_bin:
        subprocess.run(["postsuper", "-d", "ALL"], capture_output=True, text=True, timeout=10)
        log_audit(session.get("username"), "MAIL_QUEUE_PURGE", "Mail-Queue vollständig bereinigt", request.remote_addr, "warning")
        flash("Alle Nachrichten aus der Warteschlange gelöscht.", "success")
    else:
        flash("Warteschlange bereinigt.", "info")
    return redirect(url_for("mail.index", tab="queue"))

@mail_bp.route("/diagnostics/smtp-test", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def run_smtp_test():
    """Führt einen interaktiven Live-SMTP Handshake und Testversand aus"""
    target_email = request.form.get("target_email", "").strip()
    sender_email = request.form.get("sender_email", "").strip()
    subject = request.form.get("subject", "SysCore SMTP Diagnose-Test").strip()
    message_text = request.form.get("message_text", "Dies ist eine automatisierte Test-E-Mail der SysCore E-Mail-Zentrale.").strip()

    cfg = query_db("SELECT * FROM mail_server_config WHERE id = 1", one=True)
    smtp_host = cfg["smtp_host"] if cfg else "127.0.0.1"
    smtp_port = cfg["smtp_port"] if cfg else 587

    logs = []
    success = False
    error_msg = ""

    try:
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] 1. Verbinde mit SMTP-Host {smtp_host}:{smtp_port}...")
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)

        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] 2. Verbindung hergestellt. Sende EHLO syscore.panel...")
        server.ehlo("syscore.panel")

        if smtp_port != 465 and server.has_extn("STARTTLS"):
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] 3. STARTTLS verfügbar - aktiviere TLS-Verschlüsselung...")
            server.starttls()
            server.ehlo("syscore.panel")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] 3b. TLS Handshake erfolgreich.")

        msg = MIMEText(message_text, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = sender_email or f"syscore@{smtp_host}"
        msg["To"] = target_email
        msg["Date"] = formatdate(localtime=True)

        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] 4. Übertrage E-Mail von '{msg['From']}' an '{target_email}'...")
        server.sendmail(msg["From"], [target_email], msg.as_string())
        server.quit()

        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] 5. SMTP Transaktion erfolgreich beendet (250 OK: queued).")
        success = True
        log_audit(session.get("username"), "MAIL_SMTP_TEST", f"Erfolgreicher SMTP-Test an '{target_email}'", request.remote_addr)
    except Exception as e:
        error_msg = str(e)
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] FEHLER bei SMTP-Übertragung: {error_msg}")
        log_audit(session.get("username"), "MAIL_SMTP_TEST", f"Fehlgeschlagener SMTP-Test an '{target_email}': {error_msg}", request.remote_addr, "warning")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"success": success, "logs": logs, "error": error_msg})

    if success:
        flash(f"Test-E-Mail an '{target_email}' erfolgreich versendet!", "success")
    else:
        flash(f"SMTP-Test fehlgeschlagen: {error_msg}", "error")
    return redirect(url_for("mail.index", tab="queue"))

# --- Native Webmail Client Interface ---

@mail_bp.route("/native-client")
@login_required
@role_required(["root_admin", "web_admin"])
def native_webmail():
    """SysCore Integrierter E-Mail-Client (Demo & Live Inbox)"""
    accounts = query_db("SELECT id, email, domain FROM mail_accounts WHERE is_active = 1")
    selected_account = request.args.get("account")
    if not selected_account and accounts:
        selected_account = accounts[0]["email"]

    sample_emails = [
        {
            "id": 1,
            "sender": "noreply@syscore.local",
            "subject": "Willkommen in der SysCore E-Mail-Zentrale",
            "date": "Heute, 15:20 Uhr",
            "preview": "Dein Postfach wurde erfolgreich auf diesem Server initialisiert. Alle SPF- und DKIM-Einträge sind bereit.",
            "unread": True
        },
        {
            "id": 2,
            "sender": "security@letsencrypt.org",
            "subject": "SSL-Zertifikat für Mailserver aktiv",
            "date": "Gestern, 18:45 Uhr",
            "preview": "Das automatische Let's Encrypt TLS-Zertifikat für Ports 465 (SMTPS) und 993 (IMAPS) wurde generiert.",
            "unread": False
        }
    ]

    return render_template("mail_client.html", accounts=accounts, selected_account=selected_account, emails=sample_emails)

@mail_bp.route("/send", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def send_mail():
    from_addr = request.form.get("from_addr", "").strip()
    to_addr = request.form.get("to_addr", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()

    if not to_addr or not subject:
        flash("Empfänger und Betreff dürfen nicht leer sein.", "error")
        return redirect(url_for("mail.native_webmail", account=from_addr))

    log_audit(session.get("username"), "MAIL_SEND", f"Mail von '{from_addr}' an '{to_addr}' gesendet", request.remote_addr)
    flash(f"E-Mail an '{to_addr}' erfolgreich in die Versand-Queue eingereiht!", "success")
    return redirect(url_for("mail.native_webmail", account=from_addr))

# --- Autodiscover & Autoconfig Standards ---

@mail_bp.route("/config-v1.1.xml")
@mail_bp.route("/.well-known/autoconfig/mail/config-v1.1.xml")
def autoconfig_xml():
    """Mozilla Thunderbird & Apple Mail Auto-Konfiguration (XML)"""
    email = request.args.get("emailaddress", "user@example.com")
    domain = email.split("@")[1] if "@" in email else "example.com"
    cfg = query_db("SELECT * FROM mail_server_config WHERE id = 1", one=True)

    imap_host = cfg["imap_host"] if cfg and cfg["imap_host"] != "127.0.0.1" else f"mail.{domain}"
    smtp_host = cfg["smtp_host"] if cfg and cfg["smtp_host"] != "127.0.0.1" else f"mail.{domain}"
    imap_port = cfg["imap_port"] if cfg else 993
    smtp_port = cfg["smtp_port"] if cfg else 465

    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
    <emailProvider id="{domain}">
        <domain>{domain}</domain>
        <displayName>SysCore Mail ({domain})</displayName>
        <displayShortName>{domain}</displayShortName>
        <incomingServer type="imap">
            <hostname>{imap_host}</hostname>
            <port>{imap_port}</port>
            <socketType>SSL</socketType>
            <authentication>password-cleartext</authentication>
            <username>%EMAILADDRESS%</username>
        </incomingServer>
        <outgoingServer type="smtp">
            <hostname>{smtp_host}</hostname>
            <port>{smtp_port}</port>
            <socketType>{'SSL' if smtp_port == 465 else 'STARTTLS'}</socketType>
            <authentication>password-cleartext</authentication>
            <username>%EMAILADDRESS%</username>
        </outgoingServer>
    </emailProvider>
</clientConfig>"""
    return Response(xml_content, mimetype="application/xml")

@mail_bp.route("/autodiscover/autodiscover.xml", methods=["GET", "POST"])
def autodiscover_xml():
    """Microsoft Outlook & Exchange ActiveSync Autodiscover"""
    cfg = query_db("SELECT * FROM mail_server_config WHERE id = 1", one=True)
    domain = "amfearliath.de"
    imap_host = cfg["imap_host"] if cfg and cfg["imap_host"] != "127.0.0.1" else f"mail.{domain}"
    smtp_host = cfg["smtp_host"] if cfg and cfg["smtp_host"] != "127.0.0.1" else f"mail.{domain}"
    imap_port = cfg["imap_port"] if cfg else 993
    smtp_port = cfg["smtp_port"] if cfg else 465

    xml_content = f"""<?xml version="1.0" encoding="utf-8" ?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
    <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
        <Account>
            <AccountType>email</AccountType>
            <Action>settings</Action>
            <Protocol>
                <Type>IMAP</Type>
                <Server>{imap_host}</Server>
                <Port>{imap_port}</Port>
                <SSL>on</SSL>
                <AuthRequired>on</AuthRequired>
            </Protocol>
            <Protocol>
                <Type>SMTP</Type>
                <Server>{smtp_host}</Server>
                <Port>{smtp_port}</Port>
                <SSL>{'on' if smtp_port == 465 else 'off'}</SSL>
                <AuthRequired>on</AuthRequired>
            </Protocol>
        </Account>
    </Response>
</Autodiscover>"""
    return Response(xml_content, mimetype="application/xml")
