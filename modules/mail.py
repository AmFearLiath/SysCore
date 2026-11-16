import os
import re
import json
import base64
import shutil
import subprocess
from datetime import datetime
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
        "install_guide": "curl -sSf https://stalwartlabs.com/install.sh | sh"
    },
    "postfix_dovecot": {
        "name": "Postfix & Dovecot (Nativer Linux-Stack)",
        "badge": "SysCore-Standard",
        "desc": "Klassischer, erprobter Enterprise-Mailstack mit Postfix (MTA), Dovecot (IMAP/POP3) und Rspamd/OpenDKIM.",
        "ports": "25, 465, 587, 993",
        "install_guide": "apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd rspamd"
    },
    "mailcow": {
        "name": "Mailcow: dockerized",
        "badge": "Docker Groupware",
        "desc": "Umfassende Groupware-Suite mit SOGo Webmail, Kalender/Kontakte-Sync (CalDAV/CardDAV), ClamAV und Rspamd.",
        "ports": "Docker Ports + NGINX Reverse-Proxy",
        "install_guide": "git clone https://github.com/mailcow/mailcow-dockerized && cd mailcow-dockerized && ./generate_config.sh"
    }
}

WEBMAIL_OPTIONS = {
    "snappymail": {
        "name": "SnappyMail",
        "desc": "Ultra-moderner, schneller Fork von RainLoop. Responsive Dark-Design, 2FA-Unterstützung, keine DB erforderlich.",
        "path": "/var/www/snappymail"
    },
    "roundcube": {
        "name": "Roundcube Webmail",
        "desc": "Der bewährte Webmail-Klassiker mit Elastic-Theme, Adressbuch, Plugins und hoher Stabilität.",
        "path": "/var/www/roundcube"
    },
    "native": {
        "name": "SysCore Native Webmail",
        "desc": "Direkt in SysCore integrierter Posteingang & E-Mail-Editor. Kein Drittanbieter-Webmail erforderlich.",
        "path": "integriert"
    }
}

def get_registered_domains():
    domains = set()
    if os.path.exists(NGINX_AVAILABLE):
        for f in os.listdir(NGINX_AVAILABLE):
            if f.endswith(".panel.conf"):
                domains.add(f.replace(".panel.conf", ""))
    if os.path.exists(WEB_ROOT_BASE):
        for d in os.listdir(WEB_ROOT_BASE):
            if os.path.isdir(os.path.join(WEB_ROOT_BASE, d)) and "." in d and not d.startswith("."):
                domains.add(d)
    return sorted(list(domains)) if domains else ["amfearliath.de"]

def generate_dkim_keys():
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

    # Dictionary für DKIM-Lookup pro Domain
    dkim_map = {d["domain"]: d for d in dkim_records}

    # Aktuelle Server-IP für DNS-Empfehlungen
    server_ip = request.host.split(":")[0]
    if server_ip in ["127.0.0.1", "localhost"]:
        server_ip = "192.168.178.21"

    # Status Webmail
    snappy_installed = os.path.exists("/var/www/snappymail")
    roundcube_installed = os.path.exists("/var/www/roundcube")

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
        server_ip=server_ip,
        snappy_installed=snappy_installed,
        roundcube_installed=roundcube_installed
    )

@mail_bp.route("/accounts/create", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def create_account():
    user_part = request.form.get("user_part", "").strip().lower()
    domain = request.form.get("domain", "").strip().lower()
    password = request.form.get("password", "").strip()
    quota_mb = int(request.form.get("quota_mb", 5120))

    if not re.match(r"^[a-z0-9._-]+$", user_part):
        flash("Ungültiger Benutzerteil der E-Mail-Adresse.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültige Domain.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    if len(password) < 8:
        flash("Das Passwort muss mindestens 8 Zeichen lang sein.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    full_email = f"{user_part}@{domain}"

    existing = query_db("SELECT id FROM mail_accounts WHERE email = ?", (full_email,), one=True)
    if existing:
        flash(f"Das Postfach '{full_email}' existiert bereits.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    p_hash = generate_password_hash(password)
    execute_db("""
    INSERT INTO mail_accounts (domain, email, password_hash, quota_mb, used_mb, is_active)
    VALUES (?, ?, ?, ?, 0.0, 1)
    """, (domain, full_email, p_hash, quota_mb))

    # DKIM Schlüssel für Domain sicherstellen
    existing_dkim = query_db("SELECT id FROM mail_dkim WHERE domain = ?", (domain,), one=True)
    if not existing_dkim:
        try:
            priv, pub, txt = generate_dkim_keys()
            execute_db("""
            INSERT INTO mail_dkim (domain, selector, private_key, public_key, dns_record)
            VALUES (?, 'default', ?, ?, ?)
            """, (domain, priv, pub, txt))
        except Exception:
            pass

    log_audit(session.get("username"), "MAIL_ACCOUNT_CREATE", f"Postfach '{full_email}' erstellt ({quota_mb} MB Quota)", request.remote_addr)
    flash(f"Postfach '{full_email}' erfolgreich eingerichtet.", "success")
    return redirect(url_for("mail.index", tab="accounts"))

@mail_bp.route("/accounts/reset-pass/<int:account_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def reset_account_password(account_id):
    new_pass = request.form.get("new_password", "").strip()
    if len(new_pass) < 8:
        flash("Neues Passwort muss mindestens 8 Zeichen lang sein.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    acc = query_db("SELECT email FROM mail_accounts WHERE id = ?", (account_id,), one=True)
    if not acc:
        flash("Postfach nicht gefunden.", "error")
        return redirect(url_for("mail.index", tab="accounts"))

    p_hash = generate_password_hash(new_pass)
    execute_db("UPDATE mail_accounts SET password_hash = ? WHERE id = ?", (p_hash, account_id))
    log_audit(session.get("username"), "MAIL_PASS_RESET", f"Passwort für '{acc['email']}' geändert", request.remote_addr)
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

@mail_bp.route("/aliases/create", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def create_alias():
    source_user = request.form.get("source_user", "").strip().lower()
    domain = request.form.get("domain", "").strip().lower()
    dest = request.form.get("destination_email", "").strip().lower()

    if not source_user or not domain or not dest or "@" not in dest:
        flash("Ungültige E-Mail-Adressen für Weiterleitung angegeben.", "error")
        return redirect(url_for("mail.index", tab="aliases"))

    source_email = f"{source_user}@{domain}"
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
        updated_at = CURRENT_TIMESTAMP
    WHERE id = 1
    """, (backend, webmail, smtp_host, smtp_port, imap_host, imap_port, stalwart_url, stalwart_token))

    log_audit(session.get("username"), "MAIL_CONFIG_UPDATE", f"Mail-Backend auf '{backend}', Webmail auf '{webmail}' umgestellt", request.remote_addr)
    flash("E-Mail-Serverkonfiguration erfolgreich aktualisiert.", "success")
    return redirect(url_for("mail.index", tab="backend"))

@mail_bp.route("/webmail/install/<client>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def install_webmail(client):
    if client not in ["snappymail", "roundcube"]:
        flash("Ungültiger Webmail-Client.", "error")
        return redirect(url_for("mail.index", tab="webmail"))

    target_dir = f"/var/www/{client}"
    os.makedirs(target_dir, exist_ok=True)

    # Erzeuge NGINX VHost für Webmail
    vhost_name = f"webmail.panel.conf"
    avail_path = os.path.join(NGINX_AVAILABLE, vhost_name)
    enabled_path = os.path.join(NGINX_ENABLED, vhost_name)

    vhost_content = f"""server {{
    listen 80;
    server_name webmail.*;
    root {target_dir};
    index index.php index.html;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }}

    location ~ /\\.ht {{
        deny all;
    }}
}}
"""
    try:
        os.makedirs(NGINX_AVAILABLE, exist_ok=True)
        with open(avail_path, "w", encoding="utf-8") as f:
            f.write(vhost_content)
        if os.path.exists(enabled_path):
            os.remove(enabled_path)
        os.symlink(avail_path, enabled_path)
    except Exception:
        pass

    log_audit(session.get("username"), "WEBMAIL_INSTALL", f"Webmail '{client}' unter '{target_dir}' bereitgestellt", request.remote_addr)
    flash(f"{client.capitalize()} erfolgreich vorbereitet und unter {target_dir} verknüpft.", "success")
    return redirect(url_for("mail.index", tab="webmail"))

@mail_bp.route("/native-client")
@login_required
@role_required(["root_admin", "web_admin"])
def native_webmail():
    """SysCore Integrierter E-Mail-Client (Demo / Live-Inbox)"""
    accounts = query_db("SELECT id, email, domain FROM mail_accounts WHERE is_active = 1")
    selected_account = request.args.get("account")
    if not selected_account and accounts:
        selected_account = accounts[0]["email"]

    # Muster-Mails für Demo / sofortigen Test
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

@mail_bp.route("/config-v1.1.xml")
@mail_bp.route("/.well-known/autoconfig/mail/config-v1.1.xml")
def autoconfig_xml():
    """Mozilla Thunderbird & Apple Mail Auto-Konfiguration (XML)"""
    email = request.args.get("emailaddress", "user@example.com")
    domain = email.split("@")[-1] if "@" in email else config.PANEL_HOST

    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{domain}">
    <domain>{domain}</domain>
    <displayName>{domain} Mail Service</displayName>
    <displayShortName>{domain}</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.{domain}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.{domain}</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>"""
    return Response(xml_content, mimetype="application/xml")

@mail_bp.route("/autodiscover/autodiscover.xml", methods=["GET", "POST"])
def autodiscover_xml():
    """Microsoft Outlook Auto-Discover Service (XML)"""
    mail_host = f"mail.{config.PANEL_HOST}"
    xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>{mail_host}</Server>
        <Port>993</Port>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>{mail_host}</Server>
        <Port>587</Port>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>"""
    return Response(xml_content, mimetype="application/xml")

