import os
import secrets
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix
import config
import db
from modules.csrf import init_csrf

# Module Importieren
from modules.auth_users import auth_bp, current_user
from modules.system import system_bp
from modules.webserver import webserver_bp
from modules.database import database_bp
from modules.files import files_bp
from modules.cron import cron_bp
from modules.packages import packages_bp
from modules.apps import apps_bp
from modules.backups import backups_bp
from modules.settings import settings_bp, get_cached_git_commit
from modules.mail import mail_bp
from modules.security import security_bp
from modules.users import users_bp

# Initialisiere SQLite Datenbank & Tabellen & Bootstrap Admin
db.init_db()

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB Max Upload

# NGINX Reverse-Proxy Headers respektieren (SEC-018 / SSL & Client-IP Support)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Sitzungs- & Cookie-Härtung (SEC-017)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

# Standard Security Headers (HSTS, Nosniff, Clickjacking)
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Intelligente automatische HTTPS-Umleitung für Domain-Aufrufe über Port 8888
@app.before_request
def auto_redirect_port_8888_to_https():
    """
    Falls der Benutzer das Panel im Browser direkt über http://domain.de:8888 aufruft,
    leiten wir ihn automatisch auf https://domain.de (Port 443 mit NGINX SSL) um.
    Lokale Aufrufe (127.0.0.1, localhost) und direkte IP-Aufrufe bleiben für Notfallzugriff erlaubt.
    """
    raw_host = request.host  # z.B. syscore.amfearliath.de:8888
    if f":{config.PANEL_PORT}" in raw_host and not request.is_secure:
        host_no_port = raw_host.split(":")[0].strip().lower()
        # Nur echte Domains umleiten, nicht 127.0.0.1, localhost oder reine IP-Adressen
        is_ip = host_no_port.replace(".", "").isdigit() or host_no_port in ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if not is_ip:
            qs = f"?{request.query_string.decode('utf-8')}" if request.query_string else ""
            target_url = f"https://{host_no_port}{request.path}{qs}"
            return redirect(target_url, code=301)

# Zentraler CSRF-Schutz initialisieren (SEC-008)
init_csrf(app)

# Blueprints Registrieren
app.register_blueprint(auth_bp)
app.register_blueprint(system_bp)
app.register_blueprint(webserver_bp)
app.register_blueprint(database_bp)
app.register_blueprint(files_bp)
app.register_blueprint(cron_bp)
app.register_blueprint(packages_bp)
app.register_blueprint(apps_bp)
app.register_blueprint(backups_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(mail_bp)
app.register_blueprint(security_bp)
app.register_blueprint(users_bp)

# Globale Context-Variablen für Templates
@app.context_processor
def inject_global_template_vars():
    user = current_user()
    return {
        "current_user_obj": user,
        "current_user_role": session.get("role", "monitor"),
        "panel_host": config.PANEL_HOST,
        "panel_port": config.PANEL_PORT,
        "syscore_version": getattr(config, "SYSCORE_VERSION", "0.9.1.0"),
        "syscore_commit": get_cached_git_commit(),
        "db_fallback_active": getattr(db, "FALLBACK_TO_SQLITE", False),
        "db_fallback_error": getattr(db, "MYSQL_LAST_ERROR", "")
    }

# Authentifizierungs-Guard
@app.before_request
def require_authentication():
    # Öffentlich zugängliche Routen
    open_endpoints = {
        "auth.login",
        "auth.verify_2fa",
        "auth.qr_status",
        "auth.approve_qr",
        "auth.logout",
        "static"
    }

    if (request.path.startswith("/api/webhook/") or 
        request.path.startswith("/web/webhook/deploy/") or
        request.path.startswith("/mail/config-v1.1.xml") or 
        request.path.startswith("/login/2fa/") or
        "autodiscover" in request.path or 
        (request.endpoint and request.endpoint in open_endpoints)):
        return None

    # Falls nicht angemeldet -> Redirect zum Login
    user_id = session.get("user_id")
    if not user_id or not session.get("authenticated"):
        return redirect(url_for("auth.login", next=request.path))

    # Live-Überprüfung des Benutzerkontos in der Datenbank (SEC-009)
    # Verhindert, dass gesperrte oder gelöschte Konten aktive Sitzungen weiternutzen können
    user = db.query_db("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,), one=True)
    if not user or not user["is_active"]:
        session.clear()
        flash("Deine Sitzung ist ungültig oder das Benutzerkonto wurde deaktiviert.", "error")
        return redirect(url_for("auth.login"))

    # Rolle & Benutzername live synchronisieren
    session["role"] = user["role"]
    session["username"] = user["username"]

# Fehlerseiten
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    # Generiere eindeutige Referenz-ID für diesen Fehler (SEC-016)
    error_id = f"ERR-{secrets.token_hex(4).upper()}"
    import traceback
    tb = traceback.format_exc()
    
    # Technische Details und Stacktrace ausschließlich serverseitig protokollieren
    print(f"[SysCore Server Exception {error_id}] {e}\n{tb}")
    try:
        db.log_audit(
            username=session.get("username", "ANONYMOUS"),
            action="SERVER_ERROR_500",
            details=f"Fehler {error_id}: {str(e)[:250]} auf Pfad '{request.path}'",
            ip_address=request.remote_addr,
            status="error"
        )
    except Exception:
        pass

    # Benutzerfreundliche, maskierte Meldung ohne interne Datenlecks
    masked_message = f"Ein unerwarteter interner Verarbeitungsfehler ist aufgetreten. Referenz: {error_id}"
    try:
        return render_template("500.html", error=masked_message, error_id=error_id), 500
    except Exception:
        return f"""<!DOCTYPE html>
<html lang="de" class="dark">
<head>
    <meta charset="UTF-8">
    <title>500 - Interner Systemfehler // SysCore</title>
    <style>
        body {{ background-color: #030712; color: #f3f4f6; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; padding: 2rem; }}
        .box {{ max-width: 600px; margin: 4rem auto; background: #111827; border: 1px solid #1f2937; border-radius: 1rem; padding: 2.5rem; text-align: center; }}
        h1 {{ color: #f43f5e; font-size: 1.5rem; margin-top: 0; }}
        p {{ color: #9ca3af; font-size: 0.9rem; line-height: 1.5; }}
        .ref-box {{ display: inline-block; background: #030712; border: 1px solid #374151; padding: 0.5rem 1rem; border-radius: 0.5rem; color: #34d399; font-weight: bold; margin: 1.5rem 0; font-size: 0.85rem; }}
        a {{ color: #10b981; text-decoration: none; font-weight: bold; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>500 - Interner Systemfehler</h1>
        <p>Ein interner Fehler ist aufgetreten. Aus Sicherheitsgründen werden technische Details nicht öffentlich ausgegeben.</p>
        <div class="ref-box">Fehler-Referenz: {error_id}</div>
        <p>Bitte wende dich mit dieser Referenz-ID an den Server-Administrator.</p>
        <p style="margin-top: 2rem;"><a href="/">&larr; Zurück zum Dashboard</a></p>
    </div>
</body>
</html>""", 500

if __name__ == "__main__":
    print(f"""
    =======================================================
       SYSCORE NEXT-GEN SERVER MANAGEMENT SYSTEM
    =======================================================
       Web-Panel aktiv auf: http://{config.PANEL_HOST}:{config.PANEL_PORT}
       Datenbank:            {config.DB_PATH}
       Modus:                {'DEBUG' if config.DEBUG else 'PRODUCTION DAEMON'}
    =======================================================
    """)
    app.run(host=config.PANEL_HOST, port=config.PANEL_PORT, debug=config.DEBUG)
