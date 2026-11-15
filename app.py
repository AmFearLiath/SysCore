import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import config
import db

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
        "syscore_version": getattr(config, "SYSCORE_VERSION", "v2.5"),
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
        request.path.startswith("/mail/config-v1.1.xml") or 
        request.path.startswith("/login/2fa/") or
        "autodiscover" in request.path or 
        (request.endpoint and request.endpoint in open_endpoints)):
        return None

    # Falls nicht angemeldet -> Redirect zum Login
    if not session.get("user_id") or not session.get("authenticated"):
        return redirect(url_for("auth.login", next=request.path))

# Fehlerseiten
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", error=str(e)), 500

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
