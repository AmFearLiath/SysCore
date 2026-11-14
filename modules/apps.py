import os
import io
import re
import json
import zipfile
import secrets
import shutil
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from config import WEB_ROOT_BASE
from modules.auth_users import login_required, role_required
from db import query_db, execute_db, log_audit

apps_bp = Blueprint("apps", __name__, url_prefix="/apps")

SAMPLE_MANIFEST = {
    "name": "Mein Web-Projekt",
    "version": "1.0.0",
    "type": "php",
    "php_version": "8.2",
    "public_subdir": "public",
    "requires_db": True,
    "env_template": ".env.example",
    "env_mapping": {
        "DB_DATABASE": "{{DB_NAME}}",
        "DB_USERNAME": "{{DB_USER}}",
        "DB_PASSWORD": "{{DB_PASS}}",
        "APP_URL": "https://{{DOMAIN}}"
    },
    "setup_sql": "schema.sql",
    "post_install_commands": [
        "composer install --no-dev --optimize-autoloader"
    ]
}

def safe_extract_zip(zip_file, extract_to):
    """Sicheres Entpacken mit Zip-Slip Path Traversal Schutz"""
    base_path = os.path.realpath(extract_to)
    os.makedirs(base_path, exist_ok=True)

    with zipfile.ZipFile(zip_file, 'r') as z:
        for member in z.infolist():
            member_path = os.path.realpath(os.path.join(base_path, member.filename))
            if not member_path.startswith(base_path):
                raise Exception(f"Sicherheitsrisiko (Zip-Slip): {member.filename}")
        z.extractall(base_path)

def create_app_database(db_name, db_user, db_pass):
    sql = (
        f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; "
        f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}'; "
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; "
        f"FLUSH PRIVILEGES;"
    )
    if shutil.which("mysql"):
        res = subprocess.run(["mysql", "-e", sql], capture_output=True, text=True)
        return res.returncode == 0, res.stderr
    return True, "Dev Mode: DB-Erstellung simuliert"

@apps_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    deployments = query_db("SELECT * FROM app_deployments ORDER BY deployed_at DESC")
    return render_template("apps.html", deployments=deployments, sample_manifest_json=json.dumps(SAMPLE_MANIFEST, indent=2))

@apps_bp.route("/deploy", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def deploy():
    domain = request.form.get("domain", "").strip().lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültige Domain.", "error")
        return redirect(url_for("apps.index"))

    zip_file = request.files.get("app_zip")
    if not zip_file or not zip_file.filename.endswith(".zip"):
        flash("Bitte eine gültige .zip Datei auswählen.", "error")
        return redirect(url_for("apps.index"))

    # Zielverzeichnis vorbereiten
    target_dir = os.path.join(WEB_ROOT_BASE, domain)
    os.makedirs(target_dir, exist_ok=True)

    try:
        # ZIP entpacken
        safe_extract_zip(zip_file, target_dir)

        # Manifest prüfen
        manifest_path = os.path.join(target_dir, "syscore.manifest.json")
        if not os.path.exists(manifest_path):
            flash("Deployment fehlgeschlagen: Keine 'syscore.manifest.json' im Root des Archivs gefunden.", "error")
            return redirect(url_for("apps.index"))

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        app_name = manifest.get("name", "Unbenannte App")
        version = manifest.get("version", "1.0.0")
        app_type = manifest.get("type", "php")

        db_name = ""
        db_user = ""
        db_pass = ""

        # Datenbank anlegen falls erforderlich
        if manifest.get("requires_db"):
            clean_dom = re.sub(r"[^a-zA-Z0-9]", "_", domain)[:14].strip("_")
            db_name = f"app_{clean_dom}"
            db_user = f"u_{clean_dom}"[:16]
            db_pass = secrets.token_urlsafe(16)

            ok, err = create_app_database(db_name, db_user, db_pass)
            if not ok:
                flash(f"Datenbank konnte nicht angelegt werden: {err}", "error")

            # SQL Schema importieren falls vorhanden
            setup_sql = manifest.get("setup_sql")
            if setup_sql:
                sql_path = os.path.join(target_dir, setup_sql)
                if os.path.exists(sql_path) and shutil.which("mysql"):
                    with open(sql_path, "r", encoding="utf-8") as sf:
                        subprocess.run(["mysql", db_name], stdin=sf, capture_output=True, text=True)

        # .env Erstellung aus Template
        env_tmpl = manifest.get("env_template")
        if env_tmpl:
            tmpl_path = os.path.join(target_dir, env_tmpl)
            if os.path.exists(tmpl_path):
                with open(tmpl_path, "r", encoding="utf-8") as f:
                    env_content = f.read()

                env_content = env_content.replace("{{DB_NAME}}", db_name)
                env_content = env_content.replace("{{DB_USER}}", db_user)
                env_content = env_content.replace("{{DB_PASS}}", db_pass)
                env_content = env_content.replace("{{DOMAIN}}", domain)
                env_content = env_content.replace("{{APP_KEY}}", secrets.token_hex(16))

                with open(os.path.join(target_dir, ".env"), "w", encoding="utf-8") as f:
                    f.write(env_content)

        # Post-Install-Befehle ausführen
        post_cmds = manifest.get("post_install_commands", [])
        for cmd in post_cmds:
            try:
                subprocess.run(cmd, shell=True, cwd=target_dir, timeout=60, capture_output=True)
            except Exception:
                pass

        # Berechtigungen setzen
        if shutil.which("chown"):
            subprocess.run(["chown", "-R", "www-data:www-data", target_dir])

        # In Datenbank protokollieren
        execute_db("""
        INSERT INTO app_deployments (domain, app_name, version, app_type, status, details)
        VALUES (?, ?, ?, ?, 'active', ?);
        """, (domain, app_name, version, app_type, f"DB: {db_name} | Type: {app_type}"))

        log_audit(session.get("username"), "APP_DEPLOY", f"App '{app_name}' auf '{domain}' bereitgestellt", request.remote_addr)
        flash(f"App '{app_name}' (v{version}) erfolgreich auf {domain} deployed!", "success")

    except Exception as e:
        flash(f"Deployment-Fehler: {str(e)}", "error")

    return redirect(url_for("apps.index"))

@apps_bp.route("/starter-template")
@login_required
def download_starter_template():
    """Generiert on-the-fly ein Starter-Template-ZIP mit syscore.manifest.json"""
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
        # 1. syscore.manifest.json
        manifest_data = {
            "name": "SysCore Starter Web App",
            "version": "1.0.0",
            "type": "php",
            "php_version": "8.2",
            "public_subdir": "public",
            "requires_db": True,
            "env_template": ".env.example",
            "setup_sql": "database.sql",
            "post_install_commands": []
        }
        z.writestr("syscore.manifest.json", json.dumps(manifest_data, indent=2))

        # 2. .env.example
        env_example = """APP_NAME="SysCore App"
APP_ENV=production
APP_URL=https://{{DOMAIN}}

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE={{DB_NAME}}
DB_USERNAME={{DB_USER}}
DB_PASSWORD={{DB_PASS}}
"""
        z.writestr(".env.example", env_example)

        # 3. database.sql
        db_sql = """CREATE TABLE IF NOT EXISTS demo_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO demo_entries (title) VALUES ('Erster Test-Eintrag aus syscore.manifest.json!');
"""
        z.writestr("database.sql", db_sql)

        # 4. public/index.php
        php_index = """<?php
echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>App Live</title></head>';
echo '<body style="background: #090d16; color: #fff; font-family: sans-serif; text-align: center; padding: 50px;">';
echo '<h1 style="color: #10b981;">Deine App wurde erfolgreich deployed!</h1>';
echo '<p>Bereitgestellt über den <strong>SysCore App-Importer</strong>.</p>';
if (file_exists('../.env')) {
    echo '<p style="color: #38bdf8;">.env wurde automatisch generiert.</p>';
}
echo '</body></html>';
"""
        z.writestr("public/index.php", php_index)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name="syscore-starter-app.zip"
    )
