import os
import io
import re
import json
import zipfile
import secrets
import shutil
import tempfile
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from config import WEB_ROOT_BASE
from modules.auth_users import login_required, role_required
from db import query_db, execute_db, log_audit

apps_bp = Blueprint("apps", __name__, url_prefix="/apps")

# Maximale Sicherheitsgrenzen für ZIP-Archive & Manifest-Dateien (SEC-004, SEC-014)
MAX_ZIP_FILES = 10000
MAX_ZIP_SINGLE_FILE_BYTES = 100 * 1024 * 1024       # 100 MB pro Datei
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 300 * 1024 * 1024 # 300 MB entpackte Gesamtgröße
MAX_MANIFEST_FILE_SIZE = 10 * 1024 * 1024           # 10 MB für SQL- und Env-Templates

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
    "actions": [
        {"type": "create_directories", "paths": ["storage/logs", "storage/framework/views", "bootstrap/cache"]},
        {"type": "set_permissions", "permissions": {"storage": "0775", "bootstrap/cache": "0775"}},
        {"type": "composer_install"}
    ]
}

ALLOWED_MANIFEST_KEYS = {
    "name", "version", "type", "php_version", "public_subdir",
    "requires_db", "env_template", "env_mapping", "setup_sql", "actions"
}

ALLOWED_APP_TYPES = {"php", "static", "node"}

def safe_extract_zip(zip_source, extract_to):
    """
    Sicheres Entpacken von ZIP-Archiven (SEC-004):
    - Extraktion in ein isoliertes temporäres Quarantäneverzeichnis
    - Kanonische Prüfung aller Dateipfade mit commonpath
    - Ablehnung absoluter Pfade und '..'-Traversal
    - Ablehnung von Symlinks und Gerätedateien
    - Obergrenzen für Dateianzahl, Einzeldateigröße und Gesamtgröße (Schutz vor ZIP-Bomben)
    - Atomare Synchronisation ins Zielverzeichnis erst nach erfolgreicher Validierung
    """
    base_target = os.path.realpath(extract_to)
    os.makedirs(base_target, exist_ok=True)

    tmp_dir = tempfile.mkdtemp(prefix="syscore_app_unpack_")
    try:
        with zipfile.ZipFile(zip_source, "r") as z:
            infolist = z.infolist()
            if len(infolist) > MAX_ZIP_FILES:
                raise ValueError(f"Sicherheitsrisiko (Zip-Bomb): Zu viele Dateien im Archiv ({len(infolist)} > {MAX_ZIP_FILES})")

            total_bytes = 0
            for member in infolist:
                # 1. Dateiname normalisieren & prüfen
                fname = member.filename.replace("\\", "/")
                if fname.startswith("/") or fname.startswith("\\"):
                    raise ValueError(f"Sicherheitsrisiko (Zip-Slip): Absoluter Pfad im Archiv abgewiesen: {member.filename}")
                parts = [p for p in fname.split("/") if p]
                if ".." in parts:
                    raise ValueError(f"Sicherheitsrisiko (Zip-Slip): Pfad-Traversal '..' abgewiesen: {member.filename}")

                # 2. Größenprüfung (Zip-Bomb)
                if member.file_size > MAX_ZIP_SINGLE_FILE_BYTES:
                    raise ValueError(f"Sicherheitsrisiko (Zip-Bomb): Einzeldatei überschreitet Limit ({member.file_size} Bytes > {MAX_ZIP_SINGLE_FILE_BYTES}): {member.filename}")
                total_bytes += member.file_size
                if total_bytes > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                    raise ValueError(f"Sicherheitsrisiko (Zip-Bomb): Gesamt-Entpackungsgröße überschritten ({total_bytes} Bytes > {MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES})")

                # 3. Symlink / Device-Node Prüfung (Unix-Attribute)
                is_symlink = ((member.external_attr >> 16) & 0o170000) == 0o120000
                if is_symlink:
                    raise ValueError(f"Sicherheitsrisiko: Symlinks innerhalb von App-Paketen sind nicht gestattet: {member.filename}")

                # 4. Kanonische Zielpfadprüfung im Quarantäne-Verzeichnis
                target_path = os.path.realpath(os.path.join(tmp_dir, fname))
                if os.path.commonpath([tmp_dir, target_path]) != tmp_dir:
                    raise ValueError(f"Sicherheitsrisiko (Zip-Slip): Pfad bricht aus Zielverzeichnis aus: {member.filename}")

            # Sichere Extraktion in Quarantäneverzeichnis
            z.extractall(tmp_dir)

        # Nach erfolgreicher Validierung: Dateien ins Zielverzeichnis übertragen
        for item in os.listdir(tmp_dir):
            s = os.path.join(tmp_dir, item)
            d = os.path.join(base_target, item)
            if os.path.isdir(s):
                if os.path.exists(d):
                    shutil.rmtree(d, ignore_errors=True)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

def resolve_manifest_path(base_dir, rel_path, max_bytes=MAX_MANIFEST_FILE_SIZE):
    """
    Kanonische Pfadprüfung für Manifest-Dateien wie setup_sql und env_template (SEC-006).
    Verhindert Zugriff auf Dateien außerhalb des App-Verzeichnisses (z. B. ../../../../etc/passwd).
    """
    if not rel_path or not isinstance(rel_path, str):
        raise ValueError("Ungültiger Dateipfad im Manifest")

    clean_rel = rel_path.strip().replace("\\", "/").lstrip("/")
    parts = [p for p in clean_rel.split("/") if p]
    if ".." in parts:
        raise ValueError(f"Sicherheitsrisiko: Pfad-Traversal ('..') im Manifest verboten: {rel_path}")

    real_base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(real_base, clean_rel))

    if os.path.commonpath([real_base, target]) != real_base:
        raise ValueError(f"Sicherheitsrisiko: Pfad liegt außerhalb des App-Verzeichnisses: {rel_path}")

    if not os.path.isfile(target):
        raise FileNotFoundError(f"Manifest-Datei nicht gefunden oder kein reguläres File: {rel_path}")

    if os.path.islink(target):
        link_target = os.path.realpath(target)
        if os.path.commonpath([real_base, link_target]) != real_base:
            raise ValueError(f"Sicherheitsrisiko: Symlink zeigt außerhalb des App-Verzeichnisses: {rel_path}")

    if os.path.getsize(target) > max_bytes:
        raise ValueError(f"Datei überschreitet maximale erlaubte Größe ({max_bytes // (1024*1024)} MB): {rel_path}")

    return target

def action_create_directories(target_dir, params):
    """Aktion: Erstellt Unterverzeichnisse innerhalb des Zielordners"""
    paths = params.get("paths", [])
    if not isinstance(paths, list):
        raise ValueError("'create_directories' erfordert eine 'paths'-Liste")
    real_base = os.path.realpath(target_dir)
    for p in paths:
        if not isinstance(p, str):
            continue
        clean_p = p.strip().replace("\\", "/").lstrip("/")
        parts = [part for part in clean_p.split("/") if part]
        if ".." in parts:
            raise ValueError(f"Pfad-Traversal in 'create_directories' abgewiesen: {p}")
        target = os.path.realpath(os.path.join(real_base, clean_p))
        if os.path.commonpath([real_base, target]) != real_base:
            raise ValueError(f"Verzeichnis liegt außerhalb des Zielordners: {p}")
        os.makedirs(target, exist_ok=True)

def action_set_permissions(target_dir, params):
    """Aktion: Setzt Dateiberechtigungen anhand einer Whitelist erlaubter Modi"""
    perms = params.get("permissions", {})
    if not isinstance(perms, dict):
        raise ValueError("'set_permissions' erfordert ein 'permissions'-Objekt")
    allowed_modes = {"0644": 0o644, "0755": 0o755, "0775": 0o775, "0770": 0o770}
    real_base = os.path.realpath(target_dir)
    for rel_path, mode_str in perms.items():
        if mode_str not in allowed_modes:
            raise ValueError(f"Unzulässige Berechtigung '{mode_str}'. Erlaubt sind: {list(allowed_modes.keys())}")
        clean_p = rel_path.strip().replace("\\", "/").lstrip("/")
        parts = [part for part in clean_p.split("/") if part]
        if ".." in parts:
            raise ValueError(f"Pfad-Traversal in 'set_permissions' abgewiesen: {rel_path}")
        target = os.path.realpath(os.path.join(real_base, clean_p))
        if os.path.commonpath([real_base, target]) != real_base or not os.path.exists(target):
            continue
        try:
            os.chmod(target, allowed_modes[mode_str])
        except Exception as e:
            print(f"[SysCore App Importer] Warnung bei chmod: {e}")

def action_composer_install(target_dir, params):
    """Aktion: Führt strikt kontrollierten Composer-Install ohne Shell aus"""
    composer_json = os.path.join(target_dir, "composer.json")
    if not os.path.exists(composer_json):
        return
    composer_bin = shutil.which("composer")
    if not composer_bin:
        raise RuntimeError("Composer ist auf dem Server nicht installiert.")
    cmd = [composer_bin, "install", "--no-dev", "--no-interaction", "--optimize-autoloader", "--prefer-dist"]
    res = subprocess.run(cmd, cwd=target_dir, capture_output=True, text=True, timeout=180, shell=False)
    if res.returncode != 0:
        raise RuntimeError(f"Composer-Install fehlgeschlagen: {res.stderr[:300]}")

def action_npm_build(target_dir, params):
    """Aktion: Führt strikt kontrollierten NPM-Install und optionalen Build ohne Shell aus"""
    pkg_json = os.path.join(target_dir, "package.json")
    if not os.path.exists(pkg_json):
        return
    npm_bin = shutil.which("npm")
    if not npm_bin:
        raise RuntimeError("NPM ist auf dem Server nicht installiert.")
    ci_cmd = [npm_bin, "ci", "--only=production"] if os.path.exists(os.path.join(target_dir, "package-lock.json")) else [npm_bin, "install", "--only=production"]
    res = subprocess.run(ci_cmd, cwd=target_dir, capture_output=True, text=True, timeout=180, shell=False)
    if res.returncode != 0:
        raise RuntimeError(f"NPM-Install fehlgeschlagen: {res.stderr[:300]}")
    try:
        with open(pkg_json, "r", encoding="utf-8") as f:
            pkg_data = json.load(f)
            if isinstance(pkg_data.get("scripts"), dict) and "build" in pkg_data["scripts"]:
                res_build = subprocess.run([npm_bin, "run", "build"], cwd=target_dir, capture_output=True, text=True, timeout=180, shell=False)
                if res_build.returncode != 0:
                    raise RuntimeError(f"NPM-Build fehlgeschlagen: {res_build.stderr[:300]}")
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise

# Zentrale Action-Registry (SEC-002: Keine beliebige Shell-Ausführung)
ACTION_REGISTRY = {
    "create_directories": action_create_directories,
    "set_permissions": action_set_permissions,
    "composer_install": action_composer_install,
    "npm_build": action_npm_build
}

def validate_manifest(manifest):
    """
    Validiert ein Manifest strikt gegen das SysCore-Sicherheitsschema.
    Lehnt unbekannte Felder und gefährliche Shell-Attribute (SEC-002) rigoros ab.
    """
    if not isinstance(manifest, dict):
        raise ValueError("Ungültiges Manifest: JSON-Objekt erwartet")

    if "post_install_commands" in manifest:
        raise ValueError(
            "Sicherheitsrichtlinie SEC-002: 'post_install_commands' sind aus Sicherheitsgründen "
            "strikt verboten (RCE-Schutz). Bitte nutze die deklarative 'actions'-Registry."
        )

    unknown_keys = set(manifest.keys()) - ALLOWED_MANIFEST_KEYS
    if unknown_keys:
        raise ValueError(f"Unbekannte Manifest-Felder abgewiesen: {', '.join(unknown_keys)}")

    if not manifest.get("name") or not isinstance(manifest.get("name"), str):
        raise ValueError("Manifest-Fehler: 'name' ist erforderlich und muss ein String sein")

    app_type = manifest.get("type", "php").lower()
    if app_type not in ALLOWED_APP_TYPES:
        raise ValueError(f"Ungültiger App-Typ '{app_type}'. Erlaubt: {', '.join(ALLOWED_APP_TYPES)}")

    actions = manifest.get("actions", [])
    if not isinstance(actions, list):
        raise ValueError("Manifest-Fehler: 'actions' muss eine Liste sein")

    for idx, act in enumerate(actions):
        if not isinstance(act, dict):
            raise ValueError(f"Aktion #{idx+1} ist kein gültiges JSON-Objekt")
        act_type = act.get("type")
        if not act_type or act_type not in ACTION_REGISTRY:
            raise ValueError(
                f"Unbekannte oder unzulässige Installations-Aktion '{act_type}' in Aktion #{idx+1}. "
                f"Erlaubte Aktionen: {', '.join(ACTION_REGISTRY.keys())}"
            )

def create_app_database(db_name, db_user, db_pass):
    # Validierung von Bezeichnern gegen SQL-Injection
    if not re.match(r"^[a-zA-Z0-9_]{1,32}$", db_name) or not re.match(r"^[a-zA-Z0-9_]{1,32}$", db_user):
        return False, "Ungültiger Datenbank- oder Benutzername."

    sql = (
        f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; "
        f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}'; "
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; "
        f"FLUSH PRIVILEGES;"
    )
    if shutil.which("mysql"):
        res = subprocess.run(["mysql", "-e", sql], capture_output=True, text=True, shell=False)
        return res.returncode == 0, res.stderr
    return True, "Dev Mode: DB-Erstellung simuliert"

@apps_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    # Menü-Konsolidierung: App-Importer ist nun integrierter Bestandteil des Package Managers
    return redirect(url_for("packages.index", tab="apps"))

@apps_bp.route("/deploy", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def deploy():
    domain = request.form.get("domain", "").strip().lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültige Domain.", "error")
        return redirect(url_for("packages.index", tab="apps"))

    zip_file = request.files.get("app_zip")
    if not zip_file or not zip_file.filename.endswith(".zip"):
        flash("Bitte eine gültige .zip Datei auswählen.", "error")
        return redirect(url_for("packages.index", tab="apps"))

    # Zielverzeichnis vorbereiten
    target_dir = os.path.join(WEB_ROOT_BASE, domain)
    os.makedirs(target_dir, exist_ok=True)

    try:
        # 1. ZIP sicher entpacken mit Quarantäne und Anti-Zip-Slip Prüfung (SEC-004)
        safe_extract_zip(zip_file, target_dir)

        # 2. Manifest laden und strikt validieren (SEC-002)
        manifest_path = os.path.join(target_dir, "syscore.manifest.json")
        if not os.path.exists(manifest_path):
            flash("Deployment fehlgeschlagen: Keine 'syscore.manifest.json' im Root des Archivs gefunden.", "error")
            return redirect(url_for("packages.index", tab="apps"))

        with open(manifest_path, "r", encoding="utf-8") as f:
            try:
                manifest = json.load(f)
            except Exception as e:
                flash(f"Deployment fehlgeschlagen: 'syscore.manifest.json' ist kein valides JSON: {e}", "error")
                return redirect(url_for("packages.index", tab="apps"))

        # Strikte Schema- und Sicherheitsvalidierung
        validate_manifest(manifest)

        app_name = manifest.get("name", "Unbenannte App")
        version = manifest.get("version", "1.0.0")
        app_type = manifest.get("type", "php")

        db_name = ""
        db_user = ""
        db_pass = ""

        # 3. Datenbank anlegen falls erforderlich
        if manifest.get("requires_db"):
            clean_dom = re.sub(r"[^a-zA-Z0-9]", "_", domain)[:14].strip("_")
            db_name = f"app_{clean_dom}"
            db_user = f"u_{clean_dom}"[:16]
            db_pass = secrets.token_urlsafe(16)

            ok, err = create_app_database(db_name, db_user, db_pass)
            if not ok:
                flash(f"Datenbank konnte nicht angelegt werden: {err}", "error")

            # 4. SQL Schema importieren mit strikter Pfadvalidierung (SEC-006)
            setup_sql = manifest.get("setup_sql")
            if setup_sql:
                try:
                    sql_path = resolve_manifest_path(target_dir, setup_sql)
                    if shutil.which("mysql"):
                        with open(sql_path, "r", encoding="utf-8") as sf:
                            subprocess.run(["mysql", db_name], stdin=sf, capture_output=True, text=True, shell=False)
                except Exception as e:
                    flash(f"Warnung beim SQL-Import: {e}", "warning")

        # 5. .env Erstellung aus Template mit strikter Pfadvalidierung (SEC-006)
        env_tmpl = manifest.get("env_template")
        if env_tmpl:
            try:
                tmpl_path = resolve_manifest_path(target_dir, env_tmpl)
                with open(tmpl_path, "r", encoding="utf-8") as f:
                    env_content = f.read()

                env_content = env_content.replace("{{DB_NAME}}", db_name)
                env_content = env_content.replace("{{DB_USER}}", db_user)
                env_content = env_content.replace("{{DB_PASS}}", db_pass)
                env_content = env_content.replace("{{DOMAIN}}", domain)
                env_content = env_content.replace("{{APP_KEY}}", secrets.token_hex(16))

                # Benutzerdefinierte Mappings anwenden
                custom_mapping = manifest.get("env_mapping", {})
                if isinstance(custom_mapping, dict):
                    for env_key, env_val in custom_mapping.items():
                        if isinstance(env_val, str):
                            val_expanded = env_val.replace("{{DB_NAME}}", db_name)\
                                                  .replace("{{DB_USER}}", db_user)\
                                                  .replace("{{DB_PASS}}", db_pass)\
                                                  .replace("{{DOMAIN}}", domain)
                            pattern = rf"^{re.escape(env_key)}=.*$"
                            if re.search(pattern, env_content, flags=re.MULTILINE):
                                env_content = re.sub(pattern, f"{env_key}={val_expanded}", env_content, flags=re.MULTILINE)
                            else:
                                env_content += f"\n{env_key}={val_expanded}\n"

                env_target_file = os.path.join(target_dir, ".env")
                with open(env_target_file, "w", encoding="utf-8") as f:
                    f.write(env_content)
                try:
                    os.chmod(env_target_file, 0o600)
                except Exception:
                    pass
            except Exception as e:
                flash(f"Warnung bei .env-Erstellung: {e}", "warning")

        # 6. Deklarative Aktionen ausführen (SEC-002 Action-Registry)
        actions = manifest.get("actions", [])
        for act in actions:
            act_type = act.get("type")
            handler = ACTION_REGISTRY.get(act_type)
            if handler:
                try:
                    handler(target_dir, act)
                except Exception as act_err:
                    flash(f"Hinweis bei Aktion '{act_type}': {act_err}", "warning")

        # 7. Berechtigungen setzen (ohne Shell)
        if shutil.which("chown"):
            subprocess.run(["chown", "-R", "www-data:www-data", target_dir], shell=False)

        # 8. In Datenbank protokollieren
        execute_db("""
        INSERT INTO app_deployments (domain, app_name, version, app_type, status, details)
        VALUES (?, ?, ?, ?, 'active', ?);
        """, (domain, app_name, version, app_type, f"DB: {db_name} | Type: {app_type}"))

        log_audit(session.get("username"), "APP_DEPLOY", f"App '{app_name}' auf '{domain}' bereitgestellt (deklarative Registry)", request.remote_addr)
        flash(f"App '{app_name}' (v{version}) erfolgreich und sicher auf {domain} deployed!", "success")

    except Exception as e:
        flash(f"Deployment-Sicherheitsfehler: {str(e)}", "error")

    return redirect(url_for("packages.index", tab="apps"))

@apps_bp.route("/starter-template")
@login_required
def download_starter_template():
    """Generiert on-the-fly ein sicheres Starter-Template-ZIP mit deklarativer syscore.manifest.json"""
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
        # 1. syscore.manifest.json (deklarativ ohne post_install_commands)
        manifest_data = {
            "name": "SysCore Starter Web App",
            "version": "1.0.0",
            "type": "php",
            "php_version": "8.2",
            "public_subdir": "public",
            "requires_db": True,
            "env_template": ".env.example",
            "setup_sql": "database.sql",
            "actions": [
                {"type": "create_directories", "paths": ["storage/logs", "bootstrap/cache"]},
                {"type": "set_permissions", "permissions": {"storage": "0775"}}
            ]
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
echo '<p>Bereitgestellt über den gehärteten <strong>SysCore App-Importer</strong> (deklarative Action-Registry).</p>';
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
