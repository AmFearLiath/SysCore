import os
import re
import tarfile
import gzip
import shutil
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session
from config import WEB_ROOT_BASE, BACKUP_DIR
from modules.auth_users import login_required, role_required
from db import query_db, execute_db, log_audit

backups_bp = Blueprint("backups", __name__, url_prefix="/backups")

def format_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    return f"{size:.1f} TB"

@backups_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backups_list = query_db("SELECT * FROM backups ORDER BY created_at DESC")

    # Verfügbare Domains aus /var/www auflisten
    available_domains = []
    if os.path.exists(WEB_ROOT_BASE):
        for item in sorted(os.listdir(WEB_ROOT_BASE)):
            if os.path.isdir(os.path.join(WEB_ROOT_BASE, item)) and not item.startswith("."):
                available_domains.append(item)

    return render_template("backups.html", backups=backups_list, domains=available_domains, backup_dir=BACKUP_DIR)

@backups_bp.route("/create", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def create_backup():
    domain = request.form.get("domain", "").strip().lower()
    include_db = request.form.get("include_db") == "1"
    db_name = request.form.get("db_name", "").strip()

    if not domain or not re.match(r"^[a-z0-9.-]+$", domain):
        flash("Ungültige Domain angegeben.", "error")
        return redirect(url_for("backups.index"))

    domain_dir = os.path.join(WEB_ROOT_BASE, domain)
    if not os.path.exists(domain_dir):
        flash(f"Webroot-Verzeichnis für '{domain}' nicht gefunden.", "error")
        return redirect(url_for("backups.index"))

    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{domain}_{timestamp}.tar.gz"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)

    tmp_dir = os.path.join(BACKUP_DIR, f"tmp_{timestamp}")
    os.makedirs(tmp_dir, exist_ok=True)

    try:
        # 1. Webroot sichern
        files_tar = os.path.join(tmp_dir, "webroot.tar.gz")
        with tarfile.open(files_tar, "w:gz") as tar:
            tar.add(domain_dir, arcname="webroot")

        # 2. Datenbank sichern (falls gewünscht)
        has_db = 0
        if include_db:
            target_db = db_name if db_name else f"app_{re.sub(r'[^a-zA-Z0-9]', '_', domain)[:14].strip('_')}"
            sql_file = os.path.join(tmp_dir, "database.sql")
            if shutil.which("mysqldump"):
                res = subprocess.run(["mysqldump", target_db], stdout=open(sql_file, "w"), stderr=subprocess.PIPE, text=True)
                if res.returncode == 0:
                    has_db = 1
                else:
                    if os.path.exists(sql_file):
                        os.remove(sql_file)

        # 3. Beide in ein gemeinsames TAR packen
        with tarfile.open(backup_path, "w:gz") as final_tar:
            final_tar.add(files_tar, arcname="webroot.tar.gz")
            if has_db and os.path.exists(os.path.join(tmp_dir, "database.sql")):
                final_tar.add(os.path.join(tmp_dir, "database.sql"), arcname="database.sql")

        file_size = os.path.getsize(backup_path)

        # In DB speichern
        execute_db("""
        INSERT INTO backups (domain, filename, filepath, size_bytes, includes_db, includes_files)
        VALUES (?, ?, ?, ?, ?, 1)
        """, (domain, backup_filename, backup_path, file_size, has_db))

        log_audit(session.get("username"), "BACKUP_CREATE", f"Sicherung für '{domain}' erstellt ({format_size(file_size)})", request.remote_addr)
        flash(f"Sicherung für '{domain}' erfolgreich erstellt ({format_size(file_size)}).", "success")

    except Exception as e:
        flash(f"Backup-Fehler: {str(e)}", "error")
    finally:
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return redirect(url_for("backups.index"))

@backups_bp.route("/download/<int:backup_id>")
@login_required
@role_required(["root_admin", "web_admin"])
def download_backup(backup_id):
    backup = query_db("SELECT * FROM backups WHERE id = ?", (backup_id,), one=True)
    if not backup or not os.path.exists(backup["filepath"]):
        flash("Sicherungsdatei nicht gefunden.", "error")
        return redirect(url_for("backups.index"))

    return send_file(backup["filepath"], as_attachment=True, download_name=backup["filename"])

@backups_bp.route("/restore/<int:backup_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def restore_backup(backup_id):
    backup = query_db("SELECT * FROM backups WHERE id = ?", (backup_id,), one=True)
    if not backup or not os.path.exists(backup["filepath"]):
        flash("Sicherungsdatei existiert nicht auf dem Server.", "error")
        return redirect(url_for("backups.index"))

    domain = backup["domain"]
    domain_dir = os.path.join(WEB_ROOT_BASE, domain)
    tmp_restore = os.path.join(BACKUP_DIR, f"restore_tmp_{backup_id}")
    os.makedirs(tmp_restore, exist_ok=True)

    try:
        # Entpacken
        with tarfile.open(backup["filepath"], "r:gz") as tar:
            tar.extractall(tmp_restore)

        # Webroot wiederherstellen
        inner_webroot = os.path.join(tmp_restore, "webroot.tar.gz")
        if os.path.exists(inner_webroot):
            os.makedirs(domain_dir, exist_ok=True)
            with tarfile.open(inner_webroot, "r:gz") as wtar:
                wtar.extractall(domain_dir)
            if shutil.which("chown"):
                subprocess.run(["chown", "-R", "www-data:www-data", domain_dir])

        # Datenbank wiederherstellen
        inner_sql = os.path.join(tmp_restore, "database.sql")
        if os.path.exists(inner_sql) and shutil.which("mysql"):
            target_db = f"app_{re.sub(r'[^a-zA-Z0-9]', '_', domain)[:14].strip('_')}"
            with open(inner_sql, "r") as sf:
                subprocess.run(["mysql", target_db], stdin=sf)

        log_audit(session.get("username"), "BACKUP_RESTORE", f"Domain '{domain}' aus Backup #{backup_id} wiederhergestellt", request.remote_addr)
        flash(f"Domain '{domain}' erfolgreich wiederhergestellt!", "success")

    except Exception as e:
        flash(f"Wiederherstellung fehlgeschlagen: {e}", "error")
    finally:
        if os.path.exists(tmp_restore):
            shutil.rmtree(tmp_restore, ignore_errors=True)

    return redirect(url_for("backups.index"))

@backups_bp.route("/delete/<int:backup_id>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def delete_backup(backup_id):
    backup = query_db("SELECT * FROM backups WHERE id = ?", (backup_id,), one=True)
    if backup:
        if os.path.exists(backup["filepath"]):
            try:
                os.remove(backup["filepath"])
            except Exception:
                pass
        execute_db("DELETE FROM backups WHERE id = ?", (backup_id,))
        log_audit(session.get("username"), "BACKUP_DELETE", f"Backup #{backup_id} ({backup['filename']}) gelöscht", request.remote_addr, "warning")
        flash("Sicherungsdatei gelöscht.", "success")
    return redirect(url_for("backups.index"))
