import os
import re
import tarfile
import gzip
import shutil
import tempfile
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session
from config import WEB_ROOT_BASE, BACKUP_DIR
from modules.auth_users import login_required, role_required
from modules.system_agent import run_privileged
from db import query_db, execute_db, log_audit

backups_bp = Blueprint("backups", __name__, url_prefix="/backups")

# Obergrenzen für sichere Tar-Extraktion (SEC-007, SEC-014)
MAX_TAR_MEMBERS = 25000
MAX_TAR_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB

def safe_extract_tar(tar_path, dest_dir, max_files=MAX_TAR_MEMBERS, max_total_bytes=MAX_TAR_TOTAL_UNCOMPRESSED_BYTES):
    """
    Sicheres Entpacken von TAR-Archiven mit Anti-Tar-Slip Schutz (SEC-007):
    - Überprüfung aller Archivmitglieder vor der Extraktion
    - Verbot von absoluten Pfaden und '..'-Traversal
    - Verbot von Sonderdateien (FIFOs, Block-/Char-Devices)
    - Verbot von Symlinks und Hardlinks, die aus dem Zielordner ausbrechen
    - Obergrenzen für Dateianzahl und entpackte Gesamtgröße (Tar-Bomben Schutz)
    - Sichere Einzeldateiextraktion mit members-Filter
    """
    real_dest = os.path.realpath(dest_dir)
    os.makedirs(real_dest, exist_ok=True)

    with tarfile.open(tar_path, "r:*") as tar:
        members = tar.getmembers()
        if len(members) > max_files:
            raise ValueError(f"Sicherheitsrisiko (Tar-Bomb): Zu viele Dateien im Archiv ({len(members)} > {max_files})")

        total_bytes = 0
        safe_members = []
        for m in members:
            # 1. Dateiname normalisieren & Traversal prüfen
            fname = m.name.replace("\\", "/")
            if fname.startswith("/") or fname.startswith("\\"):
                raise ValueError(f"Sicherheitsrisiko (Tar-Slip): Absoluter Pfad im Archiv: {m.name}")
            parts = [p for p in fname.split("/") if p]
            if ".." in parts:
                raise ValueError(f"Sicherheitsrisiko (Tar-Slip): Traversal '..' im Pfad: {m.name}")

            # 2. Sonderdateien abweisen
            if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
                raise ValueError(f"Sicherheitsrisiko: Sonderdateien / Gerätedateien im Archiv abgewiesen: {m.name}")

            # 3. Kanonische Zielprüfung
            target_path = os.path.realpath(os.path.join(real_dest, fname))
            if os.path.commonpath([real_dest, target_path]) != real_dest:
                raise ValueError(f"Sicherheitsrisiko (Tar-Slip): Pfad bricht aus Zielordner aus: {m.name}")

            # 4. Symlinks & Hardlinks prüfen
            if m.issym() or m.islnk():
                link_target = m.linkname.replace("\\", "/")
                # Aufgelöstes Link-Ziel ermitteln
                resolved_link = os.path.realpath(os.path.join(os.path.dirname(target_path), link_target))
                if os.path.commonpath([real_dest, resolved_link]) != real_dest:
                    raise ValueError(f"Sicherheitsrisiko: Symlink/Hardlink '{m.name}' zeigt außerhalb des Zielordners ({m.linkname})")

            # 5. Größenprüfung gegen Tar-Bomben
            if m.size > 0:
                total_bytes += m.size
                if total_bytes > max_total_bytes:
                    raise ValueError(f"Sicherheitsrisiko (Tar-Bomb): Gesamtgröße überschritten ({total_bytes} > {max_total_bytes})")

            safe_members.append(m)

        # Sicher mit gefilterten Membern entpacken
        tar.extractall(real_dest, members=safe_members)

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
    domain_dir = os.path.realpath(os.path.join(WEB_ROOT_BASE, domain))
    base_web = os.path.realpath(WEB_ROOT_BASE)
    if os.path.commonpath([base_web, domain_dir]) != base_web:
        flash("Sicherheitsfehler: Ungültiger Domain-Pfad für Wiederherstellung.", "error")
        return redirect(url_for("backups.index"))

    tmp_restore = tempfile.mkdtemp(prefix=f"syscore_restore_{backup_id}_")

    try:
        # 1. Hauptarchiv sicher in Quarantäneverzeichnis entpacken (SEC-007)
        safe_extract_tar(backup["filepath"], tmp_restore)

        # 2. Webroot-Archiv prüfen & wiederherstellen
        inner_webroot = os.path.join(tmp_restore, "webroot.tar.gz")
        if os.path.exists(inner_webroot):
            os.makedirs(domain_dir, exist_ok=True)
            # Entpacken mit Anti-Tar-Slip direkt in das validierte Domain-Verzeichnis
            safe_extract_tar(inner_webroot, domain_dir)
            if shutil.which("chown"):
                run_privileged(["chown", "-R", "www-data:www-data", domain_dir])

        # 3. Datenbank wiederherstellen
        inner_sql = os.path.join(tmp_restore, "database.sql")
        if os.path.exists(inner_sql) and shutil.which("mysql"):
            clean_dom = re.sub(r"[^a-zA-Z0-9_]", "_", domain)[:14].strip("_")
            target_db = f"app_{clean_dom}"
            with open(inner_sql, "r", encoding="utf-8", errors="replace") as sf:
                subprocess.run(["mysql", target_db], stdin=sf, capture_output=True, text=True, shell=False)

        log_audit(session.get("username"), "BACKUP_RESTORE", f"Domain '{domain}' aus Backup #{backup_id} sicher wiederhergestellt", request.remote_addr)
        flash(f"Domain '{domain}' erfolgreich und sicher aus Sicherung wiederhergestellt!", "success")

    except Exception as e:
        flash(f"Wiederherstellung fehlgeschlagen (Sicherheitsabbruch): {e}", "error")
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
