import os
import re
import tempfile
import shutil
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, session
from modules.auth_users import login_required, role_required
from db import log_audit

database_bp = Blueprint("database", __name__, url_prefix="/db")
SYSTEM_DBS = {"information_schema", "mysql", "performance_schema", "sys", "pterodactyl"}

def run_mysql(query):
    if not shutil.which("mysql"):
        return False, "", "Entwicklungsumgebung: MySQL CLI nicht verfügbar"
    res = subprocess.run(["mysql", "-N", "-e", query], capture_output=True, text=True)
    return res.returncode == 0, res.stdout.strip(), res.stderr.strip()

@database_bp.route("/")
@login_required
@role_required(["root_admin", "web_admin"])
def index():
    ok, out, _ = run_mysql("SHOW DATABASES;")
    databases = []
    if ok:
        for db in out.splitlines():
            if db in SYSTEM_DBS:
                continue
            q = f"SELECT COUNT(*), IFNULL(ROUND(SUM(data_length + index_length) / 1024 / 1024, 2), 0) FROM information_schema.tables WHERE table_schema = '{db}';"
            ok_s, stats_out, _ = run_mysql(q)
            tables, size_mb = ("0", "0.00")
            if ok_s and "\t" in stats_out:
                tables, size_mb = stats_out.split("\t")
            databases.append({"name": db, "tables": tables, "size_mb": size_mb})

    # DB-Benutzer
    ok_u, users_out, _ = run_mysql("SELECT User, Host FROM mysql.user WHERE User NOT IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint', 'pterodactyl');")
    users = []
    if ok_u:
        for line in users_out.splitlines():
            if "\t" in line:
                u, h = line.split("\t")
                users.append({"user": u, "host": h})

    # Prüfen ob phpMyAdmin verfügbar ist
    pma_installed = os.path.exists("/var/www/phpmyadmin")

    return render_template("database.html", databases=databases, users=users, pma_installed=pma_installed)

@database_bp.route("/create", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def create_db():
    db_name = request.form.get("db_name", "").strip()
    db_user = request.form.get("db_user", "").strip()
    db_pass = request.form.get("db_pass", "").strip()

    if not re.match(r"^[a-zA-Z0-9_]{2,32}$", db_name) or not re.match(r"^[a-zA-Z0-9_]{2,32}$", db_user):
        flash("Datenbank- und Benutzername dürfen nur Buchstaben, Zahlen und Unterstriche enthalten (2-32 Zeichen).", "error")
        return redirect(url_for("database.index"))

    if "'" in db_pass or "\\" in db_pass or len(db_pass) < 6:
        flash("Passwort muss mind. 6 Zeichen lang sein und darf keine einfachen Anführungszeichen enthalten.", "error")
        return redirect(url_for("database.index"))

    sql = (
        f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; "
        f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}'; "
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; "
        f"FLUSH PRIVILEGES;"
    )
    ok, _, err = run_mysql(sql)
    if ok:
        log_audit(session.get("username"), "DB_CREATE", f"Datenbank '{db_name}' & Benutzer '{db_user}' angelegt", request.remote_addr)
        flash(f"Datenbank '{db_name}' und Benutzer '{db_user}' erfolgreich erstellt.", "success")
    else:
        flash(f"MySQL Fehler: {err}", "error")
    return redirect(url_for("database.index"))

@database_bp.route("/user/reset-password", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def reset_db_password():
    db_user = request.form.get("db_user", "").strip()
    db_host = request.form.get("db_host", "localhost").strip()
    new_pass = request.form.get("new_pass", "").strip()

    if not re.match(r"^[a-zA-Z0-9_]{2,32}$", db_user) or db_user in ["root", "pterodactyl"]:
        flash("Ungültiger oder geschützter DB-Benutzer.", "error")
        return redirect(url_for("database.index"))

    if "'" in new_pass or "\\" in new_pass or len(new_pass) < 6:
        flash("Passwort muss mind. 6 Zeichen lang sein.", "error")
        return redirect(url_for("database.index"))

    sql = f"ALTER USER '{db_user}'@'{db_host}' IDENTIFIED BY '{new_pass}'; FLUSH PRIVILEGES;"
    ok, _, err = run_mysql(sql)
    if ok:
        log_audit(session.get("username"), "DB_USER_PASS_RESET", f"Passwort für '{db_user}'@'{db_host}' zurückgesetzt", request.remote_addr)
        flash(f"Passwort für DB-Benutzer '{db_user}' erfolgreich geändert.", "success")
    else:
        flash(f"Fehler beim Ändern des Passworts: {err}", "error")
    return redirect(url_for("database.index"))

@database_bp.route("/export/<db_name>")
@login_required
@role_required(["root_admin", "web_admin"])
def export_db(db_name):
    if db_name in SYSTEM_DBS or not re.match(r"^[a-zA-Z0-9_]{2,32}$", db_name):
        flash("Ungültige oder geschützte Datenbank.", "error")
        return redirect(url_for("database.index"))

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sql")
    tmp.close()

    if not shutil.which("mysqldump"):
        flash("mysqldump CLI nicht verfügbar.", "error")
        return redirect(url_for("database.index"))

    res = subprocess.run(["mysqldump", db_name], stdout=open(tmp.name, "w"), stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        os.remove(tmp.name)
        flash(f"Export fehlgeschlagen: {res.stderr}", "error")
        return redirect(url_for("database.index"))

    log_audit(session.get("username"), "DB_EXPORT", f"Dump für '{db_name}' exportiert", request.remote_addr)
    return send_file(tmp.name, as_attachment=True, download_name=f"{db_name}_backup.sql")

@database_bp.route("/import/<db_name>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def import_db(db_name):
    if db_name in SYSTEM_DBS or not re.match(r"^[a-zA-Z0-9_]{2,32}$", db_name):
        flash("Ungültige Datenbank.", "error")
        return redirect(url_for("database.index"))

    file = request.files.get("sql_file")
    if not file or not file.filename.endswith(".sql"):
        flash("Bitte eine gültige .sql Datei hochladen.", "error")
        return redirect(url_for("database.index"))

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sql")
    file.save(tmp.name)
    tmp.close()

    res = None
    if shutil.which("mysql"):
        with open(tmp.name, "r", encoding="utf-8", errors="replace") as f:
            res = subprocess.run(["mysql", db_name], stdin=f, capture_output=True, text=True)
    os.remove(tmp.name)

    if res and res.returncode == 0:
        log_audit(session.get("username"), "DB_IMPORT", f"SQL Dump in '{db_name}' importiert", request.remote_addr)
        flash(f"SQL-Dump erfolgreich in '{db_name}' importiert.", "success")
    else:
        err = res.stderr if res else "MySQL CLI nicht verfügbar"
        flash(f"Import-Fehler: {err}", "error")

    return redirect(url_for("database.index"))

@database_bp.route("/delete/<db_name>", methods=["POST"])
@login_required
@role_required(["root_admin", "web_admin"])
def delete_db(db_name):
    if db_name in SYSTEM_DBS or not re.match(r"^[a-zA-Z0-9_]{2,32}$", db_name):
        flash("Geschützte Datenbank kann nicht gelöscht werden.", "error")
        return redirect(url_for("database.index"))

    ok, _, err = run_mysql(f"DROP DATABASE `{db_name}`;")
    if ok:
        log_audit(session.get("username"), "DB_DROP", f"Datenbank '{db_name}' gelöscht", request.remote_addr, "warning")
        flash(f"Datenbank '{db_name}' gelöscht.", "success")
    else:
        flash(f"Fehler: {err}", "error")
    return redirect(url_for("database.index"))
