import os
import re
import json
import glob
import shutil
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, Response
from modules.auth_users import login_required, role_required, current_user
from db import query_db, execute_db, log_audit, get_db
import config

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")

NGINX_DROPIN = "/etc/nginx/conf.d/99-syscore.conf"

def get_current_timezone():
    if shutil.which("timedatectl"):
        try:
            res = subprocess.run(["timedatectl", "show", "--property=Timezone", "--value"], capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return "Europe/Berlin"

def get_swap_info():
    if shutil.which("swapon"):
        try:
            res = subprocess.run(["swapon", "--show", "--noheadings"], capture_output=True, text=True)
            return bool(res.stdout.strip())
        except Exception:
            pass
    return False

def get_pm2_processes():
    if not shutil.which("pm2"):
        return []
    try:
        res = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            processes = []
            for p in data:
                processes.append({
                    "id": p.get("pm_id"),
                    "name": p.get("name"),
                    "status": p.get("pm2_env", {}).get("status", "unknown"),
                    "cpu": p.get("monit", {}).get("cpu", 0),
                    "memory": round(p.get("monit", {}).get("memory", 0) / (1024 * 1024), 1),
                    "uptime": p.get("pm2_env", {}).get("pm_uptime")
                })
            return processes
    except Exception:
        pass
    return []

def get_certbot_timer_status():
    if shutil.which("systemctl"):
        try:
            res = subprocess.run(["systemctl", "is-active", "certbot.timer"], capture_output=True, text=True)
            return res.stdout.strip() == "active"
        except Exception:
            pass
    return False

def get_git_updater_status():
    local_hash = ""
    local_short = "v2.5"
    remote_hash = ""
    remote_short = ""
    is_up_to_date = True
    recent_commits = []

    try:
        res_loc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=3)
        if res_loc.returncode == 0:
            local_hash = res_loc.stdout.strip()
            local_short = local_hash[:7]

        # Check remote main branch
        res_rem = subprocess.run(["git", "ls-remote", "origin", "-h", "refs/heads/main"], capture_output=True, text=True, timeout=5)
        if res_rem.returncode == 0 and res_rem.stdout.strip():
            remote_hash = res_rem.stdout.strip().split()[0]
            remote_short = remote_hash[:7]

        if remote_hash and local_hash:
            is_up_to_date = (remote_hash == local_hash)

        # Letzte 10 Commits für Rollback auflisten
        res_log = subprocess.run(["git", "log", "-n", "10", "--pretty=format:%h|%s|%ad|%ar", "--date=short"], capture_output=True, text=True, timeout=3)
        if res_log.returncode == 0:
            for line in res_log.stdout.splitlines():
                parts = line.split("|")
                if len(parts) == 4:
                    recent_commits.append({
                        "hash": parts[0],
                        "msg": parts[1],
                        "date": parts[2],
                        "rel_date": parts[3],
                        "is_current": (parts[0] == local_short)
                    })
    except Exception as e:
        print(f"[Updater Error] {e}")

    return {
        "local_hash": local_hash,
        "local_short": local_short,
        "remote_hash": remote_hash,
        "remote_short": remote_short,
        "is_up_to_date": is_up_to_date,
        "recent_commits": recent_commits
    }

def read_global_nginx_limits():
    limits = {"client_max_body_size": "64M"}
    if os.path.exists(NGINX_DROPIN):
        try:
            with open(NGINX_DROPIN, "r", encoding="utf-8") as f:
                content = f.read()
            m = re.search(r"client_max_body_size\s+([^;]+);", content)
            if m:
                limits["client_max_body_size"] = m.group(1).strip()
        except Exception:
            pass
    return limits

def read_global_php_limits():
    limits = {
        "memory_limit": "256M",
        "upload_max_filesize": "64M",
        "post_max_size": "64M",
        "max_execution_time": "120"
    }
    # Check drop-in in /etc/php/*/fpm/conf.d/99-syscore.ini
    ini_files = glob.glob("/etc/php/*/fpm/conf.d/99-syscore.ini")
    if ini_files and os.path.exists(ini_files[0]):
        try:
            with open(ini_files[0], "r", encoding="utf-8") as f:
                c = f.read()
            for k in limits.keys():
                m = re.search(rf"^{k}\s*=\s*(.+)$", c, re.MULTILINE)
                if m:
                    limits[k] = m.group(1).strip()
        except Exception:
            pass
    return limits

@settings_bp.route("/")
@login_required
def index():
    tab = request.args.get("tab", "server")
    user = current_user()
    user_role = session.get("role", "monitor")

    # Nur root_admin hat Zugriff auf Server- & globale Diensttuning-Optionen
    if user_role != "root_admin" and tab in ["server", "tuning", "users"]:
        tab = "security"

    users_list = []
    audit_logs = []
    if user_role == "root_admin":
        users_list = query_db("SELECT id, username, role, email, totp_enabled, created_at, last_login FROM users ORDER BY id ASC")
        audit_logs = query_db("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50")

    server_info = {
        "timezone": get_current_timezone(),
        "swap_active": get_swap_info(),
        "certbot_email": config.CERTBOT_EMAIL,
        "certbot_timer": get_certbot_timer_status(),
        "nginx_limits": read_global_nginx_limits(),
        "php_limits": read_global_php_limits()
    }

    pm2_procs = get_pm2_processes()
    updater_info = get_git_updater_status()

    return render_template(
        "settings.html",
        active_tab=tab,
        user=user,
        users_list=users_list,
        audit_logs=audit_logs,
        server_info=server_info,
        pm2_procs=pm2_procs,
        updater_info=updater_info,
        user_role=user_role
    )

@settings_bp.route("/server/timezone", methods=["POST"])
@login_required
@role_required(["root_admin"])
def set_timezone():
    tz = request.form.get("timezone", "").strip()
    if re.match(r"^[A-Za-z0-9_/-]{2,64}$", tz):
        if shutil.which("timedatectl"):
            subprocess.run(["timedatectl", "set-timezone", tz])
        log_audit(session.get("username"), "TIMEZONE_CHANGE", f"Zeitzone geändert auf {tz}", request.remote_addr)
        flash(f"Zeitzone auf {tz} geändert.", "success")
    else:
        flash("Ungültige Zeitzone.", "error")
    return redirect(url_for("settings.index", tab="server"))

@settings_bp.route("/server/swap", methods=["POST"])
@login_required
@role_required(["root_admin"])
def configure_swap():
    action = request.form.get("action", "")
    if action == "create_2g":
        if shutil.which("fallocate"):
            subprocess.run(["fallocate", "-l", "2G", "/swapfile"])
            subprocess.run(["chmod", "600", "/swapfile"])
            subprocess.run(["mkswap", "/swapfile"])
            subprocess.run(["swapon", "/swapfile"])
            log_audit(session.get("username"), "SWAP_CREATE", "2GB Swap-Speicher aktiviert", request.remote_addr)
            flash("2GB Swap-Speicher erfolgreich angelegt und aktiviert.", "success")
    elif action == "disable":
        if shutil.which("swapoff"):
            subprocess.run(["swapoff", "-a"])
            log_audit(session.get("username"), "SWAP_DISABLE", "Swap-Speicher deaktiviert", request.remote_addr, "warning")
            flash("Swap-Speicher deaktiviert.", "success")
    return redirect(url_for("settings.index", tab="server"))

@settings_bp.route("/tuning/save", methods=["POST"])
@login_required
@role_required(["root_admin"])
def save_tuning():
    client_max_body = request.form.get("client_max_body_size", "64M").strip()
    memory_limit = request.form.get("memory_limit", "256M").strip()
    upload_max = request.form.get("upload_max_filesize", "64M").strip()
    post_max = request.form.get("post_max_size", "64M").strip()
    max_exec = request.form.get("max_execution_time", "120").strip()

    # NGINX Drop-In
    os.makedirs("/etc/nginx/conf.d", exist_ok=True)
    nginx_content = f"# Generiert durch SysCore Settings Hub\nclient_max_body_size {client_max_body};\n"
    try:
        with open(NGINX_DROPIN, "w", encoding="utf-8") as f:
            f.write(nginx_content)
        if shutil.which("nginx"):
            subprocess.run(["nginx", "-t"], capture_output=True)
            subprocess.run(["systemctl", "reload", "nginx"], check=False)
    except Exception:
        pass

    # PHP Drop-Ins für alle installierten FPM-Versionen
    php_content = f"""; Generiert durch SysCore Settings Hub
memory_limit = {memory_limit}
upload_max_filesize = {upload_max}
post_max_size = {post_max}
max_execution_time = {max_exec}
"""
    for fpm_dir in glob.glob("/etc/php/*/fpm/conf.d"):
        try:
            with open(os.path.join(fpm_dir, "99-syscore.ini"), "w", encoding="utf-8") as f:
                f.write(php_content)
        except Exception:
            pass

    # PHP-FPM neuladen
    for svc in glob.glob("/run/php/php*-fpm.sock"):
        m = re.search(r"php(\d+\.\d+)-fpm", svc)
        if m and shutil.which("systemctl"):
            subprocess.run(["systemctl", "reload", f"php{m.group(1)}-fpm"], check=False)

    log_audit(session.get("username"), "GLOBAL_LIMITS_TUNING", "Globale NGINX & PHP Limits gespeichert", request.remote_addr)
    flash("Globale Limits für NGINX und PHP erfolgreich gespeichert und Dienste neu geladen.", "success")
    return redirect(url_for("settings.index", tab="tuning"))

@settings_bp.route("/certbot/dry-run", methods=["POST"])
@login_required
@role_required(["root_admin"])
def certbot_dry_run():
    if not shutil.which("certbot"):
        flash("Certbot ist nicht installiert.", "error")
        return redirect(url_for("settings.index", tab="server"))

    res = subprocess.run(["certbot", "renew", "--dry-run"], capture_output=True, text=True, timeout=60)
    if res.returncode == 0:
        flash("Certbot Dry-Run erfolgreich! Alle Zertifikate können erneuert werden.", "success")
    else:
        flash(f"Certbot Dry-Run Warnung: {res.stderr[:200]}", "warning")
    return redirect(url_for("settings.index", tab="server"))

@settings_bp.route("/pm2/action/<int:pm_id>/<action>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def pm2_action(pm_id, action):
    if action in ["restart", "stop", "delete"] and shutil.which("pm2"):
        subprocess.run(["pm2", action, str(pm_id)])
        log_audit(session.get("username"), f"PM2_{action.upper()}", f"PM2 Prozess #{pm_id} -> {action}", request.remote_addr)
        flash(f"PM2 Prozess #{pm_id} -> {action} ausgeführt.", "success")
    return redirect(url_for("settings.index", tab="pm2"))

@settings_bp.route("/updater/update", methods=["POST"])
@login_required
@role_required(["root_admin"])
def run_system_update():
    """Führt ein 1-Klick Git-Update mit Live-Streaming im Terminal Drawer aus"""
    log_audit(session.get("username"), "SYSTEM_UPDATE_START", "SysCore Auto-Update von GitHub gestartet", request.remote_addr)

    def generate():
        yield "data: === Starte SysCore System-Update von GitHub ===\n\n"
        
        # 1. Snapshot Tag anlegen zur Rollback-Sicherheit
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        tag_name = f"syscore-backup-{timestamp}"
        yield f"data: [1/4] Erstelle Sicherheits-Snapshot Tag: {tag_name}...\n\n"
        subprocess.run(["git", "tag", tag_name], capture_output=True)

        # 2. Git Pull
        yield "data: [2/4] Ziehe neuesten Code von origin/main...\n\n"
        proc = subprocess.Popen(["git", "pull", "origin", "main"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            yield f"data: {line.strip()}\n\n"
        proc.wait()

        # 3. Pip dependencies & DB migration
        yield "data: [3/4] Prüfe Abhängigkeiten & führe Datenbank-Migrationen aus...\n\n"
        try:
            import db
            db.init_db()
            yield "data: SQLite Datenbanktabellen erfolgreich verifiziert & migriert.\n\n"
        except Exception as e:
            yield f"data: [WARNUNG] DB Init: {e}\n\n"

        # 4. Service Reload
        yield "data: [4/4] Starte SysCore Daemon neu...\n\n"
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "restart", "syscore"], check=False)
            yield "data: Systemd Service 'syscore' neu gestartet.\n\n"

        yield "data: [ERFOLG] SysCore erfolgreich auf die neueste Version aktualisiert!\n\n"
        log_audit(session.get("username"), "SYSTEM_UPDATE_FINISH", "SysCore Update erfolgreich abgeschlossen", request.remote_addr)

    return Response(generate(), mimetype="text/event-stream")

@settings_bp.route("/updater/rollback/<commit_hash>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def run_system_rollback(commit_hash):
    """Setzt SysCore auf einen früheren Git-Commit zurück"""
    if not re.match(r"^[a-f0-9]{7,40}$", commit_hash):
        flash("Ungültiger Commit-Hash.", "error")
        return redirect(url_for("settings.index", tab="updates"))

    res = subprocess.run(["git", "checkout", commit_hash], capture_output=True, text=True)
    if res.returncode == 0:
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "restart", "syscore"], check=False)
        log_audit(session.get("username"), "SYSTEM_ROLLBACK", f"SysCore auf Commit '{commit_hash}' zurückgesetzt", request.remote_addr, "warning")
        flash(f"SysCore erfolgreich auf Commit {commit_hash} zurückgesetzt!", "success")
    else:
        flash(f"Rollback fehlgeschlagen: {res.stderr}", "error")

    return redirect(url_for("settings.index", tab="updates"))

