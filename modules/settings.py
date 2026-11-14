import os
import re
import time
from datetime import datetime
import json
import glob
import shutil
import threading
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

def trigger_system_restart(delay_seconds=2):
    """
    Startet den SysCore Systemdienst entkoppelt und zuverlässig neu.
    Nutzt 'systemd-run' (transienter Timer außerhalb der Cgroup) oder detached Popen mit '--no-block',
    damit Systemd den Dienst nicht während des Restart-Aufrufs abbricht.
    """
    if os.name == "nt":
        return

    # 1. Bevorzugt: systemd-run erzeugt einen unabhängigen transienten Timer
    if shutil.which("systemd-run"):
        try:
            cmd = "systemctl restart syscore-panel || systemctl restart syscore"
            res = subprocess.run([
                "systemd-run",
                f"--on-active={delay_seconds}s",
                "--unit=syscore-auto-restart",
                "sh", "-c", cmd
            ], capture_output=True, text=True)
            if res.returncode == 0:
                return
        except Exception:
            pass

    # 2. Fallback: Vollständig entkoppelter Kindprozess mit setsid und --no-block
    try:
        cmd = f"sleep {delay_seconds}; systemctl restart --no-block syscore-panel || systemctl restart --no-block syscore"
        subprocess.Popen(
            ["sh", "-c", cmd],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )
    except Exception:
        pass

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

def get_panel_proxy_status():
    vhost_path = "/etc/nginx/sites-available/syscore-panel.panel.conf"
    if not os.path.exists(vhost_path):
        return {"configured": False, "domain": "", "ssl": False, "enabled": False}

    domain = ""
    ssl_active = False
    enabled = os.path.exists("/etc/nginx/sites-enabled/syscore-panel.panel.conf")

    try:
        with open(vhost_path, "r", encoding="utf-8") as f:
            content = f.read()
        m = re.search(r"server_name\s+([^;]+);", content)
        if m:
            domain = m.group(1).strip().split()[0]
        ssl_active = "ssl_certificate" in content or "443 ssl" in content
    except Exception:
        pass

    return {
        "configured": True,
        "domain": domain,
        "ssl": ssl_active,
        "enabled": enabled,
        "vhost_path": vhost_path
    }

def get_alert_settings():
    res = query_db("SELECT key, value FROM settings WHERE key LIKE 'alert_%'")
    alerts = {
        "discord_webhook": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "disk_threshold": "90",
        "service_down": "1",
        "exploit_alerts": "1"
    }
    for r in res:
        key_short = r["key"].replace("alert_", "")
        alerts[key_short] = r["value"]
    return alerts

def get_git_updater_status():
    local_hash = ""
    local_short = "v2.5"
    remote_hash = ""
    remote_short = ""
    is_up_to_date = True
    recent_commits = []
    base_dir = str(config.BASE_DIR)

    try:
        # Sicherstellen dass safe.directory konfiguriert ist
        subprocess.run(["git", "config", "--global", "--add", "safe.directory", base_dir], capture_output=True, timeout=2)

        # Prüfen ob origin existiert und auf das richtige Repo zeigt
        rem_check = subprocess.run(["git", "remote", "get-url", "origin"], cwd=base_dir, capture_output=True, text=True, timeout=2)
        if rem_check.returncode != 0:
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/AmFearLiath/SysCore.git"], cwd=base_dir, capture_output=True, timeout=2)
        elif "AmFearLiath/SysCore" not in rem_check.stdout:
            subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/AmFearLiath/SysCore.git"], cwd=base_dir, capture_output=True, timeout=2)

        res_loc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=base_dir, capture_output=True, text=True, timeout=3)
        if res_loc.returncode == 0 and res_loc.stdout.strip():
            local_hash = res_loc.stdout.strip()
            local_short = local_hash[:7]

        # Check remote main branch (mit Fallback auf direkte HTTPS URL)
        res_rem = subprocess.run(["git", "ls-remote", "origin", "-h", "refs/heads/main"], cwd=base_dir, capture_output=True, text=True, timeout=6)
        if res_rem.returncode != 0 or not res_rem.stdout.strip():
            res_rem = subprocess.run(["git", "ls-remote", "https://github.com/AmFearLiath/SysCore.git", "-h", "refs/heads/main"], cwd=base_dir, capture_output=True, text=True, timeout=6)

        if res_rem.returncode == 0 and res_rem.stdout.strip():
            remote_hash = res_rem.stdout.strip().split()[0]
            remote_short = remote_hash[:7]

        if remote_hash and local_hash:
            is_up_to_date = (remote_hash == local_hash)
        elif remote_hash and not local_hash:
            is_up_to_date = False

        # Letzte 10 Commits für Rollback auflisten
        res_log = subprocess.run(["git", "log", "-n", "10", "--pretty=format:%h|%s|%ad|%ar", "--date=short"], cwd=base_dir, capture_output=True, text=True, timeout=3)
        if res_log.returncode == 0 and res_log.stdout.strip():
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
    panel_proxy = get_panel_proxy_status()
    alert_settings = get_alert_settings()

    return render_template(
        "settings.html",
        active_tab=tab,
        user=user,
        users_list=users_list,
        audit_logs=audit_logs,
        server_info=server_info,
        pm2_procs=pm2_procs,
        updater_info=updater_info,
        panel_proxy=panel_proxy,
        alert_settings=alert_settings,
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
    base_dir = str(config.BASE_DIR)

    def generate():
        yield "data: === Starte SysCore System-Update von GitHub ===\n\n"
        
        # Sicherstellen dass safe.directory und origin sauber konfiguriert sind
        subprocess.run(["git", "config", "--global", "--add", "safe.directory", base_dir], capture_output=True)
        subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/AmFearLiath/SysCore.git"], cwd=base_dir, capture_output=True)

        # 1. Snapshot Tag anlegen zur Rollback-Sicherheit
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        tag_name = f"syscore-backup-{timestamp}"
        yield f"data: [1/4] Erstelle Sicherheits-Snapshot Tag: {tag_name}...\n\n"
        subprocess.run(["git", "tag", tag_name], cwd=base_dir, capture_output=True)

        # 2. Git Fetch & Pull
        yield "data: [2/4] Ziehe neuesten Code von origin/main...\n\n"
        subprocess.run(["git", "fetch", "origin", "main"], cwd=base_dir, capture_output=True, timeout=15)
        proc = subprocess.Popen(["git", "pull", "--rebase=false", "origin", "main"], cwd=base_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            yield f"data: {line.strip()}\n\n"
        proc.wait()

        if proc.returncode != 0:
            yield "data: [Hinweis] Synchronisiere Arbeitskopie mit origin/main...\n\n"
            reset_proc = subprocess.Popen(["git", "reset", "--hard", "origin/main"], cwd=base_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in reset_proc.stdout:
                yield f"data: {line.strip()}\n\n"
            reset_proc.wait()

        # 3. Pip dependencies & DB migration
        yield "data: [3/4] Prüfe Abhängigkeiten & führe Datenbank-Migrationen aus...\n\n"
        if shutil.which("pip3"):
            pip_cmd = ["pip3", "install", "-r", "requirements.txt", "--break-system-packages"]
            try:
                pip_res = subprocess.run(pip_cmd, cwd=base_dir, capture_output=True, text=True, timeout=60)
                if pip_res.returncode == 0:
                    yield "data: Python Abhängigkeiten verifiziert.\n\n"
                else:
                    yield f"data: Pip Info: {pip_res.stderr[:100]}\n\n"
            except Exception as e:
                yield f"data: Pip Warnung: {e}\n\n"

        try:
            import db
            db.init_db()
            yield "data: SQLite Datenbanktabellen erfolgreich verifiziert & migriert.\n\n"
        except Exception as e:
            yield f"data: [WARNUNG] DB Init: {e}\n\n"

        # 4. Service Reload mit Verzögerung (damit HTTP Stream sauber beendet wird)
        yield "data: [4/4] Aktualisierung abgeschlossen! Server-Dienst startet in 2 Sekunden automatisch neu...\n\n"
        yield "data: [ERFOLG] SysCore erfolgreich auf die neueste Version aktualisiert!\n\n"
        log_audit(session.get("username"), "SYSTEM_UPDATE_FINISH", "SysCore Update erfolgreich abgeschlossen", request.remote_addr)

        trigger_system_restart(delay_seconds=2)

    def safe_generate():
        try:
            for item in generate():
                yield item
        except Exception as e:
            yield f"data: [FEHLER BEIM UPDATE] {e}\n\n"

    return Response(safe_generate(), mimetype="text/event-stream")

@settings_bp.route("/updater/rollback/<commit_hash>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def run_system_rollback(commit_hash):
    """Setzt SysCore auf einen früheren Git-Commit zurück"""
    if not re.match(r"^[a-f0-9]{7,40}$", commit_hash):
        flash("Ungültiger Commit-Hash.", "error")
        return redirect(url_for("settings.index", tab="updates"))

    base_dir = str(config.BASE_DIR)
    res = subprocess.run(["git", "checkout", commit_hash], cwd=base_dir, capture_output=True, text=True)
    if res.returncode == 0:
        trigger_system_restart(delay_seconds=2)
        log_audit(session.get("username"), "SYSTEM_ROLLBACK", f"SysCore auf Commit '{commit_hash}' zurückgesetzt", request.remote_addr, "warning")
        flash(f"SysCore erfolgreich auf Commit {commit_hash} zurückgesetzt! Dienst startet neu...", "success")
    else:
        flash(f"Rollback fehlgeschlagen: {res.stderr}", "error")

    return redirect(url_for("settings.index", tab="updates"))

@settings_bp.route("/panel-proxy/setup", methods=["POST"])
@login_required
@role_required(["root_admin"])
def setup_panel_proxy():
    domain = request.form.get("domain", "").strip().lower()
    enable_ssl = request.form.get("enable_ssl") == "1"
    certbot_email = request.form.get("certbot_email", "").strip() or config.CERTBOT_EMAIL

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        flash("Ungültiger Domainname für das Panel.", "error")
        return redirect(url_for("settings.index", tab="panel_ssl"))

    vhost_avail = "/etc/nginx/sites-available/syscore-panel.panel.conf"
    vhost_enabled = "/etc/nginx/sites-enabled/syscore-panel.panel.conf"

    # NGINX Reverse-Proxy VHost generieren
    vhost_content = f"""# ==============================================================================
# SysCore Next-Gen Management Panel NGINX Reverse Proxy
# Domain: {domain}
# ==============================================================================

server {{
    listen 80;
    server_name {domain};

    client_max_body_size 512M;

    location / {{
        proxy_pass http://127.0.0.1:{config.PANEL_PORT};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket-Unterstützung für Live-Terminals & SSE
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }}
}}
"""

    try:
        os.makedirs("/etc/nginx/sites-available", exist_ok=True)
        os.makedirs("/etc/nginx/sites-enabled", exist_ok=True)

        with open(vhost_avail, "w", encoding="utf-8") as f:
            f.write(vhost_content)

        if not os.path.exists(vhost_enabled):
            try:
                os.symlink(vhost_avail, vhost_enabled)
            except OSError:
                pass

        # NGINX Syntax-Test
        if shutil.which("nginx"):
            test_res = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            if test_res.returncode != 0:
                if os.path.exists(vhost_enabled):
                    try: os.remove(vhost_enabled)
                    except OSError: pass
                flash(f"NGINX Syntaxprüfung fehlgeschlagen: {test_res.stderr}", "error")
                return redirect(url_for("settings.index", tab="panel_ssl"))

            subprocess.run(["systemctl", "reload", "nginx"], check=False)

        # SSL via Certbot einrichten
        ssl_success = False
        if enable_ssl and shutil.which("certbot"):
            cmd = ["certbot", "--nginx", "-d", domain, "--non-interactive", "--agree-tos", "--redirect"]
            if certbot_email and "@" in certbot_email:
                cmd.extend(["--email", certbot_email])
            else:
                cmd.append("--register-unsafely-without-email")

            cert_res = subprocess.run(cmd, capture_output=True, text=True)
            if cert_res.returncode == 0:
                ssl_success = True
            else:
                flash(f"VHost erstellt, aber Certbot meldete einen Fehler: {cert_res.stderr[:200]}", "warning")

        execute_db("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_domain', ?)", (domain,))
        log_audit(session.get("username"), "PANEL_SSL_PROXY_SETUP", f"Panel-Proxy für '{domain}' (SSL: {ssl_success}) eingerichtet", request.remote_addr)
        
        protocol = "https" if ssl_success else "http"
        flash(f"SysCore Panel erfolgreich unter {protocol}://{domain} bereitgestellt!", "success")
    except Exception as e:
        flash(f"Fehler beim Einrichten des Panel-Proxies: {e}", "error")

    return redirect(url_for("settings.index", tab="panel_ssl"))

@settings_bp.route("/panel-proxy/custom-ssl", methods=["POST"])
@login_required
@role_required(["root_admin"])
def save_custom_ssl():
    domain = request.form.get("domain", "").strip().lower()
    cert_data = request.form.get("ssl_certificate", "").strip()
    key_data = request.form.get("ssl_key", "").strip()

    if not domain or not cert_data or not key_data:
        flash("Domain, Zertifikat und Private-Key müssen ausgefüllt sein.", "error")
        return redirect(url_for("settings.index", tab="panel_ssl"))

    ssl_dir = f"/etc/ssl/syscore"
    try:
        os.makedirs(ssl_dir, exist_ok=True)
        cert_file = f"{ssl_dir}/{domain}.crt"
        key_file = f"{ssl_dir}/{domain}.key"

        with open(cert_file, "w", encoding="utf-8") as f:
            f.write(cert_data)
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(key_data)

        try:
            os.chmod(key_file, 0o600)
        except Exception:
            pass

        # NGINX VHost mit Custom SSL anpassen
        vhost_avail = "/etc/nginx/sites-available/syscore-panel.panel.conf"
        vhost_content = f"""server {{
    listen 80;
    server_name {domain};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    ssl_certificate {cert_file};
    ssl_certificate_key {key_file};

    client_max_body_size 512M;

    location / {{
        proxy_pass http://127.0.0.1:{config.PANEL_PORT};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
    }}
}}
"""
        with open(vhost_avail, "w", encoding="utf-8") as f:
            f.write(vhost_content)

        if shutil.which("nginx"):
            test_res = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            if test_res.returncode != 0:
                flash(f"SSL-Zertifikat ungültig (NGINX Test fehlgeschlagen): {test_res.stderr}", "error")
                return redirect(url_for("settings.index", tab="panel_ssl"))
            subprocess.run(["systemctl", "reload", "nginx"], check=False)

        log_audit(session.get("username"), "PANEL_CUSTOM_SSL", f"Custom SSL für {domain} hinterlegt", request.remote_addr)
        flash(f"Custom SSL-Zertifikat für {domain} erfolgreich aktiviert!", "success")
    except Exception as e:
        flash(f"Fehler beim Speichern des Zertifikats: {e}", "error")

    return redirect(url_for("settings.index", tab="panel_ssl"))

@settings_bp.route("/alerts/save", methods=["POST"])
@login_required
@role_required(["root_admin"])
def save_alerts():
    discord = request.form.get("discord_webhook", "").strip()
    tg_token = request.form.get("telegram_bot_token", "").strip()
    tg_chat = request.form.get("telegram_chat_id", "").strip()
    disk_thresh = request.form.get("disk_threshold", "90").strip()

    execute_db("INSERT OR REPLACE INTO settings (key, value) VALUES ('alert_discord_webhook', ?)", (discord,))
    execute_db("INSERT OR REPLACE INTO settings (key, value) VALUES ('alert_telegram_bot_token', ?)", (tg_token,))
    execute_db("INSERT OR REPLACE INTO settings (key, value) VALUES ('alert_telegram_chat_id', ?)", (tg_chat,))
    execute_db("INSERT OR REPLACE INTO settings (key, value) VALUES ('alert_disk_threshold', ?)", (disk_thresh,))

    log_audit(session.get("username"), "ALERTS_SETTINGS_SAVE", "Benachrichtigungseinstellungen aktualisiert", request.remote_addr)
    flash("Server-Health Benachrichtigungseinstellungen erfolgreich gespeichert.", "success")
    return redirect(url_for("settings.index", tab="alerts"))

@settings_bp.route("/alerts/test", methods=["POST"])
@login_required
@role_required(["root_admin"])
def test_alert():
    discord_url = request.form.get("discord_webhook", "").strip()
    if not discord_url:
        res = query_db("SELECT value FROM settings WHERE key = 'alert_discord_webhook'", one=True)
        if res: discord_url = res["value"]

    if discord_url and discord_url.startswith("http"):
        try:
            import urllib.request
            payload = {
                "username": "SysCore Sentinel",
                "embeds": [{
                    "title": "🛡️ SysCore Server-Health Test-Alarm",
                    "description": "Die Benachrichtigungs-Schnittstelle von SysCore funktioniert einwandfrei!",
                    "color": 1095937, # Emerald
                    "fields": [
                        {"name": "Server-Host", "value": config.PANEL_HOST, "inline": True},
                        {"name": "Status", "value": "🟢 Alle Dienste online", "inline": True},
                        {"name": "Ausgelöst durch", "value": session.get("username", "admin"), "inline": True}
                    ],
                    "footer": {"text": "SysCore Next-Gen Server Management"}
                }]
            }
            req = urllib.request.Request(
                discord_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "SysCore/2.5"}
            )
            urllib.request.urlopen(req, timeout=5)
            flash("Test-Benachrichtigung erfolgreich an Discord gesendet!", "success")
        except Exception as e:
            flash(f"Fehler beim Senden an Discord Webhook: {e}", "error")
    else:
        flash("Bitte trage zuerst eine gültige Discord Webhook-URL ein.", "warning")

    return redirect(url_for("settings.index", tab="alerts"))


