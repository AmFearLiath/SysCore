import os
import re
import time
import shutil
import platform
import subprocess
import psutil
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, session
from config import MANAGED_SERVICES
from modules.auth_users import login_required, role_required
from db import log_audit

system_bp = Blueprint("system", __name__)

# Cache für Netzwerk-Geschwindigkeitsmessung
_last_net_check = {"time": time.time(), "bytes_recv": 0, "bytes_sent": 0}
try:
    _net = psutil.net_io_counters()
    _last_net_check["bytes_recv"] = _net.bytes_recv
    _last_net_check["bytes_sent"] = _net.bytes_sent
except Exception:
    pass

def get_platform_info():
    uname = platform.uname()
    return {
        "hostname": uname.node,
        "os": f"{uname.system} {uname.release}",
        "arch": uname.machine,
        "python": platform.python_version()
    }

def get_active_services():
    services = {}
    has_systemctl = shutil.which("systemctl") is not None

    for svc in MANAGED_SERVICES:
        if has_systemctl:
            try:
                # Prüfen ob Service unit existiert
                check = subprocess.run(["systemctl", "list-unit-files", f"{svc}.service"], capture_output=True, text=True, timeout=2)
                if svc in check.stdout:
                    res = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=2)
                    services[svc] = res.stdout.strip() == "active"
                else:
                    services[svc] = False
            except Exception:
                services[svc] = False
        else:
            # Fallback für Development-Modus
            services[svc] = False
    return services

def get_ufw_rules():
    if not shutil.which("ufw"):
        return False, []
    try:
        res = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True, timeout=3)
        if "inactive" in res.stdout.lower():
            return False, []
        rules = []
        for line in res.stdout.splitlines():
            match = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line.strip())
            if match:
                rules.append({"id": match.group(1), "rule": match.group(2)})
        return True, rules
    except Exception:
        return False, []

def get_top_processes(limit=8):
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            if info['name']:
                procs.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "user": info['username'] or "root",
                    "cpu": round(info['cpu_percent'] or 0.0, 1),
                    "mem": round(info['memory_percent'] or 0.0, 1)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: (x['cpu'], x['mem']), reverse=True)
    return procs[:limit]

@system_bp.route("/")
@login_required
def index():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    uptime_sec = time.time() - psutil.boot_time()
    days, rem = divmod(int(uptime_sec), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    load_avg = [0.0, 0.0, 0.0]
    if hasattr(os, "getloadavg"):
        try:
            load_avg = [round(x, 2) for x in os.getloadavg()]
        except Exception:
            pass

    stats = {
        "hostname": platform.node(),
        "cpu": psutil.cpu_percent(interval=0.1),
        "cpu_cores": psutil.cpu_count(logical=True),
        "cpu_freq": round(psutil.cpu_freq().current, 0) if psutil.cpu_freq() else 0,
        "ram_used": round(mem.used / (1024**3), 2),
        "ram_total": round(mem.total / (1024**3), 2),
        "ram_percent": mem.percent,
        "swap_used": round(swap.used / (1024**3), 2),
        "swap_total": round(swap.total / (1024**3), 2),
        "swap_percent": swap.percent,
        "disk_used": round(disk.used / (1024**3), 1),
        "disk_total": round(disk.total / (1024**3), 1),
        "disk_percent": disk.percent,
        "uptime": f"{days}d {hours}h {minutes}m",
        "load_avg": load_avg,
    }

    services = get_active_services()
    ufw_active, ufw_rules = get_ufw_rules()
    processes = get_top_processes()
    plat_info = get_platform_info()

    return render_template("system.html", stats=stats, services=services, ufw_active=ufw_active, ufw_rules=ufw_rules, processes=processes, plat_info=plat_info)

# ==========================================
# Realtime Metriken API (/api/metrics)
# ==========================================
@system_bp.route("/api/metrics")
@login_required
def api_metrics():
    global _last_net_check
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime_sec = time.time() - psutil.boot_time()
    days, rem = divmod(int(uptime_sec), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    load_avg = [0.0, 0.0, 0.0]
    if hasattr(os, "getloadavg"):
        try:
            load_avg = [round(x, 2) for x in os.getloadavg()]
        except Exception:
            pass

    # Netzwerk-Durchsatz berechnen
    now = time.time()
    elapsed = max(0.1, now - _last_net_check["time"])
    net_rx_str = "0 KB/s"
    net_tx_str = "0 KB/s"
    try:
        net = psutil.net_io_counters()
        rx_diff = (net.bytes_recv - _last_net_check["bytes_recv"]) / elapsed
        tx_diff = (net.bytes_sent - _last_net_check["bytes_sent"]) / elapsed
        _last_net_check = {"time": now, "bytes_recv": net.bytes_recv, "bytes_sent": net.bytes_sent}

        def format_rate(rate_bytes):
            if rate_bytes > 1024 * 1024:
                return f"{rate_bytes / (1024 * 1024):.1f} MB/s"
            return f"{rate_bytes / 1024:.1f} KB/s"

        net_rx_str = format_rate(rx_diff)
        net_tx_str = format_rate(tx_diff)
    except Exception:
        pass

    return jsonify({
        "cpu": psutil.cpu_percent(),
        "ram_used": round(mem.used / (1024**3), 2),
        "ram_total": round(mem.total / (1024**3), 2),
        "ram_percent": mem.percent,
        "disk_used": round(disk.used / (1024**3), 1),
        "disk_total": round(disk.total / (1024**3), 1),
        "disk_percent": disk.percent,
        "load_avg": load_avg,
        "uptime": f"{days}d {hours}h {minutes}m",
        "net_rx": net_rx_str,
        "net_tx": net_tx_str
    })

# ==========================================
# Service & Firewall Aktionen
# ==========================================
@system_bp.route("/service/<name>/<action>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def control_service(name, action):
    if name in MANAGED_SERVICES and action in ["restart", "start", "stop"]:
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", action, name])
        log_audit(session.get("username"), f"SERVICE_{action.upper()}", f"Dienst '{name}' -> {action}", request.remote_addr)
        flash(f"Dienst '{name}' -> {action} ausgeführt.", "success")
    return redirect(url_for("system.index"))

@system_bp.route("/settings/hostname", methods=["POST"])
@login_required
@role_required(["root_admin"])
def set_hostname():
    new_host = request.form.get("hostname", "").strip()
    if re.match(r"^[a-zA-Z0-9.-]{2,64}$", new_host):
        if shutil.which("hostnamectl"):
            subprocess.run(["hostnamectl", "set-hostname", new_host])
        log_audit(session.get("username"), "HOSTNAME_CHANGE", f"Hostname geändert auf '{new_host}'", request.remote_addr)
        flash(f"Hostname auf '{new_host}' geändert.", "success")
    else:
        flash("Ungültiger Hostname.", "error")
    return redirect(url_for("system.index"))

@system_bp.route("/firewall/add", methods=["POST"])
@login_required
@role_required(["root_admin"])
def firewall_add():
    port = request.form.get("port", "").strip()
    proto = request.form.get("proto", "tcp").strip()
    comment = request.form.get("comment", "").strip()

    if port.isdigit() and 1 <= int(port) <= 65535 and proto in ["tcp", "udp"]:
        if shutil.which("ufw"):
            cmd = ["ufw", "allow", f"{port}/{proto}"]
            if comment and re.match(r"^[a-zA-Z0-9_-]{1,32}$", comment):
                cmd.extend(["comment", comment])
            subprocess.run(cmd)
        log_audit(session.get("username"), "FIREWALL_RULE_ADD", f"Port {port}/{proto} freigegeben", request.remote_addr)
        flash(f"Port {port}/{proto} in UFW freigegeben.", "success")
    else:
        flash("Ungültiger Port (1-65535 erforderlich).", "error")
    return redirect(url_for("system.index"))

@system_bp.route("/firewall/delete/<rule_id>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def firewall_delete(rule_id):
    if rule_id.isdigit():
        if shutil.which("ufw"):
            subprocess.run(["ufw", "--force", "delete", rule_id])
        log_audit(session.get("username"), "FIREWALL_RULE_DELETE", f"Firewall-Regel #{rule_id} gelöscht", request.remote_addr, "warning")
        flash(f"Firewall-Regel #{rule_id} gelöscht.", "success")
    return redirect(url_for("system.index"))
