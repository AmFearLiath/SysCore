import os
import re
import shutil
import subprocess
import psutil
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, session
from modules.auth_users import login_required, role_required, log_audit
import db
import config

security_bp = Blueprint("security", __name__, url_prefix="/security")

def get_ufw_status():
    if not shutil.which("ufw"):
        return {"installed": False, "active": False, "rules": []}
    try:
        res = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=5)
        out = res.stdout
        is_active = "Status: active" in out
        rules = []
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Status:") and not line.startswith("Logging:") and not line.startswith("Default:") and not line.startswith("New profiles:") and not line.startswith("To") and not line.startswith("--"):
                rules.append(line)
        return {"installed": True, "active": is_active, "rules": rules, "raw": out}
    except Exception as e:
        return {"installed": True, "active": False, "rules": [], "error": str(e)}

def get_fail2ban_status():
    if not shutil.which("fail2ban-client"):
        return {"installed": False, "running": False, "jails": [], "banned_ips": []}
    try:
        res = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            return {"installed": True, "running": False, "jails": [], "banned_ips": []}
        
        jails = []
        banned = []
        for line in res.stdout.splitlines():
            if "Jail list:" in line:
                raw_jails = line.split("Jail list:")[-1].strip().split(",")
                jails = [j.strip() for j in raw_jails if j.strip()]

        for jail in jails:
            j_res = subprocess.run(["fail2ban-client", "status", jail], capture_output=True, text=True, timeout=5)
            for j_line in j_res.stdout.splitlines():
                if "Banned IP list:" in j_line:
                    ips = j_line.split("Banned IP list:")[-1].strip().split()
                    for ip in ips:
                        if ip.strip():
                            banned.append({"ip": ip.strip(), "jail": jail})

        return {"installed": True, "running": True, "jails": jails, "banned_ips": banned}
    except Exception as e:
        return {"installed": True, "running": False, "jails": [], "banned_ips": [], "error": str(e)}

def get_ssh_audit():
    sshd_config_paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"]
    content = ""
    for p in sshd_config_paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content += f.read() + "\n"
            except Exception:
                pass
        elif os.path.isdir(p):
            for fname in os.listdir(p):
                if fname.endswith(".conf"):
                    try:
                        with open(os.path.join(p, fname), "r", encoding="utf-8", errors="ignore") as f:
                            content += f.read() + "\n"
                    except Exception:
                        pass

    port = 22
    permit_root = "yes"  # OpenSSH default falls nicht explizit gesetzt
    password_auth = "yes"

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        key = parts[0].lower()
        val = parts[1].lower() if len(parts) > 1 else ""

        if key == "port" and val.isdigit():
            port = int(val)
        elif key == "permitrootlogin":
            permit_root = val
        elif key == "passwordauthentication":
            password_auth = val

    is_hardened = (permit_root in ("no", "prohibit-password")) and (password_auth == "no" or port != 22)
    return {
        "port": port,
        "permit_root_login": permit_root,
        "password_auth": password_auth,
        "is_hardened": is_hardened
    }

def get_open_ports_audit():
    danger_ports = {
        3306: ("MySQL / MariaDB", "Datenbank sollte niemals öffentlich auf 0.0.0.0 erreichbar sein!"),
        5432: ("PostgreSQL", "Enterprise DB sollte nur lokal (127.0.0.1) lauschen."),
        6379: ("Redis Cache", "Redis ohne Authentifizierung auf 0.0.0.0 ist ein extremes Sicherheitsrisiko!"),
        27017: ("MongoDB", "NoSQL-Datenbank öffentlich erreichbar."),
        11211: ("Memcached", "Verstärkungsangriffe / Exploitgefahr.")
    }

    listeners = []
    warnings = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                ip = conn.laddr.ip
                port = conn.laddr.port
                proc_name = "Unbekannt"
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                    except Exception:
                        pass
                
                is_public = (ip in ("0.0.0.0", "::", ""))
                listeners.append({
                    "ip": ip,
                    "port": port,
                    "process": proc_name,
                    "public": is_public
                })

                if is_public and port in danger_ports:
                    name, desc = danger_ports[port]
                    warnings.append({
                        "port": port,
                        "service": name,
                        "description": desc,
                        "level": "critical"
                    })
    except Exception:
        pass

    listeners.sort(key=lambda x: (not x["public"], x["port"]))
    return {"listeners": listeners, "warnings": warnings}

def get_clamav_status():
    installed = bool(shutil.which("clamscan"))
    daemon_running = False
    if shutil.which("systemctl"):
        res = subprocess.run(["systemctl", "is-active", "clamav-daemon"], capture_output=True, text=True)
        daemon_running = (res.stdout.strip() == "active")
    
    recent_scans = db.query_db("SELECT * FROM clamav_scans ORDER BY id DESC LIMIT 5")
    return {
        "installed": installed,
        "daemon_running": daemon_running,
        "recent_scans": recent_scans
    }

def scan_nginx_exploit_probes():
    """Analysiert NGINX Logs nach verdächtigen Exploit- und Scannermustern."""
    log_candidates = [
        "/var/log/nginx/error.log",
        "/var/log/nginx/access.log"
    ]
    
    suspicious_patterns = [
        (re.compile(r"(\.env|wp-login\.php|xmlrpc\.php|phpmyadmin|\.git/config|cgi-bin|eval-stdin)", re.I), "Web-Exploit / Probing"),
        (re.compile(r"(\.\./|etc/passwd|boot\.ini|win\.ini)", re.I), "Path Traversal"),
        (re.compile(r"(UNION\s+SELECT|CONCAT\(|'\s*OR\s*'1'='1)", re.I), "SQL Injection Versuch"),
        (re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab)", re.I), "Automatisierter Schwachstellen-Scanner")
    ]

    probes = []
    ip_counter = {}

    for path in log_candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-1500:]  # Letzte 1500 Zeilen
            
            for line in reversed(lines):
                for pattern, category in suspicious_patterns:
                    match = pattern.search(line)
                    if match:
                        # Extrahiere IP Adresse
                        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                        ip = ip_match.group(0) if ip_match else "Unbekannt"
                        
                        # Extrahiere Timestamp falls vorhanden
                        ts_match = re.search(r"\[([^\]]+)\]", line)
                        ts = ts_match.group(1) if ts_match else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                        ip_counter[ip] = ip_counter.get(ip, 0) + 1

                        if len(probes) < 25:
                            probes.append({
                                "ip": ip,
                                "category": category,
                                "matched": match.group(0),
                                "raw_line": line[:200],
                                "timestamp": ts
                            })
                        break
        except Exception:
            continue

    top_attackers = sorted(
        [{"ip": ip, "count": count} for ip, count in ip_counter.items() if ip != "Unbekannt" and ip != "127.0.0.1"],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    return {"recent_probes": probes, "top_attackers": top_attackers}

def calculate_security_score(ufw, f2b, ssh, ports):
    score = 100
    deductions = []

    if not ufw.get("active"):
        score -= 30
        deductions.append("UFW Firewall ist deaktiviert (-30%)")
    
    if not f2b.get("running"):
        score -= 20
        deductions.append("Fail2Ban / Intrusion Prevention ist nicht aktiv (-20%)")

    if ssh.get("permit_root_login") == "yes":
        score -= 15
        deductions.append("SSH erlaubt direkten Root-Login (-15%)")

    if ssh.get("port") == 22 and ssh.get("password_auth") == "yes":
        score -= 10
        deductions.append("SSH nutzt Standardport 22 mit Passwort-Auth (-10%)")

    if ports.get("warnings"):
        for w in ports["warnings"]:
            score -= 15
            deductions.append(f"Kritischer Port {w['port']} ({w['service']}) lauscht öffentlich (-15%)")

    score = max(0, min(100, score))
    return score, deductions

@security_bp.route("/")
@login_required
@role_required(["root_admin"])
def index():
    ufw = get_ufw_status()
    f2b = get_fail2ban_status()
    ssh = get_ssh_audit()
    ports = get_open_ports_audit()
    clamav = get_clamav_status()
    exploit_scan = scan_nginx_exploit_probes()
    score, deductions = calculate_security_score(ufw, f2b, ssh, ports)

    banned_db = db.query_db("SELECT * FROM security_ip_bans ORDER BY id DESC LIMIT 50")

    # Verfügbare Webspace-Pfade für ClamAV Scan
    webspaces = []
    web_base = config.WEB_ROOT_BASE
    if os.path.exists(web_base):
        try:
            for item in sorted(os.listdir(web_base)):
                full_p = os.path.join(web_base, item)
                if os.path.isdir(full_p):
                    webspaces.append(item)
        except Exception:
            pass

    return render_template(
        "security.html",
        score=score,
        deductions=deductions,
        ufw=ufw,
        f2b=f2b,
        ssh=ssh,
        ports=ports,
        clamav=clamav,
        exploit_scan=exploit_scan,
        banned_db=banned_db,
        webspaces=webspaces
    )

@security_bp.route("/ban-ip", methods=["POST"])
@login_required
@role_required(["root_admin"])
def ban_ip():
    ip = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "Manuelle Sperre im SysCore Angriffs-Radar").strip()
    ban_type = request.form.get("ban_type", "ufw").strip()

    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        flash("Ungültige IPv4-Adresse.", "error")
        return redirect(url_for("security.index"))

    if ip in ("127.0.0.1", "0.0.0.0"):
        flash("Lokale Loopback-IPs können nicht gesperrt werden.", "error")
        return redirect(url_for("security.index"))

    # UFW Bann ausführen
    if shutil.which("ufw"):
        subprocess.run(["ufw", "deny", "from", ip], capture_output=True, text=True)

    # In DB speichern
    try:
        db.execute_db("""
        INSERT OR REPLACE INTO security_ip_bans (ip_address, reason, banned_by, ban_type)
        VALUES (?, ?, ?, ?)
        """, (ip, reason, session.get("username", "admin"), ban_type))
        log_audit(session.get("username"), "SECURITY_BAN_IP", f"IP {ip} gesperrt ({reason})", request.remote_addr)
        flash(f"IP-Adresse {ip} erfolgreich gesperrt und in der Firewall geblockt.", "success")
    except Exception as e:
        flash(f"Fehler beim Sperren der IP: {e}", "error")

    return redirect(url_for("security.index"))

@security_bp.route("/unban-ip", methods=["POST"])
@login_required
@role_required(["root_admin"])
def unban_ip():
    ip = request.form.get("ip_address", "").strip()
    if not ip:
        flash("Keine IP angegeben.", "error")
        return redirect(url_for("security.index"))

    # UFW Regel entfernen
    if shutil.which("ufw"):
        subprocess.run(["ufw", "delete", "deny", "from", ip], capture_output=True, text=True)

    # Fail2Ban Unban versuchen falls installiert
    if shutil.which("fail2ban-client"):
        subprocess.run(["fail2ban-client", "unban", ip], capture_output=True, text=True)

    db.execute_db("DELETE FROM security_ip_bans WHERE ip_address = ?", (ip,))
    log_audit(session.get("username"), "SECURITY_UNBAN_IP", f"IP {ip} entsperrt", request.remote_addr)
    flash(f"IP-Adresse {ip} wurde erfolgreich entsperrt.", "success")
    return redirect(url_for("security.index"))

@security_bp.route("/clamav/scan", methods=["POST"])
@login_required
@role_required(["root_admin"])
def clamav_scan():
    target = request.form.get("target_path", "/var/www").strip()
    if not os.path.exists(target):
        flash(f"Zielpfad '{target}' existiert nicht.", "error")
        return redirect(url_for("security.index"))

    if not shutil.which("clamscan"):
        # Fallback Simulation auf Systemen ohne ClamAV
        scan_id = db.execute_db("""
        INSERT INTO clamav_scans (target_path, scanned_files, infected_files, scan_log, status)
        VALUES (?, ?, ?, ?, 'completed')
        """, (target, 0, 0, f"[SysCore Info] ClamAV ist nicht installiert. Bitte im Paket-Manager installieren.\nPfad: {target} geprüft."))
        flash("ClamAV (clamscan) ist auf diesem Server nicht installiert. Bitte im Paket-Manager installieren.", "warning")
        return redirect(url_for("security.index"))

    try:
        # Clamscan ausführen (rekursiv, nur infizierte ausgeben)
        res = subprocess.run(
            ["clamscan", "-r", "-i", "--max-filesize=50M", "--max-scansize=100M", target],
            capture_output=True,
            text=True,
            timeout=300
        )
        out = res.stdout + "\n" + res.stderr
        
        # Parse Statistik
        scanned_match = re.search(r"Scanned files:\s+(\d+)", out)
        infected_match = re.search(r"Infected files:\s+(\d+)", out)

        scanned = int(scanned_match.group(1)) if scanned_match else 0
        infected = int(infected_match.group(1)) if infected_match else 0

        status = "infected" if infected > 0 else "clean"

        db.execute_db("""
        INSERT INTO clamav_scans (target_path, scanned_files, infected_files, scan_log, status)
        VALUES (?, ?, ?, ?, ?)
        """, (target, scanned, infected, out[:4000], status))

        log_audit(session.get("username"), "CLAMAV_SCAN", f"Scan von '{target}' beendet ({scanned} Dateien, {infected} Infektionen)", request.remote_addr)

        if infected > 0:
            flash(f"Achtung: ClamAV hat {infected} infizierte Datei(en) in '{target}' entdeckt!", "error")
        else:
            flash(f"ClamAV Scan abgeschlossen: {scanned} Datei(en) geprüft. Keine Bedrohungen gefunden!", "success")
    except subprocess.TimeoutExpired:
        flash("ClamAV Scan hat das Zeitlimit von 5 Minuten überschritten.", "error")
    except Exception as e:
        flash(f"Fehler beim Ausführen von ClamAV: {e}", "error")

    return redirect(url_for("security.index"))

@security_bp.route("/audit/export")
@login_required
@role_required(["root_admin"])
def export_audit_report():
    """Generiert einen detaillierten System- und Sicherheits-Prüfbericht inklusive Prompt für KI-Agenten."""
    ufw = get_ufw_status()
    f2b = get_fail2ban_status()
    ssh = get_ssh_audit()
    ports = get_open_ports_audit()
    clamav = get_clamav_status()
    score, deductions = calculate_security_score(ufw, f2b, ssh, ports)

    # Hardware & OS Daten
    uname = os.uname() if hasattr(os, "uname") else None
    kernel = uname.release if uname else "Unknown"
    uptime_sec = int(psutil.boot_time())
    
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    load = psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0, 0, 0)

    # Veraltete Pakete prüfen
    upgradable_count = 0
    upgradable_pkgs = []
    if shutil.which("apt-get"):
        try:
            res = subprocess.run(["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=10)
            for line in res.stdout.splitlines():
                if line.startswith("Inst "):
                    upgradable_count += 1
                    if len(upgradable_pkgs) < 15:
                        upgradable_pkgs.append(line.split()[1])
        except Exception:
            pass

    # Markdown Report aufbauen
    report = f"""# SysCore System-Audit & Diagnosebericht
**Generiert am:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Hostname:** {config.PANEL_HOST}
**Sicherheits-Score:** {score}/100%

---

## 🤖 PROMPT FÜR KI-AGENTEN (Claude, Gemini, GPT)
> Kopiere diesen Block direkt in deinen KI-Agenten, um einen priorisierten Optimierungs- und Härtungsplan zu erhalten:

```text
Du bist ein erfahrener Senior Linux Infrastructure Architect & Cybersecurity Specialist.
Hier ist der vollständige Diagnose- und Sicherheitsbericht meines Debian-Servers (SysCore Audit).

Bitte erstelle mir auf Basis dieser Daten:
1. Eine priorisierte Risiko- und Schwachstellenanalyse (Kritisch, Hoch, Mittel, Niedrig).
2. Konkrete Maßnahmen zur Leistungsoptimierung (RAM, Swap, NVMe I/O, NGINX Worker, PHP-FPM, MySQL Buffer Pool).
3. Einen schrittweisen, sofort ausführbaren Terminal-Aktionsplan mit den exakten Bash-Befehlen zur Behebung.
4. Empfehlungen zur weiteren Härtung (SSH, UFW, Fail2Ban/CrowdSec).
```

---

## 1. Sicherheits- & Härtungs-Status
- **Gesamt-Score:** {score} / 100
- **Identifizierte Abzüge:**
{chr(10).join(['  - ' + d for d in deductions]) if deductions else '  - Keine kritischen Abzüge festgestellt.'}

### UFW Firewall
- **Status:** {'Aktiv' if ufw.get('active') else 'INAKTIV (Sicherheitsrisiko)'}
- **Aktive Regeln:** {len(ufw.get('rules', []))}

### Fail2Ban / Intrusion Prevention
- **Status:** {'Aktiv' if f2b.get('running') else 'INAKTIV'}
- **Aktive Jails:** {', '.join(f2b.get('jails', [])) if f2b.get('jails') else 'Keine'}
- **Aktuell gebannte IPs:** {len(f2b.get('banned_ips', []))}

### SSH-Konfiguration
- **Port:** {ssh.get('port', 22)}
- **PermitRootLogin:** {ssh.get('permit_root_login')}
- **PasswordAuthentication:** {ssh.get('password_auth')}
- **Gehärtet:** {'Ja' if ssh.get('is_hardened') else 'Nein (Empfehlung: Root-Login verbieten und SSH-Keys erzwingen)'}

---

## 2. Hardware- & Ressourcen-Auslastung
- **Kernel:** {kernel}
- **Load Average (1, 5, 15 Min):** {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}
- **CPU Kerne:** {psutil.cpu_count(logical=True)}
- **Arbeitsspeicher (RAM):** {mem.used / (1024**3):.2f} GB / {mem.total / (1024**3):.2f} GB ({mem.percent}% belegt)
- **Swap-Speicher:** {swap.used / (1024**3):.2f} GB / {swap.total / (1024**3):.2f} GB ({swap.percent}% belegt)
- **Hauptspeicher (NVMe/SSD /):** {disk.used / (1024**3):.2f} GB / {disk.total / (1024**3):.2f} GB ({disk.percent}% belegt)

---

## 3. Offene Ports & Externe Angriffsflächen
{chr(10).join([f"- Port {p['port']} ({p['process']}) auf {p['ip']} [{'ÖFFENTLICH' if p['public'] else 'LOKAL'}]" for p in ports.get('listeners', [])])}

### Kritische Port-Warnungen:
{chr(10).join([f"- ⚠️ {w['service']} auf Port {w['port']}: {w['description']}" for w in ports.get('warnings', [])]) if ports.get('warnings') else '- Keine sensiblen Ports ungeschützt auf 0.0.0.0 entdeckt.'}

---

## 4. Software- & Paket-Status
- **Anstehende APT Updates:** {upgradable_count} Pakete
- **Auszug:** {', '.join(upgradable_pkgs) if upgradable_pkgs else 'System ist aktuell'}
- **ClamAV Virenscanner:** {'Installiert & Betriebsbereit' if clamav.get('installed') else 'Nicht installiert'}

---
*Bericht erstellt mit SysCore Next-Gen Server Management.*
"""
    return Response(
        report,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=syscore-audit-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.md"}
    )
