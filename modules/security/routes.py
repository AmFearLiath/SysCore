"""
SysCore Sentinel - Security Center 2.0 Web Routes
Verwaltet alle Web- und API-Endpunkte für die Sicherheitszentrale:
- Übersicht, Score & Easy/Advanced Mode
- Firewall & Port-Schutz
- Software Inventory & Registry
- Profilwechsel & Safe-Apply Rollbacks
- Angriffs-Radar & Exploit-Probes
- Sentinel KI-Assistent & Chat-Sitzungen
- Automatisierungs-Regeln
"""

import os
import re
import json
import shutil
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, session
from modules.auth_users import login_required, role_required, log_audit
import db
import config

# Submodule importieren
from modules.security.core.risk_engine import calculate_system_risk
from modules.security.core.policy_engine import PolicyEngine
from modules.security.core.safe_apply import SafeApply
from modules.security.core.audit import generate_markdown_audit_report
from modules.security.inventory.discovery import SoftwareDiscovery
from modules.security.inventory.software_registry import SoftwareRegistry
from modules.security.profiles.manager import ProfileManager
from modules.security.protection.firewall import (
    get_ufw_status, add_ufw_deny, remove_ufw_deny, set_ufw_enabled,
    detect_candidate_firewall_rules, activate_firewall_with_rules
)
from modules.security.protection.ssh import get_ssh_audit
from modules.security.protection.fail2ban import get_fail2ban_status, fail2ban_unban
from modules.security.protection.clamav import get_clamav_status, run_clamscan
from modules.security.protection.waf import get_waf_status, apply_waf_profile
from modules.security.protection.file_integrity import FileIntegrityMonitor
from modules.security.detection.probes import scan_nginx_exploit_probes
from modules.security.detection.threats import get_open_ports_audit
from modules.security.detection.incidents import IncidentManager
from modules.security.automation.rules import AutomationRulesManager
from modules.security.automation.autoban import RadarAutoBanManager, CATEGORY_TITLES
from modules.security.assistant.sentinel import SentinelAssistant

security_bp = Blueprint("security", __name__, url_prefix="/security")

# Kompatibilitäts-Wrapper für ältere Module
def calculate_security_score(ufw, f2b, ssh, ports):
    score, deductions = calculate_system_risk(ufw, f2b, ssh, ports)
    # Rückwärtskompatible String-Liste für deductions
    str_deductions = [d["title"] if isinstance(d, dict) else str(d) for d in deductions]
    return score, str_deductions

@security_bp.route("/")
@login_required
@role_required(["root_admin"])
def index():
    """Hauptseite des Security Center 2.0 (Sentinel)."""
    # 1. System-Audits durchführen
    ufw = get_ufw_status()
    f2b = get_fail2ban_status()
    ssh = get_ssh_audit()
    ports = get_open_ports_audit()
    clamav = get_clamav_status()
    waf = get_waf_status()

    # Gebannte IPs vorab ermitteln für saubere Filterung
    banned_db = db.query_db("SELECT * FROM security_ip_bans ORDER BY id DESC LIMIT 50")
    banned_ip_set = {b["ip_address"] for b in banned_db} if banned_db else set()
    if f2b.get("banned_ips"):
        banned_ip_set.update(f2b["banned_ips"])

    exploit_scan = scan_nginx_exploit_probes(banned_ips=banned_ip_set)
    recent_probes = exploit_scan.get("recent_probes", [])

    # Automatische Exploit-Sperre prüfen, falls aktiv
    autoban_config = RadarAutoBanManager.get_config()
    if autoban_config.get("enabled"):
        autoban_res = RadarAutoBanManager.execute_autoban(recent_probes, banned_ip_set)
        if autoban_res.get("banned_count", 0) > 0:
            banned_db = db.query_db("SELECT * FROM security_ip_bans ORDER BY id DESC LIMIT 50")
            exploit_scan = scan_nginx_exploit_probes(banned_ips=banned_ip_set)
            recent_probes = exploit_scan.get("recent_probes", [])

    # 2. Software-Inventar abrufen
    inventory = SoftwareRegistry.get_all()
    if not inventory:
        inventory = SoftwareDiscovery.run_discovery()

    # 3. Offene Befunde aus DB abrufen
    open_findings = db.query_db("SELECT * FROM security_findings WHERE status = 'open'")
    findings_list = [dict(f) for f in open_findings] if open_findings else []

    # 4. Risk Engine: Dynamischer Gesamtscore
    score, raw_deductions = calculate_system_risk(
        ufw, f2b, ssh, ports,
        probe_count=len(recent_probes),
        open_findings=findings_list
    )
    deductions = [d["title"] if isinstance(d, dict) else str(d) for d in raw_deductions]

    # 5. Policies abgleichen
    policies = PolicyEngine.evaluate_live_policies(ufw, ssh, f2b, ports)
    compliance_stats = PolicyEngine.get_compliance_stats(policies)

    # 6. Profile laden
    profiles = ProfileManager.get_all_profiles()
    active_profile = ProfileManager.get_active_profile()

    # 7. Automatisierungsregeln & Vorfälle
    auto_rules = AutomationRulesManager.get_rules()
    incidents = IncidentManager.get_recent_incidents(15)

    # 8. Letzte Snapshots für Rollback
    snapshots = db.query_db("SELECT * FROM security_snapshots ORDER BY id DESC LIMIT 5")
    snapshot_list = [dict(s) for s in snapshots] if snapshots else []

    # 9. Gebannte IPs & Webspaces für Scans
    webspaces = []
    if os.path.exists(config.WEB_ROOT_BASE):
        try:
            for item in sorted(os.listdir(config.WEB_ROOT_BASE)):
                if os.path.isdir(os.path.join(config.WEB_ROOT_BASE, item)):
                    webspaces.append(item)
        except Exception:
            pass

    # 10. Kandidaten-Ports für Firewall-Aktivierungs-Assistent
    candidate_ports = detect_candidate_firewall_rules()

    return render_template(
        "security.html",
        score=score,
        deductions=deductions,
        raw_deductions=raw_deductions,
        ufw=ufw,
        f2b=f2b,
        ssh=ssh,
        ports=ports,
        clamav=clamav,
        waf=waf,
        exploit_scan=exploit_scan,
        inventory=inventory,
        policies=policies,
        compliance_stats=compliance_stats,
        profiles=profiles,
        active_profile=active_profile,
        auto_rules=auto_rules,
        incidents=incidents,
        snapshots=snapshot_list,
        banned_db=banned_db,
        webspaces=webspaces,
        candidate_ports=candidate_ports,
        autoban_config=autoban_config,
        autoban_titles=CATEGORY_TITLES
    )

# ==================== IP BANNING & FIREWALL ====================

@security_bp.route("/ban-ip", methods=["POST"])
@login_required
@role_required(["root_admin"])
def ban_ip():
    """Sperrt eine IP-Adresse manuell (unterstützt Form-Post & async AJAX/JSON)."""
    is_ajax = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in request.headers.get("Accept", "")
    )

    if request.is_json:
        data = request.get_json() or {}
        ip = data.get("ip_address", "").strip()
        reason = data.get("reason", "Manuelle Sperre im SysCore Angriffs-Radar").strip()
        ban_type = data.get("ban_type", "ufw").strip()
    else:
        ip = request.form.get("ip_address", "").strip()
        reason = request.form.get("reason", "Manuelle Sperre im SysCore Angriffs-Radar").strip()
        ban_type = request.form.get("ban_type", "ufw").strip()

    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        if is_ajax:
            return jsonify({"success": False, "error": "Ungültige IPv4-Adresse."}), 400
        flash("Ungültige IPv4-Adresse.", "error")
        return redirect(url_for("security.index"))

    if ip in ("127.0.0.1", "0.0.0.0"):
        if is_ajax:
            return jsonify({"success": False, "error": "Lokale Loopback-IPs können nicht gesperrt werden."}), 400
        flash("Lokale Loopback-IPs können nicht gesperrt werden.", "error")
        return redirect(url_for("security.index"))

    add_ufw_deny(ip)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = session.get("username", "admin")
    try:
        db.execute_db("""
            INSERT OR REPLACE INTO security_ip_bans (ip_address, reason, banned_by, ban_type, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, reason, username, ban_type, now_str))
        log_audit(username, "SECURITY_BAN_IP", f"IP {ip} gesperrt ({reason})", request.remote_addr)

        if is_ajax:
            return jsonify({
                "success": True,
                "message": f"IP-Adresse {ip} erfolgreich gesperrt und in der Firewall geblockt.",
                "ip": ip,
                "reason": reason,
                "banned_by": username,
                "ban_type": ban_type,
                "created_at": now_str
            })
        flash(f"IP-Adresse {ip} erfolgreich gesperrt und in der Firewall geblockt.", "success")
    except Exception as e:
        if is_ajax:
            return jsonify({"success": False, "error": f"Fehler beim Sperren der IP: {e}"}), 500
        flash(f"Fehler beim Sperren der IP: {e}", "error")

    return redirect(url_for("security.index"))

@security_bp.route("/unban-ip", methods=["POST"])
@login_required
@role_required(["root_admin"])
def unban_ip():
    """Entsperrt eine IP-Adresse (unterstützt Form-Post & async AJAX/JSON)."""
    is_ajax = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in request.headers.get("Accept", "")
    )

    if request.is_json:
        data = request.get_json() or {}
        ip = data.get("ip_address", "").strip()
    else:
        ip = request.form.get("ip_address", "").strip()

    if not ip:
        if is_ajax:
            return jsonify({"success": False, "error": "Keine IP angegeben."}), 400
        flash("Keine IP angegeben.", "error")
        return redirect(url_for("security.index"))

    remove_ufw_deny(ip)
    fail2ban_unban(ip)

    db.execute_db("DELETE FROM security_ip_bans WHERE ip_address = ?", (ip,))
    log_audit(session.get("username"), "SECURITY_UNBAN_IP", f"IP {ip} entsperrt", request.remote_addr)

    if is_ajax:
        return jsonify({
            "success": True,
            "message": f"IP-Adresse {ip} wurde erfolgreich entsperrt.",
            "ip": ip
        })
    flash(f"IP-Adresse {ip} wurde erfolgreich entsperrt.", "success")
    return redirect(url_for("security.index"))

@security_bp.route("/autoban/settings", methods=["POST"])
@login_required
@role_required(["root_admin"])
def update_autoban_settings():
    """Speichert die Einstellungen für die automatische Exploit-Sperre."""
    is_ajax = (
        request.is_json
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in request.headers.get("Accept", "")
    )

    if request.is_json:
        data = request.get_json() or {}
    else:
        cats = {
            "sqli": "cat_sqli" in request.form,
            "path_traversal": "cat_path_traversal" in request.form,
            "web_exploit": "cat_web_exploit" in request.form,
            "scanners": "cat_scanners" in request.form,
            "xss": "cat_xss" in request.form
        }
        data = {
            "enabled": request.form.get("enabled") in ("1", "true", "on"),
            "threshold": int(request.form.get("threshold", 1)),
            "ban_duration": request.form.get("ban_duration", "permanent"),
            "whitelist": request.form.get("whitelist", "127.0.0.1, ::1"),
            "notify_incident": request.form.get("notify_incident") in ("1", "true", "on"),
            "categories": cats
        }

    ok = RadarAutoBanManager.save_config(data)
    if ok:
        log_audit(
            session.get("username"),
            "SECURITY_AUTOBAN_CONFIG",
            f"Auto-Ban Regeln aktualisiert: aktiv={data.get('enabled')}, Schwelle={data.get('threshold')}",
            request.remote_addr
        )
        saved_cfg = RadarAutoBanManager.get_config()
        if is_ajax:
            return jsonify({
                "success": True,
                "message": "Auto-Ban Einstellungen erfolgreich gespeichert.",
                "config": saved_cfg
            })
        flash("Auto-Ban Einstellungen erfolgreich gespeichert.", "success")
    else:
        if is_ajax:
            return jsonify({"success": False, "error": "Fehler beim Speichern der Konfiguration."}), 500
        flash("Fehler beim Speichern der Konfiguration.", "error")

    return redirect(url_for("security.index"))

@security_bp.route("/autoban/apply", methods=["POST"])
@login_required
@role_required(["root_admin"])
def apply_autoban_now():
    """Führt eine sofortige Auswertung der Exploit-Logs nach den Auto-Ban-Regeln durch."""
    res = RadarAutoBanManager.execute_autoban()
    return jsonify({
        "success": True,
        "active": res.get("active", False),
        "banned_count": res.get("banned_count", 0),
        "banned_ips": res.get("banned_ips", []),
        "message": res.get("message", "")
    })

@security_bp.route("/firewall/toggle", methods=["POST"])
@login_required
@role_required(["root_admin"])
def toggle_firewall():
    """Aktiviert oder deaktiviert UFW direkt (z.B. Deaktivieren)."""
    enable = request.form.get("enable") in ("1", "true", "True")
    ok = set_ufw_enabled(enable)
    if ok:
        flash(f"UFW Firewall {'aktiviert' if enable else 'deaktiviert'}.", "success")
    else:
        flash("UFW konnte nicht geschaltet werden.", "error")
    return redirect(url_for("security.index"))

@security_bp.route("/firewall/preflight", methods=["GET"])
@login_required
@role_required(["root_admin"])
def firewall_preflight():
    """Liefert JSON aller erkannten aktiven Kandidaten-Ports (Pterodactyl, Docker, Web, SSH)."""
    candidates = detect_candidate_firewall_rules()
    return jsonify({"success": True, "candidates": candidates})

@security_bp.route("/firewall/activate", methods=["POST"])
@login_required
@role_required(["root_admin"])
def activate_firewall_wizard():
    """Aktiviert UFW sicher mit den vom Admin bestätigten Port-Freigaben."""
    selected_ports = request.form.getlist("ports")
    custom_ranges = request.form.get("custom_ranges", "").strip()

    ok, msg, count = activate_firewall_with_rules(
        selected_rules=selected_ports,
        custom_ranges=custom_ranges,
        username=session.get("username", "admin")
    )

    if ok:
        log_audit(session.get("username"), "FIREWALL_ACTIVATED_WIZARD", f"UFW aktiviert mit {count} freigegebenen Ports", request.remote_addr)
        flash(msg, "success")
    else:
        flash(msg, "error")

    return redirect(url_for("security.index"))

# ==================== CLAMAV SCANS ====================

@security_bp.route("/clamav/scan", methods=["POST"])
@login_required
@role_required(["root_admin"])
def clamav_scan():
    """Startet einen ClamAV-Scan auf einem Zielpfad."""
    target = request.form.get("target_path", "/var/www").strip()
    res = run_clamscan(target)

    if not res.get("success"):
        flash(res.get("message") or res.get("error") or "Scan fehlgeschlagen.", "warning")
    else:
        scanned = res.get("scanned", 0)
        infected = res.get("infected", 0)
        if infected > 0:
            flash(f"Achtung: ClamAV hat {infected} infizierte Datei(en) in '{target}' entdeckt!", "error")
        else:
            flash(f"ClamAV Scan abgeschlossen: {scanned} Datei(en) geprüft. Keine Bedrohungen gefunden!", "success")

    log_audit(session.get("username"), "CLAMAV_SCAN", f"Scan von '{target}' beendet", request.remote_addr)
    return redirect(url_for("security.index"))

# ==================== SECURITY PROFILES ====================

@security_bp.route("/profiles/preview", methods=["POST"])
@login_required
@role_required(["root_admin"])
def preview_profile():
    """Liefert einen JSON-Diff / Change Plan für einen Profilwechsel."""
    data = request.get_json() or {}
    target = data.get("target_profile", "standard")
    try:
        plan = ProfileManager.generate_change_plan(target)
        return jsonify({"success": True, "plan": plan})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@security_bp.route("/profiles/apply", methods=["POST"])
@login_required
@role_required(["root_admin"])
def apply_profile():
    """Aktiviert ein Sicherheitsprofil transaktional mit Safe-Apply."""
    target = request.form.get("profile_name", "").strip()
    if not target:
        flash("Kein Profil angegeben.", "error")
        return redirect(url_for("security.index"))

    ok, msg = ProfileManager.apply_profile(target, username=session.get("username", "admin"))
    if ok:
        log_audit(session.get("username"), "SECURITY_PROFILE_APPLIED", f"Profil '{target}' aktiviert", request.remote_addr)
        flash(msg, "success")
    else:
        flash(msg, "error")

    return redirect(url_for("security.index"))

# ==================== SOFTWARE INVENTORY ====================

@security_bp.route("/inventory/rescan", methods=["POST"])
@login_required
@role_required(["root_admin"])
def rescan_inventory():
    """Führt einen erneuten Software-Erkennungsscan durch."""
    items = SoftwareDiscovery.run_discovery()
    flash(f"Software-Inventar aktualisiert: {len(items)} Komponenten identifiziert.", "success")
    return redirect(url_for("security.index"))

@security_bp.route("/inventory/mode", methods=["POST"])
@login_required
@role_required(["root_admin"])
def update_protection_mode():
    """Aktualisiert den Schutzmodus einer Softwarekomponente."""
    sw_id = request.form.get("software_id", type=int)
    mode = request.form.get("mode", "").strip()

    if sw_id and SoftwareRegistry.set_protection_mode(sw_id, mode):
        flash("Schutzmodus erfolgreich geändert.", "success")
    else:
        flash("Ungültiger Schutzmodus oder Software nicht gefunden.", "error")

    return redirect(url_for("security.index"))

# ==================== SENTINEL ASSISTANT ====================

@security_bp.route("/assistant/chat", methods=["POST"])
@login_required
@role_required(["root_admin"])
def assistant_chat():
    """Interaktiver Chat mit dem Sentinel Sicherheitsassistenten."""
    data = request.get_json() or {}
    message = (data.get("message") or "").strip()
    session_id = data.get("session_id") or session.get("username", "default_admin")

    if not message:
        return jsonify({"success": False, "error": "Leere Nachricht"}), 400

    # Aktuellen System-Kontext zusammenstellen
    ufw = get_ufw_status()
    f2b = get_fail2ban_status()
    ssh = get_ssh_audit()
    ports = get_open_ports_audit()
    score, deductions = calculate_system_risk(ufw, f2b, ssh, ports)
    inventory = SoftwareRegistry.get_all()

    system_context = {
        "score": score,
        "deductions": deductions,
        "ufw": ufw,
        "ssh": ssh,
        "ports": ports,
        "inventory": inventory
    }

    reply = SentinelAssistant.ask(session_id, message, system_context)
    return jsonify({"success": True, "response": reply})

# ==================== SAFE-APPLY & ROLLBACK ====================

@security_bp.route("/rollback", methods=["POST"])
@login_required
@role_required(["root_admin"])
def rollback():
    """Rollback zu einem früheren Snapshot."""
    snapshot_id = request.form.get("snapshot_id", type=int)
    if not snapshot_id:
        flash("Kein Snapshot angegeben.", "error")
        return redirect(url_for("security.index"))

    ok, msg = SafeApply.rollback_snapshot(snapshot_id)
    if ok:
        log_audit(session.get("username"), "SECURITY_ROLLBACK", f"Snapshot #{snapshot_id} wiederhergestellt", request.remote_addr)
        flash(msg, "success")
    else:
        flash(msg, "error")

    return redirect(url_for("security.index"))

# ==================== AUDIT REPORT EXPORT ====================

@security_bp.route("/audit/export")
@login_required
@role_required(["root_admin"])
def export_audit_report():
    """Generiert einen detaillierten Diagnosebericht inklusive KI-Prompt."""
    ufw = get_ufw_status()
    f2b = get_fail2ban_status()
    ssh = get_ssh_audit()
    ports = get_open_ports_audit()
    clamav = get_clamav_status()
    inventory = SoftwareRegistry.get_all()
    score, deductions = calculate_system_risk(ufw, f2b, ssh, ports)

    report = generate_markdown_audit_report(
        score=score,
        deductions=deductions,
        ufw=ufw,
        f2b=f2b,
        ssh=ssh,
        ports=ports,
        clamav=clamav,
        software_inventory=inventory
    )

    return Response(
        report,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=syscore-sentinel-audit-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.md"}
    )
