import functools
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash
from db import query_db, execute_db, log_audit

users_bp = Blueprint("users", __name__, url_prefix="/users")

SYSTEM_PERMISSIONS = [
    {
        "key": "system",
        "label": "System & Metriken",
        "desc": "Dashboard, Hostname, Zeitzone, Swap-Speicher, Daemon-Status & SysCore Updates",
        "icon": "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
    },
    {
        "key": "security",
        "label": "Sicherheitszentrale",
        "desc": "Firewall-Regeln, Angriffs-Radar, ClamAV Malware-Scanner & IP-Sperren",
        "icon": "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
    },
    {
        "key": "web",
        "label": "Webserver & Domains",
        "desc": "Domains, VHosts, SSL Let's Encrypt, PHP-Versionen, HTTPS-Proxy & NGINX-Direktiven",
        "icon": "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
    },
    {
        "key": "mail",
        "label": "E-Mail-Zentrale",
        "desc": "Postfächer, Aliase, Weiterleitungen, DKIM-Schlüssel, DNS-Assistent & Webmail",
        "icon": "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
    },
    {
        "key": "db",
        "label": "Datenbanken",
        "desc": "MySQL/MariaDB Datenbanken, Benutzerkonten und interaktive SQL-Konsole",
        "icon": "M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"
    },
    {
        "key": "files",
        "label": "Dateimanager",
        "desc": "Webspace-Dateien, Uploads, Archiv-Extraktion, Code-Editor und chmod-Rechte",
        "icon": "M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"
    },
    {
        "key": "apps",
        "label": "App-Importer",
        "desc": "Deployment via ZIP & Manifest, Quick-Installer für gängige CMS/Frameworks",
        "icon": "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"
    },
    {
        "key": "backups",
        "label": "Backups & Restore",
        "desc": "Erstellung, Download und Wiederherstellung von Webspace- und MySQL-Backups",
        "icon": "M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"
    },
    {
        "key": "packages",
        "label": "Paket-Installer",
        "desc": "Installation und Konfiguration von PHP-Versionen, Node.js, Composer, Redis etc.",
        "icon": "M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"
    },
    {
        "key": "cron",
        "label": "Cronjobs & Aufgaben",
        "desc": "Geplante Hintergrund-Aufgaben und Crontab-Einträge",
        "icon": "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
    },
    {
        "key": "users",
        "label": "Benutzer & Rollen",
        "desc": "Vollständige Benutzerverwaltung, Rollen-Matrix, 2FA-Reset und Zugriffsrechte",
        "icon": "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
    },
    {
        "key": "monitor",
        "label": "Nur-Lese-Monitoring",
        "desc": "Einsicht in Systemmetriken, Protokolle und Audit-Logs ohne Schreibrechte",
        "icon": "M15 12a3 3 0 11-6 0 3 3 0 016 0z"
    }
]

def require_users_permission(view):
    """Prüft ob der Benutzer root_admin ist oder über die Berechtigung 'users' verfügt."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get("user_id") or not session.get("authenticated"):
            return redirect(url_for("auth.login", next=request.path))

        user_role = session.get("role", "monitor")
        if user_role == "root_admin":
            return view(**kwargs)

        role_record = query_db("SELECT permissions FROM roles WHERE name = ?", (user_role,), one=True)
        perms = [p.strip() for p in (role_record["permissions"].split(",") if role_record and role_record["permissions"] else [])]

        if "users" not in perms:
            log_audit(
                username=session.get("username", "unknown"),
                action="PERMISSION_DENIED",
                details=f"Unberechtigter Zugriff auf Benutzerverwaltung (Rolle: {user_role})",
                ip_address=request.remote_addr,
                status="warning"
            )
            flash("Zugriff verweigert: Du hast keine Berechtigung für die Benutzer- und Rollenverwaltung.", "error")
            return redirect(url_for("system.index"))

        return view(**kwargs)
    return wrapped_view

@users_bp.route("/")
@require_users_permission
def index():
    tab = request.args.get("tab", "users")
    
    # 1. Benutzerliste mit Rolleninformationen
    users = query_db("""
    SELECT 
        u.id, 
        u.username, 
        u.role, 
        u.email, 
        u.totp_enabled, 
        u.is_active, 
        u.created_at, 
        u.last_login,
        r.display_name AS role_display,
        r.permissions AS role_permissions,
        r.is_system AS role_is_system
    FROM users u
    LEFT JOIN roles r ON u.role = r.name
    ORDER BY u.id ASC
    """)

    # 2. Rollenliste mit Zählung der zugeordneten Benutzer
    roles = query_db("""
    SELECT 
        r.id, 
        r.name, 
        r.display_name, 
        r.description, 
        r.permissions, 
        r.is_system, 
        r.created_at,
        COUNT(u.id) AS user_count
    FROM roles r
    LEFT JOIN users u ON r.name = u.role
    GROUP BY r.id
    ORDER BY r.is_system DESC, r.name ASC
    """)

    # Rollen-Mapping für einfache Lookup im Template
    roles_list = []
    for r in roles:
        r_dict = dict(r)
        r_dict["permissions_list"] = [p.strip() for p in (r["permissions"].split(",") if r["permissions"] else [])]
        roles_list.append(r_dict)

    # 3. Audit-Log (Benutzer- & Sicherheitsaktionen)
    audit_logs = query_db("""
    SELECT * FROM audit_logs 
    WHERE action LIKE '%USER%' OR action LIKE '%2FA%' OR action LIKE '%ROLE%' OR action LIKE '%PASSWORD%'
    ORDER BY id DESC LIMIT 50
    """)

    # KPIs
    total_users = len(users)
    active_users = sum(1 for u in users if u["is_active"] == 1)
    totp_users = sum(1 for u in users if u["totp_enabled"] == 1)
    total_roles = len(roles)

    return render_template(
        "users.html",
        users=users,
        roles=roles_list,
        audit_logs=audit_logs,
        system_permissions=SYSTEM_PERMISSIONS,
        active_tab=tab,
        total_users=total_users,
        active_users=active_users,
        totp_users=totp_users,
        total_roles=total_roles
    )

# --- Benutzer-Aktionen ---

@users_bp.route("/create", methods=["POST"])
@require_users_permission
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "web_admin").strip()
    is_active = 1 if request.form.get("is_active") == "1" else 0

    if not username or len(username) < 3:
        flash("Der Benutzername muss mindestens 3 Zeichen lang sein.", "error")
        return redirect(url_for("users.index", tab="users"))

    if not username.replace("_", "").replace("-", "").isalnum():
        flash("Der Benutzername darf nur alphanumerische Zeichen, Unterstriche und Bindestriche enthalten.", "error")
        return redirect(url_for("users.index", tab="users"))

    if len(password) < 8:
        flash("Das Passwort muss mindestens 8 Zeichen lang sein.", "error")
        return redirect(url_for("users.index", tab="users"))

    # Prüfen ob Rolle existiert
    role_exists = query_db("SELECT id FROM roles WHERE name = ?", (role,), one=True)
    if not role_exists:
        flash(f"Ungültige Rolle '{role}' ausgewählt.", "error")
        return redirect(url_for("users.index", tab="users"))

    # Prüfen ob Benutzername existiert
    existing = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
    if existing:
        flash(f"Der Benutzername '{username}' existiert bereits.", "error")
        return redirect(url_for("users.index", tab="users"))

    p_hash = generate_password_hash(password)
    execute_db("""
    INSERT INTO users (username, password_hash, role, email, is_active)
    VALUES (?, ?, ?, ?, ?)
    """, (username, p_hash, role, email, is_active))

    log_audit(
        username=session.get("username", "admin"),
        action="USER_CREATED",
        details=f"Neuer Benutzer '{username}' mit Rolle '{role}' erstellt",
        ip_address=request.remote_addr,
        status="success"
    )

    flash(f"Benutzer '{username}' wurde erfolgreich angelegt.", "success")
    return redirect(url_for("users.index", tab="users"))

@users_bp.route("/update/<int:user_id>", methods=["POST"])
@require_users_permission
def update_user(user_id):
    target = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not target:
        flash("Benutzer nicht gefunden.", "error")
        return redirect(url_for("users.index", tab="users"))

    email = request.form.get("email", "").strip()
    role = request.form.get("role", target["role"]).strip()
    new_password = request.form.get("new_password", "").strip()
    is_active = 1 if request.form.get("is_active") == "1" else 0

    current_uid = session.get("user_id")

    # Eigener Account Schutz
    if current_uid == user_id:
        if is_active == 0:
            flash("Du kannst deinen eigenen Benutzeraccount nicht deaktivieren.", "error")
            return redirect(url_for("users.index", tab="users"))
        if role != target["role"]:
            flash("Du kannst deine eigene Rolle nicht über diese Ansicht ändern.", "error")
            return redirect(url_for("users.index", tab="users"))

    # Schutz vor Deaktivierung/Demotierung des letzten root_admin
    if target["role"] == "root_admin" and (role != "root_admin" or is_active == 0):
        admin_count = query_db("SELECT COUNT(*) FROM users WHERE role = 'root_admin' AND is_active = 1", one=True)[0]
        if admin_count <= 1:
            flash("Der letzte aktive Root Administrator kann nicht deaktiviert oder herabgestuft werden.", "error")
            return redirect(url_for("users.index", tab="users"))

    # Rolle prüfen
    role_exists = query_db("SELECT id FROM roles WHERE name = ?", (role,), one=True)
    if not role_exists:
        flash("Die gewählte Rolle existiert nicht.", "error")
        return redirect(url_for("users.index", tab="users"))

    if new_password:
        if len(new_password) < 8:
            flash("Das neue Passwort muss mindestens 8 Zeichen lang sein.", "error")
            return redirect(url_for("users.index", tab="users"))
        p_hash = generate_password_hash(new_password)
        execute_db("""
        UPDATE users SET email = ?, role = ?, is_active = ?, password_hash = ? WHERE id = ?
        """, (email, role, is_active, p_hash, user_id))
        pwd_msg = " und neues Passwort gesetzt"
    else:
        execute_db("""
        UPDATE users SET email = ?, role = ?, is_active = ? WHERE id = ?
        """, (email, role, is_active, user_id))
        pwd_msg = ""

    log_audit(
        username=session.get("username", "admin"),
        action="USER_UPDATED",
        details=f"Benutzer '{target['username']}' bearbeitet (Rolle: {role}, Aktiv: {is_active}){pwd_msg}",
        ip_address=request.remote_addr,
        status="success"
    )

    flash(f"Benutzer '{target['username']}' wurde erfolgreich aktualisiert{pwd_msg}.", "success")
    return redirect(url_for("users.index", tab="users"))

@users_bp.route("/toggle-status/<int:user_id>", methods=["POST"])
@require_users_permission
def toggle_status(user_id):
    current_uid = session.get("user_id")
    if current_uid == user_id:
        flash("Du kannst deinen eigenen Benutzeraccount nicht sperren.", "error")
        return redirect(url_for("users.index", tab="users"))

    target = query_db("SELECT username, role, is_active FROM users WHERE id = ?", (user_id,), one=True)
    if not target:
        flash("Benutzer nicht gefunden.", "error")
        return redirect(url_for("users.index", tab="users"))

    new_status = 0 if target["is_active"] == 1 else 1

    # Schutz vor Deaktivierung des letzten root_admin
    if target["role"] == "root_admin" and new_status == 0:
        admin_count = query_db("SELECT COUNT(*) FROM users WHERE role = 'root_admin' AND is_active = 1", one=True)[0]
        if admin_count <= 1:
            flash("Der letzte aktive Root Administrator kann nicht gesperrt werden.", "error")
            return redirect(url_for("users.index", tab="users"))

    execute_db("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))

    status_str = "gesperrt" if new_status == 0 else "reaktiviert"
    log_audit(
        username=session.get("username", "admin"),
        action="USER_STATUS_TOGGLED",
        details=f"Benutzer '{target['username']}' wurde {status_str}",
        ip_address=request.remote_addr,
        status="warning" if new_status == 0 else "success"
    )

    flash(f"Benutzer '{target['username']}' wurde {status_str}.", "success")
    return redirect(url_for("users.index", tab="users"))

@users_bp.route("/reset-2fa/<int:user_id>", methods=["POST"])
@require_users_permission
def reset_2fa(user_id):
    target = query_db("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
    if not target:
        flash("Benutzer nicht gefunden.", "error")
        return redirect(url_for("users.index", tab="users"))

    execute_db("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", (user_id,))

    log_audit(
        username=session.get("username", "admin"),
        action="2FA_RESET_BY_ADMIN",
        details=f"2FA für Benutzer '{target['username']}' wurde durch Administrator zurückgesetzt",
        ip_address=request.remote_addr,
        status="warning"
    )

    flash(f"Zwei-Faktor-Authentifizierung für '{target['username']}' wurde erfolgreich zurückgesetzt.", "success")
    return redirect(url_for("users.index", tab="users"))

@users_bp.route("/delete/<int:user_id>", methods=["POST"])
@require_users_permission
def delete_user(user_id):
    current_uid = session.get("user_id")
    if current_uid == user_id:
        flash("Du kannst deinen eigenen Benutzeraccount nicht löschen.", "error")
        return redirect(url_for("users.index", tab="users"))

    target = query_db("SELECT username, role FROM users WHERE id = ?", (user_id,), one=True)
    if not target:
        flash("Benutzer nicht gefunden.", "error")
        return redirect(url_for("users.index", tab="users"))

    if target["role"] == "root_admin":
        admin_count = query_db("SELECT COUNT(*) FROM users WHERE role = 'root_admin' AND is_active = 1", one=True)[0]
        if admin_count <= 1:
            flash("Der letzte Root Administrator kann nicht gelöscht werden.", "error")
            return redirect(url_for("users.index", tab="users"))

    execute_db("DELETE FROM users WHERE id = ?", (user_id,))

    log_audit(
        username=session.get("username", "admin"),
        action="USER_DELETED",
        details=f"Benutzer '{target['username']}' unwiderruflich gelöscht",
        ip_address=request.remote_addr,
        status="warning"
    )

    flash(f"Benutzer '{target['username']}' wurde gelöscht.", "success")
    return redirect(url_for("users.index", tab="users"))

# --- Rollen- & Berechtigungs-Aktionen ---

@users_bp.route("/role/create", methods=["POST"])
@require_users_permission
def create_role():
    name = request.form.get("name", "").strip().lower()
    display_name = request.form.get("display_name", "").strip()
    description = request.form.get("description", "").strip()
    perms = request.form.getlist("permissions")

    if not name or len(name) < 3 or not name.replace("_", "").isalnum():
        flash("Der Rollen-Kennzeichner (Code) darf nur Kleinbuchstaben, Zahlen und Unterstriche enthalten (min. 3 Zeichen).", "error")
        return redirect(url_for("users.index", tab="roles"))

    if not display_name:
        flash("Bitte gib einen aussagekräftigen Anzeigenamen für die Rolle an.", "error")
        return redirect(url_for("users.index", tab="roles"))

    existing = query_db("SELECT id FROM roles WHERE name = ?", (name,), one=True)
    if existing:
        flash(f"Eine Rolle mit dem Kennzeichner '{name}' existiert bereits.", "error")
        return redirect(url_for("users.index", tab="roles"))

    # Berechtigungen filtern & komprimieren
    valid_keys = {p["key"] for p in SYSTEM_PERMISSIONS}
    clean_perms = [p for p in perms if p in valid_keys]
    perms_str = ",".join(clean_perms)

    execute_db("""
    INSERT INTO roles (name, display_name, description, permissions, is_system)
    VALUES (?, ?, ?, ?, 0)
    """, (name, display_name, description, perms_str))

    log_audit(
        username=session.get("username", "admin"),
        action="ROLE_CREATED",
        details=f"Neue Rolle '{display_name}' ({name}) mit Berechtigungen [{perms_str}] erstellt",
        ip_address=request.remote_addr,
        status="success"
    )

    flash(f"Rolle '{display_name}' erfolgreich erstellt.", "success")
    return redirect(url_for("users.index", tab="roles"))

@users_bp.route("/role/update/<int:role_id>", methods=["POST"])
@require_users_permission
def update_role(role_id):
    target = query_db("SELECT * FROM roles WHERE id = ?", (role_id,), one=True)
    if not target:
        flash("Rolle nicht gefunden.", "error")
        return redirect(url_for("users.index", tab="roles"))

    display_name = request.form.get("display_name", "").strip()
    description = request.form.get("description", "").strip()
    perms = request.form.getlist("permissions")

    if not display_name:
        flash("Der Anzeigename darf nicht leer sein.", "error")
        return redirect(url_for("users.index", tab="roles"))

    valid_keys = {p["key"] for p in SYSTEM_PERMISSIONS}
    clean_perms = [p for p in perms if p in valid_keys]

    # Sonderfall root_admin: Berechtigungen müssen vollständig bleiben
    if target["name"] == "root_admin":
        perms_str = ",".join(sorted(valid_keys))
    else:
        perms_str = ",".join(clean_perms)

    execute_db("""
    UPDATE roles SET display_name = ?, description = ?, permissions = ? WHERE id = ?
    """, (display_name, description, perms_str, role_id))

    log_audit(
        username=session.get("username", "admin"),
        action="ROLE_UPDATED",
        details=f"Rolle '{target['name']}' aktualisiert: [{perms_str}]",
        ip_address=request.remote_addr,
        status="success"
    )

    flash(f"Rolle '{display_name}' wurde erfolgreich aktualisiert.", "success")
    return redirect(url_for("users.index", tab="roles"))

@users_bp.route("/role/delete/<int:role_id>", methods=["POST"])
@require_users_permission
def delete_role(role_id):
    target = query_db("SELECT * FROM roles WHERE id = ?", (role_id,), one=True)
    if not target:
        flash("Rolle nicht gefunden.", "error")
        return redirect(url_for("users.index", tab="roles"))

    if target["is_system"] == 1:
        flash(f"Die Systemrolle '{target['display_name']}' ist geschützt und kann nicht gelöscht werden.", "error")
        return redirect(url_for("users.index", tab="roles"))

    # Prüfen ob noch Benutzer dieser Rolle zugewiesen sind
    assigned_users = query_db("SELECT COUNT(*) FROM users WHERE role = ?", (target["name"],), one=True)[0]
    if assigned_users > 0:
        flash(f"Die Rolle kann nicht gelöscht werden, da ihr noch {assigned_users} Benutzer zugewiesen sind. Bitte weise diesen Benutzern zuerst eine andere Rolle zu.", "error")
        return redirect(url_for("users.index", tab="roles"))

    execute_db("DELETE FROM roles WHERE id = ?", (role_id,))

    log_audit(
        username=session.get("username", "admin"),
        action="ROLE_DELETED",
        details=f"Benutzerdefinierte Rolle '{target['name']}' gelöscht",
        ip_address=request.remote_addr,
        status="warning"
    )

    flash(f"Rolle '{target['display_name']}' wurde gelöscht.", "success")
    return redirect(url_for("users.index", tab="roles"))
