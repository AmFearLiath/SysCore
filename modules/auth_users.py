import io
import base64
import functools
import pyotp
import qrcode
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from db import query_db, execute_db, log_audit

auth_bp = Blueprint("auth", __name__)

# Rollen-Hierarchie
ROLE_PERMISSIONS = {
    "root_admin": ["system", "packages", "webserver", "database", "files", "apps", "backups", "cron", "settings", "users", "monitor"],
    "web_admin":  ["webserver", "database", "files", "apps", "backups", "monitor"],
    "monitor":    ["monitor"]
}

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return query_db("SELECT id, username, role, email, totp_enabled, created_at, last_login FROM users WHERE id = ? AND is_active = 1", (user_id,), one=True)

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get("user_id") or not session.get("authenticated"):
            return redirect(url_for("auth.login", next=request.path))
        return view(**kwargs)
    return wrapped_view

def role_required(allowed_roles):
    def decorator(view):
        @functools.wraps(view)
        def wrapped_view(**kwargs):
            if not session.get("user_id") or not session.get("authenticated"):
                return redirect(url_for("auth.login", next=request.path))
            
            user_role = session.get("role", "monitor")
            if user_role not in allowed_roles:
                log_audit(
                    username=session.get("username", "unknown"),
                    action="PERMISSION_DENIED",
                    details=f"Unberechtigter Zugriff auf {request.path} (Rolle: {user_role}, benötigt: {allowed_roles})",
                    ip_address=request.remote_addr,
                    status="warning"
                )
                flash("Zugriff verweigert: Deine Benutzerrolle verfügt nicht über ausreichende Berechtigungen.", "error")
                return redirect(url_for("system.index"))
            return view(**kwargs)
        return wrapped_view
    return decorator

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") and session.get("authenticated"):
        return redirect(url_for("system.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = query_db("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,), one=True)

        if user and check_password_hash(user["password_hash"], password):
            # Prüfen ob 2FA aktiv ist
            if user["totp_enabled"] and user["totp_secret"]:
                session["pending_2fa_user_id"] = user["id"]
                session["pending_2fa_username"] = user["username"]
                return redirect(url_for("auth.verify_2fa"))

            # Vollständiger Login
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["authenticated"] = True

            execute_db("UPDATE users SET last_login = ? WHERE id = ?", (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            log_audit(username, "USER_LOGIN", "Erfolgreich angemeldet", request.remote_addr, "success")
            flash(f"Willkommen zurück, {user['username']}!", "success")

            next_url = request.args.get("next")
            return redirect(next_url or url_for("system.index"))

        log_audit(username, "USER_LOGIN_FAILED", "Fehlgeschlagener Login-Versuch", request.remote_addr, "warning")
        flash("Ungültige Zugangsdaten.", "error")

    return render_template("login.html")

@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = query_db("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,), one=True)
    if not user or not user["totp_secret"]:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code, valid_window=1):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["authenticated"] = True

            execute_db("UPDATE users SET last_login = ? WHERE id = ?", (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            log_audit(user["username"], "2FA_VERIFY_SUCCESS", "Zwei-Faktor-Authentifizierung erfolgreich", request.remote_addr, "success")
            flash(f"Willkommen zurück, {user['username']}!", "success")
            return redirect(url_for("system.index"))

        log_audit(user["username"], "2FA_VERIFY_FAILED", "Ungültiger 2FA Token eingegeben", request.remote_addr, "warning")
        flash("Ungültiger 2FA Code. Bitte erneut versuchen.", "error")

    return render_template("verify_2fa.html", username=user["username"])

@auth_bp.route("/logout")
def logout():
    uname = session.get("username", "unknown")
    log_audit(uname, "USER_LOGOUT", "Benutzer hat sich abgemeldet", request.remote_addr, "success")
    session.clear()
    flash("Du wurdest erfolgreich abgemeldet.", "success")
    return redirect(url_for("auth.login"))

# --- 2FA Verwaltung (Eigenes Profil) ---

@auth_bp.route("/profile/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = current_user()
    if not user:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip().replace(" ", "")
        secret = session.get("temp_totp_secret")

        if not secret:
            flash("Sitzung abgelaufen. Bitte 2FA-Einrichtung erneut starten.", "error")
            return redirect(url_for("auth.setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(token, valid_window=1):
            execute_db("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?", (secret, user["id"]))
            session.pop("temp_totp_secret", None)
            log_audit(user["username"], "2FA_ENABLED", "2FA erfolgreich aktiviert", request.remote_addr, "success")
            flash("Zwei-Faktor-Authentifizierung wurde erfolgreich aktiviert!", "success")
            return redirect(url_for("settings.index", tab="security"))
        else:
            flash("Ungültiger Bestätigungscode. Bitte prüfe deine Authenticator-App.", "error")

    # Neues Secret generieren falls keines in Bearbeitung
    secret = session.get("temp_totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["temp_totp_secret"] = secret

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user["username"], issuer_name="SysCore Server")

    # QR-Code generieren als Base64
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#10b981", back_color="#090d16")

    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template("setup_2fa.html", qr_base64=qr_base64, secret=secret, user=user)

@auth_bp.route("/profile/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    user = current_user()
    execute_db("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", (user["id"],))
    log_audit(user["username"], "2FA_DISABLED", "2FA deaktiviert", request.remote_addr, "warning")
    flash("Zwei-Faktor-Authentifizierung wurde deaktiviert.", "success")
    return redirect(url_for("settings.index", tab="security"))

# --- Benutzerverwaltung (Nur root_admin) ---

@auth_bp.route("/users/create", methods=["POST"])
@login_required
@role_required(["root_admin"])
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "web_admin")

    if not username or len(username) < 3 or not username.isalnum():
        flash("Benutzername muss mindestens 3 Zeichen lang sein und darf nur Buchstaben und Zahlen enthalten.", "error")
        return redirect(url_for("settings.index", tab="users"))

    if len(password) < 8:
        flash("Das Passwort muss mindestens 8 Zeichen lang sein.", "error")
        return redirect(url_for("settings.index", tab="users"))

    if role not in ROLE_PERMISSIONS:
        flash("Ungültige Benutzerrolle gewählt.", "error")
        return redirect(url_for("settings.index", tab="users"))

    existing = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
    if existing:
        flash(f"Benutzername '{username}' ist bereits vergeben.", "error")
        return redirect(url_for("settings.index", tab="users"))

    p_hash = generate_password_hash(password)
    execute_db("""
    INSERT INTO users (username, password_hash, role, email, is_active)
    VALUES (?, ?, ?, ?, 1)
    """, (username, p_hash, role, email))

    log_audit(session.get("username"), "USER_CREATED", f"Benutzer '{username}' mit Rolle '{role}' erstellt", request.remote_addr)
    flash(f"Benutzer '{username}' erfolgreich angelegt.", "success")
    return redirect(url_for("settings.index", tab="users"))

@auth_bp.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("Du kannst deinen eigenen Benutzeraccount nicht löschen.", "error")
        return redirect(url_for("settings.index", tab="users"))

    target_user = query_db("SELECT username, role FROM users WHERE id = ?", (user_id,), one=True)
    if not target_user:
        flash("Benutzer nicht gefunden.", "error")
        return redirect(url_for("settings.index", tab="users"))

    # Schutz vor Löschen des letzten root_admin
    if target_user["role"] == "root_admin":
        admin_count = query_db("SELECT COUNT(*) FROM users WHERE role = 'root_admin' AND is_active = 1", one=True)[0]
        if admin_count <= 1:
            flash("Der letzte verbliebene root_admin kann nicht gelöscht werden.", "error")
            return redirect(url_for("settings.index", tab="users"))

    execute_db("DELETE FROM users WHERE id = ?", (user_id,))
    log_audit(session.get("username"), "USER_DELETED", f"Benutzer '{target_user['username']}' gelöscht", request.remote_addr, "warning")
    flash(f"Benutzer '{target_user['username']}' wurde gelöscht.", "success")
    return redirect(url_for("settings.index", tab="users"))

@auth_bp.route("/users/reset-password/<int:user_id>", methods=["POST"])
@login_required
@role_required(["root_admin"])
def reset_user_password(user_id):
    new_password = request.form.get("new_password", "").strip()
    if len(new_password) < 8:
        flash("Neues Passwort muss mindestens 8 Zeichen lang sein.", "error")
        return redirect(url_for("settings.index", tab="users"))

    target_user = query_db("SELECT username FROM users WHERE id = ?", (user_id,), one=True)
    if not target_user:
        flash("Benutzer nicht gefunden.", "error")
        return redirect(url_for("settings.index", tab="users"))

    p_hash = generate_password_hash(new_password)
    execute_db("UPDATE users SET password_hash = ? WHERE id = ?", (p_hash, user_id))
    log_audit(session.get("username"), "USER_PASSWORD_RESET", f"Passwort für '{target_user['username']}' zurückgesetzt", request.remote_addr)
    flash(f"Passwort für '{target_user['username']}' erfolgreich geändert.", "success")
    return redirect(url_for("settings.index", tab="users"))

@auth_bp.route("/profile/change-password", methods=["POST"])
@login_required
def change_own_password():
    user_id = session.get("user_id")
    user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if not check_password_hash(user["password_hash"], old_password):
        flash("Das bisherige Passwort ist nicht korrekt.", "error")
        return redirect(url_for("settings.index", tab="security"))

    if len(new_password) < 8:
        flash("Das neue Passwort muss mindestens 8 Zeichen lang sein.", "error")
        return redirect(url_for("settings.index", tab="security"))

    p_hash = generate_password_hash(new_password)
    execute_db("UPDATE users SET password_hash = ? WHERE id = ?", (p_hash, user_id))
    log_audit(user["username"], "PASSWORD_CHANGED", "Eigenes Passwort geändert", request.remote_addr)
    flash("Dein Passwort wurde erfolgreich aktualisiert.", "success")
    return redirect(url_for("settings.index", tab="security"))
