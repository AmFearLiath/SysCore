import io
import re
import base64
import secrets
import functools
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from db import query_db, execute_db, log_audit

try:
    import pyotp
except ImportError:
    pyotp = None

try:
    import qrcode
    import qrcode.constants
    import qrcode.image.svg
except ImportError:
    qrcode = None

__all__ = ["auth_bp", "current_user", "login_required", "role_required", "log_audit", "is_safe_redirect_url"]

auth_bp = Blueprint("auth", __name__)

def is_safe_redirect_url(target):
    """
    Schutz vor Open Redirects (SEC-010):
    Erlaubt ausschließlich relative Pfade innerhalb derselben Instanz (beginnend mit '/'),
    verbietet externe URLs ('http://', 'https://') und protokoll-relative URLs ('//evil.com', '/\\evil.com').
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if not target.startswith("/") or target.startswith("//") or target.startswith("/\\"):
        return False
    try:
        parsed = urlsplit(target)
        return not parsed.scheme and not parsed.netloc
    except Exception:
        return False

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    from db import is_system_owner
    u = query_db("SELECT id, username, role, email, totp_enabled, is_owner, created_at, last_login FROM users WHERE id = ? AND is_active = 1", (user_id,), one=True)
    if u and is_system_owner(u):
        # Sicherstellen, dass u['is_owner'] für Templates immer 1 ist wenn es der System-Owner ist
        if hasattr(u, "_values") and hasattr(u, "_col_names"):
            pass
    return u

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id or not session.get("authenticated"):
            return redirect(url_for("auth.login", next=request.path))
        
        # Live DB-Validierung: Konto aktiv? (SEC-009)
        u = query_db("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,), one=True)
        if not u or not u["is_active"]:
            session.clear()
            flash("Deine Sitzung ist ungültig oder das Benutzerkonto wurde deaktiviert.", "error")
            return redirect(url_for("auth.login"))

        session["role"] = u["role"]
        session["username"] = u["username"]
        return view(*args, **kwargs)
    return wrapped_view

def role_required(allowed_roles):
    def decorator(view):
        @functools.wraps(view)
        def wrapped_view(*args, **kwargs):
            user_id = session.get("user_id")
            if not user_id or not session.get("authenticated"):
                return redirect(url_for("auth.login", next=request.path))
            
            # Live DB-Validierung: Rolle und Sperrstatus direkt abfragen (SEC-009)
            u = query_db("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,), one=True)
            if not u or not u["is_active"]:
                session.clear()
                flash("Deine Sitzung ist ungültig oder das Benutzerkonto wurde deaktiviert.", "error")
                return redirect(url_for("auth.login"))

            session["role"] = u["role"]
            session["username"] = u["username"]
            user_role = u["role"]

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
            return view(*args, **kwargs)
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
            # Validiere next_url gegen Open Redirect (SEC-010)
            raw_next = request.args.get("next") or request.form.get("next")
            safe_next = raw_next if is_safe_redirect_url(raw_next) else None

            # Prüfen ob 2FA aktiv ist
            if user["totp_enabled"] and user["totp_secret"]:
                session["pending_2fa_user_id"] = user["id"]
                session["pending_2fa_username"] = user["username"]
                if safe_next:
                    session["pending_next_url"] = safe_next
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

            return redirect(safe_next or url_for("system.index"))

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

        if not pyotp:
            flash("2FA-Modul (pyotp) ist nicht verfügbar.", "error")
            return redirect(url_for("auth.verify_2fa"))

        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code, valid_window=2):
            safe_next = session.get("pending_next_url")
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["authenticated"] = True

            execute_db("UPDATE users SET last_login = ? WHERE id = ?", (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            execute_db("DELETE FROM qr_login_tokens WHERE user_id = ?", (user["id"],))
            log_audit(user["username"], "2FA_VERIFY_SUCCESS", "Zwei-Faktor-Authentifizierung via Code erfolgreich", request.remote_addr, "success")
            flash(f"Willkommen zurück, {user['username']}!", "success")
            return redirect(safe_next or url_for("system.index"))

        log_audit(user["username"], "2FA_VERIFY_FAILED", "Ungültiger 2FA Token eingegeben", request.remote_addr, "warning")
        flash("Ungültiger 2FA Code. Bitte erneut versuchen.", "error")
        return redirect(url_for("auth.verify_2fa"))

    # --- GET: Vorbereitung des Login-QR-Codes (1-Klick Freigabe) ---
    # Gültigkeit gehärtet auf max. 3 Minuten (SEC-011)
    now = datetime.utcnow()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = (now + timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S")

    # Veraltete Tokens aufräumen
    execute_db("DELETE FROM qr_login_tokens WHERE expires_at < ?", (now_str,))

    qr_token = session.get("pending_2fa_qr_token")
    if qr_token:
        existing = query_db("SELECT * FROM qr_login_tokens WHERE token = ? AND expires_at > ?", (qr_token, now_str), one=True)
        if not existing:
            qr_token = None

    if not qr_token:
        qr_token = secrets.token_urlsafe(32)
        session["pending_2fa_qr_token"] = qr_token
        execute_db(
            "INSERT INTO qr_login_tokens (token, user_id, username, ip_address, approved, created_at, expires_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
            (qr_token, user["id"], user["username"], request.remote_addr, now_str, expires_at)
        )

    qr_approval_url = url_for("auth.approve_qr", token=qr_token, _external=True)
    qr_base64 = None

    if qrcode:
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=3
            )
            qr.add_data(qr_approval_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        except Exception as e:
            print(f"[SysCore 2FA QR Error] {e}")

    resp = make_response(render_template(
        "verify_2fa.html",
        username=user["username"],
        qr_base64=qr_base64,
        qr_token=qr_token,
        qr_url=qr_approval_url
    ))
    # Anti-Caching & No-Referrer Header (SEC-011)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

@auth_bp.route("/login/2fa/qr-status")
def qr_status():
    """Prüft asynchron, ob die mobile QR-Freigabe erteilt wurde."""
    qr_token = session.get("pending_2fa_qr_token")
    user_id = session.get("pending_2fa_user_id")

    if not qr_token or not user_id:
        return jsonify({"approved": False, "expired": True})

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    row = query_db("SELECT * FROM qr_login_tokens WHERE token = ? AND expires_at > ?", (qr_token, now_str), one=True)

    if not row:
        return jsonify({"approved": False, "expired": True})

    if row["approved"] == 1:
        user = query_db("SELECT * FROM users WHERE id = ? AND is_active = 1", (row["user_id"],), one=True)
        if user:
            safe_next = session.get("pending_next_url")
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["authenticated"] = True

            execute_db("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user["id"]))
            # Einmalige Nutzung: Token sofort nach erfolgreichem Login zerstören (SEC-011)
            execute_db("DELETE FROM qr_login_tokens WHERE token = ?", (qr_token,))
            log_audit(user["username"], "2FA_QR_LOGIN_SUCCESS", f"Zwei-Faktor-Login via QR-Scan freigegeben (Desktop-IP: {row['ip_address']})", request.remote_addr, "success")
            flash(f"Willkommen zurück, {user['username']}! (Erfolgreich via QR-Code autorisiert)", "success")
            return jsonify({"approved": True, "redirect": safe_next or url_for("system.index")})

    return jsonify({"approved": False})

@auth_bp.route("/login/2fa/approve/<token>", methods=["GET", "POST"])
def approve_qr(token):
    """Mobile Seite: Erlaubt das Freigeben des Desktop-Logins per Smartphone-Klick."""
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    row = query_db("SELECT * FROM qr_login_tokens WHERE token = ? AND expires_at > ?", (token, now_str), one=True)

    if not row:
        resp = make_response(render_template(
            "approve_qr.html",
            error="Diese Anmeldeanforderung ist ungültig oder abgelaufen. Bitte lade die Login-Seite am Desktop neu."
        ))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    user = query_db("SELECT * FROM users WHERE id = ? AND is_active = 1", (row["user_id"],), one=True)
    if not user:
        resp = make_response(render_template("approve_qr.html", error="Benutzerkonto nicht aktiv oder nicht gefunden."))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    if row["approved"] == 1:
        resp = make_response(render_template("approve_qr.html", success=True, already_approved=True, username=row["username"]))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    if request.method == "POST":
        # Bestätigung speichern (Single-Use Token Markierung)
        execute_db("UPDATE qr_login_tokens SET approved = 1 WHERE token = ?", (token,))
        log_audit(user["username"], "2FA_QR_APPROVED", f"QR-Login freigegeben für Rechner-IP {row['ip_address']}", request.remote_addr, "success")
        resp = make_response(render_template(
            "approve_qr.html",
            success=True,
            username=row["username"],
            requester_ip=row["ip_address"]
        ))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    resp = make_response(render_template(
        "approve_qr.html",
        row=row,
        username=row["username"],
        requester_ip=row["ip_address"],
        token=token
    ))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

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

    if not pyotp:
        flash("Das Python-Modul 'pyotp' ist nicht installiert. Bitte führe 'pip install pyotp qrcode' aus.", "error")
        return redirect(url_for("system.index"))

    if request.method == "POST":
        token = request.form.get("token", "").strip().replace(" ", "")
        secret = session.get("temp_totp_secret")

        if not secret:
            flash("Sitzung abgelaufen. Bitte 2FA-Einrichtung erneut starten.", "error")
            return redirect(url_for("auth.setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(token, valid_window=2):
            execute_db("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?", (secret, user["id"]))
            session.pop("temp_totp_secret", None)
            log_audit(user["username"], "2FA_ENABLED", "2FA erfolgreich aktiviert", request.remote_addr, "success")
            flash("Zwei-Faktor-Authentifizierung wurde erfolgreich aktiviert!", "success")
            return redirect(url_for("system.index"))
        else:
            flash("Ungültiger Bestätigungscode. Bitte prüfe deine Authenticator-App und die Systemzeit.", "error")

    # Neues Secret generieren falls keines in Bearbeitung
    secret = session.get("temp_totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["temp_totp_secret"] = secret

    totp = pyotp.TOTP(secret)
    # Eindeutiger Issuer ohne Sonderzeichen/Leerzeichen für maximale Authenticator-Kompatibilität
    provisioning_uri = totp.provisioning_uri(name=user["username"], issuer_name="SysCore")

    qr_svg = None
    qr_base64 = None

    if qrcode:
        # 1. Bevorzugt: Gestochen scharfes PNG mit Standard Schwarz-auf-Weiß (Pillow) & 4-Modul Quiet Zone
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        except Exception:
            pass

        # 2. Fallback: Valides, responsives Vektor-SVG mit weißem Hintergrund und 4-Modul Quiet Zone
        if not qr_base64:
            try:
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=10,
                    border=4,
                    image_factory=qrcode.image.svg.SvgPathImage
                )
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                img = qr.make_image()
                buffered = io.BytesIO()
                img.save(buffered)
                svg_str = buffered.getvalue().decode("utf-8")
                
                # mm-Dimensionen durch 100% ersetzen für saubere CSS-Skalierung
                svg_str = re.sub(r'width="[^"]+"', 'width="100%"', svg_str, count=1)
                svg_str = re.sub(r'height="[^"]+"', 'height="100%"', svg_str, count=1)
                
                # Weißen Hintergrund-Rechteck in SVG einfügen
                svg_start = svg_str.find("<svg")
                if svg_start != -1:
                    svg_tag_end = svg_str.find(">", svg_start)
                    if svg_tag_end != -1:
                        bg_rect = '<rect width="100%" height="100%" fill="#FFFFFF"/>'
                        svg_str = svg_str[:svg_tag_end+1] + bg_rect + svg_str[svg_tag_end+1:]
                qr_svg = svg_str
            except Exception:
                pass

    return render_template("setup_2fa.html", qr_svg=qr_svg, qr_base64=qr_base64, secret=secret, user=user)

@auth_bp.route("/profile/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    user = current_user()
    execute_db("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", (user["id"],))
    log_audit(user["username"], "2FA_DISABLED", "2FA deaktiviert", request.remote_addr, "warning")
    flash("Zwei-Faktor-Authentifizierung wurde deaktiviert.", "success")
    return redirect(request.referrer or url_for("system.index"))

@auth_bp.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    user = current_user()
    email = request.form.get("email", "").strip()
    if email and "@" not in email:
        flash("Bitte eine gültige E-Mail-Adresse angeben.", "error")
        return redirect(request.referrer or url_for("system.index"))

    execute_db("UPDATE users SET email = ? WHERE id = ?", (email, user["id"]))
    log_audit(user["username"], "PROFILE_UPDATE", f"Profil-E-Mail aktualisiert auf '{email}'", request.remote_addr, "success")
    flash("Profil-Einstellungen erfolgreich gespeichert.", "success")
    return redirect(request.referrer or url_for("system.index"))

@auth_bp.route("/profile/change-password", methods=["POST"])
@login_required
def change_own_password():
    user_id = session.get("user_id")
    user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if not check_password_hash(user["password_hash"], old_password):
        flash("Das bisherige Passwort ist nicht korrekt.", "error")
        return redirect(request.referrer or url_for("system.index"))

    if len(new_password) < 8:
        flash("Das neue Passwort muss mindestens 8 Zeichen lang sein.", "error")
        return redirect(request.referrer or url_for("system.index"))

    p_hash = generate_password_hash(new_password)
    execute_db("UPDATE users SET password_hash = ? WHERE id = ?", (p_hash, user_id))
    log_audit(user["username"], "PASSWORD_CHANGED", "Eigenes Passwort geändert", request.remote_addr)
    flash("Dein Passwort wurde erfolgreich aktualisiert.", "success")
    return redirect(request.referrer or url_for("system.index"))
