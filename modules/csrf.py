import hmac
import secrets
from functools import wraps
from flask import request, session, abort, jsonify
from db import log_audit

EXEMPT_PATHS = (
    "/api/webhook/",
    "/mail/config-v1.1.xml",
    "/static/"
)

def get_csrf_token():
    """Generiert oder liefert das aktive CSRF-Token der aktuellen Benutzersitzung (SEC-008)"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def csrf_exempt(view_func):
    """Dekorator zur expliziten Ausnahme von Endpunkten von der CSRF-Prüfung"""
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        return view_func(*args, **kwargs)
    decorated_view._csrf_exempt = True
    return decorated_view

def init_csrf(app):
    """Initialisiert den zentralen CSRF-Schutz für die Flask-Applikation (SEC-008)"""
    # 1. Global in Jinja2 bereitstellen
    app.jinja_env.globals["csrf_token"] = get_csrf_token

    # 2. Vor jeder HTTP-Anfrage validieren
    @app.before_request
    def check_csrf():
        # Sichere Lese-Methoden sind immer erlaubt
        if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return None

        # Ausgenommene Pfade (z. B. externe Webhooks mit HMAC-Prüfung)
        for exempt_prefix in EXEMPT_PATHS:
            if request.path.startswith(exempt_prefix):
                return None

        # Auf View-Dekorator prüfen
        if request.endpoint:
            view = app.view_functions.get(request.endpoint)
            if view and getattr(view, "_csrf_exempt", False):
                return None

        # Token aus Header oder Form extrahieren
        token = (
            request.headers.get("X-CSRF-Token") or
            request.headers.get("X-CSRFToken") or
            request.form.get("csrf_token")
        )

        if not token and request.is_json:
            try:
                json_data = request.get_json(silent=True)
                if isinstance(json_data, dict):
                    token = json_data.get("csrf_token")
            except Exception:
                pass

        session_token = session.get("_csrf_token")

        # Strikter Constant-Time Vergleich gegen Timing-Attacks
        if not token or not session_token or not hmac.compare_digest(str(token), str(session_token)):
            uname = session.get("username", "ANONYMOUS")
            log_audit(
                username=uname,
                action="CSRF_REJECTED",
                details=f"Statusverändernde Anfrage auf '{request.path}' wegen ungültigem/fehlendem CSRF-Token abgewiesen",
                ip_address=request.remote_addr,
                status="warning"
            )
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({
                    "error": "Ungültiges oder abgelaufenes CSRF-Token.",
                    "status": 403
                }), 403

            abort(403, description="Sicherheitsfehler (CSRF): Ungültiges oder abgelaufenes Token. Bitte lade die Seite neu.")
