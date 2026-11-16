import os
import secrets
from pathlib import Path

def ensure_secure_file_permissions(file_path):
    """Sicherheitsanforderung SEC-012: Dateirechte für Secrets auf 0600 (nur Besitzer) beschränken"""
    try:
        if os.name != "nt" and os.path.exists(file_path):
            os.chmod(file_path, 0o600)
    except Exception:
        pass

# Versuche .env Datei zu laden (sofern python-dotenv verfügbar)
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        ensure_secure_file_permissions(env_path)
        load_dotenv(dotenv_path=env_path, override=True)
except ImportError:
    pass

# --- Basis-Version ---
SYSCORE_VERSION = "0.9.0.0"

# --- Basis-Verzeichnis des SysCore-Projekts ---
BASE_DIR = Path(__file__).resolve().parent

# --- Sicherheit & Flask Secret ---
SECRET_KEY = os.getenv("SYSCORE_SECRET_KEY")
if not SECRET_KEY:
    # Falls kein Key in .env konfiguriert ist, persistenten Keyfile nutzen statt bei jedem Neustart Sessions zu verlieren
    keyfile = BASE_DIR / ".secret_key"
    if keyfile.exists():
        SECRET_KEY = keyfile.read_text().strip()
        ensure_secure_file_permissions(keyfile)
    else:
        SECRET_KEY = secrets.token_hex(32)
        try:
            keyfile.write_text(SECRET_KEY)
            ensure_secure_file_permissions(keyfile)
        except OSError:
            pass

# --- Netzwerk & Daemon ---
PANEL_HOST = os.getenv("SYSCORE_HOST", "0.0.0.0")
PANEL_PORT = int(os.getenv("SYSCORE_PORT", "8888"))
DEBUG = os.getenv("SYSCORE_DEBUG", "false").lower() in ("true", "1", "yes")

# --- Bootstrap Zugangsdaten & System-Owner ---
BOOTSTRAP_ADMIN_USER = os.getenv("SYSCORE_ADMIN_USER", "admin")
BOOTSTRAP_ADMIN_PASS = os.getenv("SYSCORE_ADMIN_PASS", "")
BOOTSTRAP_ADMIN_EMAIL = os.getenv("SYSCORE_ADMIN_EMAIL", "admin@localhost")
OWNER_USER = os.getenv("SYSCORE_OWNER_USER", "").strip()

# --- Datenbank Engine & Konfiguration (SQLite vs MySQL) ---
DB_TYPE = os.getenv("SYSCORE_DB_TYPE", "sqlite").lower()
DB_PATH = os.getenv("SYSCORE_DB_PATH", str(BASE_DIR / "syscore.db"))

MYSQL_HOST = os.getenv("SYSCORE_MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("SYSCORE_MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("SYSCORE_MYSQL_USER", "root")
MYSQL_PASS = os.getenv("SYSCORE_MYSQL_PASS", "")
MYSQL_DB = os.getenv("SYSCORE_MYSQL_DB", "syscore")

# --- System- & Web-Pfade ---
WEB_ROOT_BASE = os.getenv("SYSCORE_WEB_ROOT_BASE", "/var/www")
NGINX_AVAILABLE = os.getenv("SYSCORE_NGINX_AVAILABLE", "/etc/nginx/sites-available")
NGINX_ENABLED = os.getenv("SYSCORE_NGINX_ENABLED", "/etc/nginx/sites-enabled")
APACHE_PORTS_CONF = os.getenv("SYSCORE_APACHE_PORTS_CONF", "/etc/apache2/ports.conf")
BACKUP_DIR = os.getenv("SYSCORE_BACKUP_DIR", "/var/backups/syscore")
CERTBOT_EMAIL = os.getenv("SYSCORE_CERTBOT_EMAIL", "admin@localhost")

# Verwaltete Systemd-Dienste
MANAGED_SERVICES = [
    "nginx",
    "apache2",
    "mysql",
    "mariadb",
    "wings",
    "php8.2-fpm",
    "php8.3-fpm",
    "php8.4-fpm",
    "redis-server",
    "fail2ban",
    "ufw"
]
