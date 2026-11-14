import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash
import config

def get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # 1. Benutzer-Tabelle mit RBAC & 2FA
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'web_admin',
        email TEXT,
        totp_secret TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );
    """)

    # 2. Audit-Log für lückenlose Rückverfolgbarkeit aller Aktionen
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        status TEXT DEFAULT 'success'
    );
    """)

    # 3. App-Deployments via Manifest
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS app_deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        app_name TEXT NOT NULL,
        version TEXT,
        app_type TEXT,
        status TEXT DEFAULT 'active',
        details TEXT,
        deployed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Globale Einstellungen (Key/Value)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Backups-Verzeichnis & Metadaten
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        size_bytes INTEGER DEFAULT 0,
        includes_db INTEGER DEFAULT 1,
        includes_files INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 6. E-Mail Postfächer
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mail_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        quota_mb INTEGER DEFAULT 5120,
        used_mb REAL DEFAULT 0.0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 7. E-Mail Aliase & Weiterleitungen
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mail_aliases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        source_email TEXT NOT NULL,
        destination_email TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 8. E-Mail DKIM-Schlüssel
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mail_dkim (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        selector TEXT DEFAULT 'default',
        private_key TEXT NOT NULL,
        public_key TEXT NOT NULL,
        dns_record TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 9. Mailserver-Konfiguration
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mail_server_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        backend_type TEXT DEFAULT 'stalwart',
        webmail_client TEXT DEFAULT 'snappymail',
        smtp_host TEXT DEFAULT '127.0.0.1',
        smtp_port INTEGER DEFAULT 587,
        imap_host TEXT DEFAULT '127.0.0.1',
        imap_port INTEGER DEFAULT 993,
        stalwart_api_url TEXT DEFAULT 'http://127.0.0.1:8080',
        stalwart_api_token TEXT DEFAULT '',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 10. ClamAV Malware Scans
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clamav_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_path TEXT NOT NULL,
        scanned_files INTEGER DEFAULT 0,
        infected_files INTEGER DEFAULT 0,
        scan_log TEXT,
        status TEXT DEFAULT 'completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 11. Manuelle & Automatische IP-Bans
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_ip_bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        reason TEXT,
        banned_by TEXT DEFAULT 'admin',
        ban_type TEXT DEFAULT 'ufw',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 12. Git Webhook Auto-Deployer
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS web_deploy_hooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        token TEXT UNIQUE NOT NULL,
        branch TEXT DEFAULT 'main',
        post_deploy_cmd TEXT DEFAULT '',
        last_deployed_at TIMESTAMP,
        last_status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 13. Dynamische Rollen & Berechtigungen (RBAC)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        description TEXT,
        permissions TEXT NOT NULL,
        is_system INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 14. Paket-Konfigurationen & Routing (Subdomains für phpMyAdmin, Adminer, Uptime Kuma etc.)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS package_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_key TEXT UNIQUE NOT NULL,
        domain TEXT,
        mode TEXT DEFAULT 'subdomain',
        port INTEGER,
        ssl_enabled INTEGER DEFAULT 1,
        php_version TEXT DEFAULT '8.2',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Standard-Rollen anlegen falls noch keine vorhanden
    cursor.execute("SELECT COUNT(*) FROM roles;")
    if cursor.fetchone()[0] == 0:
        default_roles = [
            ("root_admin", "Root Administrator", "Vollzugriff auf alle System-, Sicherheits-, Benutzer- und Webserver-Funktionen", "system,security,web,mail,db,files,apps,backups,packages,cron,users,monitor", 1),
            ("web_admin", "Webspace Administrator", "Verwaltung von Domains, Webspace-Dateien, Datenbanken und Backups", "web,db,files,apps,backups,monitor", 1),
            ("database_admin", "Datenbank Administrator", "Verwaltung von MySQL Datenbanken, DB-Benutzern, SQL-Konsole und Backups", "db,backups,monitor", 0),
            ("mail_admin", "E-Mail Administrator", "Verwaltung von Postfächern, Aliasen und DKIM/DNS-Records", "mail,monitor", 0),
            ("monitor", "Monitoring & Audit", "Nur-Lese-Zugriff auf Metriken, Logs und Systemstatus", "monitor", 1)
        ]
        cursor.executemany("""
        INSERT INTO roles (name, display_name, description, permissions, is_system)
        VALUES (?, ?, ?, ?, ?);
        """, default_roles)

    conn.commit()

    # Bootstrap Initialer Admin (falls noch kein Benutzer existiert)
    cursor.execute("SELECT COUNT(*) FROM users;")
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        admin_user = config.BOOTSTRAP_ADMIN_USER or "admin"
        admin_email = config.BOOTSTRAP_ADMIN_EMAIL or f"{admin_user}@localhost"
        admin_pass = config.BOOTSTRAP_ADMIN_PASS

        generated = False
        if not admin_pass:
            import secrets
            admin_pass = secrets.token_urlsafe(12)
            generated = True

        p_hash = generate_password_hash(admin_pass)

        cursor.execute("""
        INSERT INTO users (username, password_hash, role, email, is_active)
        VALUES (?, ?, 'root_admin', ?, 1);
        """, (admin_user, p_hash, admin_email))

        conn.commit()

        if generated:
            try:
                pass_file = config.BASE_DIR / ".initial_admin_password"
                pass_file.write_text(f"Benutzername: {admin_user}\nPasswort: {admin_pass}\nErstellt am: {datetime.utcnow().isoformat()}\nBitte nach erstem Login löschen!")
                try:
                    os.chmod(pass_file, 0o600)
                except Exception:
                    pass
                print(f"""
                =======================================================
                [SysCore Security] Initialer Administrator erstellt:
                Benutzername: {admin_user}
                Passwort:     {admin_pass}
                (Gespeichert in: {pass_file})
                =======================================================
                """)
            except Exception as e:
                print(f"[SysCore Security] Konnte initiales Passwort nicht in Datei schreiben: {e}")

        log_audit(
            username="SYSTEM",
            action="BOOTSTRAP_INIT",
            details=f"SysCore initialisiert. Initialer root_admin '{admin_user}' erstellt.",
            ip_address="127.0.0.1",
            status="success"
        )

    conn.close()

def log_audit(username, action, details="", ip_address="", status="success"):
    try:
        conn = get_db()
        conn.execute("""
        INSERT INTO audit_logs (username, action, details, ip_address, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?);
        """, (username or "anonymous", action, details, ip_address or "unknown", status, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SysCore DB Error] Audit-Log konnte nicht geschrieben werden: {e}")

def query_db(query, args=(), one=False):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query, args)
    rows = cursor.fetchall()
    conn.close()
    return (rows[0] if rows else None) if one else rows

def execute_db(query, args=()):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query, args)
    conn.commit()
    last_id = cursor.lastrowid
    conn.close()
    return last_id
