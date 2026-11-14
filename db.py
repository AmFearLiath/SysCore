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

    cursor.execute("SELECT COUNT(*) FROM mail_server_config WHERE id = 1;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO mail_server_config (id, backend_type, webmail_client, smtp_host, smtp_port, imap_host, imap_port)
        VALUES (1, 'stalwart', 'snappymail', '127.0.0.1', 587, '127.0.0.1', 993);
        """)

    conn.commit()

    # Bootstrap Initialer Admin
    cursor.execute("SELECT COUNT(*) FROM users;")
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        admin_user = config.BOOTSTRAP_ADMIN_USER
        admin_pass = config.BOOTSTRAP_ADMIN_PASS
        admin_email = config.BOOTSTRAP_ADMIN_EMAIL
        p_hash = generate_password_hash(admin_pass)

        cursor.execute("""
        INSERT INTO users (username, password_hash, role, email, is_active)
        VALUES (?, ?, 'root_admin', ?, 1);
        """, (admin_user, p_hash, admin_email))

        conn.commit()
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
