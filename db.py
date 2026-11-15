import sqlite3
import os
import json
from datetime import datetime
from pathlib import Path
from werkzeug.security import generate_password_hash
import config

try:
    import pymysql
except ImportError:
    pymysql = None

# Globaler Notfall-Fallback-Status für unterbrechungsfreien Betrieb
FALLBACK_TO_SQLITE = False
MYSQL_LAST_ERROR = None

class MySQLRow(dict):
    """
    Simuliert sqlite3.Row für PyMySQL:
    Erlaubt sowohl schlüsselbasierten Zugriff (row['username'])
    als auch indexbasierten Zugriff (row[0], row[1], ...).
    """
    def __init__(self, data, col_names):
        super().__init__(data)
        self._col_names = col_names
        self._values = [data.get(k) for k in col_names]

    def __getitem__(self, item):
        if isinstance(item, int):
            return self._values[item]
        return super().__getitem__(item)

    def keys(self):
        return self._col_names

ALL_TABLES = [
    "roles",
    "users",
    "settings",
    "audit_logs",
    "app_deployments",
    "backups",
    "mail_accounts",
    "mail_aliases",
    "mail_dkim",
    "mail_server_config",
    "clamav_scans",
    "security_ip_bans",
    "web_deploy_hooks",
    "package_configs",
    "qr_login_tokens"
]

SCHEMA_STATEMENTS = [
    # 1. Benutzer-Tabelle mit RBAC & 2FA
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(191) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(64) NOT NULL DEFAULT 'web_admin',
        email VARCHAR(191),
        totp_secret TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );
    """,
    # 2. Audit-Log
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username VARCHAR(191) NOT NULL,
        action VARCHAR(100) NOT NULL,
        details TEXT,
        ip_address VARCHAR(64),
        status VARCHAR(32) DEFAULT 'success'
    );
    """,
    # 3. App-Deployments via Manifest
    """
    CREATE TABLE IF NOT EXISTS app_deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain VARCHAR(191) NOT NULL,
        app_name VARCHAR(100) NOT NULL,
        version VARCHAR(64),
        app_type VARCHAR(64),
        status VARCHAR(32) DEFAULT 'active',
        details TEXT,
        deployed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 4. Globale Einstellungen (Key/Value)
    """
    CREATE TABLE IF NOT EXISTS settings (
        `key` VARCHAR(191) PRIMARY KEY,
        `value` TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 5. Backups-Verzeichnis & Metadaten
    """
    CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain VARCHAR(191) NOT NULL,
        filename VARCHAR(255) NOT NULL,
        filepath TEXT NOT NULL,
        size_bytes BIGINT DEFAULT 0,
        includes_db INTEGER DEFAULT 1,
        includes_files INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 6. E-Mail Postfächer
    """
    CREATE TABLE IF NOT EXISTS mail_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain VARCHAR(191) NOT NULL,
        email VARCHAR(191) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        quota_mb INTEGER DEFAULT 5120,
        used_mb REAL DEFAULT 0.0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 7. E-Mail Aliase & Weiterleitungen
    """
    CREATE TABLE IF NOT EXISTS mail_aliases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain VARCHAR(191) NOT NULL,
        source_email VARCHAR(191) NOT NULL,
        destination_email VARCHAR(191) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 8. E-Mail DKIM-Schlüssel
    """
    CREATE TABLE IF NOT EXISTS mail_dkim (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain VARCHAR(191) UNIQUE NOT NULL,
        selector VARCHAR(64) DEFAULT 'default',
        private_key TEXT NOT NULL,
        public_key TEXT NOT NULL,
        dns_record TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 9. Mailserver-Konfiguration
    """
    CREATE TABLE IF NOT EXISTS mail_server_config (
        id INT PRIMARY KEY,
        backend_type VARCHAR(64) DEFAULT 'stalwart',
        webmail_client VARCHAR(64) DEFAULT 'snappymail',
        smtp_host VARCHAR(191) DEFAULT '127.0.0.1',
        smtp_port INTEGER DEFAULT 587,
        imap_host VARCHAR(191) DEFAULT '127.0.0.1',
        imap_port INTEGER DEFAULT 993,
        stalwart_api_url VARCHAR(255) DEFAULT 'http://127.0.0.1:8080',
        stalwart_api_token TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 10. ClamAV Malware Scans
    """
    CREATE TABLE IF NOT EXISTS clamav_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_path TEXT NOT NULL,
        scanned_files INTEGER DEFAULT 0,
        infected_files INTEGER DEFAULT 0,
        scan_log TEXT,
        status VARCHAR(32) DEFAULT 'completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 11. Manuelle & Automatische IP-Bans
    """
    CREATE TABLE IF NOT EXISTS security_ip_bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address VARCHAR(64) UNIQUE NOT NULL,
        reason TEXT,
        banned_by VARCHAR(100) DEFAULT 'admin',
        ban_type VARCHAR(32) DEFAULT 'ufw',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 12. Git Webhook Auto-Deployer
    """
    CREATE TABLE IF NOT EXISTS web_deploy_hooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain VARCHAR(191) UNIQUE NOT NULL,
        token VARCHAR(191) UNIQUE NOT NULL,
        branch VARCHAR(64) DEFAULT 'main',
        post_deploy_cmd TEXT,
        last_deployed_at TIMESTAMP,
        last_status VARCHAR(32) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 13. Dynamische Rollen & Berechtigungen (RBAC)
    """
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(64) UNIQUE NOT NULL,
        display_name VARCHAR(100) NOT NULL,
        description TEXT,
        permissions TEXT NOT NULL,
        is_system INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 14. Paket-Konfigurationen & Routing
    """
    CREATE TABLE IF NOT EXISTS package_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_key VARCHAR(64) UNIQUE NOT NULL,
        domain VARCHAR(191),
        mode VARCHAR(32) DEFAULT 'subdomain',
        port INTEGER,
        ssl_enabled INTEGER DEFAULT 1,
        php_version VARCHAR(32) DEFAULT '8.2',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    # 15. QR-Code 2FA Login Sessions
    """
    CREATE TABLE IF NOT EXISTS qr_login_tokens (
        token VARCHAR(191) PRIMARY KEY,
        user_id INTEGER NOT NULL,
        username VARCHAR(191) NOT NULL,
        ip_address VARCHAR(64),
        approved INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP
    );
    """
]

def _get_sqlite_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def _connect_mysql(m_cfg, with_db=True, timeout=4):
    """
    Stellt eine Verbindung zu MySQL / MariaDB her.
    Unterstützt automatische Erkennung lokaler Unix-Sockets auf Debian/Ubuntu (/run/mysqld/mysqld.sock),
    normalisiert 'localhost' zu TCP 127.0.0.1 (verhindert PyMySQL /tmp/mysql.sock Fehler)
    und bietet automatischen Fallback zwischen TCP und Socket bei lokalen Verbindungen.
    """
    if not pymysql:
        raise RuntimeError("Das Python-Modul 'pymysql' ist nicht installiert. Bitte führe 'pip install pymysql' aus.")

    host = (m_cfg.get("host") or "127.0.0.1").strip()
    port = int(m_cfg.get("port") or 3306)
    user = (m_cfg.get("user") or "root").strip()
    password = m_cfg.get("password") or ""
    database = (m_cfg.get("database") or "syscore").strip() if with_db else None

    kwargs = {
        "user": user,
        "password": password,
        "charset": "utf8mb4",
        "autocommit": True,
        "connect_timeout": timeout
    }
    if database:
        kwargs["database"] = database

    # Prüfen, ob lokaler Socket auf Debian/Ubuntu verfügbar ist
    known_sockets = ["/run/mysqld/mysqld.sock", "/var/run/mysqld/mysqld.sock", "/tmp/mysql.sock"]
    found_socket = next((s for s in known_sockets if os.path.exists(s)), None)
    is_local = host.lower() in ("localhost", "127.0.0.1", "::1")

    # Wenn 'localhost' angegeben wurde und ein Socket existiert: Bevorzuge Socket
    if host.lower() == "localhost" and found_socket:
        try:
            return pymysql.connect(unix_socket=found_socket, **kwargs)
        except Exception as e_sock:
            # Falls Socket fehlschlägt, versuche TCP 127.0.0.1
            try:
                return pymysql.connect(host="127.0.0.1", port=port, **kwargs)
            except Exception:
                raise e_sock

    # Wenn 'localhost' ohne Socket angegeben wurde: Normalisiere zu TCP 127.0.0.1
    target_host = "127.0.0.1" if host.lower() == "localhost" else host

    try:
        return pymysql.connect(host=target_host, port=port, **kwargs)
    except Exception as e_tcp:
        # Falls TCP fehlschlägt, aber es sich um eine lokale Verbindung handelt und ein Socket existiert:
        # Versuche Fallback auf Socket (z.B. bei Debian MariaDB auth_socket für root)
        if is_local and found_socket:
            try:
                return pymysql.connect(unix_socket=found_socket, **kwargs)
            except Exception:
                pass
        raise e_tcp

def get_db(custom_type=None, custom_mysql=None):
    """
    Liefert eine aktive Datenbankverbindung für die konfigurierte Engine (SQLite oder MySQL).
    Bei einem MySQL-Verbindungsfehler im regulären Betrieb wird unterbrechungsfrei auf SQLite zurückgegriffen.
    """
    global FALLBACK_TO_SQLITE, MYSQL_LAST_ERROR
    db_type = (custom_type or getattr(config, "DB_TYPE", "sqlite")).lower()

    # Wenn custom_type nicht explizit erzwungen ist und der Notfall-Fallback aktiv ist, sofort SQLite nutzen
    if not custom_type and FALLBACK_TO_SQLITE:
        return _get_sqlite_db()

    if db_type == "mysql":
        if not pymysql:
            if custom_type:
                raise RuntimeError("Das Modul 'pymysql' ist nicht installiert. Bitte führe 'pip install pymysql' aus.")
            FALLBACK_TO_SQLITE = True
            MYSQL_LAST_ERROR = "Das Python-Modul 'pymysql' ist nicht installiert."
            return _get_sqlite_db()

        m_cfg = custom_mysql or {
            "host": getattr(config, "MYSQL_HOST", "127.0.0.1"),
            "port": getattr(config, "MYSQL_PORT", 3306),
            "user": getattr(config, "MYSQL_USER", "root"),
            "password": getattr(config, "MYSQL_PASS", ""),
            "database": getattr(config, "MYSQL_DB", "syscore"),
        }

        try:
            conn = _connect_mysql(m_cfg, with_db=True, timeout=3)
            FALLBACK_TO_SQLITE = False
            MYSQL_LAST_ERROR = None
            return conn
        except Exception as e:
            if custom_type:
                raise
            FALLBACK_TO_SQLITE = True
            MYSQL_LAST_ERROR = str(e)
            print(f"[SysCore DB Error] MySQL-Verbindung fehlgeschlagen: {e}. Aktiviere Notfall-Fallback auf SQLite ({config.DB_PATH})!")
            return _get_sqlite_db()
    else:
        FALLBACK_TO_SQLITE = False
        MYSQL_LAST_ERROR = None
        return _get_sqlite_db()

def _prepare_sql(query):
    if getattr(config, "DB_TYPE", "sqlite") == "mysql" and not FALLBACK_TO_SQLITE:
        return query.replace("?", "%s")
    return query

def setup_mysql_database_and_tables(m_cfg):
    """
    Stellt sicher, dass die MySQL-Datenbank existiert und alle Tabellen angelegt sind.
    """
    if not pymysql:
        raise RuntimeError("Das Python-Modul 'pymysql' ist nicht installiert.")

    db_name = m_cfg.get("database", "syscore")

    # 1. Verbindung ohne DB herstellen und CREATE DATABASE ausführen
    try:
        tmp = _connect_mysql(m_cfg, with_db=False, timeout=4)
        with tmp.cursor() as cur:
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        tmp.close()
    except Exception as e:
        print(f"[SysCore DB Note] CREATE DATABASE step notice: {e}")

    # 2. Verbindung MIT DB herstellen und alle 15 Tabellen anlegen
    conn = _connect_mysql(m_cfg, with_db=True, timeout=4)
    with conn.cursor() as cur:
        for stmt in SCHEMA_STATEMENTS:
            sql = stmt.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
            cur.execute(sql)
    conn.close()
    return True

def test_mysql_connection(host, port, user, password, db_name):
    """Prüft eine MySQL/MariaDB Verbindung, legt die DB & Tabellen bei Bedarf an und liefert Server-Info"""
    if not pymysql:
        return False, "Das Python-Paket 'pymysql' ist nicht installiert. Bitte 'pip install pymysql' ausführen."
    try:
        m_cfg = {
            "host": host,
            "port": int(port) if port else 3306,
            "user": user,
            "password": password,
            "database": db_name
        }
        setup_mysql_database_and_tables(m_cfg)

        conn = _connect_mysql(m_cfg, with_db=True, timeout=4)
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION();")
            ver_row = cur.fetchone()
            ver = ver_row[0] if ver_row else "Unbekannt"
        conn.close()
        return True, f"Verbindung erfolgreich! Server: MariaDB/MySQL {ver}. Datenbank '{db_name}' und alle Tabellen sind einsatzbereit."
    except Exception as e:
        return False, f"Verbindungsfehler: {e}"

def init_db():
    """Initialisiert das Datenbankschema auf der konfigurierten Engine"""
    global FALLBACK_TO_SQLITE, MYSQL_LAST_ERROR
    db_type = getattr(config, "DB_TYPE", "sqlite").lower()

    if db_type == "mysql":
        if not pymysql:
            print("[SysCore DB Warning] pymysql nicht installiert, starte mit SQLite Fallback.")
            FALLBACK_TO_SQLITE = True
            MYSQL_LAST_ERROR = "pymysql nicht installiert"
        else:
            try:
                m_cfg = {
                    "host": getattr(config, "MYSQL_HOST", "127.0.0.1"),
                    "port": getattr(config, "MYSQL_PORT", 3306),
                    "user": getattr(config, "MYSQL_USER", "root"),
                    "password": getattr(config, "MYSQL_PASS", ""),
                    "database": getattr(config, "MYSQL_DB", "syscore"),
                }
                setup_mysql_database_and_tables(m_cfg)
                FALLBACK_TO_SQLITE = False
                MYSQL_LAST_ERROR = None
            except Exception as e:
                FALLBACK_TO_SQLITE = True
                MYSQL_LAST_ERROR = str(e)
                print(f"[SysCore DB Warning] MySQL Setup fehlgeschlagen: {e}. Starte mit Notfall-Fallback auf SQLite ({config.DB_PATH})!")

    try:
        conn = get_db()
        cursor = conn.cursor()

        is_mysql = (db_type == "mysql" and not FALLBACK_TO_SQLITE)

        for stmt in SCHEMA_STATEMENTS:
            sql = stmt
            if is_mysql:
                sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
            cursor.execute(sql)

        # Standard-Rollen anlegen falls noch keine vorhanden
        cursor.execute("SELECT COUNT(*) FROM `roles`;")
        count_row = cursor.fetchone()
        role_count = count_row[0] if count_row else 0
        if role_count == 0:
            default_roles = [
                ("root_admin", "Root Administrator", "Vollzugriff auf alle System-, Sicherheits-, Benutzer- und Webserver-Funktionen", "system,security,web,mail,db,files,apps,backups,packages,cron,users,monitor", 1),
                ("web_admin", "Webspace Administrator", "Verwaltung von Domains, Webspace-Dateien, Datenbanken und Backups", "web,db,files,apps,backups,monitor", 1),
                ("database_admin", "Datenbank Administrator", "Verwaltung von MySQL Datenbanken, DB-Benutzern, SQL-Konsole und Backups", "db,backups,monitor", 0),
                ("mail_admin", "E-Mail Administrator", "Verwaltung von Postfächern, Aliasen und DKIM/DNS-Records", "mail,monitor", 0),
                ("monitor", "Monitoring & Audit", "Nur-Lese-Zugriff auf Metriken, Logs und Systemstatus", "monitor", 1)
            ]
            insert_roles_sql = "INSERT INTO `roles` (name, display_name, description, permissions, is_system) VALUES (%s, %s, %s, %s, %s);" if is_mysql else "INSERT INTO roles (name, display_name, description, permissions, is_system) VALUES (?, ?, ?, ?, ?);"
            cursor.executemany(insert_roles_sql, default_roles)

        if not is_mysql:
            conn.commit()

        # Bootstrap Initialer Admin (falls noch kein Benutzer existiert)
        cursor.execute("SELECT COUNT(*) FROM `users`;")
        u_row = cursor.fetchone()
        user_count = u_row[0] if u_row else 0

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
            insert_user_sql = "INSERT INTO `users` (username, password_hash, role, email, is_active) VALUES (%s, %s, 'root_admin', %s, 1);" if is_mysql else "INSERT INTO users (username, password_hash, role, email, is_active) VALUES (?, ?, 'root_admin', ?, 1);"
            cursor.execute(insert_user_sql, (admin_user, p_hash, admin_email))

            if not is_mysql:
                conn.commit()

            if generated:
                try:
                    pass_file = config.BASE_DIR / ".initial_admin_password"
                    pass_file.write_text(f"Benutzername: {admin_user}\nPasswort: {admin_pass}\nErstellt am: {datetime.utcnow().isoformat()}\nBitte nach erstem Login löschen!")
                    try:
                        os.chmod(pass_file, 0o600)
                    except Exception:
                        pass
                except Exception as e:
                    print(f"[SysCore Security] Konnte initiales Passwort nicht schreiben: {e}")

            log_audit(
                username="SYSTEM",
                action="INITIAL_BOOTSTRAP",
                details=f"Initialer Administrator '{admin_user}' angelegt (Engine: {'MySQL' if is_mysql else 'SQLite'})",
                ip_address="127.0.0.1",
                status="success"
            )

        conn.close()
    except Exception as e:
        print(f"[SysCore DB Error in init_db] {e}")

    ensure_git_post_merge_hook()

def migrate_db_data(target_type, mysql_config=None):
    """
    Kopiert sämtliche Datensätze aller SysCore-Tabellen zwischen SQLite und MySQL:
    target_type: 'mysql' (von SQLite nach MySQL) oder 'sqlite' (von MySQL nach SQLite)
    """
    source_type = "sqlite" if target_type == "mysql" else "mysql"

    if target_type == "mysql":
        m_cfg = mysql_config or {
            "host": getattr(config, "MYSQL_HOST", "127.0.0.1"),
            "port": getattr(config, "MYSQL_PORT", 3306),
            "user": getattr(config, "MYSQL_USER", "root"),
            "password": getattr(config, "MYSQL_PASS", ""),
            "database": getattr(config, "MYSQL_DB", "syscore"),
        }
        # 1. ZUERST sicherstellen, dass Datenbank und alle Tabellen in MySQL existieren!
        setup_mysql_database_and_tables(m_cfg)
    else:
        # SQLite Ziel sicherstellen
        init_db()

    # Verbindungen herstellen
    src_conn = get_db(custom_type=source_type, custom_mysql=mysql_config)
    dst_conn = get_db(custom_type=target_type, custom_mysql=mysql_config)

    src_cur = src_conn.cursor()
    dst_cur = dst_conn.cursor()

    if target_type == "mysql":
        dst_cur.execute("SET FOREIGN_KEY_CHECKS = 0;")
    else:
        dst_cur.execute("PRAGMA foreign_keys = OFF;")

    stats = {}

    for table in ALL_TABLES:
        try:
            # Zeilen aus Quelle holen
            src_cur.execute(f"SELECT * FROM `{table}`;")
            cols = [desc[0] for desc in src_cur.description] if src_cur.description else []
            rows = src_cur.fetchall()

            if not cols:
                continue

            # Zieltabelle leeren
            dst_cur.execute(f"DELETE FROM `{table}`;")

            # Batch einfügen
            col_list = ", ".join([f"`{c}`" for c in cols])
            placeholders = ", ".join(["%s" if target_type == "mysql" else "?" for _ in cols])
            insert_sql = f"INSERT INTO `{table}` ({col_list}) VALUES ({placeholders});"

            if rows:
                row_tuples = [tuple(r) for r in rows]
                dst_cur.executemany(insert_sql, row_tuples)

            stats[table] = len(rows)
        except Exception as e:
            stats[table] = f"Fehler: {e}"

    if target_type == "mysql":
        dst_cur.execute("SET FOREIGN_KEY_CHECKS = 1;")
    else:
        dst_cur.execute("PRAGMA foreign_keys = ON;")
        dst_conn.commit()

    # Validierung: Prüfen ob die kritische Benutzertabelle Datensätze enthält!
    src_cur.execute("SELECT COUNT(*) FROM `users`;")
    src_user_cnt = src_cur.fetchone()[0]
    dst_cur.execute("SELECT COUNT(*) FROM `users`;")
    dst_user_cnt = dst_cur.fetchone()[0]
    if src_user_cnt > 0 and dst_user_cnt == 0:
        src_conn.close()
        dst_conn.close()
        raise RuntimeError(f"Migrationsfehler: Die Tabelle 'users' ist in der Zieldatenbank leer! Details: {stats}")

    src_conn.close()
    dst_conn.close()
    return stats

def get_database_engine_info():
    """Liefert detaillierte Informationen zur aktiven und alternativen Datenbank-Engine"""
    configured_engine = getattr(config, "DB_TYPE", "sqlite").lower()
    active_engine = "sqlite" if (configured_engine == "sqlite" or FALLBACK_TO_SQLITE) else "mysql"

    # SQLite Statistiken
    sqlite_size_kb = 0
    sqlite_exists = os.path.exists(config.DB_PATH)
    if sqlite_exists:
        try:
            sqlite_size_kb = round(os.path.getsize(config.DB_PATH) / 1024, 1)
        except Exception:
            pass

    # Tabellenzähler
    table_counts = {}
    try:
        for tbl in ["users", "audit_logs", "roles", "package_configs"]:
            res = query_db(f"SELECT COUNT(*) FROM `{tbl}`;", one=True)
            if res:
                table_counts[tbl] = res[0]
    except Exception:
        pass

    return {
        "active_engine": active_engine,
        "configured_engine": configured_engine,
        "fallback_active": FALLBACK_TO_SQLITE,
        "fallback_error": MYSQL_LAST_ERROR,
        "is_sqlite": configured_engine == "sqlite",
        "is_mysql": configured_engine == "mysql",
        "active_is_sqlite": active_engine == "sqlite",
        "active_is_mysql": active_engine == "mysql",
        "sqlite_path": config.DB_PATH,
        "sqlite_size_kb": sqlite_size_kb,
        "sqlite_exists": sqlite_exists,
        "mysql_host": getattr(config, "MYSQL_HOST", "127.0.0.1"),
        "mysql_port": getattr(config, "MYSQL_PORT", 3306),
        "mysql_user": getattr(config, "MYSQL_USER", "root"),
        "mysql_pass_set": bool(getattr(config, "MYSQL_PASS", "")),
        "mysql_db": getattr(config, "MYSQL_DB", "syscore"),
        "pymysql_available": pymysql is not None,
        "table_counts": table_counts
    }

def ensure_git_post_merge_hook():
    """Richtet den Git post-merge Hook ein, sodass nach jedem 'git pull' der Dienst neu startet"""
    try:
        git_dir = os.path.join(str(config.BASE_DIR), ".git")
        if not os.path.exists(git_dir):
            return

        hooks_dir = os.path.join(git_dir, "hooks")
        os.makedirs(hooks_dir, exist_ok=True)
        hook_path = os.path.join(hooks_dir, "post-merge")

        hook_content = """#!/usr/bin/env bash
# SysCore Auto-Restart nach Git Pull
systemctl restart syscore >/dev/null 2>&1 || true
"""
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_content)
        try:
            os.chmod(hook_path, 0o755)
        except Exception:
            pass
    except Exception:
        pass

def log_audit(username, action, details="", ip_address=None, status="success"):
    try:
        execute_db("""
        INSERT INTO audit_logs (username, action, details, ip_address, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?);
        """, (username or "anonymous", action, details, ip_address or "unknown", status, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    except Exception as e:
        print(f"[SysCore DB Error] Audit-Log konnte nicht geschrieben werden: {e}")

def query_db(query, args=(), one=False):
    """
    Führt SELECT-Abfragen aus. Bei einem MySQL-Fehler wird transparent auf SQLite gewechselt!
    """
    global FALLBACK_TO_SQLITE, MYSQL_LAST_ERROR
    conn = get_db()
    cursor = conn.cursor()
    sql = _prepare_sql(query)
    try:
        cursor.execute(sql, args)
        if getattr(config, "DB_TYPE", "sqlite") == "mysql" and not FALLBACK_TO_SQLITE:
            cols = [desc[0] for desc in cursor.description] if cursor.description else []
            raw_rows = cursor.fetchall()
            rows = [MySQLRow(dict(zip(cols, r)), cols) for r in raw_rows]
        else:
            rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return (rows[0] if rows else None) if one else rows
    except Exception as e:
        cursor.close()
        conn.close()
        # Falls MySQL während des Betriebs abbricht: Notfall-Retry mit SQLite!
        if getattr(config, "DB_TYPE", "sqlite") == "mysql" and not FALLBACK_TO_SQLITE:
            FALLBACK_TO_SQLITE = True
            MYSQL_LAST_ERROR = str(e)
            print(f"[SysCore DB Exception] {e}. Wiederhole Query auf SQLite...")
            return query_db(query, args, one)
        raise

def execute_db(query, args=()):
    """
    Führt Schreiboperationen aus. Bei einem MySQL-Fehler wird transparent auf SQLite gewechselt!
    """
    global FALLBACK_TO_SQLITE, MYSQL_LAST_ERROR
    conn = get_db()
    cursor = conn.cursor()
    sql = _prepare_sql(query)
    try:
        cursor.execute(sql, args)
        if getattr(config, "DB_TYPE", "sqlite") != "mysql" or FALLBACK_TO_SQLITE:
            conn.commit()
        last_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return last_id
    except Exception as e:
        cursor.close()
        conn.close()
        if getattr(config, "DB_TYPE", "sqlite") == "mysql" and not FALLBACK_TO_SQLITE:
            FALLBACK_TO_SQLITE = True
            MYSQL_LAST_ERROR = str(e)
            print(f"[SysCore DB Exception] {e}. Wiederhole Execute auf SQLite...")
            return execute_db(query, args)
        raise
