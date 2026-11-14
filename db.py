import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash
import config

try:
    import pymysql
    import pymysql.cursors
except ImportError:
    pymysql = None

class MySQLRow(dict):
    """Dictionary-Objekt, das wie sqlite3.Row auch positionale Indexierung (row[0]) unterstützt"""
    def __init__(self, data=None, column_names=None):
        super().__init__(data or {})
        self._col_names = column_names or list(self.keys())

    def __getitem__(self, key):
        if isinstance(key, int):
            if 0 <= key < len(self._col_names):
                return super().__getitem__(self._col_names[key])
            raise IndexError("Index out of range")
        return super().__getitem__(key)

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
    "package_configs"
]

def get_db(custom_type=None, custom_mysql=None):
    """
    Liefert eine aktive Datenbankverbindung für die konfigurierte Engine (SQLite oder MySQL).
    """
    db_type = (custom_type or getattr(config, "DB_TYPE", "sqlite")).lower()

    if db_type == "mysql":
        if not pymysql:
            raise RuntimeError("Das Modul 'pymysql' ist nicht installiert. Bitte führe 'pip install pymysql' aus.")
        
        m_cfg = custom_mysql or {
            "host": getattr(config, "MYSQL_HOST", "127.0.0.1"),
            "port": getattr(config, "MYSQL_PORT", 3306),
            "user": getattr(config, "MYSQL_USER", "root"),
            "password": getattr(config, "MYSQL_PASS", ""),
            "database": getattr(config, "MYSQL_DB", "syscore"),
        }
        
        conn = pymysql.connect(
            host=m_cfg["host"],
            port=int(m_cfg["port"]),
            user=m_cfg["user"],
            password=m_cfg["password"],
            database=m_cfg["database"],
            charset="utf8mb4",
            autocommit=True
        )
        return conn
    else:
        conn = sqlite3.connect(config.DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

def _prepare_sql(query):
    if getattr(config, "DB_TYPE", "sqlite") == "mysql":
        return query.replace("?", "%s")
    return query

def test_mysql_connection(host, port, user, password, db_name):
    """Prüft eine MySQL/MariaDB Verbindung und stellt sicher, dass die Datenbank angelegt werden kann"""
    if not pymysql:
        return False, "Das Python-Paket 'pymysql' ist nicht installiert. Bitte 'pip install pymysql' ausführen."
    try:
        conn = pymysql.connect(
            host=host,
            port=int(port),
            user=user,
            password=password,
            charset="utf8mb4",
            connect_timeout=4
        )
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION();")
            ver_row = cur.fetchone()
            ver = ver_row[0] if ver_row else "Unbekannt"
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        conn.close()
        return True, f"Verbindung erfolgreich! Server: MariaDB/MySQL {ver}. Datenbank '{db_name}' ist erreichbar & schreibbereit."
    except Exception as e:
        return False, f"Verbindungsfehler: {e}"

def init_db():
    db_type = getattr(config, "DB_TYPE", "sqlite").lower()

    if db_type == "mysql":
        if not pymysql:
            print("[SysCore DB Warning] pymysql nicht installiert, kann MySQL nicht initialisieren.")
            return
        try:
            # Zuerst Serververbindung aufbauen um DB sicherzustellen
            tmp = pymysql.connect(
                host=config.MYSQL_HOST,
                port=int(config.MYSQL_PORT),
                user=config.MYSQL_USER,
                password=config.MYSQL_PASS,
                charset="utf8mb4",
                autocommit=True
            )
            with tmp.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{config.MYSQL_DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            tmp.close()
        except Exception as e:
            print(f"[SysCore DB Error] MySQL Datenbank konnte nicht erstellt werden: {e}")

    conn = get_db()
    cursor = conn.cursor()

    # DDL Statements (kompatibel für SQLite und MySQL)
    schema_statements = [
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
        """
    ]

    for stmt in schema_statements:
        sql = stmt
        if db_type == "mysql":
            sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INT AUTO_INCREMENT PRIMARY KEY")
        cursor.execute(sql)

    # Standard-Rollen anlegen falls noch keine vorhanden
    cursor.execute("SELECT COUNT(*) FROM roles;")
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
        insert_roles_sql = "INSERT INTO roles (name, display_name, description, permissions, is_system) VALUES (%s, %s, %s, %s, %s);" if db_type == "mysql" else "INSERT INTO roles (name, display_name, description, permissions, is_system) VALUES (?, ?, ?, ?, ?);"
        cursor.executemany(insert_roles_sql, default_roles)

    if db_type != "mysql":
        conn.commit()

    # Bootstrap Initialer Admin (falls noch kein Benutzer existiert)
    cursor.execute("SELECT COUNT(*) FROM users;")
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
        insert_user_sql = "INSERT INTO users (username, password_hash, role, email, is_active) VALUES (%s, %s, 'root_admin', %s, 1);" if db_type == "mysql" else "INSERT INTO users (username, password_hash, role, email, is_active) VALUES (?, ?, 'root_admin', ?, 1);"
        cursor.execute(insert_user_sql, (admin_user, p_hash, admin_email))

        if db_type != "mysql":
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
            details=f"SysCore initialisiert ({db_type.upper()}). Initialer root_admin '{admin_user}' erstellt.",
            ip_address="127.0.0.1",
            status="success"
        )

    conn.close()
    ensure_git_post_merge_hook()

def migrate_db_data(target_type, mysql_config=None):
    """
    Kopiert sämtliche Datensätze aller SysCore-Tabellen zwischen SQLite und MySQL:
    target_type: 'mysql' (von SQLite nach MySQL) oder 'sqlite' (von MySQL nach SQLite)
    """
    source_type = "sqlite" if target_type == "mysql" else "mysql"

    # Verbindungen herstellen
    src_conn = get_db(custom_type=source_type, custom_mysql=mysql_config)
    dst_conn = get_db(custom_type=target_type, custom_mysql=mysql_config)

    src_cur = src_conn.cursor()
    dst_cur = dst_conn.cursor()

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
                if source_type == "sqlite":
                    row_tuples = [tuple(r) for r in rows]
                else:
                    row_tuples = [tuple(r) for r in rows]
                dst_cur.executemany(insert_sql, row_tuples)

            stats[table] = len(rows)
        except Exception as e:
            stats[table] = f"Fehler: {e}"

    if target_type != "mysql":
        dst_conn.commit()

    src_conn.close()
    dst_conn.close()
    return stats

def get_database_engine_info():
    """Liefert detaillierte Informationen zur aktiven und alternativen Datenbank-Engine"""
    active_engine = getattr(config, "DB_TYPE", "sqlite").lower()

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
        "is_sqlite": active_engine == "sqlite",
        "is_mysql": active_engine == "mysql",
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

        hook_script = """#!/bin/sh
# SysCore Auto-Restart Hook: wird automatisch nach jedem 'git pull' ausgefuehrt
echo "[SysCore] Aktualisierung erkannt - starte Dienst neu..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart --no-block syscore-panel 2>/dev/null || systemctl restart --no-block syscore 2>/dev/null || true
fi
"""
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_script)

        try:
            os.chmod(hook_path, 0o755)
        except Exception:
            pass
    except Exception:
        pass

def log_audit(username, action, details="", ip_address="", status="success"):
    try:
        execute_db("""
        INSERT INTO audit_logs (username, action, details, ip_address, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?);
        """, (username or "anonymous", action, details, ip_address or "unknown", status, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    except Exception as e:
        print(f"[SysCore DB Error] Audit-Log konnte nicht geschrieben werden: {e}")

def query_db(query, args=(), one=False):
    conn = get_db()
    cursor = conn.cursor()
    sql = _prepare_sql(query)
    cursor.execute(sql, args)

    if getattr(config, "DB_TYPE", "sqlite") == "mysql":
        cols = [desc[0] for desc in cursor.description] if cursor.description else []
        raw_rows = cursor.fetchall()
        rows = []
        for r in raw_rows:
            d = dict(zip(cols, r))
            rows.append(MySQLRow(d, cols))
    else:
        rows = cursor.fetchall()

    conn.close()
    return (rows[0] if rows else None) if one else rows

def execute_db(query, args=()):
    conn = get_db()
    cursor = conn.cursor()
    sql = _prepare_sql(query)
    cursor.execute(sql, args)
    if getattr(config, "DB_TYPE", "sqlite") != "mysql":
        conn.commit()
    last_id = cursor.lastrowid
    conn.close()
    return last_id
