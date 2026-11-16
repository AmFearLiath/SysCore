#!/usr/bin/env python3
"""
SysCore CLI Tool
Verwaltungswerkzeug für Administrator-Konten, Datenbank-Initialisierung und System-Audits.
"""
import sys
import getpass
import argparse
from werkzeug.security import generate_password_hash
import db

def create_or_reset_admin(username, password, email=None, role="root_admin"):
    db.init_db()
    conn = db.get_db()
    cursor = conn.cursor()

    p_hash = generate_password_hash(password)
    email = email or f"{username}@localhost"

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
        UPDATE users 
        SET password_hash = ?, role = ?, email = ?, is_active = 1 
        WHERE username = ?
        """, (p_hash, role, email, username))
        action = "UPDATE_ADMIN"
        msg = f"Passwort für Administrator '{username}' erfolgreich aktualisiert."
    else:
        cursor.execute("""
        INSERT INTO users (username, password_hash, role, email, is_active)
        VALUES (?, ?, ?, ?, 1)
        """, (username, p_hash, role, email))
        action = "CREATE_ADMIN"
        msg = f"Administrator '{username}' ({role}) erfolgreich erstellt."

    conn.commit()
    conn.close()

    db.log_audit("CLI", action, f"{msg} (Rolle: {role})", "127.0.0.1", "success")
    print(f"[SysCore CLI] {msg}")
    return True

def list_users():
    db.init_db()
    users = db.query_db("SELECT id, username, role, email, totp_enabled, is_active, created_at, last_login FROM users")
    print("\n--- Registrierte SysCore Benutzer ---")
    for u in users:
        totp = "2FA Aktiv" if u["totp_enabled"] else "Kein 2FA"
        status = "Aktiv" if u["is_active"] else "Gesperrt"
        print(f"ID: {u['id']:<3} | User: {u['username']:<15} | Rolle: {u['role']:<12} | {totp:<9} | {status:<7} | Email: {u['email']}")
    print("-------------------------------------\n")

def run_cli_update():
    import subprocess
    import shutil
    import config

    base_dir = str(config.BASE_DIR)
    print("\n=======================================================")
    print("   SYSCORE CLI UPDATE & AUTOMATISCHER RESTART         ")
    print("=======================================================")
    print("[1/4] Ziehe neuesten Stand von GitHub (origin/main)...")
    subprocess.run(["git", "fetch", "origin", "main"], cwd=base_dir, capture_output=True)
    pull = subprocess.run(["git", "pull", "--rebase=false", "origin", "main"], cwd=base_dir, capture_output=True, text=True)
    out = (pull.stdout or "").strip()
    print(out if out else "Bereits auf dem neuesten Stand.")

    print("[2/4] Überprüfe Python-Abhängigkeiten in SysCore-Venv (SEC-019)...")
    venv_pip = os.path.join(base_dir, "venv", "bin", "pip")
    if not os.path.exists(venv_pip):
        venv_pip = os.path.join(base_dir, "venv", "Scripts", "pip.exe")
    if os.path.exists(venv_pip):
        subprocess.run([venv_pip, "install", "-r", "requirements.txt", "--quiet"], cwd=base_dir)
    else:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"], cwd=base_dir)

    print("[3/4] Initialisiere Datenbank & Hooks...")
    db.init_db()

    print("[4/4] Starte SysCore Systemdienst neu...")
    if shutil.which("systemctl"):
        res = subprocess.run(["systemctl", "restart", "syscore-panel"], capture_output=True, text=True)
        if res.returncode != 0:
            subprocess.run(["systemctl", "restart", "syscore"], capture_output=True, text=True)
        print("[ERFOLG] SysCore wurde aktualisiert und der Dienst wurde neu gestartet!\n")
    else:
        print("[HINWEIS] Kein systemctl gefunden.\n")

def run_system_doctor():
    """Führt eine umfassende Integritäts- und Vorbereitungsprüfung durch (Pre-Flight Check)"""
    import sys
    import os
    import shutil
    import socket
    import config

    print("\n=======================================================")
    print("   SYSCORE PRE-FLIGHT SYSTEM- & SICHERHEITSPRÜFUNG     ")
    print("=======================================================\n")

    checks_passed = 0
    checks_total = 0

    def print_result(label, ok, details=""):
        nonlocal checks_passed, checks_total
        checks_total += 1
        if ok:
            checks_passed += 1
            status_str = "\033[92m[OK]\033[0m"
        else:
            status_str = "\033[93m[WARNUNG]\033[0m"
        print(f" {status_str} {label:<42} {details}")

    # 1. Python Version
    py_ok = sys.version_info >= (3, 10)
    py_str = f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print_result("Python Runtime", py_ok, py_str if py_ok else f"{py_str} (Empfohlen: >= 3.10)")

    # 2. Datenbank
    try:
        db.init_db()
        users_cnt = db.query_db("SELECT COUNT(*) as c FROM users", one=True)
        db_ok = True
        db_info = f"Typ: {config.DB_TYPE.upper()} ({users_cnt['c'] if users_cnt else 0} Benutzer registriert)"
    except Exception as e:
        db_ok = False
        db_info = f"Fehler: {e}"
    print_result("Datenbank-Initialisierung", db_ok, db_info)

    # 3. Secret & Berechtigungen
    secret_keyfile = config.BASE_DIR / ".secret_key"
    env_file = config.BASE_DIR / ".env"
    sec_ok = bool(config.SECRET_KEY)
    sec_details = "Aktiv"
    if os.name != "nt":
        if env_file.exists():
            mode = oct(os.stat(env_file).st_mode & 0o777)
            sec_details += f" (.env Mode: {mode})"
    print_result("Sitzungs- & Secret-Schutz", sec_ok, sec_details)

    # 4. Verzeichnisse
    dirs_to_check = [
        ("Webroot Basis", config.WEB_ROOT_BASE),
        ("Backup Verzeichnis", config.BACKUP_DIR),
        ("SysCore Basis", str(config.BASE_DIR))
    ]
    for d_name, d_path in dirs_to_check:
        d_exists = os.path.exists(d_path)
        d_writeable = os.access(d_path, os.W_OK) if d_exists else False
        d_ok = d_exists and d_writeable
        d_detail = "Vorhanden & schreibbar" if d_ok else ("Fehlt / Nicht schreibbar" if d_exists else "Existiert nicht")
        print_result(f"Verzeichnis: {d_name}", d_ok, f"{d_path} ({d_detail})")

    # 5. System-Binaries (Debian Root Server)
    binaries = [
        ("NGINX Webserver", "nginx"),
        ("Certbot Let's Encrypt", "certbot"),
        ("UFW Firewall", "ufw"),
        ("Git Versionskontrolle", "git"),
        ("Systemd Service Manager", "systemctl")
    ]
    for b_name, b_cmd in binaries:
        b_found = bool(shutil.which(b_cmd))
        print_result(f"Dienst: {b_name}", b_found, "Installiert" if b_found else "Nicht in PATH gefunden")

    # 6. Web-Port Prüfung
    port_open = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        res = sock.connect_ex(("127.0.0.1", config.PANEL_PORT))
        port_open = (res == 0)
    except Exception:
        pass
    finally:
        sock.close()
    print_result(f"Port {config.PANEL_PORT} Status", True, "Bereits aktiv (Daemon läuft)" if port_open else "Frei für Bindung")

    print("\n-------------------------------------------------------")
    print(f" Ergebnis: {checks_passed}/{checks_total} Prüfungen erfolgreich absolviert.")
    print("=======================================================\n")

def main():
    parser = argparse.ArgumentParser(description="SysCore Server Management CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Command: admin
    admin_parser = subparsers.add_parser("admin", help="Administrator-Konto anlegen oder Passwort zurücksetzen")
    admin_parser.add_argument("--username", "-u", default=None, help="Benutzername des Administrators")
    admin_parser.add_argument("--password", "-p", default=None, help="Passwort (wird abgefragt falls nicht angegeben)")
    admin_parser.add_argument("--email", "-e", default=None, help="E-Mail-Adresse")
    admin_parser.add_argument("--role", "-r", default="root_admin", choices=["root_admin", "web_admin", "monitor"])

    # Command: list-users
    subparsers.add_parser("list-users", help="Alle registrierten Benutzer anzeigen")

    # Command: init-db
    subparsers.add_parser("init-db", help="Initialisiere Datenbanktabellen")

    # Command: update
    subparsers.add_parser("update", help="SysCore auf neueste Version aktualisieren und Dienst neu starten")

    # Command: doctor
    subparsers.add_parser("doctor", help="System-Gesundheits- & Sicherheitsprüfung ausführen (Pre-Flight Check)")

    args = parser.parse_args()

    if args.command == "init-db":
        db.init_db()
        print("[SysCore CLI] Datenbank erfolgreich initialisiert.")
    elif args.command == "update":
        run_cli_update()
    elif args.command == "list-users":
        list_users()
    elif args.command == "admin":
        username = args.username
        if not username:
            username = input("Administrator Benutzername [admin]: ").strip() or "admin"
        
        password = args.password
        if not password:
            while True:
                p1 = getpass.getpass(f"Passwort für '{username}': ")
                if not p1:
                    print("Passwort darf nicht leer sein.")
                    continue
                p2 = getpass.getpass("Passwort wiederholen: ")
                if p1 != p2:
                    print("Passwörter stimmen nicht überein. Bitte erneut versuchen.")
                    continue
                password = p1
                break
        
        email = args.email
        if not email and not args.username:
            email = input(f"E-Mail für '{username}' [{username}@localhost]: ").strip() or f"{username}@localhost"

        create_or_reset_admin(username, password, email, args.role)
    elif args.command == "doctor":
        run_system_doctor()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
