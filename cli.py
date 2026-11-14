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

    args = parser.parse_args()

    if args.command == "init-db":
        db.init_db()
        print("[SysCore CLI] Datenbank erfolgreich initialisiert.")
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
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
