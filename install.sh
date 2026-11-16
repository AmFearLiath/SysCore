#!/usr/bin/env bash
# ==============================================================================
# SysCore - Turn-Key Systemd Service & Server Installer for Debian Linux
# ==============================================================================
set -euo pipefail

echo "======================================================="
echo "   SYSCORE NEXT-GEN SERVER MANAGEMENT SYSTEM INSTALLER "
echo "======================================================="

# Prüfen ob als root ausgeführt
if [ "$EUID" -ne 0 ]; then
  echo "[FEHLER] Dieses Skript muss als root ausgeführt werden."
  exit 1
fi

INSTALL_DIR="/opt/syscore"
SERVICE_NAME="syscore"
PYTHON_BIN="/usr/bin/python3"

echo "[1/6] Installiere System-Abhängigkeiten via APT..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-pip python3-venv git curl ufw sudo

# Privilege Separation: Unprivilegierten Benutzer 'syscore' anlegen (SEC-001)
if ! id -u syscore >/dev/null 2>&1; then
    echo "[SysCore Security] Erstelle unprivilegierten Systembenutzer 'syscore'..."
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" -M -c "SysCore Panel Daemon" syscore
fi
# syscore zur www-data Gruppe hinzufügen für Webroot-Zugriff
usermod -a -G www-data syscore || true

# Sudoers Whitelist für Privilege Separation (SEC-001)
echo "[SysCore Security] Richte sudoers Whitelist für 'syscore' ein (/etc/sudoers.d/syscore)..."
cat << 'EOF' > /etc/sudoers.d/syscore
# SysCore Privilege Separation Sudoers Whitelist (SEC-001)
Defaults:syscore !requiretty
syscore ALL=(ALL) NOPASSWD: /bin/systemctl, /usr/bin/systemctl, /usr/bin/certbot, /usr/sbin/ufw, /usr/bin/timedatectl, /usr/sbin/chown, /usr/bin/apt-get, /usr/sbin/nginx, /usr/bin/nginx
EOF
chmod 0440 /etc/sudoers.d/syscore

echo "[2/6] Richte Verzeichnisse ein..."
mkdir -p "$INSTALL_DIR"
mkdir -p /var/www
mkdir -p /var/backups/syscore
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled
mkdir -p /etc/nginx/conf.d

# Kopiere SysCore Dateien nach /opt/syscore (falls noch nicht dort)
CURRENT_DIR=$(pwd)
if [ "$CURRENT_DIR" != "$INSTALL_DIR" ]; then
    echo "[SysCore] Kopiere Projekt-Dateien nach $INSTALL_DIR..."
    cp -r "$CURRENT_DIR"/* "$INSTALL_DIR"/
fi

cd "$INSTALL_DIR"

echo "[3/6] Erstelle isolierte Python Virtual Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

echo "[4/6] Installiere Python-Pakete..."
pip install --upgrade pip
pip install -r requirements.txt

# Initialisiere .env falls nicht vorhanden
if [ ! -f ".env" ]; then
    echo "[SysCore] Erzeuge initiale .env aus .env.example..."
    cp .env.example .env
    RANDOM_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/change_me_to_a_very_secure_random_string_in_production/$RANDOM_KEY/" .env
fi

echo "[5/6] Initialisiere SysCore Datenbank & Administrator..."
python3 cli.py init-db

# Prüfen ob bereits ein Administrator existiert
USER_EXISTS=$(python3 -c "import db; conn = db.get_db(); cur = conn.cursor(); cur.execute('SELECT COUNT(*) FROM users'); print(cur.fetchone()[0]); conn.close()")

if [ "$USER_EXISTS" -eq 0 ]; then
    echo ""
    echo "======================================================="
    echo "   ERSTEINRICHTUNG: ADMINISTRATOR-KONTO ANLEGEN        "
    echo "======================================================="
    if [ -t 0 ]; then
        read -rp "Admin-Benutzername [admin]: " ADMIN_USER
        ADMIN_USER=${ADMIN_USER:-admin}

        read -rp "Admin-E-Mail [admin@localhost]: " ADMIN_EMAIL
        ADMIN_EMAIL=${ADMIN_EMAIL:-admin@localhost}

        while true; do
            read -rsp "Admin-Passwort: " ADMIN_PASS
            echo ""
            if [ -z "$ADMIN_PASS" ]; then
                echo "Passwort darf nicht leer sein!"
                continue
            fi
            read -rsp "Passwort bestätigen: " ADMIN_PASS_CONFIRM
            echo ""
            if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
                echo "Passwörter stimmen nicht überein! Bitte erneut versuchen."
                continue
            fi
            break
        done

        python3 cli.py admin -u "$ADMIN_USER" -p "$ADMIN_PASS" -e "$ADMIN_EMAIL"
    else
        # Nicht-interaktiver Modus (z. B. Automatisierte Bereitstellung)
        RANDOM_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(12))")
        python3 cli.py admin -u "admin" -p "$RANDOM_PASS" -e "admin@localhost"
        echo "[SysCore Security] Nicht-interaktiv: Administrator 'admin' erstellt mit temporärem Passwort: $RANDOM_PASS"
        echo "admin:$RANDOM_PASS" > .initial_admin_password
        chmod 600 .initial_admin_password
    fi
fi

echo "[6/6] Richte Berechtigungen & systemd Daemon ein (SEC-001)..."

# Dateirechte für Benutzer syscore härten (SEC-001, SEC-012)
chown -R syscore:syscore "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
if [ -f "$INSTALL_DIR/.env" ]; then chmod 600 "$INSTALL_DIR/.env"; fi
if [ -f "$INSTALL_DIR/.secret_key" ]; then chmod 600 "$INSTALL_DIR/.secret_key"; fi
if [ -f "$INSTALL_DIR/syscore.db" ]; then chmod 660 "$INSTALL_DIR"/syscore.db*; fi
chown -R syscore:www-data /var/backups/syscore 2>/dev/null || true
chmod 770 /var/backups/syscore 2>/dev/null || true

cat << 'EOF' > /etc/systemd/system/syscore.service
[Unit]
Description=SysCore Server Management Daemon
After=network.target nginx.service

[Service]
Type=simple
User=syscore
Group=syscore
WorkingDirectory=/opt/syscore
ExecStart=/opt/syscore/venv/bin/gunicorn -w 4 -b 0.0.0.0:8888 --timeout 120 app:app
Restart=always
RestartSec=5
EnvironmentFile=/opt/syscore/.env

# systemd Security Hardening Direktiven (SEC-001)
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable syscore
systemctl restart syscore

echo ""
echo "======================================================="
echo "   SYSCORE ERFOLGREICH INSTALLIERT & GESTARTET!        "
echo "======================================================="
echo "   Status:      systemctl status syscore"
echo "   Web-Cockpit: http://<DEINE-SERVER-IP>:8888"
echo "======================================================="
