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
apt-get install -y python3 python3-pip python3-venv git curl ufw

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

echo "[5/6] Initialisiere SysCore Datenbank & RBAC..."
python3 -c "import db; db.init_db()"

echo "[6/6] Richte systemd Daemon ein..."
cat << 'EOF' > /etc/systemd/system/syscore.service
[Unit]
Description=SysCore Server Management Daemon
After=network.target nginx.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/syscore
ExecStart=/opt/syscore/venv/bin/gunicorn -w 4 -b 0.0.0.0:8888 --timeout 120 app:app
Restart=always
RestartSec=5
EnvironmentFile=/opt/syscore/.env

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
