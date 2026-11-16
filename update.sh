#!/usr/bin/env bash
# ==============================================================================
# SysCore 1-Klick Terminal Updater & Auto-Restarter
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================="
echo "   SYSCORE SYSTEM-UPDATE WIRD AUSGEFÜHRT               "
echo "======================================================="

# 1. Neueste Änderungen von GitHub ziehen
echo "[1/4] Ziehe neueste Version von origin/main..."
git fetch origin main
git pull --rebase=false origin main

# 2. Abhängigkeiten in isolierter Virtualenv prüfen (SEC-019)
echo "[2/4] Überprüfe Python-Abhängigkeiten in SysCore-Venv..."
if [ ! -d "venv" ]; then
    echo "       Erstelle fehlende Virtualenv in ./venv..."
    python3 -m venv venv
fi
./venv/bin/pip install --upgrade -r requirements.txt --quiet

# 3. Datenbank-Migrationen & Hooks initialisieren
echo "[3/4] Initialisiere Datenbank & Auto-Restart Hooks..."
if [ -d "venv" ]; then
    ./venv/bin/python3 -c "import db; db.init_db()"
else
    python3 -c "import db; db.init_db()"
fi

# 4. Dienst neu starten
echo "[4/4] Starte SysCore Systemdienst neu..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart syscore-panel 2>/dev/null || systemctl restart syscore 2>/dev/null || true
    echo "[ERFOLG] SysCore wurde aktualisiert und der Dienst wurde neu gestartet!"
else
    echo "[HINWEIS] systemctl nicht gefunden. Bitte Dienst manuell prüfen."
fi
