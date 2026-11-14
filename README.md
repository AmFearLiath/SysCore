# SysCore — Next-Gen Server- & Webspace-Management (Plesk-Klasse)

SysCore ist ein hochmodernes, eigenständiges Server- und Webspace-Management-System, konzipiert für Debian Root-Server. Es kombiniert die Leistungsfähigkeit und Flexibilität von Plesk oder CloudPanel mit strikter Unabhängigkeit von NGINX/Apache als eigenständiger `systemd`-Daemon.

---

## 💎 Design- & Architektur-Highlights

- **Enterprise High-Tech UI:** Tiefes Dark-Graphite-Cockpit (`#090d16`), Karten in `#111827`, Status-Glows, Emerald- (`#10b981`) & Teal-Akzente (`#14b8a6`), Typografie in `Inter` und `JetBrains Mono`.
- **Echtzeit-Hardware-Metriken:** CPU-Auslastung mit SVG-Sparklines, RAM, Swap, NVMe/Disk I/O, Netzwerk RX/TX und Load Average live via `/api/metrics` ohne Seiten-Reload.
- **Global Command Palette (`Ctrl+K` / `Cmd+K`):** Blitzschnelles Springen zwischen Domains, Datenbanken, Systemdiensten, Werkzeugen und Einstellungen per Tastenkombination.
- **Live-Terminal Drawer:** Integrierte Streaming-Konsole für Apt-Installationen, NGINX-Tests und Log-Streaming via Server-Sent Events (SSE).
- **Strikte Isolation & Pterodactyl-Schutz:** Eigene NGINX-VHosts nutzen ausschließlich das Suffix `.panel.conf`. Bestehende Serverkonfigurationen (`pterodactyl.conf`, System-Crontabs, System-Datenbanken) werden niemals überschrieben oder beschädigt.
- **Sicherheit & Git-Exclusion:** Vollständige Trennung aller sensitiven Zugangsdaten über `.env` und `.gitignore`. Passwörter werden sicher mit Scrypt/Argon2 gehasht.

---

## 🚀 Funktionsübersicht der Module

### 1. Benutzerverwaltung & RBAC (`modules/auth_users.py`)
- SQLite-basierte Benutzerverwaltung (`syscore.db`) mit sicheren Password-Hashes (`werkzeug.security`).
- **Zwei-Faktor-Authentifizierung (TOTP):** Integrierter QR-Code-Generator für Authenticator-Apps (Google Authenticator, Bitwarden, 2FAS, Ente).
- **Rollenmodell (RBAC):**
  - `root_admin`: Vollzugriff auf alle System-, Paket-, Firewall-, Benutzer- und Webserver-Funktionen.
  - `web_admin`: Verwaltung von Domains, Dateimanager (`/var/www`), Datenbanken, Backups und App-Importer.
  - `monitor`: Nur-Lese-Zugriff auf Metriken, Status und Logs.
- **Lückenloses Audit-Log:** Protokollierung aller sicherheitsrelevanten Vorgänge mit Zeitstempel, Benutzer, IP und Status.

### 2. Webserver & Domains (`modules/webserver.py`)
- Multi-Domain & Subdomain-Verwaltung mit frei konfigurierbarem DocumentRoot (`/var/www/<domain>/public`).
- **PHP-Version-Selector pro Domain:** Wahl zwischen PHP 8.2, 8.3 und 8.4 via PHP-FPM Sockets.
- **Reverse-Proxy-Modus:** Integrierte Weiterleitung auf lokale Ports (Node.js, Docker, FastAPI) inkl. WebSocket `Upgrade`-Header.
- **1-Klick Let's Encrypt SSL:** Automatische Ausstellung via Certbot, HTTP $\rightarrow$ HTTPS Weiterleitung und Prüfung des Ablaufdatums (`openssl`).
- **NGINX VHost-Direktiven-Editor:** Custom-Direktiven (z. B. `client_max_body_size`, Security-Headers, Gzip) injizieren mit automatischer `nginx -t` Syntaxprüfung und Rollback bei Fehlern.
- **Domain-Live-Log-Viewer:** Direkte Ansicht der `access.log` und `error.log` im Modal.

### 3. E-Mail-Zentrale (`modules/mail.py`)
- **Postfach-Verwaltung:** Anlegen von Postfächern (`user@domain.de`), Passwörtern und Quotas (Speicherplatzlimits).
- **Aliase & Weiterleitungen:** Automatische E-Mail-Umleitung an interne Postfächer oder externe Adressen.
- **DNS- & Zustellbarkeits-Assistent:** Automatische 2048-Bit DKIM-Schlüsselgenerierung, SPF- und DMARC-Records mit 1-Klick-Kopierbuttons für Cloudflare/Hetzner.
- **Backend-Auswahl:** Unterstützung für **Stalwart Mail Server** (Rust All-in-One), **Postfix & Dovecot** (Nativer Linux-Stack) und **Mailcow: dockerized**.
- **Webmail-Zentrale:** 1-Klick-Bereitstellung von **SnappyMail** oder **Roundcube** sowie integrierter nativer **SysCore Webmail Client**.

### 4. Paket- & Stack-Installer (`modules/packages.py`)
- Geführter 1-Klick-Installer mit Live-Konsolenausgabe im Terminal-Drawer für:
  - **Runtimes:** PHP 8.2, 8.3, 8.4 + Extensions (`curl`, `mbstring`, `xml`, `zip`, `gd`, `mysql`, `intl`), Composer, Node.js 20 LTS + PM2.
  - **Tools:** phpMyAdmin (unter `/var/www/phpmyadmin` bereitgestellt), Fail2Ban, UFW, Certbot.
  - **Datenbanken:** Redis In-Memory Server.

### 4. App-Importer via ZIP & Manifest (`modules/apps.py`)
- Upload und schlüsselfertiges Deployment eigener Web-Apps als `.zip`-Archiv mit `syscore.manifest.json`.
- **Automatische Schritte:**
  - Zip-Slip-sicheres Entpacken in `/var/www/<domain>`.
  - Automatische Generierung einer isolierten MySQL-Datenbank + User mit sicherem Zufallspasswort.
  - Automatische Erzeugung der `.env` durch Platzhalter-Ersetzung (`{{DB_NAME}}`, `{{DB_USER}}`, `{{DB_PASS}}`, `{{DOMAIN}}`, `{{APP_KEY}}`).
  - Ausführung von Initialisierungs-SQL (`setup_sql`) und Post-Install-Befehlen (z. B. `composer install`).
  - Berechtigungsanpassung auf `www-data:www-data`.
- 1-Klick-Download eines Starter-Templates direkt im Panel.

### 5. Zentrales Einstellungs-Hub (`modules/settings.py`)
- **Server:** Hostname, Zeitzone (`timedatectl`), Swapfile-Verwaltung, Certbot-Renewal-Test (`--dry-run`).
- **Tuning:** Globale Limits (`client_max_body_size`, `memory_limit`, `upload_max_filesize`, `max_execution_time`) über saubere Drop-In-Dateien (`/etc/nginx/conf.d/99-syscore.conf` bzw. `99-syscore.ini`).
- **Node.js / PM2:** Statusanzeige aller PM2-Prozesse mit Neustart- und Stop-Möglichkeit.
- **RBAC & Sicherheit:** Benutzer erstellen, Passwörter zurücksetzen und Audit-Logs einsehen.

### 6. Dateimanager (`modules/files.py`)
- Vollwertiger Explorer für `/var/www` mit Path-Traversal-Schutz (`os.path.realpath`).
- Datei- und Ordner-Erstellung, Multi-Upload, Download und Löschen.
- Umbenennen (`rename`) und Berechtigungs-Editor (`chmod`).
- ZIP-Archive direkt im Browser erstellen und entpacken.
- Integrierter Code-Editor mit Zeilennummerierung und Dark-Cockpit-Theme.

### 7. Datenbanken (`modules/database.py`)
- Erstellung und Verwaltung von MySQL/MariaDB-Datenbanken und isolierten Benutzern.
- Passwort-Reset für DB-Benutzer.
- SQL-Dumps per 1-Klick exportieren und importieren.
- Direkte Verknüpfung zu phpMyAdmin.

### 8. Backups & Restore (`modules/backups.py`)
- Kombinierte Sicherung (Webroot `.tar.gz` + MySQL `.sql`) pro Domain.
- 1-Klick-Wiederherstellung mit automatischem Entpacken und DB-Import.
- Download und Verwaltung aller Sicherungsdateien.

### 9. Cronjobs & Aufgaben (`modules/cron.py`)
- Zeitplan-Vorlagen (Jede Minute, Alle 5 Min, Stündlich, Täglich um Mitternacht, Wöchentlich).
- Schützt System-Cronjobs und kennzeichnet eigene Jobs mit `# SYSCORE_MANAGED`.

---

## 🛠️ Installation & Schnellstart

### Automatische 1-Klick-Installation (Debian Linux)

```bash
git clone https://github.com/dein-repo/syscore.git /opt/syscore
cd /opt/syscore
sudo bash install.sh
```

Das Skript richtet automatisch Python-Venv, Abhängigkeiten, Verzeichnisse, die SQLite-Datenbank und den `systemd`-Service `syscore.service` ein.

### Manuelle Installation & Lokaler Start

1. **Abhängigkeiten installieren:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Umgebung konfigurieren:**
   ```bash
   cp .env.example .env
   # Passe die Werte in .env nach Wunsch an
   ```

3. **Starten:**
   ```bash
   python app.py
   ```
   SysCore ist nun unter `http://127.0.0.1:8888` erreichbar.

---

## 📄 Lizenz
Proprietäres High-End Server Management System. Entwickelt für höchste Performance und maximale Ausfallsicherheit.
