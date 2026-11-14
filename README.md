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
- **Git Auto-Deploy Webhooks (CI/CD Light):** Eigene Webhook-Trigger-URLs pro Domain. Bei Push auf GitHub/Gitea/GitLab aktualisiert SysCore das Webroot automatisch per `git pull` und führt optionale Build-Befehle (`npm run build`, `composer install`) aus.
- **1-Klick Let's Encrypt SSL:** Automatische Ausstellung via Certbot, HTTP $\rightarrow$ HTTPS Weiterleitung und Prüfung des Ablaufdatums (`openssl`).
- **NGINX VHost-Direktiven-Editor:** Custom-Direktiven (z. B. `client_max_body_size`, Security-Headers, Gzip) injizieren mit automatischer `nginx -t` Syntaxprüfung und Rollback bei Fehlern.
- **Domain-Live-Log-Viewer mit SSE-Streaming:** Echtzeit-Log-Streaming mit farbcodierten HTTP-Statuscodes (200=Grün, 301=Blau, 404=Gelb, 500=Rot) und Live-Pause/Resume.

### 3. Sicherheitszentrale & Angriffs-Radar (`modules/security.py`)
- **System-Sicherheitsbewertung (Score 0-100%):** Automatische Berechnung des Sicherheitsniveaus basierend auf Firewall, SSH-Härtung, offenen Ports und Fail2Ban.
- **Echtzeit Angriffs-Radar:** Scannt NGINX Error- & Access-Logs auf verdächtige Angriffsmuster (`.env`, `wp-login.php`, `xmlrpc.php`, `phpmyadmin`, SQL Injections, Path Traversals).
- **Sofortige Gegenmaßnahmen:** 1-Klick IP-Bann via UFW / Fail2Ban für auffällige Angreifer-IPs.
- **ClamAV On-Demand Malware-Scanner:** Scannt Webspaces (`/var/www/<domain>`) gezielt auf Webshells, Phishing und infizierte PHP-Dateien mit detailliertem Fundbericht.
- **KI-Audit & Optimierungsbericht-Export:** Generiert einen vollständigen, strukturierten System- und Sicherheitsbericht im Markdown-Format inklusive maßgeschneidertem Prompt zur Weiterleitung an KI-Agenten (Claude, Gemini, GPT) zur Erstellung eines schrittweisen Optimierungsplans.

### 4. E-Mail-Zentrale (`modules/mail.py`)
- **Postfach-Verwaltung:** Anlegen von Postfächern (`user@domain.de`), Passwörtern und Quotas (Speicherplatzlimits).
- **Aliase & Weiterleitungen:** Automatische E-Mail-Umleitung an interne Postfächer oder externe Adressen.
- **DNS- & Zustellbarkeits-Assistent:** Automatische 2048-Bit DKIM-Schlüsselgenerierung, SPF- und DMARC-Records mit 1-Klick-Kopierbuttons für Cloudflare/Hetzner.
- **Zero-Config Autodiscover & Autoconfig:** Bereitstellung von XML-Endpunkten für Mozilla Thunderbird, Apple Mail und Microsoft Outlook (`autodiscover.xml`).
- **Backend-Auswahl:** Unterstützung für **Stalwart Mail Server** (Rust All-in-One), **Postfix & Dovecot** (Nativer Linux-Stack) und **Mailcow: dockerized**.
- **Webmail-Zentrale:** 1-Klick-Bereitstellung von **SnappyMail** oder **Roundcube** sowie integrierter nativer **SysCore Webmail Client**.

### 5. Paket- & Stack-Installer (`modules/packages.py`)
- Geführter 1-Klick-Installer mit Live-Konsolenausgabe im Terminal-Drawer für:
  - **Runtimes:** PHP 8.2, 8.3, 8.4 + Extensions, Composer, Node.js 20 LTS + PM2.
  - **Monitoring:** GoAccess (visueller NGINX Realtime Log-Analyzer), Uptime Kuma (Status Pages & Alerts auf Port 3001).
  - **Datenbanken & Cache:** Redis In-Memory Server, PostgreSQL Enterprise Database.
  - **Tools & Web-GUIs:** Adminer (leichte 1-Datei DB-GUI), phpMyAdmin (Vollwertige MySQL-Suite).
  - **Sicherheit & VPN:** CrowdSec & Firewall Bouncer (Threat-Intelligence), WireGuard VPN, Fail2Ban, Certbot.
  - **DevOps & Container:** Docker & Docker Compose v2, Gitea (privater Self-Hosted Git-Server auf Port 3000).

### 5. App-Importer via ZIP & Manifest (`modules/apps.py`)
- Upload und schlüsselfertiges Deployment eigener Web-Apps als `.zip`-Archiv mit `syscore.manifest.json`.
- **Automatische Schritte:**
  - Zip-Slip-sicheres Entpacken in `/var/www/<domain>`.
  - Automatische Generierung einer isolierten MySQL-Datenbank + User mit sicherem Zufallspasswort.
  - Automatische Erzeugung der `.env` durch Platzhalter-Ersetzung (`{{DB_NAME}}`, `{{DB_USER}}`, `{{DB_PASS}}`, `{{DOMAIN}}`, `{{APP_KEY}}`).
  - Ausführung von Initialisierungs-SQL (`setup_sql`) und Post-Install-Befehlen (z. B. `composer install`).
  - Berechtigungsanpassung auf `www-data:www-data`.
- 1-Klick-Download eines Starter-Templates direkt im Panel.

### 7. Zentrales Einstellungs-Hub, Panel-SSL & Auto-Updater (`modules/settings.py`)
- **Panel HTTPS-Subdomain Proxy & SSL:** 1-Klick-Assistent, um SysCore selbst über eine Subdomain (z.B. `panel.amfearliath.de`) mit NGINX Reverse-Proxy und automatischem Let's Encrypt SSL-Zertifikat bereitzustellen. Unterstützung für manuelle Custom-Zertifikate.
- **Server-Health Alarme:** Push-Benachrichtigungen via Discord Webhook oder Telegram Bot bei hoher Festplattenlast (>90%) oder Angriffen.
- **Auto-Updater & Rollback-Engine:** Integrierte GitHub-Prüfung gegen `origin/main` mit Commit-Diff-Anzeige, 1-Klick-Update mit automatischem Dependency-Sync (`pip install`) & Daemon-Restart sowie 1-Klick-Rollback auf frühere Git-Commits.
- **Server:** Hostname, Zeitzone (`timedatectl`), Swapfile-Verwaltung, Certbot-Renewal-Test (`--dry-run`).
- **Tuning:** Globale Limits (`client_max_body_size`, `memory_limit`, `upload_max_filesize`, `max_execution_time`) über saubere Drop-In-Dateien (`/etc/nginx/conf.d/99-syscore.conf` bzw. `99-syscore.ini`).
- **Node.js / PM2:** Statusanzeige aller PM2-Prozesse mit Neustart- und Stop-Möglichkeit.
- **RBAC & Sicherheit:** Benutzer erstellen, Passwörter zurücksetzen und Audit-Logs einsehen.

### 8. Dateimanager (`modules/files.py`)
- Vollwertiger Explorer für `/var/www` mit Path-Traversal-Schutz (`os.path.realpath`).
- Datei- und Ordner-Erstellung, Multi-Upload, Download und Löschen.
- Umbenennen (`rename`) und Berechtigungs-Editor (`chmod`).
- ZIP-Archive direkt im Browser erstellen und entpacken.
- Integrierter Code-Editor mit Zeilennummerierung und Dark-Cockpit-Theme.

### 9. Datenbanken & SQL-Konsole (`modules/database.py`)
- Erstellung und Verwaltung von MySQL/MariaDB-Datenbanken und isolierten Benutzern.
- **Integrierte SQL-Query-Konsole:** Direkte Ausführung von Ad-hoc SQL-Befehlen (`SELECT`, `SHOW TABLES`, `SHOW PROCESSLIST`) im Browser mit Schnell-Vorlagen, automatischer Limit-Absicherung und formatierter Ergebnistabelle.
- Passwort-Reset für DB-Benutzer.
- SQL-Dumps per 1-Klick exportieren und importieren.
- Direkte Verknüpfung zu phpMyAdmin & Adminer.

### 10. Backups & Restore (`modules/backups.py`)
- Kombinierte Sicherung (Webroot `.tar.gz` + MySQL `.sql`) pro Domain.
- 1-Klick-Wiederherstellung mit automatischem Entpacken und DB-Import.
- Download und Verwaltung aller Sicherungsdateien.

### 11. Cronjobs & Aufgaben (`modules/cron.py`)
- Zeitplan-Vorlagen (Jede Minute, Alle 5 Min, Stündlich, Täglich um Mitternacht, Wöchentlich).
- Schützt System-Cronjobs und kennzeichnet eigene Jobs mit `# SYSCORE_MANAGED`.

---

## 🛠️ Installation & Schnellstart

### Automatische 1-Klick-Installation (Debian Linux)

```bash
git clone https://github.com/AmFearLiath/SysCore.git /opt/syscore
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
