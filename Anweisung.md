# Aufgabe: Ausbau von "SysCore" zu einem vollwertigen, modernen Server- & Webspace-Management-System (Plesk-Klasse)

Du bist mein leitender Full-Stack- & Systems-Engineering-Agent in der Antigravity IDE. Deine Aufgabe ist es, das bestehende Projekt **SysCore** in diesem Workspace visuell, architektonisch und funktional auf das Niveau einer modernen Serververwaltung (vergleichbar mit Plesk / CloudPanel) auszubauen – dabei jedoch **strikt unabhängig von NGINX/Apache** als eigenständiger Python-`systemd`-Daemon lauffähig zu halten.

## 1. System- & Projektkontext
- **Zielumgebung:** Debian Linux Root-Server (Intel Core i7-8700, 64 GB RAM, NVMe) mit installiertem NGINX, Apache2, MySQL/MariaDB, PHP-FPM, Node.js, Certbot (Let's Encrypt), UFW und Pterodactyl (`wings`).
- **Bestehende Basis:** Modulares Python/Flask-Backend (`app.py`, `config.py`, Blueprint-Ordner `modules/`, Jinja2-Templates in `templates/`).
- **Wichtigste Grundregel:** SysCore darf bestehende System- oder Pterodactyl-Konfigurationen (`pterodactyl.conf`, System-Datenbanken, bestehende Cronjobs) **niemals** überschreiben oder beschädigen. Eigene NGINX-VHosts nutzen weiterhin konsequent das Suffix `.panel.conf`.

---

## 2. Visuelles Design & UX-Anforderungen ("Next-Level UI")
Ersetze das bisherige Basis-Layout durch ein hochpoliertes, modernes Enterprise-Dashboard:
- **Farbsystem & Ästhetik:** Tiefes Dark-Graphite-UI (`#090d16` Hintergrund, `#111827` / `#161b22` Cards mit feinen `1px` Borders `#1f2937`), Akzentfarben in **Emerald (`#10b981`)** und **Teal (`#14b8a6`)**, subtile Status-Glows und gestochen scharfe Typografie (`Inter` + `JetBrains Mono` für Pfade, Logs, Ports und Code).
- **Full-Width Workspace:** Nutze die gesamte Bildschirmbreite ohne künstliche `max-w`-Container-Begrenzungen.
- **Interaktivität & Feedback:**
  - Echtzeit-Updates für Systemmetriken (CPU-Kerne, RAM, Disk I/O, Netzwerk-Traffic) via Leichtgewichts-JSON-API (`/api/metrics`) und animierten Charts/Sparklines ohne Seiten-Reload.
  - Toast-Benachrichtigungen (statt statischer Banner) für alle Aktionen.
  - Globale Command-Palette (`Strg+K` / `Cmd+K`) zum schnellen Springen zwischen Domains, Datenbanken, Diensten und Einstellungen.
  - Live-Terminal-Drawer / Modal für Paket-Installationen, Certbot-Ausgaben und Log-Viewer (NGINX Access/Error Logs, Syslog) via Server-Sent Events (SSE) oder Streaming-Polling.

---

## 3. Technische Architektur & Neue Module (Plesk-Funktionsumfang)

Strukturiere das Backend sauber mit einer lokalen **SQLite-Datenbank (`syscore.db`)** für Benutzer, Rollen, Audit-Logs, App-Deployments und globale Einstellungen. Implementiere bzw. erweitere folgende Module unter `modules/`:

### A. Benutzerverwaltung, RBAC & Sicherheit (`modules/auth_users.py`)
- Ablösung des statischen Passworts aus `config.py` durch SQLite-basierte Benutzerverwaltung mit sicheren Password-Hashes (`werkzeug.security`) und optionaler **2FA (TOTP / Authenticator-App)**.
- **Rollenmodell (RBAC):**
  1. `root_admin`: Vollzugriff auf alle System-, Paket-, Firewall-, Benutzer- und Webserver-Funktionen.
  2. `web_admin`: Verwaltung von Domains, Dateimanager (`/var/www`), Datenbanken, Backups und App-Importer (kein Zugriff auf Systemdienste, UFW, Pakete oder Root-Cronjobs).
  3. `monitor`: Nur-Lese-Zugriff auf Metriken, Status und Logs.
- **Audit-Log:** Lückenlose Protokollierung kritischer Aktionen (Wer hat wann welche Domain geändert, Pakete installiert oder Dienste neu gestartet?).

### B. Erweiterter Webserver- & Domain-Manager (`modules/webserver.py`)
- **Vollständige Domain-Verwaltung:** Anlegen, Bearbeiten und Löschen von Domains & Subdomains mit frei wählbarem `DocumentRoot` (z. B. `/var/www/amfearliath.de/public`), PHP-Version-Selector pro Domain oder Reverse-Proxy-Konfiguration (inkl. WebSocket-Support).
- **Apache/NGINX-Koexistenz:** Automatische Erkennung von Port-Konflikten (Apache auf 8080, NGINX als Haupt-Proxy auf 80/443).
- **Pro-Domain-Features (Plesk-Style):**
  - 1-Klick Let's Encrypt SSL + Auto-Redirect HTTP $\rightarrow$ HTTPS + Zertifikats-Ablaufdatum-Anzeige.
  - **NGINX VHost-Direktiven-Editor:** Zusätzliche Custom-Direktiven (z. B. `client_max_body_size`, Security-Header, Gzip/Brotli, Passwortschutz/.htpasswd) sauber in die `.panel.conf` injizieren, inkl. vorheriger `nginx -t` Syntaxprüfung und automatischem Rollback bei Fehlern.
  - **Domain-Log-Viewer:** Live-Ansicht der `access.log` und `error.log` direkt in der Domain-Detailansicht.

### C. Paket- & Stack-Installer mit Assistent (`modules/packages.py`)
- Geführter Installations-Assistent mit Live-Konsolen-Output (`DEBIAN_FRONTEND=noninteractive`) für gängige Server-Komponenten:
  - **Web & Runtimes:** PHP-Versionen (8.2, 8.3, 8.4 inkl. gängiger Extensions wie `curl`, `mbstring`, `xml`, `zip`, `gd`, `mysql`, `intl`), Composer, Node.js LTS (via NodeSource) + `pm2`, Redis.
  - **Tools:** **phpMyAdmin** (automatisch unter `/var/www/phpmyadmin` oder Subdomain bereitgestellt und über NGINX abgesichert), Fail2Ban, UFW, Certbot.
- Statusanzeige installierter Versionen und 1-Klick-Update-Prüfung.

### D. App-Importer via ZIP-Paket & Manifest (`modules/apps.py`)
- Upload und automatisches Deployment eigener Anwendungen als `.zip`-Archiv mit einer `syscore.manifest.json` im Root des Archivs.
- **Manifest-Spezifikation:**
  - Unterstützt `name`, `version`, `type` (`php`, `static`, `node`), `php_version`, `public_subdir`, `requires_db` (bool), `env_template` (z. B. `.env.example`), `env_mapping` (automatisches Ersetzen von `{{DB_NAME}}`, `{{DB_USER}}`, `{{DB_PASS}}`, `{{DOMAIN}}`), `setup_sql` (automatischer DB-Import) und `post_install_commands` (z. B. `composer install`, `npm run build` oder `php artisan migrate`).
- **UI-Dokumentation:** Integrierter Hilfe-Tab im Modul mit vollständiger Spezifikation, Beispiel-Manifest und Download eines Starter-Template-ZIPs.

### E. Zentrales Einstellungs-Hub (`modules/settings.py`)
- Übersichtliche Tab-Navigation für alle System- und Dienstkonfigurationen:
  - **Server:** Hostname, Zeitzone (`timedatectl`), Swap-Speicher-Verwaltung, Unattended-Upgrades.
  - **NGINX & PHP Global:** Anpassung globaler Limits (`client_max_body_size`, `memory_limit`, `upload_max_filesize`, `max_execution_time`) über isolierte Drop-in-Config-Dateien (`/etc/nginx/conf.d/99-syscore.conf` bzw. `conf.d/99-syscore.ini`).
  - **Let's Encrypt:** Globale Admin-E-Mail für Certbot, Renewal-Timer-Status und Testlauf (`certbot renew --dry-run`).
  - **Node.js / PM2:** Verwaltung laufender Node-Prozesse, Neustart und Autostart-Setup.

### F. Ausbau der bestehenden Module (`files.py`, `database.py`, `cron.py`, `system.py`)
- **Dateimanager:** Hinzufügen von Umbenennen, ZIP entpacken/packen im Browser, `chmod`/Rechte-Anzeige und Syntax-Highlighting im Code-Editor (z. B. via CodeMirror/Monaco CDN).
- **Datenbanken:** Passwort-Reset für bestehende DB-Benutzer, Benutzer-Rechteverwaltung und direktes Öffnen in phpMyAdmin (falls installiert).
- **Backup-Manager (`modules/backups.py`):** Kombinierte Sicherung (Webroot `.tar.gz` + MySQL `.sql.gz`) pro Domain mit 1-Klick-Wiederherstellung.

---

## 4. Arbeitsweise & Vorgehen in der IDE
1. **Bestandsaufnahme:** Lies zuerst alle existierenden Dateien im aktuellen Workspace (`app.py`, `config.py`, `modules/*`, `templates/*`), um den aktuellen Stand exakt zu erfassen.
2. **Architektur- & Migrationsplan:** Erstelle einen kompakten Umsetzungsplan, welche neuen Dateien angelegt und welche bestehenden refactored werden.
3. **Sicherheit & Code-Qualität:**
   - Strikte Input-Validierung (Regex-Whitelists für Domains, DB-Namen, Ports, Dateinamen) und `os.path.realpath`-Checks gegen Path-Traversal.
   - Kein Shell-Injection-Risiko (`subprocess.run([...], shell=False)` als Standard).
   - Saubere Trennung zwischen Backend-Services/Logik und Flask-Routen.
4. **Schrittweise Implementierung:** Beginne mit der Datenbank- & Auth-Basis (`syscore.db` + RBAC) sowie dem neuen Master-Layout (`base.html` + Echtzeit-Metrik-API), und arbeite danach Modul für Modul durch. Aktualisiere am Ende auch `install.sh` und `README.md`.

---

## 5. Verbindliche Sicherheitsarchitektur & Sicherheits-Manifest (Enterprise Security Standard)
Dieses Manifest basiert auf dem umfassenden Sicherheits-Audit (`Allgemeine Sicherheit.md`) und ist **verbindlicher Standard für jeden Codebestandteil von SysCore**. Da das System die vollständige Kontrolle über Webserver, Domains, Datenbanken und Systemdienste besitzt, müssen folgende Grundsätze ausnahmslos eingehalten werden:

### 1. Privilege Separation & Ausführungsumgebung (SEC-001)
- Die Flask/Gunicorn-Webanwendung darf **niemals als Root** laufen.
- Der Webprozess wird unter einem dedizierten, unprivilegierten Systembenutzer (`syscore`) ausgeführt.
- Privilegierte Systemoperationen (z. B. NGINX-Reload, Certbot, UFW, Systemd, User-Management) werden strikt vom Webinterface getrennt und über einen sicheren, validierten internen IPC-Agenten bzw. Sudoer-Wrapper mit expliziter Command-Whitelist ausgeführt.

### 2. Keine beliebige Code-/Shell-Ausführung (SEC-002, SEC-018)
- Keine Ausführung von `post_install_commands` oder Shell-Skripten aus hochgeladenen/importierten App-Paketen.
- Umstellung auf eine deklarative Installationslogik über eine feste, serverseitige Action-Registry mit validierten Parametern.
- Keine dynamische Interpretation von Benutzereingaben in Shell-Kontexten; stets `subprocess.run([...], shell=False)` mit expliziten Argumentlisten.

### 3. Absolute Domain-Isolation & Symlink-Schutz (SEC-003, SEC-005, SEC-006)
- **Strikte Mandantentrennung im Dateimanager:** Jeder Zugriff ist zwingend auf das zugehörige Domain-Verzeichnis beschränkt (z. B. `/var/www/domain.de/`).
- Kein Ausbruch auf `/var/www` oder fremde Domains möglich – weder über Pfadmanipulation (`../`), absolute Pfade noch über Symlinks oder Hardlinks.
- Sichere Pfadvalidierung mit kanonischer Verzeichnisgrenzenprüfung (`os.path.commonpath`) und Symlink-Auflösungsprüfung vor jeder Dateisystemoperation.

### 4. Sichere Archiv-Verarbeitung & DoS-Schutz (SEC-004, SEC-007, SEC-014)
- Vollständiger Schutz gegen Zip-Slip und Tar-Slip bei allen Import- und Restore-Vorgängen.
- Vor der Extraktion: Einzelprüfung aller Archivmitglieder (keine absoluten Pfade, kein `..`, keine Symlinks auf Systemziele, keine Sonderdateien).
- Harte Begrenzung von Upload-Größen pro Funktion, maximaler Dateianzahl und Gesamt-Entpackungsgröße (Schutz vor Zip-/Tar-Bomben).
- Archiv-Extraktionen erfolgen stets zuerst in isolierte temporäre Quarantäne-Verzeichnisse mit atomarer Übernahme erst nach vollständiger Validierung.

### 5. Durchgängiger Web- & Session-Schutz (SEC-008, SEC-009, SEC-010, SEC-011, SEC-017)
- **CSRF-Schutz:** Sämtliche statusverändernden HTTP-Anfragen (POST, PUT, DELETE) und AJAX-Calls sind durch CSRF-Tokens geschützt.
- **Echtzeit-Berechtigungsprüfung:** Rollen- und Aktivitätsprüfungen (`role_required`, `is_active`) werden bei jeder privilegierten Anfrage live gegen die Datenbank validiert – nicht allein aus der Flask-Session.
- **Sichere Session-Cookies:** `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, sowie `SESSION_COOKIE_SECURE = True` unter HTTPS. Session-Regenerierung bei Login und Logout.
- **Open-Redirect-Schutz:** `next`-Parameter werden strikt auf relative, interne Pfade validiert.
- **QR-Login-Härtung:** Einmalige Token-Verwendung, kurze Ablaufzeiten, CSRF-Schutz bei Bestätigung und strikte Bindung an die anfragende Session.

### 6. Secrets, Datenbankrechte & System-Updates (SEC-012, SEC-013, SEC-015, SEC-016, SEC-019)
- Dateirechte `0600` für `.env`, `.secret_key` und Datenbankdateien.
- Keine Offenlegung von Stacktraces oder internen Pfaden in öffentlichen Fehlerseiten (`SEC-016`); technische Details ausschließlich in geschützten Server-Logs mit Request-ID.
- Webhook-Endpunkte mit kryptografischer Signaturprüfung (HMAC-SHA256) und Replay-Schutz.
- SysCore-Updates laufen ausschließlich isoliert innerhalb der virtuellen Umgebung (`/opt/syscore/venv`) – niemals global mit `--break-system-packages`.

---
