# SysCore – Security Hardening
## Vollständige Liste identifizierter Sicherheitsprobleme und verbindliche Maßnahmen

**Projekt:** SysCore  
**Ziel:** Systematische Behebung aller identifizierten Sicherheitsprobleme  
**Priorität:** Kritisch – umgehende Bearbeitung  
**Vorgehensweise:** Bestehende Funktionalität erhalten, Sicherheitsarchitektur verbessern und Änderungen nachvollziehbar testen.

---

# 1. Allgemeine Arbeitsanweisungen

Vor Beginn der Änderungen:

1. Das gesamte SysCore-Projekt analysieren.
2. Die nachfolgend genannten Dateien und Funktionen im aktuellen Projektstand überprüfen.
3. Prüfen, ob einzelne Probleme zwischenzeitlich bereits behoben wurden.
4. Abhängigkeiten zwischen den betroffenen Modulen identifizieren.
5. Eine sichere Umsetzung planen, bevor Änderungen vorgenommen werden.

**Wichtige Vorgaben:**

- Keine bestehenden Funktionen ohne zwingenden Grund entfernen.
- Keine Sicherheitsprobleme durch reine UI-Prüfungen umgehen.
- Sämtliche Berechtigungen serverseitig validieren.
- Keine ungeprüften Pfade oder Benutzereingaben an privilegierte Operationen übergeben.
- Keine beliebige Shell-Ausführung aus Benutzereingaben oder importierten Manifesten zulassen.
- Sicherheitsprüfungen zentral implementieren, wo immer das sinnvoll ist.
- Bestehende APIs, Modulstrukturen und Funktionsabläufe möglichst kompatibel halten.
- Fehler und abgelehnte Zugriffe nachvollziehbar protokollieren, ohne Secrets oder sensible Daten offenzulegen.
- Keine Änderungen als abgeschlossen betrachten, bevor die entsprechenden Tests erfolgreich durchgeführt wurden.

---

# 2. Kritische Sicherheitsprobleme

## SEC-001 – Root-Ausführung des gesamten SysCore-Webservers

**Priorität:** KRITISCH

**Betroffene Datei:** `install.sh`  
**Betroffener Bereich:** systemd-Service / Gunicorn

### Identifiziertes Problem

Der SysCore-Webserver wird aktuell als Root-Prozess gestartet.

Bisherige Konfiguration:

```ini
[Service]
Type=simple
User=root
WorkingDirectory=/opt/syscore
ExecStart=/opt/syscore/venv/bin/gunicorn -w 4 -b 0.0.0.0:8888 --timeout 120 app:app
Restart=always
```

Dadurch laufen Flask und sämtliche Gunicorn-Worker mit Root-Rechten.

Eine Schwachstelle in einer Webroute, einem Modul oder einer Importfunktion kann somit unter Umständen unmittelbar zu einer vollständigen Kompromittierung des Servers führen.

### Anforderungen

- SysCore-Webanwendung unter einem eigenen unprivilegierten Systembenutzer betreiben.
- Eigenen Benutzer `syscore` verwenden.
- Dateisystemrechte für `/opt/syscore` entsprechend anpassen.
- Schreibrechte nur dort gewähren, wo sie tatsächlich erforderlich sind.
- Privilegierte Systemoperationen von der Webanwendung trennen.
- Für privilegierte Operationen einen separaten Systemdienst bzw. Agenten implementieren.
- Kommunikation zwischen Webanwendung und privilegiertem Dienst absichern.
- Ausschließlich explizit freigegebene Aktionen zulassen.
- Keine beliebigen Shell-Befehle über den privilegierten Dienst ermöglichen.

### Architekturziel

```text
Browser
   |
   v
SysCore Webinterface
   |
   v
Flask / Gunicorn
User: syscore
   |
   v
Validierte interne API / IPC
   |
   v
SysCore Privileged Agent
   |
   v
Explizit erlaubte Systemoperationen
```

### Abnahmekriterien

- Gunicorn läuft nachweislich nicht mehr als Root.
- Webanwendung kann keine beliebigen privilegierten Systembefehle ausführen.
- Erforderliche Systemoperationen funktionieren weiterhin.
- Nicht freigegebene Aktionen werden zuverlässig abgelehnt.
- Berechtigungen des Systembenutzers sind auf das notwendige Minimum beschränkt.

---

## SEC-002 – Remote Code Execution über den App-Importer

**Priorität:** KRITISCH

**Betroffene Datei:** `modules/apps.py`  
**Betroffener Bereich:** App-Installation / Manifest-Verarbeitung

### Identifiziertes Problem

Importierte App-Manifeste können `post_install_commands` enthalten.

Diese werden aktuell über eine Shell ausgeführt:

```python
subprocess.run(
    cmd,
    shell=True,
    cwd=target_dir,
    ...
)
```

Damit können Befehle aus einem importierten App-Paket ausgeführt werden.

In Verbindung mit dem bisherigen Root-Betrieb des Webservers entsteht ein unmittelbares Risiko für eine vollständige Serverkompromittierung.

### Anforderungen

- `post_install_commands` vollständig aus dem bisherigen Ausführungsmodell entfernen.
- Keine Shell-Befehle aus importierten ZIP-Dateien ausführen.
- Keine beliebigen Python-Skripte aus importierten Paketen automatisch ausführen.
- Eine deklarative Installationslogik implementieren.
- Erlaubte Installationsaktionen über eine zentrale Action Registry bereitstellen.
- Jede Aktion muss einen festen Funktionsaufruf mit validierten Parametern verwenden.
- Keine dynamische Auswertung von Python-, Shell- oder sonstigem ausführbarem Code.
- App-Manifeste strikt validieren.
- Unbekannte Manifest-Felder und Aktionen ablehnen.
- App-Pakete optional signieren und ihre Integrität über Prüfsummen kontrollieren.
- Herkunft, Version und Integrität eines Pakets dokumentieren.
- Installationsaktionen vor der Ausführung nachvollziehbar darstellen.
- Jede Installation protokollieren.

### Denkbare erlaubte Aktionen

- Verzeichnis erstellen.
- Datei aus Paket installieren.
- Konfigurationsdatei anhand einer Vorlage erzeugen.
- Datenbank anlegen.
- Datenbankmigration ausführen.
- Berechtigungen über fest definierte Regeln setzen.
- Dienst über einen freigegebenen Dienstaufruf aktivieren.
- Webserver-Konfiguration über validierte Vorlagen erzeugen.

### Abnahmekriterien

- Importierte Manifeste können keine Shell-Befehle ausführen.
- Unbekannte Installationsaktionen werden abgelehnt.
- Manipulierte Parameter können keine anderen Dateien oder Dienste beeinflussen.
- Installation und Fehlerbehandlung funktionieren weiterhin.
- Privilegierte Aktionen laufen ausschließlich über die dafür vorgesehene Schnittstelle.

---

## SEC-003 – Path Traversal und fehlende Domain-Isolation im Dateimanager

**Priorität:** KRITISCH

**Betroffene Datei:** `modules/files.py`  
**Betroffener Bereich:** `resolve_safe_path()` / sämtliche Dateioperationen

### Identifiziertes Problem

Die bisherige Pfadprüfung verwendet einen einfachen String-Präfixvergleich:

```python
if not target.startswith(base):
    return base, ""
```

Dieser Vergleich ist keine sichere Prüfung von Verzeichnisgrenzen.

Beispielsweise kann `/var/www-secret` ebenfalls mit `/var/www` beginnen.

Darüber hinaus reicht eine Beschränkung auf `/var/www` für SysCore ausdrücklich nicht aus.

### Verbindliche Sicherheitsanforderung: Domain-Isolation

Der Dateimanager muss pro Domain vollständig isoliert arbeiten.

Wenn ein Benutzer den Dateimanager für eine Domain öffnet, darf er ausschließlich auf das tatsächliche Verzeichnis dieser Domain zugreifen.

Beispiel:

```text
/var/www/
├── example.de/
│   ├── httpdocs/
│   ├── logs/
│   └── tmp/
│
├── example.org/
│   ├── httpdocs/
│   ├── logs/
│   └── tmp/
│
└── example.net/
    ├── httpdocs/
    ├── logs/
    └── tmp/
```

Wenn der Dateimanager für `example.de` geöffnet wird, darf er ausschließlich innerhalb des dafür freigegebenen Domain-Verzeichnisses arbeiten.

**Nicht erlaubt:**

- Zugriff auf `/var/www`.
- Zugriff auf `/var/www/example.org`.
- Zugriff auf `/var/www/example.net`.
- Zugriff auf `/var`.
- Zugriff auf `/etc`.
- Zugriff auf `/opt/syscore`.
- Zugriff auf andere Domains.
- Zugriff auf übergeordnete Verzeichnisse.
- Zugriff auf Dateien außerhalb der Domain durch manipulierte Pfade.

Die Domain-Isolation muss unabhängig davon funktionieren, welche URL oder welchen Dateipfad der Benutzer an den Server übergibt.

### Technische Anforderungen

1. Domain-Verzeichnis ausschließlich serverseitig anhand der authentifizierten Domain-Zuordnung bestimmen.
2. Niemals einen vom Client übergebenen Basisverzeichnispfad als vertrauenswürdig behandeln.
3. Einen zentralen sicheren Path Resolver implementieren.
4. Pfade kanonisieren und auf tatsächliche Verzeichnisgrenzen prüfen.
5. `os.path.commonpath()` oder eine gleichwertige sichere Pfadprüfung verwenden.
6. Absolute Pfade außerhalb des Domain-Verzeichnisses ablehnen.
7. `..`-Traversal zuverlässig verhindern.
8. Symlinks berücksichtigen und einen Ausbruch über Symlinks verhindern.
9. Bei Dateioperationen auch Hardlinks und Sonderdateien angemessen berücksichtigen.
10. Race Conditions zwischen Pfadprüfung und Dateioperation vermeiden.
11. Keine ungeprüften Pfade an Dateioperationen übergeben.
12. Die Prüfung muss für sämtliche Dateioperationen gelten.

### Betroffene Funktionen

- Datei anzeigen.
- Datei herunterladen.
- Datei hochladen.
- Datei erstellen.
- Datei bearbeiten.
- Datei löschen.
- Verzeichnis erstellen.
- Verzeichnis löschen.
- Datei verschieben.
- Datei kopieren.
- Datei umbenennen.
- Verzeichnis auflisten.
- Dateiinformationen abrufen.
- Archiv erstellen.
- Archiv entpacken.

### Besonders wichtig: Symlink-Schutz

Ein Benutzer darf innerhalb seiner Domain keinen Symlink erstellen oder verwenden können, der auf ein anderes Verzeichnis des Servers zeigt.

Beispiel:

```text
/var/www/example.de/httpdocs/secret -> /etc
```

Ein Zugriff über diesen Symlink muss verhindert werden.

Eine bloße Prüfung des aufgelösten Pfades reicht nicht in jedem Fall aus, wenn sich Symlinks zwischen Prüfung und Dateioperation verändern können.

Für besonders kritische Dateioperationen sind deshalb sichere, möglichst atomare Dateisystemoperationen zu verwenden, beispielsweise auf Basis von Verzeichnis-Dateideskriptoren und `openat`-ähnlichen Verfahren mit geeigneten No-Follow-Optionen.

### Abnahmekriterien

- Jede Domain besitzt eine eigene Zugriffsschranke.
- `/var/www` ist aus einem Domain-Dateimanager nicht erreichbar.
- Andere Domain-Verzeichnisse sind nicht erreichbar.
- Pfadmanipulation über `../` ist nicht möglich.
- Absolute Pfade werden zuverlässig abgelehnt.
- Symlinks ermöglichen keinen Ausbruch.
- Auch Upload, Download, Löschen, Verschieben und Entpacken respektieren dieselbe Sicherheitsgrenze.
- Die Prüfungen werden serverseitig durchgeführt.

---

## SEC-004 – Zip-Slip im App-Importer

**Priorität:** KRITISCH

**Betroffene Datei:** `modules/apps.py`  
**Betroffener Bereich:** ZIP-Extraktion

### Identifiziertes Problem

Die bisherige ZIP-Pfadprüfung verwendet ebenfalls einen String-Präfixvergleich.

Dadurch können manipulierte Archivpfade unter bestimmten Umständen außerhalb des vorgesehenen Zielverzeichnisses landen.

Beispiel:

```text
../example.de.evil/config.php
```

### Anforderungen

- Absolute Archivpfade ablehnen.
- `..`-Traversal ablehnen.
- Zielpfad nach Auflösung gegen das tatsächliche Extraktionsverzeichnis prüfen.
- Keine String-Präfixprüfung als Sicherheitsmechanismus verwenden.
- Symlinks und Sonderdateien innerhalb des Archivs ablehnen oder ausdrücklich sicher behandeln.
- Maximale Anzahl der Dateien festlegen.
- Maximale Dateigröße festlegen.
- Maximale Gesamtgröße der entpackten Daten festlegen.
- Schutz vor ZIP-Bombs implementieren.
- Zunächst in ein temporäres Verzeichnis entpacken.
- Archivinhalt vor Übernahme vollständig validieren.
- Erst nach erfolgreicher Validierung atomar übernehmen.
- Bei Fehlern temporäre Dateien zuverlässig entfernen.

### Abnahmekriterien

- Manipulierte ZIP-Dateien können keine Dateien außerhalb des Zielverzeichnisses erzeugen oder überschreiben.
- ZIP-Bombs können keine unkontrollierte Ressourcenerschöpfung verursachen.
- Symlink-basierte Ausbrüche sind ausgeschlossen.

---

## SEC-005 – Unsichere Pfadvalidierung im Webserver-Modul

**Priorität:** KRITISCH

**Betroffene Datei:** `modules/webserver.py`  
**Betroffener Bereich:** `validate_web_path()`

### Identifiziertes Problem

Auch hier wurde eine unsichere Pfadprüfung über String-Präfixe festgestellt.

### Anforderungen

- Gleiche Sicherheitsgrundlage wie beim Dateimanager verwenden.
- Keine isolierte Sonderimplementierung mit abweichenden Sicherheitsregeln.
- Domain-Verzeichnisse serverseitig bestimmen.
- Pfadgrenzen mit kanonischen Pfaden prüfen.
- Symlinks berücksichtigen.
- Konfigurationsdateien dürfen nicht außerhalb des vorgesehenen Domain-Bereichs manipuliert werden.

### Abnahmekriterien

- Manipulierte Webserver-Pfade können keine fremden Dateien erreichen.
- Die Validierung verwendet dieselbe zentrale Sicherheitslogik wie andere Dateisystemmodule.

---

# 3. Hohe Sicherheitsrisiken

## SEC-006 – Pfadmanipulation über App-Manifeste

**Priorität:** HOCH

**Betroffene Datei:** `modules/apps.py`  
**Betroffene Manifest-Felder:** `env_template`, `setup_sql`

### Identifiziertes Problem

Manifest-Pfade werden über `os.path.join()` mit dem Deployment-Verzeichnis kombiniert, ohne sicherzustellen, dass das Ergebnis innerhalb des vorgesehenen Verzeichnisses liegt.

Beispiel:

```text
../../../../etc/passwd
```

### Mögliche Auswirkungen

- Lesen lokaler Dateien außerhalb des App-Pakets.
- Kopieren sensibler Dateien in ein Deployment-Verzeichnis.
- Auslesen beliebiger SQL-Dateien.
- Unberechtigter Zugriff auf Konfigurationen.

### Anforderungen

- Alle Manifest-Dateipfade relativ zum Paket-Root auflösen.
- Absolute Pfade ablehnen.
- `..`-Traversal ablehnen.
- `commonpath()` oder gleichwertige Verzeichnisgrenzenprüfung verwenden.
- Symlinks innerhalb der Paketstruktur berücksichtigen.
- Nur reguläre Dateien zulassen.
- Dateigrößen begrenzen.
- Manifest-Dateien vor der Verwendung vollständig validieren.

### Abnahmekriterien

Kein Manifest darf Dateien außerhalb seines eigenen Paketverzeichnisses referenzieren.

---

## SEC-007 – Unsichere Backup-Wiederherstellung

**Priorität:** HOCH

**Betroffene Datei:** `modules/backups.py`  
**Betroffener Bereich:** TAR-Extraktion / Restore

### Identifiziertes Problem

Die Wiederherstellung verwendet `tarfile.extractall()` ohne erkennbare zusätzliche Pfad- und Dateitypprüfung.

Bisherige Verwendung:

```python
with tarfile.open(backup["filepath"], "r:gz") as tar:
    tar.extractall(tmp_restore)
```

Weitere Verwendung:

```python
with tarfile.open(inner_webroot, "r:gz") as wtar:
    wtar.extractall(domain_dir)
```

Manipulierte TAR-Dateien könnten unter Umständen Dateien außerhalb des vorgesehenen Restore-Verzeichnisses überschreiben.

### Anforderungen

- Unsichere unkontrollierte `extractall()`-Verwendung ersetzen.
- Alle Archivmitglieder vor der Extraktion prüfen.
- Absolute Pfade ablehnen.
- `..`-Traversal ablehnen.
- Symlinks und Hardlinks sicher behandeln.
- Sonderdateien ablehnen.
- Keine Dateien außerhalb des Restore-Ziels erstellen oder überschreiben.
- Archivgröße und entpackte Gesamtgröße begrenzen.
- Anzahl der Dateien begrenzen.
- Prüfsummen und Integrität überprüfen.
- Restore zunächst in einem temporären Verzeichnis durchführen.
- Dateien erst nach erfolgreicher Validierung übernehmen.
- Bei Fehlern Rollback ermöglichen.
- Datenbank- und Dateisystem-Restore möglichst konsistent durchführen.

### Abnahmekriterien

- Manipulierte Backups können keine beliebigen Systemdateien überschreiben.
- Restore funktioniert weiterhin mit regulären SysCore-Backups.
- Fehlgeschlagene Restore-Vorgänge hinterlassen keinen inkonsistenten Zustand.

---

## SEC-008 – Fehlender durchgängiger CSRF-Schutz

**Priorität:** HOCH

**Betroffene Dateien:** `app.py`, sämtliche Module mit schreibenden Aktionen

### Identifiziertes Problem

Es wurde kein durchgängiger zentraler CSRF-Schutz festgestellt.

Zahlreiche Funktionen verändern den Systemzustand:

- Benutzerverwaltung.
- Firewall.
- Paketverwaltung.
- Domains.
- Datenbanken.
- Backup-Wiederherstellung.
- SSL-Verwaltung.
- Dateimanager.
- Systemkonfiguration.
- Webserver-Verwaltung.

### Anforderungen

- Zentralen CSRF-Schutz implementieren, beispielsweise mit Flask-WTF.
- Sämtliche schreibenden Formulare absichern.
- AJAX-Requests mit CSRF-Token absichern.
- State-changing GET-Routen beseitigen.
- Origin- bzw. Referer-Prüfung ergänzend berücksichtigen.
- Session-Cookies mit geeigneten SameSite-Einstellungen versehen.
- Ausnahmen nur für technisch notwendige Endpunkte zulassen.
- Webhooks nicht pauschal mit normalen Formularregeln behandeln, sondern mit eigener Signatur- und Authentifizierungsprüfung absichern.

### Abnahmekriterien

- Schreibende Aktionen ohne gültiges CSRF-Token werden abgelehnt.
- AJAX-Funktionen arbeiten weiterhin korrekt.
- Externe Angriffe über fremde Webseiten können keine authentifizierten Änderungen auslösen.

---

## SEC-009 – Rollenprüfung ausschließlich anhand der Session

**Priorität:** HOCH

**Betroffene Datei:** `modules/auth_users.py`  
**Betroffener Bereich:** `role_required`

### Identifiziertes Problem

Die Rollenprüfung verwendet:

```python
session.get("role", "monitor")
```

Die Rolle wird beim Login in die Session geschrieben.

Wird ein Benutzer später herabgestuft oder deaktiviert, kann eine bestehende Session weiterhin die alten Berechtigungen enthalten.

### Anforderungen

- Benutzerstatus und aktuelle Rolle bei privilegierten Anfragen aus der Datenbank prüfen.
- Deaktivierte Benutzer sofort sperren.
- Rollenänderungen sofort wirksam machen.
- Sessions bei Deaktivierung invalidieren.
- Sessions bei sicherheitsrelevanten Rollenänderungen invalidieren oder aktualisieren.
- Berechtigungsprüfungen zentral implementieren.
- Default-Rollen niemals als Ersatz für eine fehlende oder ungültige Benutzeridentität verwenden.
- Berechtigungen nach dem Least-Privilege-Prinzip vergeben.

### Abnahmekriterien

- Eine Rollenänderung wirkt sich unmittelbar auf aktive Sessions aus.
- Deaktivierte Benutzer können keine weiteren privilegierten Aktionen ausführen.
- Manipulierte Session-Daten führen nicht zu erhöhten Berechtigungen.

---

# 4. Weitere Sicherheitsprobleme

## SEC-010 – Open Redirect nach Login

**Priorität:** MITTEL

**Betroffene Datei:** `modules/auth_users.py`

### Identifiziertes Problem

Der Login übernimmt einen ungeprüften `next`-Parameter:

```python
next_url = request.args.get("next")
return redirect(next_url or url_for(...))
```

Dadurch können externe Weiterleitungen möglich sein.

### Anforderungen

- Nur relative interne URLs akzeptieren.
- Externe Hosts ablehnen.
- Protokoll-relative URLs wie `//example.com` ablehnen.
- Weiterleitungen auf sichere interne Ziele begrenzen.

### Abnahmekriterien

Ein Angreifer kann Benutzer nach dem Login nicht auf eine fremde Webseite umleiten.

---

## SEC-011 – Absicherung des QR-Logins

**Priorität:** MITTEL bis HOCH

**Betroffene Datei:** `modules/auth_users.py`

### Identifiziertes Problem

Der QR-Login verwendet einen geheimen Token in der URL.

Die Tokenlänge ist grundsätzlich ausreichend, allerdings müssen zusätzliche Schutzmechanismen geprüft und umgesetzt werden.

### Anforderungen

- Kurze Ablaufzeit für QR-Login-Anfragen.
- Einmalverwendung des Tokens.
- CSRF-Schutz für die Freigabe.
- Rate-Limiting.
- Bindung des Tokens an die ursprüngliche Login-Anfrage.
- Schutz vor Token-Leaks über Logs.
- Schutz vor Token-Leaks über Referrer.
- Token nach erfolgreicher Verwendung sofort invalidieren.
- Ungültige und abgelaufene Anfragen zuverlässig ablehnen.

### Abnahmekriterien

- QR-Tokens können nicht mehrfach verwendet werden.
- Abgelaufene Tokens sind ungültig.
- Eine fremde Login-Anfrage kann nicht versehentlich freigegeben werden.

---

## SEC-012 – Unsichere Berechtigungen für Secrets und Konfigurationsdateien

**Priorität:** HOCH

**Betroffene Dateien:** `install.sh`, `config.py`

### Identifiziertes Problem

`.env` und `.secret_key` werden angelegt, ohne dass explizit restriktive Dateirechte an allen relevanten Stellen sichergestellt sind.

### Anforderungen

- Secrets mit restriktiven Dateirechten anlegen.
- Dateirechte `0600` für Dateien mit geheimen Zugangsdaten verwenden, sofern die Betriebsarchitektur dies zulässt.
- Verzeichnisrechte entsprechend einschränken.
- Eigentümer und Gruppenrechte korrekt setzen.
- Umask explizit konfigurieren.
- Secrets niemals über Logs oder Fehlermeldungen ausgeben.
- Secret-Key-Generierung und Speicherung sicher gestalten.
- Bestehende Secrets bei Updates nicht ungewollt überschreiben.

### Abnahmekriterien

- Unberechtigte Systembenutzer können keine SysCore-Secrets lesen.
- Installations- und Update-Prozesse erhalten bestehende Secrets.

---

## SEC-013 – SQL-Konsole und MySQL-Administration

**Priorität:** HOCH

**Betroffene Bereiche:** SQL-Konsole / MySQL-Administration

### Identifiziertes Problem

Die SQL-Konsole und MySQL-Verwaltung arbeiten teilweise mit weitreichenden Datenbankrechten, einschließlich Superuser- bzw. GRANT-OPTION-Rechten.

### Anforderungen

- Datenbankrechte nach Least Privilege aufteilen.
- Keine unnötigen globalen MySQL-Rechte vergeben.
- Administrative Datenbankaktionen von normalen Datenbankaktionen trennen.
- SQL-Konsole nur für explizit autorisierte Benutzer zugänglich machen.
- Besonders kritische Aktionen zusätzlich absichern.
- Datenbankzugriffe und administrative Änderungen protokollieren.
- SQL-Statements nicht über unsichere String-Konkatenation zusammensetzen.
- Eingaben und Datenbanknamen validieren.
- Keine SQL-Konsole ohne ausdrückliche Berechtigung bereitstellen.

### Abnahmekriterien

- Benutzer können ausschließlich die ihnen zugewiesenen Datenbanken administrieren.
- Globale Datenbankrechte sind nur dort vorhanden, wo sie tatsächlich benötigt werden.

---

## SEC-014 – Unbegrenzte bzw. zu großzügige Upload-Größen

**Priorität:** MITTEL

**Betroffene Bereiche:** `app.py`, Upload-Endpunkte

### Identifiziertes Problem

Das globale Upload-Limit beträgt aktuell 512 MB.

Das kann zu Ressourcenerschöpfung und Denial-of-Service führen.

### Anforderungen

- Upload-Limits pro Funktion definieren.
- Dateitypen validieren.
- Uploads in kontrollierte temporäre Verzeichnisse schreiben.
- Maximale Anzahl paralleler Uploads berücksichtigen.
- Speicherplatz überwachen.
- Abgebrochene Uploads bereinigen.
- ZIP- und TAR-Archive zusätzlich auf entpackte Gesamtgröße prüfen.
- Keine ausführbaren Dateien ungeprüft in privilegierte Verzeichnisse übernehmen.

### Abnahmekriterien

- Jeder Upload-Endpunkt besitzt ein angemessenes Limit.
- Ressourcenerschöpfung durch übergroße Uploads wird verhindert.

---

## SEC-015 – Webhook-Authentifizierung und Replay-Schutz

**Priorität:** HOCH

**Betroffene Datei:** `app.py` und zugehörige Webhook-Module

### Identifiziertes Problem

Webhook-Routen sind vom globalen Authentifizierungs-Guard ausgenommen.

Das kann technisch notwendig sein, bedeutet aber, dass jede Route eigenständig abgesichert sein muss.

### Anforderungen

- Jede Webhook-Route einzeln überprüfen.
- Signatur- oder Token-Prüfung implementieren.
- Signaturen gegen den unveränderten Request-Body prüfen.
- Zeitstempel und Replay-Schutz verwenden, sofern der jeweilige Anbieter dies unterstützt.
- Rate-Limiting implementieren.
- Keine unberechtigten Systemaktionen über Webhooks ermöglichen.
- Fehlerhafte Signaturen ablehnen.
- Secrets sicher speichern.
- Webhook-Ereignisse nachvollziehbar protokollieren.

### Abnahmekriterien

- Nicht authentifizierte externe Requests können keine geschützten Aktionen auslösen.
- Wiederholte Requests können keine ungewollten Aktionen mehrfach ausführen.

---

## SEC-016 – Informationsleck durch Fehlerbehandlung

**Priorität:** MITTEL

**Betroffene Bereiche:** `app.py`, globale Exception-Handler

### Identifiziertes Problem

Der Fehler-Fallback kann Exception-Details und Tracebacks ausgeben.

Das kann interne Pfade, Datenbankdetails, Konfigurationen oder andere sensible Informationen offenlegen.

### Anforderungen

- Keine vollständigen Tracebacks an normale Benutzer ausgeben.
- Allgemeine Fehlermeldungen im Webinterface verwenden.
- Technische Details ausschließlich serverseitig protokollieren.
- Fehler mit eindeutiger Request-ID versehen.
- Logs auf sensible Informationen überprüfen.
- Debug-Modus in Produktionsumgebungen deaktivieren.

### Abnahmekriterien

- Benutzer sehen keine internen Stacktraces.
- Administratoren können Fehler über sichere Logs nachvollziehen.

---

## SEC-017 – Fehlende explizite Session-Cookie-Härtung

**Priorität:** HOCH

**Betroffene Datei:** `app.py` / zentrale Flask-Konfiguration

### Identifiziertes Problem

Die sicherheitsrelevanten Cookie-Einstellungen sind nicht durchgängig explizit konfiguriert.

### Anforderungen

- `SESSION_COOKIE_HTTPONLY = True`
- `SESSION_COOKIE_SECURE = True` in HTTPS-Produktionsumgebungen.
- Geeignetes `SESSION_COOKIE_SAMESITE` konfigurieren.
- Session-Laufzeiten begrenzen.
- Session nach Login und Berechtigungsänderungen erneuern.
- Session-Invalidierung bei Logout sicherstellen.
- Session-Secret ausreichend sicher generieren und schützen.

### Abnahmekriterien

- Session-Cookies sind für Produktionsbetrieb sicher konfiguriert.
- Sessions können nicht unbegrenzt oder nach Logout weiterverwendet werden.

---

## SEC-018 – Unsichere Paket- und Installationsrezepte

**Priorität:** HOCH

**Betroffene Datei:** `modules/packages.py`

### Identifiziertes Problem

Das Paketmodul verwendet statische Shell-Installationsrezepte.

Diese sind nicht automatisch eine Schwachstelle, sofern ausschließlich vertrauenswürdige und kontrollierte Einträge ausgeführt werden.

Problematisch wäre jedoch, wenn Paketdefinitionen oder Parameter durch Benutzer manipuliert werden könnten oder die Ausführung ohne privilegierte Kontrollinstanz erfolgt.

### Anforderungen

- Paketdefinitionen zentral validieren.
- Keine beliebigen Shell-Kommandos aus Benutzereingaben akzeptieren.
- Paketquellen und Versionen kontrollieren.
- Installationsaktionen über den privilegierten Systemdienst ausführen.
- Aktionen und Parameter protokollieren.
- Keine unsichere dynamische Interpretation von Paketdefinitionen.
- Abhängigkeiten und Installationsvoraussetzungen prüfen.
- Fehlerbehandlung und Rollback berücksichtigen.

### Abnahmekriterien

- Benutzer können keine eigenen privilegierten Shell-Rezepte einschleusen.
- Ausschließlich freigegebene Paketdefinitionen können ausgeführt werden.

---

## SEC-019 – Unsicherer Updater und Verwendung des System-Python

**Priorität:** MITTEL

**Betroffene Datei:** `cli.py`

### Identifiziertes Problem

Der Updater verwendet:

```bash
pip3 install ... --break-system-packages
```

Dadurch werden unter Umständen Pakete im globalen System-Python verändert.

Das kann Systemkomponenten beschädigen und zu schwer nachvollziehbaren Abhängigkeiten führen.

### Anforderungen

- Ausschließlich die SysCore-venv für Python-Abhängigkeiten verwenden.
- Keine globalen Python-Pakete überschreiben.
- Paketversionen kontrollieren.
- Update-Prozess auf Integrität prüfen.
- Updates vor Installation validieren.
- Vor Updates einen geeigneten Wiederherstellungspunkt schaffen.
- Bei fehlgeschlagenen Updates einen Rollback ermöglichen.
- Update-Prozess protokollieren.

### Abnahmekriterien

- SysCore-Updates verändern keine globalen Python-Pakete.
- Ein fehlgeschlagenes Update kann kontrolliert zurückgesetzt werden.

---

# 5. Zusätzliche systemweite Sicherheitsprüfungen

Neben den bereits identifizierten Problemen soll der Agent das gesamte Projekt auf weitere gleichartige Schwachstellen untersuchen.

Insbesondere:

## 5.1 Dateisystem

- Alle Verwendungen von `open()`, `os.remove()`, `os.rename()`, `shutil.copy()`, `shutil.move()` und ähnlichen Funktionen überprüfen.
- Alle Pfadparameter auf Vertrauenswürdigkeit untersuchen.
- Alle `os.path.join()`-Aufrufe mit externen oder manifestbasierten Pfaden überprüfen.
- Sämtliche Archiv-Extraktionen untersuchen.
- Symlink-Behandlung überprüfen.
- Datei- und Verzeichnisberechtigungen überprüfen.
- Temporäre Dateien sicher erstellen und löschen.
- Race Conditions zwischen Validierung und Zugriff untersuchen.

## 5.2 Prozessausführung

- Alle `subprocess`-Aufrufe suchen.
- Sämtliche Verwendungen von `shell=True` untersuchen.
- Dynamische Kommandozeilenparameter überprüfen.
- Benutzer- und Manifest-Eingaben auf mögliche Command Injection prüfen.
- Privilegien der ausführenden Prozesse überprüfen.
- Ausführungsrechte und Arbeitsverzeichnisse begrenzen.

## 5.3 Authentifizierung und Autorisierung

- Alle Flask-Routen überprüfen.
- Jede schreibende Route auf Authentifizierung prüfen.
- Jede privilegierte Route auf Rollenprüfung prüfen.
- Berechtigungen nicht ausschließlich über die Oberfläche durchsetzen.
- Session-Verhalten überprüfen.
- Passwort- und Token-Verarbeitung untersuchen.
- Rate-Limiting für Login und sensible Aktionen prüfen.

## 5.4 Datenbank

- SQL-Injection überprüfen.
- Dynamisch zusammengesetzte SQL-Statements untersuchen.
- Datenbankberechtigungen überprüfen.
- Zugangsdaten und Secrets schützen.
- Datenbank-Backups und Wiederherstellungen absichern.

## 5.5 Netzwerk und externe Kommunikation

- Webhook-Endpunkte prüfen.
- SSRF-Risiken untersuchen.
- Externe URLs validieren.
- Zertifikatsprüfungen bei HTTPS-Verbindungen sicherstellen.
- Unnötig offene Netzwerkdienste identifizieren.
- Admin-Endpunkte nicht unbeabsichtigt öffentlich verfügbar machen.

---

# 6. Verbindliche Teststrategie

Jede behobene Schwachstelle muss durch konkrete Tests abgesichert werden.

## Dateimanager – Domain-Isolation

Folgende Tests müssen implementiert werden:

| Test | Erwartetes Ergebnis |
|---|---|
| Zugriff auf Domain-eigenes Verzeichnis | Erlaubt |
| Zugriff auf `/var/www` | Verweigert |
| Zugriff auf andere Domain | Verweigert |
| Zugriff auf `/etc/passwd` | Verweigert |
| Zugriff auf `/opt/syscore` | Verweigert |
| Pfad mit `../` | Verweigert |
| Absoluter Fremdpfad | Verweigert |
| Symlink auf fremdes Verzeichnis | Verweigert |
| Symlink auf fremde Datei | Verweigert |
| Verschieben in andere Domain | Verweigert |
| Kopieren in andere Domain | Verweigert |
| Archiv mit Traversal-Pfad | Verweigert |

## App-Importer

- ZIP mit `../` testen.
- ZIP mit absolutem Pfad testen.
- ZIP mit Symlink testen.
- ZIP-Bomb testen.
- Manifest mit Shell-Kommando testen.
- Manifest mit ungültigem Dateipfad testen.
- Manifest mit unbekannter Aktion testen.

## Backup-System

- Manipuliertes TAR testen.
- TAR mit `../` testen.
- TAR mit absolutem Pfad testen.
- TAR mit Symlink testen.
- Abgebrochenen Restore testen.
- Rollback testen.

## Authentifizierung

- Rollenänderung bei aktiver Session testen.
- Deaktivierung bei aktiver Session testen.
- CSRF-Angriff testen.
- Externe Login-Weiterleitung testen.
- Abgelaufenen QR-Token testen.
- Wiederverwendung eines QR-Tokens testen.

## Systemrechte

- Prüfen, dass Gunicorn nicht als Root läuft.
- Prüfen, dass der Webprozess keine privilegierten Systemdateien verändern kann.
- Prüfen, dass der privilegierte Agent ausschließlich freigegebene Aktionen ausführt.
- Prüfen, dass ein normaler SysCore-Benutzer keine Root-Aktionen direkt auslösen kann.

---

# 7. Empfohlene Umsetzungsreihenfolge

Die Arbeiten sollten in dieser Reihenfolge durchgeführt werden, da mehrere Probleme voneinander abhängen.

| Reihenfolge | ID | Aufgabe | Priorität |
|---:|---|---|---|
| 1 | SEC-001 | Root-Ausführung beseitigen und Privilege Separation einführen | KRITISCH |
| 2 | SEC-002 | App-Importer gegen Codeausführung absichern | KRITISCH |
| 3 | SEC-003 | Dateimanager vollständig auf Domain-Isolation umstellen | KRITISCH |
| 4 | SEC-004 | ZIP-Extraktion gegen Zip-Slip absichern | KRITISCH |
| 5 | SEC-005 | Webserver-Pfadvalidierung korrigieren | KRITISCH |
| 6 | SEC-006 | Manifest-Dateipfade absichern | HOCH |
| 7 | SEC-007 | Backup-Restore absichern | HOCH |
| 8 | SEC-008 | Zentralen CSRF-Schutz einführen | HOCH |
| 9 | SEC-009 | Rollen- und Session-Prüfung korrigieren | HOCH |
| 10 | SEC-012 | Secrets und Dateirechte härten | HOCH |
| 11 | SEC-013 | SQL- und Datenbankberechtigungen härten | HOCH |
| 12 | SEC-015 | Webhooks absichern | HOCH |
| 13 | SEC-017 | Session-Cookies härten | HOCH |
| 14 | SEC-018 | Paket- und Installationsrezepte absichern | HOCH |
| 15 | SEC-010 | Open Redirect beheben | MITTEL |
| 16 | SEC-011 | QR-Login absichern | MITTEL/HOCH |
| 17 | SEC-014 | Upload-Limits und Ressourcenverbrauch kontrollieren | MITTEL |
| 18 | SEC-016 | Fehlerbehandlung absichern | MITTEL |
| 19 | SEC-019 | Updater korrigieren | MITTEL |

---

# 8. Abschlussanforderungen

Nach Abschluss der Arbeiten muss der Agent einen vollständigen Sicherheitsbericht erstellen.

Dieser muss enthalten:

1. Alle untersuchten Sicherheitsprobleme.
2. Welche Probleme tatsächlich im aktuellen Code vorhanden waren.
3. Welche Probleme bereits behoben waren.
4. Welche Änderungen vorgenommen wurden.
5. Welche Dateien geändert wurden.
6. Welche neuen Funktionen oder zentralen Sicherheitsmechanismen implementiert wurden.
7. Welche Tests durchgeführt wurden.
8. Welche Tests erfolgreich waren.
9. Welche Tests fehlgeschlagen sind.
10. Welche Restrisiken weiterhin bestehen.

Für jede SEC-ID muss ein eindeutiger Status dokumentiert werden:

- `OPEN` – noch nicht bearbeitet.
- `IN_PROGRESS` – in Bearbeitung.
- `FIXED` – Änderung implementiert.
- `VERIFIED` – Änderung implementiert und erfolgreich getestet.
- `BLOCKED` – Umsetzung aus einem dokumentierten Grund nicht möglich.

**Wichtig:** `FIXED` darf nicht automatisch als `VERIFIED` gelten.

Ein Sicherheitsproblem gilt erst dann als abgeschlossen, wenn die Implementierung geprüft und durch passende Tests abgesichert wurde.

---

# 9. Übergeordnetes Sicherheitsziel

SysCore soll nicht nur einzelne bekannte Schwachstellen beseitigen, sondern eine klare Sicherheitsarchitektur erhalten.

Die wichtigsten Grundsätze:

- Die Webanwendung läuft grundsätzlich ohne Root-Rechte.
- Privilegierte Systemoperationen sind zentral kontrolliert.
- Jede Domain ist eine eigenständige Dateisystem-Sicherheitsgrenze.
- Benutzer können ausschließlich auf explizit freigegebene Ressourcen zugreifen.
- Importierte Pakete und Manifeste sind grundsätzlich nicht vertrauenswürdig.
- Keine ungeprüften Shell-Befehle.
- Keine ungeprüften Dateisystempfade.
- Keine Berechtigungsentscheidungen ausschließlich anhand von Client-Daten oder veralteten Sessions.
- Alle sicherheitskritischen Aktionen sind nachvollziehbar und testbar.

**Ziel ist ein gehärtetes SysCore, nicht ein neu geschriebenes SysCore.** Die bestehende modulare Architektur und sämtliche benötigten Funktionen sollen erhalten bleiben, während die Sicherheitsmechanismen systematisch verbessert werden.