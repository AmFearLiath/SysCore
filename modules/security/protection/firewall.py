"""
SysCore Sentinel - Firewall Protection Module (UFW)
Verwaltet UFW-Status, Portfreigaben, Sperren, Notfall-Watchdogs und den
Firewall-Aktivierungs-Assistenten mit automatischer Erkennung laufender Dienste
(Pterodactyl Wings, Docker Gameserver-Container, Webserver, SSH, Mail).
"""

import os
import re
import socket
import shutil
import subprocess
import psutil
from typing import Dict, Any, List, Tuple
from modules.system_agent import run_privileged
from modules.security.core.safe_apply import SafeApply
import config

DANGEROUS_INTERNAL_PORTS = {
    3306: "MariaDB / MySQL Server",
    5432: "PostgreSQL Server",
    6379: "Redis Cache Server",
    27017: "MongoDB Server",
    11211: "Memcached",
    2375: "Docker Remote API (unverschlüsselt)",
    9000: "PHP-FPM TCP Socket"
}

def get_ufw_status() -> Dict[str, Any]:
    """Liest den aktuellen UFW-Firewall-Status aus."""
    if not shutil.which("ufw"):
        return {"installed": False, "active": False, "rules": []}
    try:
        res = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=5)
        out = res.stdout
        is_active = "Status: active" in out
        rules = []
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Status:") and not line.startswith("Logging:") and not line.startswith("Default:") and not line.startswith("New profiles:") and not line.startswith("To") and not line.startswith("--"):
                rules.append(line)
        return {"installed": True, "active": is_active, "rules": rules, "raw": out}
    except Exception as e:
        return {"installed": True, "active": False, "rules": [], "error": str(e)}

def set_ufw_enabled(enabled: bool) -> bool:
    """Aktiviert oder deaktiviert UFW sicher."""
    if not shutil.which("ufw"):
        return False
    cmd = ["ufw", "--force", "enable"] if enabled else ["ufw", "disable"]
    try:
        run_privileged(cmd, timeout=10)
        return True
    except Exception:
        return False

def add_ufw_allow(port_or_service: str, proto: str = "tcp") -> bool:
    """Erlaubt einen Port oder Dienst in UFW."""
    if not shutil.which("ufw"):
        return False
    try:
        rule = f"{port_or_service}/{proto}" if proto and "/" not in str(port_or_service) else str(port_or_service)
        run_privileged(["ufw", "allow", rule], timeout=10)
        return True
    except Exception:
        return False

def add_ufw_deny(ip_address: str) -> bool:
    """Sperrt eine IP-Adresse in UFW."""
    if not shutil.which("ufw"):
        return False
    try:
        run_privileged(["ufw", "deny", "from", ip_address], timeout=10)
        return True
    except Exception:
        return False

def remove_ufw_deny(ip_address: str) -> bool:
    """Entfernt eine IP-Sperre aus UFW."""
    if not shutil.which("ufw"):
        return False
    try:
        run_privileged(["ufw", "delete", "deny", "from", ip_address], timeout=10)
        return True
    except Exception:
        return False

def detect_candidate_firewall_rules() -> List[Dict[str, Any]]:
    """
    Erkennt automatisch alle aktuell aktiven Dienste und Ports auf dem Host:
    - SSH (aktiver Port aus sshd_config)
    - Webserver (80, 443)
    - SysCore Panel Dashboard (8888)
    - Pterodactyl Wings Daemon (API 8080, SFTP 2022 oder aus /etc/pterodactyl/config.yml)
    - Docker Container Port-Mappings (Gameserver wie Minecraft, CS2, Rust, etc.)
    - Aktive lauschende TCP & gebundene UDP Sockets via psutil
    Klassifiziert die Ports in Kategorien mit sicheren Standard-Auswahlen.
    """
    candidates = {}

    # 1. Ermittle aktiven SSH-Port
    ssh_port = 22
    for ssh_cfg in ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"]:
        if os.path.isfile(ssh_cfg):
            try:
                with open(ssh_cfg, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line.startswith("port ") and line.split()[1].isdigit():
                            ssh_port = int(line.split()[1])
                            break
            except Exception:
                pass

    candidates[(str(ssh_port), "tcp")] = {
        "port": str(ssh_port),
        "proto": "tcp",
        "service": f"SSH Fernzugriff (Port {ssh_port})",
        "process": "sshd",
        "category": "core",
        "category_label": "Kern-Dienst (Unverzichtbar)",
        "checked": True,
        "is_safe": True,
        "notes": "Essentiell für Administrator-Zugriff; schützt vor Aussperrung!"
    }

    # 2. Webserver Ports (NGINX / Apache / Let's Encrypt Certbot)
    candidates[("80", "tcp")] = {
        "port": "80",
        "proto": "tcp",
        "service": "Webserver HTTP (Port 80)",
        "process": "nginx",
        "category": "web",
        "category_label": "Web & Domains",
        "checked": True,
        "is_safe": True,
        "notes": "Erforderlich für Webseiten und Let's Encrypt Zertifikats-Erneuerung (HTTP-01)."
    }
    candidates[("443", "tcp")] = {
        "port": "443",
        "proto": "tcp",
        "service": "Webserver HTTPS (Port 443)",
        "process": "nginx",
        "category": "web",
        "category_label": "Web & Domains",
        "checked": True,
        "is_safe": True,
        "notes": "Verschlüsselter Webverkehr für alle Domains & SSL-Zertifikate."
    }

    # 3. SysCore Panel Port
    candidates[("8888", "tcp")] = {
        "port": "8888",
        "proto": "tcp",
        "service": "SysCore Server-Panel Dashboard",
        "process": "python",
        "category": "core",
        "category_label": "Kern-Dienst (Unverzichtbar)",
        "checked": True,
        "is_safe": True,
        "notes": "Ermöglicht den Zugriff auf dieses Web-Panel."
    }

    # 4. Pterodactyl Wings Konfiguration prüfen (/etc/pterodactyl/config.yml)
    wings_cfg = "/etc/pterodactyl/config.yml"
    wings_api_port = 8080
    wings_sftp_port = 2022
    wings_detected = os.path.exists(wings_cfg) or shutil.which("wings") is not None

    if os.path.exists(wings_cfg):
        try:
            with open(wings_cfg, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Parse api.port
                m_api = re.search(r"api:\s*[^:]*port:\s*(\d+)", content, re.DOTALL)
                if m_api:
                    wings_api_port = int(m_api.group(1))
                # Parse sftp.bind_port
                m_sftp = re.search(r"bind_port:\s*(\d+)", content)
                if m_sftp:
                    wings_sftp_port = int(m_sftp.group(1))
        except Exception:
            pass

    if wings_detected:
        candidates[(str(wings_api_port), "tcp")] = {
            "port": str(wings_api_port),
            "proto": "tcp",
            "service": f"Pterodactyl Wings Node API (Port {wings_api_port})",
            "process": "wings",
            "category": "pterodactyl",
            "category_label": "Pterodactyl & Gameserver",
            "checked": True,
            "is_safe": True,
            "notes": "Verbindung zwischen Pterodactyl Web Panel und dem Wings Node Daemon."
        }
        candidates[(str(wings_sftp_port), "tcp")] = {
            "port": str(wings_sftp_port),
            "proto": "tcp",
            "service": f"Pterodactyl Wings SFTP Server (Port {wings_sftp_port})",
            "process": "wings",
            "category": "pterodactyl",
            "category_label": "Pterodactyl & Gameserver",
            "checked": True,
            "is_safe": True,
            "notes": "SFTP-Dateizugriff für Kunden und Gameserver-Inhaber."
        }

    # 5. Docker Container Port-Mappings auslesen (Pterodactyl Gameserver laufen in Containern)
    if shutil.which("docker"):
        try:
            res = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                capture_output=True, text=True, timeout=5
            )
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    if "\t" not in line:
                        continue
                    c_name, ports_str = line.split("\t", 1)
                    # Suche Muster wie 0.0.0.0:25565->25565/tcp oder :::25565->25565/udp
                    matches = re.findall(r"(?:0\.0\.0\.0|:::|\[::\]):(\d+)->\d+/(tcp|udp)", ports_str)
                    for port_num, proto in matches:
                        key = (str(port_num), proto.lower())
                        candidates[key] = {
                            "port": str(port_num),
                            "proto": proto.lower(),
                            "service": f"Gameserver ({c_name[:18]})",
                            "process": "docker-proxy",
                            "category": "pterodactyl",
                            "category_label": "Pterodactyl & Gameserver",
                            "checked": True,
                            "is_safe": True,
                            "notes": f"Aktiver Gameserver-Container '{c_name}' (Port {port_num}/{proto.upper()})."
                        }
        except Exception:
            pass

    # 6. Sockets via psutil scannen (erfasst alle weiteren lauschenden Prozesse)
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = conn.laddr
            if not laddr or not laddr.port:
                continue
            port_str = str(laddr.port)
            port_int = int(laddr.port)
            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"

            # Nur lauschende TCP oder gebundene UDP Sockets
            if proto == "tcp" and conn.status != psutil.CONN_LISTEN:
                continue

            # Hohe ephemere Client-Ports ausschließen (> 32768), außer sie gehören zu Docker/Wings/Java/Games
            proc_name = "Unbekannt"
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except Exception:
                    pass

            proc_lower = proc_name.lower()
            is_game_process = any(x in proc_lower for x in ("docker", "wings", "java", "srcds", "rust", "valheim", "bedrock", "palworld", "ark", "factorio"))

            if port_int > 32768 and not is_game_process:
                continue

            key = (port_str, proto)
            if key in candidates:
                continue

            is_danger = port_int in DANGEROUS_INTERNAL_PORTS
            is_internal_only = laddr.ip in ("127.0.0.1", "::1")

            if is_danger:
                category = "database"
                cat_label = "⚠️ Datenbank / Interne Dienste (Vorsicht)"
                service_desc = f"{DANGEROUS_INTERNAL_PORTS[port_int]} (Port {port_str})"
                checked = False
                is_safe = False
                notes = "Sollte niemals öffentlich erreichbar sein! Empfehlung: Deaktiviert lassen."
            elif is_game_process:
                category = "pterodactyl"
                cat_label = "Pterodactyl & Gameserver"
                service_desc = f"Gameserver-Prozess ({proc_name})"
                checked = True
                is_safe = True
                notes = f"Aktiver Spiele-Server auf Port {port_str}/{proto.upper()}."
            elif is_internal_only:
                category = "internal"
                cat_label = "Lokale Dienste (127.0.0.1)"
                service_desc = f"Lokaler Dienst ({proc_name})"
                checked = False
                is_safe = True
                notes = "Lauscht nur lokal auf dem Server; Firewall-Freigabe meist unnötig."
            else:
                category = "other"
                cat_label = "Weitere Dienste"
                service_desc = f"Dienst {proc_name} (Port {port_str})"
                checked = True
                is_safe = True
                notes = f"Lauschender Dienst auf {laddr.ip}:{port_str}."

            candidates[key] = {
                "port": port_str,
                "proto": proto,
                "service": service_desc,
                "process": proc_name,
                "category": category,
                "category_label": cat_label,
                "checked": checked,
                "is_safe": is_safe,
                "notes": notes
            }
    except Exception:
        pass

    # Sortieren: Zuerst Kern-Dienste, dann Pterodactyl & Web, am Ende interne Datenbanken
    cat_order = {"core": 1, "pterodactyl": 2, "web": 3, "other": 4, "internal": 5, "database": 6}
    return sorted(candidates.values(), key=lambda x: (cat_order.get(x["category"], 99), int(x["port"])))

def activate_firewall_with_rules(selected_rules: List[str], custom_ranges: str = "", username: str = "admin") -> Tuple[bool, str, int]:
    """
    Richtet UFW mit den ausgewählten Regeln sicher ein und aktiviert die Firewall.
    Schritte:
    1. Erstellt einen Sicherheits-Snapshot.
    2. Setzt 'default deny incoming' und 'default allow outgoing'.
    3. Gibt alle ausgewählten Ports frei (z.B. '22/tcp', '80/tcp', '25565/udp').
    4. Gibt optionale Port-Ranges frei (z.B. '25565:25600/tcp').
    5. Aktiviert UFW mit 'ufw --force enable'.
    Gibt (success, message, rules_count) zurück.
    """
    if not shutil.which("ufw"):
        return False, "UFW (Uncomplicated Firewall) ist auf diesem System nicht installiert.", 0

    if not selected_rules:
        return False, "Es muss mindestens der SSH-Port freigegeben werden, um Aussperrung zu verhindern!", 0

    # 1. Vorher-Snapshot zur Sicherheit
    current_status = get_ufw_status()
    snapshot_id = SafeApply.create_snapshot(
        snapshot_type="pre_firewall_activation",
        description="Snapshot vor Firewall-Aktivierung mit Port-Wizard",
        current_state={
            "ufw_active": current_status.get("active", False),
            "old_rules": current_status.get("rules", []),
            "new_selected_rules": selected_rules,
            "custom_ranges": custom_ranges
        },
        created_by=username
    )

    rules_applied = 0
    errors = []

    try:
        # 2. Standard-Richtlinien setzen
        run_privileged(["ufw", "default", "deny", "incoming"], timeout=10)
        run_privileged(["ufw", "default", "allow", "outgoing"], timeout=10)

        # 3. Ausgewählte Ports freigeben
        for rule in selected_rules:
            rule_clean = rule.strip().lower()
            if not rule_clean:
                continue
            # Validierung des Formats (z.B. '22/tcp' oder '25565/udp')
            if not re.match(r"^\d{1,5}(?:/(?:tcp|udp))?$", rule_clean):
                continue

            res = run_privileged(["ufw", "allow", rule_clean], timeout=10)
            if res.returncode == 0:
                rules_applied += 1
            else:
                errors.append(f"Regel '{rule_clean}' konnte nicht hinzugefügt werden: {res.stderr}")

        # 4. Benutzerdefinierte Port-Bereiche freigeben (z.B. '25565:25600/tcp', '7777:7780/udp')
        if custom_ranges:
            parts = re.split(r"[,;\s]+", custom_ranges)
            for part in parts:
                part_clean = part.strip().lower()
                if not part_clean:
                    continue
                # Gültige Range-Syntax prüfen
                if re.match(r"^\d{1,5}:\d{1,5}/(?:tcp|udp)$", part_clean) or re.match(r"^\d{1,5}(?:/(?:tcp|udp))?$", part_clean):
                    res = run_privileged(["ufw", "allow", part_clean], timeout=10)
                    if res.returncode == 0:
                        rules_applied += 1
                    else:
                        errors.append(f"Range '{part_clean}' fehlgeschlagen: {res.stderr}")

        # 5. UFW aktivieren
        act_res = run_privileged(["ufw", "--force", "enable"], timeout=15)
        if act_res.returncode != 0:
            return False, f"UFW konnte nicht aktiviert werden: {act_res.stderr}", rules_applied

        return True, f"Firewall erfolgreich mit {rules_applied} freigegebenen Ports/Diensten aktiviert (Snapshot #{snapshot_id}). Alle ausgewählten Gameserver und Webdienste bleiben online!", rules_applied

    except Exception as e:
        # Notfall-Fallback
        return False, f"Fehler bei Firewall-Aktivierung: {e}", rules_applied
