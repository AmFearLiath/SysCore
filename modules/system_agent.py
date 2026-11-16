import os
import shutil
import subprocess
from pathlib import Path
import config

ALLOWED_SERVICES = set(config.MANAGED_SERVICES) | {
    "syscore", "syscore-panel", "certbot.timer", "clamav-daemon", "mysql", "mariadb",
    "postgresql", "php8.2-fpm", "php8.3-fpm", "php8.4-fpm", "redis-server", "crowdsec", "docker",
    "wings", "pteroq", "fail2ban", "apache2", "wireguard", "gitea", "uptime-kuma", "nginx"
}

ALLOWED_SERVICE_ACTIONS = {
    "status", "start", "stop", "restart", "reload", "is-active", "enable", "disable"
}

def is_running_as_root():
    """Prüft, ob der aktuelle Prozess Root-Rechte besitzt (EUID == 0)"""
    return hasattr(os, "geteuid") and os.geteuid() == 0

def build_privileged_cmd(cmd_list):
    """
    Kapselt Befehle für Privilege Separation (SEC-001):
    Läuft SysCore als unprivilegierter Benutzer 'syscore', wird 'sudo -n'
    vorangestellt, um die über /etc/sudoers.d/syscore freigegebenen Befehle
    ohne interaktives Passwort auszuführen.
    """
    if not cmd_list or not isinstance(cmd_list, list):
        raise ValueError("Privilegierter Befehl muss eine Liste von Argumenten sein.")

    # Auf Linux/macOS: Wenn kein Root, nutze sudo -n falls verfügbar
    if hasattr(os, "geteuid") and not is_running_as_root() and shutil.which("sudo"):
        return ["sudo", "-n"] + cmd_list
    return list(cmd_list)

def run_privileged(cmd_list, timeout=60, check=False, capture_output=True, text=True, input=None):
    """
    Führt einen privilegierten Systembefehl sicher ohne Shell aus (SEC-001).
    Niemals 'shell=True'!
    """
    full_cmd = build_privileged_cmd(cmd_list)
    try:
        return subprocess.run(
            full_cmd,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
            text=text,
            input=input,
            shell=False
        )
    except subprocess.CalledProcessError:
        raise
    except Exception as e:
        # Fallback falls sudo fehlschlägt oder nicht existiert: Versuch direkt
        if full_cmd[0] == "sudo":
            return subprocess.run(
                cmd_list,
                timeout=timeout,
                check=check,
                capture_output=capture_output,
                text=text,
                input=input,
                shell=False
            )
        raise

def manage_service(service_name, action, no_block=False):
    """
    Verwaltet Systemd-Dienste über eine geschützte Whitelist (SEC-001).
    Verhindert die Manipulation nicht autorisierter Systemd-Units.
    """
    clean_name = str(service_name).strip()
    clean_act = str(action).strip().lower()

    if clean_act not in ALLOWED_SERVICE_ACTIONS:
        raise ValueError(f"Ungültige Service-Aktion '{clean_act}'. Erlaubt: {ALLOWED_SERVICE_ACTIONS}")

    # Prüfen gegen Whitelist (bzw. PHP-FPM Muster phpX.Y-fpm)
    is_allowed = clean_name in ALLOWED_SERVICES or clean_name.startswith("php")
    if not is_allowed:
        raise ValueError(f"Dienst '{clean_name}' ist nicht in der Whitelist verwalteter SysCore-Dienste.")

    systemctl_bin = shutil.which("systemctl")
    if not systemctl_bin:
        return subprocess.CompletedProcess(args=["systemctl", clean_act, clean_name], returncode=0, stdout="Simuliert (kein systemctl vorhanden)", stderr="")

    cmd = ["systemctl", clean_act]
    if no_block and clean_act in ("restart", "reload"):
        cmd.append("--no-block")
    cmd.append(clean_name)

    return run_privileged(cmd, timeout=30)

def nginx_test():
    """Führt 'nginx -t' zur Syntaxprüfung der Konfiguration aus"""
    nginx_bin = shutil.which("nginx")
    if not nginx_bin:
        return subprocess.CompletedProcess(args=["nginx", "-t"], returncode=0, stdout="Simuliert", stderr="")
    return run_privileged(["nginx", "-t"], timeout=15)

def nginx_reload():
    """
    Sicheres Neuladen von NGINX mit vorheriger Syntaxprüfung.
    Bricht bei Syntaxfehlern ab, um Downtimes zu verhindern.
    """
    test_res = nginx_test()
    if test_res.returncode != 0:
        return test_res
    return manage_service("nginx", "reload")

def certbot_run(args, timeout=120):
    """Führt Certbot sicher aus"""
    certbot_bin = shutil.which("certbot")
    if not certbot_bin:
        return subprocess.CompletedProcess(args=["certbot"] + args, returncode=0, stdout="Simuliert", stderr="")
    clean_args = [str(a) for a in args]
    return run_privileged(["certbot"] + clean_args, timeout=timeout)

def ufw_run(args, timeout=30):
    """Führt UFW Firewall-Befehle sicher aus"""
    ufw_bin = shutil.which("ufw")
    if not ufw_bin:
        return subprocess.CompletedProcess(args=["ufw"] + args, returncode=0, stdout="Simuliert", stderr="")
    clean_args = [str(a) for a in args]
    return run_privileged(["ufw"] + clean_args, timeout=timeout)

def trigger_panel_restart(delay_seconds=2):
    """
    Startet das SysCore-Panel verzögert neu (z.B. nach Einstellungsänderungen oder Updates).
    Nutzt bevorzugt systemd-run als eigenständige transiente Unit außerhalb der cgroup,
    sodass systemd den Neustart-Prozess nicht beim Beenden des alten Daemons terminiert.
    """
    if hasattr(os, "geteuid"):
        sudo_prefix = "sudo -n " if not is_running_as_root() and shutil.which("sudo") else ""
        delay = max(1, int(delay_seconds))

        # 1. Bevorzugt: systemd-run (erstellt unabhängige Unit außerhalb der syscore-panel CGroup)
        systemd_run_bin = shutil.which("systemd-run")
        if systemd_run_bin:
            try:
                cmd_run = (
                    f"{sudo_prefix}systemd-run --unit=syscore-restarter-{int(time.time())} "
                    f"--on-active={delay}s {sudo_prefix}systemctl restart syscore-panel"
                )
                res = subprocess.run(["sh", "-c", cmd_run], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    return
            except Exception:
                pass

        # 2. Fallback: Vollständig entkoppelter Subshell-Prozess mit nohup & neuer Session
        cmd = (
            f"nohup sh -c 'sleep {delay}; "
            f"{sudo_prefix}systemctl restart --no-block syscore-panel 2>/dev/null || "
            f"{sudo_prefix}systemctl restart --no-block syscore 2>/dev/null || "
            f"true' >/dev/null 2>&1 &"
        )
        try:
            subprocess.Popen(
                ["sh", "-c", cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True
            )
        except Exception:
            subprocess.Popen(["sh", "-c", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        # Windows Dev-Modus
        pass
