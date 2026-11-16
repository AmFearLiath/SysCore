"""
SysCore Sentinel - Security Package Entry Point
Exportiert den Blueprint und Kern-Funktionen für Rückwärtskompatibilität.
"""

from modules.security.routes import (
    security_bp,
    calculate_security_score,
    get_ufw_status,
    get_fail2ban_status,
    get_ssh_audit,
    get_open_ports_audit,
    get_clamav_status,
    scan_nginx_exploit_probes
)

__all__ = [
    "security_bp",
    "calculate_security_score",
    "get_ufw_status",
    "get_fail2ban_status",
    "get_ssh_audit",
    "get_open_ports_audit",
    "get_clamav_status",
    "scan_nginx_exploit_probes"
]
