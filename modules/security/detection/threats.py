"""
SysCore Sentinel - Threat & Attack Surface Detection
Identifiziert offene Netzwerk-Sockets, öffentlich exponierte sensible Dienste
und Gefährdungsindikatoren.
"""

import psutil
from typing import Dict, Any, List
from modules.security.core.risk_engine import DANGER_PORTS

def get_open_ports_audit() -> Dict[str, Any]:
    """Scannt alle lauschenden TCP/UDP Sockets und klassifiziert das Risiko."""
    listeners = []
    warnings = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                ip = conn.laddr.ip
                port = conn.laddr.port
                proc_name = "Unbekannt"
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                    except Exception:
                        pass

                is_public = (ip in ("0.0.0.0", "::", ""))
                listeners.append({
                    "ip": ip,
                    "port": port,
                    "process": proc_name,
                    "public": is_public
                })

                if is_public and port in DANGER_PORTS:
                    name, desc, sev, _ = DANGER_PORTS[port]
                    warnings.append({
                        "port": port,
                        "service": name,
                        "description": desc,
                        "level": sev
                    })
    except Exception:
        pass

    listeners.sort(key=lambda x: (not x["public"], x["port"]))
    return {"listeners": listeners, "warnings": warnings}
