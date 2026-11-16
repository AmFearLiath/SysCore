"""
SysCore Sentinel - Software Ownership Mapper
Ordnungsgemäße Zuordnung von Dateien, Netzwerk-Sockets und Systemdiensten
zu registrierten Software-Komponenten, um unbeabsichtigte Kollisionen zu verhindern.
"""

from typing import Dict, Any, Optional
import os
import db

class OwnershipMapper:
    """Ermittelt den Besitzer und die Schutzklasse für gegebene Ressourcen."""

    @staticmethod
    def get_port_owner(port: int) -> Optional[Dict[str, Any]]:
        """Prüft, zu welcher Software ein bestimmter Port gehört."""
        rows = db.query_db("SELECT * FROM software_inventory WHERE ports_json LIKE ?", (f"%{port}%",))
        if rows:
            return dict(rows[0])
        return None

    @staticmethod
    def get_path_owner(path: str) -> Optional[Dict[str, Any]]:
        """Prüft, zu welcher Software ein Pfad gehört."""
        norm = os.path.normpath(path)
        rows = db.query_db("SELECT * FROM software_inventory")
        if not rows:
            return None

        for r in rows:
            cpaths = r["config_paths_json"]
            if cpaths and norm in cpaths:
                return dict(r)
        return None

    @staticmethod
    def is_protected_operation(resource_type: str, resource_identifier: str) -> bool:
        """Prüft, ob eine Operation auf einer Ressource blockiert werden muss."""
        if resource_type == "port":
            try:
                owner = OwnershipMapper.get_port_owner(int(resource_identifier))
                if owner and owner.get("protection_mode") == "protected":
                    return True
            except Exception:
                pass
        elif resource_type == "path":
            owner = OwnershipMapper.get_path_owner(resource_identifier)
            if owner and owner.get("protection_mode") == "protected":
                return True
        return False
