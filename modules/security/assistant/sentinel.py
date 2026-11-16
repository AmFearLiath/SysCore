"""
SysCore Sentinel - Assistant Coordinator
Koordiniert Chat-Sitzungen mit dem Sentinel-Assistenten.
Erzwingt strikte Sicherheitsgrenzen (SEC-006):
- Die KI besitzt KEINE Root- oder Ausführungsrechte.
- Aktionen werden ausschließlich als Change Plans (JSON) formuliert.
- Ausführung erfolgt ausnahmslos erst nach expliziter Bestätigung durch den Administrator.
"""

import json
from typing import Dict, Any, List
import db
from modules.security.assistant.providers import OfflineRuleProvider, RemoteOllamaProvider

class SentinelAssistant:
    """Zentraler Sicherheitsberater für Administratoren."""

    @staticmethod
    def ask(session_id: str, message: str, system_context: Dict[str, Any]) -> Dict[str, Any]:
        """Verarbeitet eine Nutzerfrage und gibt eine strukturierte Antwort zurück."""
        # 1. Prüfe ob Remote Provider konfiguriert ist
        ai_provider = "offline"
        row = db.query_db("SELECT value FROM settings WHERE `key` = 'sentinel_ai_provider'", one=True)
        if row and row["value"]:
            ai_provider = row["value"]

        # 2. Antwort generieren
        if ai_provider == "ollama":
            url_row = db.query_db("SELECT value FROM settings WHERE `key` = 'sentinel_ollama_url'", one=True)
            model_row = db.query_db("SELECT value FROM settings WHERE `key` = 'sentinel_ollama_model'", one=True)
            url = url_row["value"] if url_row and url_row["value"] else "http://127.0.0.1:11434"
            model = model_row["value"] if model_row and model_row["value"] else "llama3"
            response = RemoteOllamaProvider.answer(url, model, message, system_context)
        else:
            response = OfflineRuleProvider.answer(message, system_context)

        # 3. In Datenbank speichern
        try:
            db.execute_db("""
                INSERT INTO sentinel_conversations (session_id, role, content, change_plan_json)
                VALUES (?, 'user', ?, NULL)
            """, (session_id, message))

            c_plan_str = json.dumps(response.get("change_plan")) if response.get("change_plan") else None
            db.execute_db("""
                INSERT INTO sentinel_conversations (session_id, role, content, change_plan_json)
                VALUES (?, 'assistant', ?, ?)
            """, (session_id, response.get("text", ""), c_plan_str))
        except Exception:
            pass

        return response

    @staticmethod
    def get_conversation_history(session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Liest den Verlauf einer Sitzung aus."""
        rows = db.query_db("""
            SELECT * FROM sentinel_conversations 
            WHERE session_id = ? 
            ORDER BY id ASC LIMIT ?
        """, (session_id, limit))
        return [dict(r) for r in rows] if rows else []
