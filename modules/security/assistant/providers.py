"""
SysCore Sentinel - AI & Diagnostic Providers
Schnittstellen für den Sentinel Assistant:
1. Rule-Based Offline Provider (standardmäßig aktiv, 100% offline, kein LLM nötig).
2. Remote Ollama Provider (optional, HTTP-Aufruf an entfernte oder lokale GPU-Instanz).
3. Cloud Provider (optional, OpenAI-kompatible API).
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, List

class OfflineRuleProvider:
    """100% Offline Experten-Diagnosesystem ohne externe Abhängigkeiten oder GPU."""

    @staticmethod
    def answer(user_message: str, system_context: Dict[str, Any]) -> Dict[str, Any]:
        msg_lower = user_message.lower().strip()
        score = system_context.get("score", 100)
        deductions = system_context.get("deductions", [])
        ufw = system_context.get("ufw", {})
        ssh = system_context.get("ssh", {})
        ports = system_context.get("ports", {})
        inventory = system_context.get("inventory", [])

        # Intelligente Keyword- und Situationserkennung
        if any(w in msg_lower for w in ("score", "status", "wie sicher", "bewertung", "analyse")):
            reply = f"Dein aktueller Sicherheits-Score liegt bei **{score}%**.\n\n"
            if deductions:
                reply += "Folgende Punkte sollten behoben werden:\n"
                for d in deductions:
                    t = d.get('title') if isinstance(d, dict) else d
                    reply += f"- ⚠️ **{t}**\n"
                reply += "\nEmpfehlung: Du kannst das Profil **'Hardened Production'** aktivieren oder die Punkte einzeln beheben."
            else:
                reply += "✅ Hervorragend! Alle Kern-Sicherheitsmechanismen sind optimal konfiguriert."

            return {"text": reply, "change_plan": None}

        elif any(w in msg_lower for w in ("ssh", "root", "port 22", "key")):
            reply = "### SSH Sicherheitsstatus:\n"
            reply += f"- **Aktueller Port:** {ssh.get('port', 22)}\n"
            reply += f"- **Root-Login erlaubt:** `{ssh.get('permit_root_login')}`\n"
            reply += f"- **Passwort-Login erlaubt:** `{ssh.get('password_auth')}`\n\n"
            if ssh.get('permit_root_login') == 'yes':
                reply += "⚠️ **Dringende Empfehlung:** Direkten Root-Login verbieten und Authentifizierung über SSH-Keys erzwingen."
                change_plan = {
                    "action": "harden_ssh",
                    "files_write": {
                        "/etc/ssh/sshd_config.d/99-syscore.conf": "PermitRootLogin no\nPasswordAuthentication yes\n"
                    }
                }
                return {"text": reply, "change_plan": change_plan}
            return {"text": reply + "\n✅ SSH ist gut konfiguriert.", "change_plan": None}

        elif any(w in msg_lower for w in ("firewall", "ufw", "ports", "offen")):
            reply = "### Firewall & Port Status:\n"
            reply += f"- **UFW Status:** {'Aktiv' if ufw.get('active') else 'INAKTIV'}\n"
            reply += f"- **Aktive Regeln:** {len(ufw.get('rules', []))}\n\n"
            if not ufw.get("active"):
                reply += "⚠️ Die Firewall sollte sofort aktiviert werden, um unerlaubte Zugriffe zu sperren."
                return {"text": reply, "change_plan": {"action": "enable_ufw"}}
            return {"text": reply + "\n✅ Firewall schützt das System.", "change_plan": None}

        elif any(w in msg_lower for w in ("pterodactyl", "wings", "gameserver")):
            reply = "### Pterodactyl Integration & Schutzstatus:\n"
            ptero = next((s for s in inventory if "pterodactyl" in s.get("name", "").lower()), None)
            if ptero:
                reply += f"- **Erkannt:** {ptero.get('name')}\n"
                reply += f"- **Schutzmodus:** `{ptero.get('protection_mode').upper()}` (Geschützt)\n"
                reply += "SysCore Sentinel schützt alle Pterodactyl-Ports (8080, 2022) und verhindert, dass Firewall-Regeln oder Paket-Updates den Spielbetrieb unterbrechen."
            else:
                reply += "Keine Pterodactyl-Instanz auf diesem Server erkannt. Der Server ist bereit für eine saubere Neuinstallation."
            return {"text": reply, "change_plan": None}

        # Allgemeiner Rat
        reply = (
            f"Hallo! Ich bin **Sentinel**, dein Sicherheitsberater.\n\n"
            f"Aktueller Sicherheits-Score: **{score}%**\n"
            f"- Firewall: {'✅ Aktiv' if ufw.get('active') else '❌ Inaktiv'}\n"
            f"- SSH Gehärtet: {'✅ Ja' if ssh.get('is_hardened') else '⚠️ Nein'}\n\n"
            f"Du kannst mich jederzeit fragen:\n"
            f"- *'Wie kann ich die Sicherheit verbessern?'*\n"
            f"- *'Wie ist der SSH Status?'*\n"
            f"- *'Sind Pterodactyl und meine Datenbanken geschützt?'*"
        )
        return {"text": reply, "change_plan": None}


class RemoteOllamaProvider:
    """Sendet Anfragen an einen entfernten oder lokalen Ollama Server."""

    @staticmethod
    def answer(endpoint_url: str, model_name: str, user_message: str, system_context: Dict[str, Any]) -> Dict[str, Any]:
        prompt = f"""Du bist Sentinel, der KI-Sicherheitsassistent des SysCore Server Panels.
Antworte präzise auf Deutsch.

SYSTEM-KONTEXT:
- Sicherheits-Score: {system_context.get('score')}%
- Abzüge: {system_context.get('deductions')}
- Firewall: {system_context.get('ufw')}
- SSH: {system_context.get('ssh')}
- Software: {[s.get('name') for s in system_context.get('inventory', [])]}

BENUTZER-FRAGE: {user_message}
"""
        req_data = json.dumps({
            "model": model_name or "llama3",
            "prompt": prompt,
            "stream": False
        }).encode("utf-8")

        req = urllib.request.Request(
            endpoint_url.rstrip("/") + "/api/generate",
            data=req_data,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                return {"text": res_json.get("response", "Keine Antwort erhalten."), "change_plan": None}
        except Exception as e:
            # Automatischer Fallback auf Rule Provider bei Netzwerkfehler
            fallback = OfflineRuleProvider.answer(user_message, system_context)
            fallback["text"] = f"[Hinweis: Remote AI nicht erreichbar ({e}). Offline Sentinel antwortet:]\n\n" + fallback["text"]
            return fallback
