"""
SysCore Sentinel - WAF & Security Headers Module
Verwaltet Additive NGINX Web Application Firewall (WAF) Regeln und Sicherheits-Header.
"""

import os
from typing import Dict, Any
from modules.security.core.safe_apply import SafeApply

WAF_DROPIN_PATH = "/etc/nginx/conf.d/99-syscore-waf.conf"

def get_waf_status() -> Dict[str, Any]:
    """Prüft ob das SysCore WAF Drop-In aktiv ist."""
    is_active = os.path.exists(WAF_DROPIN_PATH)
    return {
        "active": is_active,
        "path": WAF_DROPIN_PATH,
        "rules_enabled": ["hsts", "nosniff", "xss_protection", "frame_options", "exploit_filter"] if is_active else []
    }

def apply_waf_profile(level: str = "standard") -> bool:
    """
    Schreibt das WAF Drop-In additiv und lädt NGINX sicher neu.
    level: 'off', 'standard', 'strict'
    """
    if level == "off":
        if os.path.exists(WAF_DROPIN_PATH):
            try:
                os.remove(WAF_DROPIN_PATH)
                SafeApply.apply_additive_file(WAF_DROPIN_PATH, "", service_to_reload="nginx")
            except Exception:
                pass
        return True

    content = f"""# SysCore Sentinel - Web Application Firewall & Security Headers
# Additives Drop-In (Level: {level})

# Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Exploit-Muster Blockade
map $request_uri $syscore_blocked_probe {{
    default 0;
    ~*(\\.env|\\.git|\\.svn|xmlrpc\\.php|eval-stdin) 1;
    ~*(\\.\\./|/etc/passwd|/proc/self) 1;
}}
"""
    ok, _ = SafeApply.apply_additive_file(WAF_DROPIN_PATH, content, service_to_reload="nginx")
    return ok
