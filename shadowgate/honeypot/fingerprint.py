import json
import logging
import urllib.request
from typing import Dict, Any, Optional

class Fingerprinter:
    def __init__(self):
        self._ip_cache = {}
        self._history = {}

    def get_fingerprint(self, ip: str, headers: dict = None, user_agent: str = None) -> dict:
        import time
        headers = headers or {}
        ua = user_agent or headers.get("User-Agent", "")
        
        geo = self._lookup_geoip(ip)
        ua_info = self._parse_user_agent(ua)
        scanner = self._check_known_scanner(headers, ua)
        
        now = time.time()
        if ip not in self._history:
            self._history[ip] = {"first_seen": now, "last_seen": now, "total_events": 0}
            
        self._history[ip]["last_seen"] = now
        self._history[ip]["total_events"] += 1
        
        return {
            "ip": ip,
            "geo": geo,
            "user_agent": ua_info,
            "known_scanner": scanner,
            "first_seen": self._history[ip]["first_seen"],
            "last_seen": self._history[ip]["last_seen"],
            "total_events": self._history[ip]["total_events"]
        }

    def _lookup_geoip(self, ip: str) -> dict:
        if ip in self._ip_cache:
            return self._ip_cache[ip]
            
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
             return {"country": "Local", "city": "Local", "org": "Local"}

        try:
            req = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={"User-Agent": "ShadowGate-Honeypot"})
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                if data.get("status") == "success":
                    geo = {"country": data.get("country", ""), "city": data.get("city", ""), "org": data.get("org", "")}
                    self._ip_cache[ip] = geo
                    return geo
        except Exception:
            pass
        return {"country": "Unknown", "city": "Unknown", "org": "Unknown"}

    def _parse_user_agent(self, ua: str) -> dict:
        ua_lower = ua.lower()
        return {
            "browser": "Firefox" if "firefox" in ua_lower else "Chrome" if "chrome" in ua_lower else "Safari" if "safari" in ua_lower else "Unknown",
            "os": "Windows" if "windows" in ua_lower else "Linux" if "linux" in ua_lower else "macOS" if "mac os" in ua_lower else "Unknown",
            "raw": ua
        }

    def _check_known_scanner(self, headers: dict, ua: str) -> Optional[str]:
        ua_lower = ua.lower()
        scanners = {"nmap": "Nmap", "masscan": "Masscan", "zmap": "ZMap", "curl": "curl", "wget": "wget"}
        for key, name in scanners.items():
            if key in ua_lower:
                return name
        return None
