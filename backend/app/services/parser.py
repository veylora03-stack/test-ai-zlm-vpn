"""ERROR-PANEL — Enhanced Config Parser Service.

Multi-format VPN configuration parser supporting:
  - WireGuard [Peer] blocks
  - OpenVPN "remote" directives
  - Base64 subscription blobs (vmess://, vless://, ss://, trojan://, hysteria2://, tuic:// URIs)
  - Direct URI lines including Reality protocol
  
Features:
  - Advanced parameter extraction (sni, alpn, flow, publicKey, type, security)
  - IPv6 support
  - Robust validation
  - Reduced false-positives with optimized regex patterns
  
Never raises on malformed input; returns whatever could be parsed.
"""

import base64
import hashlib
import ipaddress
import json
import re
from typing import Any, Optional
from urllib.parse import unquote, urlparse, parse_qs

from backend.core.logger import logger

# ── Country name/code mapping (60+ countries) ─────────────────────────

COUNTRY_MAP: dict[str, str] = {
    "germany": "DE", "deutschland": "DE", "frankfurt": "DE", "berlin": "DE",
    "iran": "IR", "tehran": "IR",
    "netherlands": "NL", "holland": "NL", "amsterdam": "NL",
    "united states": "US", "usa": "US", "america": "US", "new york": "US", "los angeles": "US",
    "united kingdom": "GB", "britain": "GB", "england": "GB", "uk": "GB", "london": "GB",
    "france": "FR", "paris": "FR",
    "canada": "CA", "toronto": "CA", "vancouver": "CA",
    "sweden": "SE", "stockholm": "SE",
    "finland": "FI", "helsinki": "FI",
    "austria": "AT", "vienna": "AT",
    "switzerland": "CH", "zurich": "CH",
    "turkey": "TR", "turkiye": "TR", "istanbul": "TR",
    "united arab emirates": "AE", "uae": "AE", "dubai": "AE",
    "japan": "JP", "tokyo": "JP", "osaka": "JP",
    "singapore": "SG",
    "australia": "AU", "sydney": "AU", "melbourne": "AU",
    "brazil": "BR", "sao paulo": "BR",
    "india": "IN", "mumbai": "IN", "delhi": "IN",
    "russia": "RU", "moscow": "RU",
    "south korea": "KR", "korea": "KR", "seoul": "KR",
    "china": "CN", "beijing": "CN", "shanghai": "CN", "hong kong": "HK",
    "poland": "PL", "warsaw": "PL",
    "romania": "RO", "bucharest": "RO",
    "ukraine": "UA", "kyiv": "UA",
    "spain": "ES", "madrid": "ES", "barcelona": "ES",
    "italy": "IT", "rome": "IT", "milan": "IT",
    "denmark": "DK", "copenhagen": "DK",
    "norway": "NO", "oslo": "NO",
    "belgium": "BE", "brussels": "BE",
    "ireland": "IE", "dublin": "IE",
    "portugal": "PT", "lisbon": "PT",
    "czech republic": "CZ", "czechia": "CZ", "prague": "CZ",
    "hungary": "HU", "budapest": "HU",
    "argentina": "AR", "buenos aires": "AR",
    "mexico": "MX", "mexico city": "MX",
    "indonesia": "ID", "jakarta": "ID",
    "thailand": "TH", "bangkok": "TH",
    "vietnam": "VN", "ho chi minh": "VN", "hanoi": "VN",
    "philippines": "PH", "manila": "PH",
    "malaysia": "MY", "kuala lumpur": "MY",
    "taiwan": "TW", "taipei": "TW",
    "israel": "IL", "tel aviv": "IL",
    "egypt": "EG", "cairo": "EG",
    "south africa": "ZA", "johannesburg": "ZA",
    "nigeria": "NG", "lagos": "NG",
    "kenya": "KE", "nairobi": "KE",
    "greece": "GR", "athens": "GR",
    "bulgaria": "BG", "sofia": "BG",
    "croatia": "HR", "zagreb": "HR",
    "serbia": "RS", "belgrade": "RS",
    "slovakia": "SK", "bratislava": "SK",
    "slovenia": "SI", "ljubljana": "SI",
    "estonia": "EE", "tallinn": "EE",
    "latvia": "LV", "riga": "LV",
    "lithuania": "LT", "vilnius": "LT",
    "cyprus": "CY", "nicosia": "CY",
    "malta": "MT", "valletta": "MT",
    "iceland": "IS", "reykjavik": "IS",
    "luxembourg": "LU",
    "new zealand": "NZ", "auckland": "NZ",
    "chile": "CL", "santiago": "CL",
    "colombia": "CO", "bogota": "CO",
    "peru": "PE", "lima": "PE",
    "pakistan": "PK", "karachi": "PK",
    "bangladesh": "BD", "dhaka": "BD",
    "sri lanka": "LK", "colombo": "LK",
    "nepal": "NP", "kathmandu": "NP",
    "kazakhstan": "KZ", "almaty": "KZ",
    "uzbekistan": "UZ", "tashkent": "UZ",
    "georgia": "GE", "tbilisi": "GE",
    "armenia": "AM", "yerevan": "AM",
    "azerbaijan": "AZ", "baku": "AZ",
}

def extract_country_code(text: str) -> Optional[str]:
    if not text:
        return None

    # مجموعه کدهای ISO دوحرفی معتبر
    ISO_CODES = {
        "DE", "US", "GB", "FR", "CA", "SE", "FI", "AT",
        "CH", "TR", "AE", "JP", "SG", "AU", "BR", "IN",
        "RU", "KR", "CN", "HK", "PL", "RO", "UA", "ES",
        "IT", "DK", "NO", "BE", "IE", "PT", "CZ", "HU",
        "AR", "MX", "ID", "TH", "VN", "PH", "MY", "TW",
        "IL", "EG", "ZA", "NG", "KE", "GR", "BG", "HR",
        "RS", "SK", "SI", "EE", "LV", "LT", "CY", "MT",
        "IS", "LU", "NZ", "CL", "CO", "PE", "PK", "BD",
        "LK", "NP", "KZ", "UZ", "GE", "AM", "AZ",
    }

    text_lower = text.lower()

    # مرحله 1: بررسی نام‌های کامل کشور
    for name, code in COUNTRY_MAP.items():
        if name in text_lower:
            return code

    # مرحله 2: بررسی کدهای دوحرفی
    m = re.search(r'\b([A-Za-z]{2})\b', text)
    if m:
        candidate = m.group(1).upper()
        if candidate in ISO_CODES:
            return candidate

    return None

# ── Validation helpers ─────────────────────────────────────────────────

def _is_valid_host(host: str) -> bool:
    """Validate hostname or IP address."""
    if not host:
        return False
    
    # Check for valid IP (IPv4 or IPv6)
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    
    # Check for valid hostname (RFC 1123)
    if len(host) > 253:
        return False
    
    hostname_regex = re.compile(
        r'^(?=.{1,253}$)'
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,63}$'
    )
    return bool(hostname_regex.match(host))

def _is_valid_port(port: Any) -> bool:
    """Validate port number (1-65535)."""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False

# ── Base64 helpers ─────────────────────────────────────────────────────

def _b64_decode_safe(s: str) -> str:
    """Decode base64 with padding fix. Returns empty string on failure."""
    try:
        # Fix padding
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        # Handle URL-safe base64
        padded = padded.replace('-', '+').replace('_', '/')
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return ""

# ── URI Parsers ────────────────────────────────────────────────────────

def _parse_vmess(uri: str) -> Optional[dict[str, Any]]:
    """Parse vmess://base64_json URI with advanced parameter extraction."""
    try:
        encoded = uri[len("vmess://"):]
        decoded = _b64_decode_safe(encoded)
        if not decoded:
            return None
        
        obj = json.loads(decoded)
        
        name = obj.get("ps", "") or "vmess-unknown"
        host = obj.get("add", "")
        port_str = obj.get("port", "0")
        port = int(port_str) if str(port_str).isdigit() else 0
        uuid_ = obj.get("id", "")
        net = obj.get("net", "tcp")
        tls = obj.get("tls", "")
        sni = obj.get("sni", "") or obj.get("host", "")
        alpn = obj.get("alpn", "")
        
        # Validation
        if not host or not _is_valid_port(port):
            logger.warning(f"Invalid vmess config: host={host}, port={port}")
            return None
        
        return {
            "name": name,
            "protocol": "vmess",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name),
            "fingerprint_data": {"uuid": uuid_, "net": net} if uuid_ else {},
            "advanced_params": {
                "net": net,
                "tls": tls,
                "sni": sni,
                "alpn": alpn,
            },
            "notes": f"net={net}, tls={tls}",
        }
    except Exception as e:
        logger.debug(f"Failed to parse vmess URI: {e}")
        return None

def _parse_vless(uri: str) -> Optional[dict[str, Any]]:
    """Parse vless://uuid@host:port?query URI with Reality support."""
    try:
        rest = uri[len("vless://"):]
        
        # Split fragment for name
        name = None
        if "#" in rest:
            rest, frag = rest.rsplit("#", 1)
            name = unquote(frag)
        
        # Split query
        query_str = ""
        if "?" in rest:
            rest, query_str = rest.split("?", 1)
        
        # uuid@host:port
        if "@" not in rest:
            return None
        
        uuid_, hostport = rest.split("@", 1)
        
        # Handle IPv6: [2001:db8::1]:443
        if hostport.startswith("["):
            bracket_end = hostport.find("]")
            if bracket_end != -1:
                host = hostport[1:bracket_end]
                rest_port = hostport[bracket_end + 1:]
                if rest_port.startswith(":"):
                    port = int(rest_port[1:]) if rest_port[1:].isdigit() else 0
                else:
                    port = 0
            else:
                return None
        elif ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0
        
        # Parse query for advanced parameters
        params = parse_qs(query_str)
        
        net_type = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        sni = params.get("sni", [""])[0]
        alpn = params.get("alpn", [""])[0]
        flow = params.get("flow", [""])[0]
        public_key = params.get("pbk", [""])[0]  # Reality publicKey
        short_id = params.get("sid", [""])[0]  # Reality shortId
        fp = params.get("fp", [""])[0]  # TLS fingerprint
        
        # Validation
        if not host or not _is_valid_port(port):
            logger.warning(f"Invalid vless config: host={host}, port={port}")
            return None
        
        if not name:
            name = f"vless-{host}"
        
        # Build fingerprint data
        fp_data = {}
        if uuid_:
            fp_data["uuid"] = uuid_
        if public_key:  # For Reality
            fp_data["public_key"] = public_key
        
        return {
            "name": name,
            "protocol": "vless",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": fp_data,
            "advanced_params": {
                "type": net_type,
                "security": security,
                "sni": sni,
                "alpn": alpn,
                "flow": flow,
                "publicKey": public_key,
                "shortId": short_id,
                "fingerprint": fp,
            },
            "notes": f"type={net_type}, security={security}",
        }
    except Exception as e:
        logger.debug(f"Failed to parse vless URI: {e}")
        return None

def _parse_ss(uri: str) -> Optional[dict[str, Any]]:
    """Parse ss:// SIP002 URI (both variants) with improved decoding."""
    try:
        rest = uri[len("ss://"):]
        
        # Extract fragment for name
        name = None
        if "#" in rest:
            rest, frag = rest.rsplit("#", 1)
            name = unquote(frag)

        # Variant 1: userinfo@host:port
        if "@" in rest:
            userinfo_enc, hostport = rest.split("@", 1)
            _userinfo = _b64_decode_safe(userinfo_enc)
        else:
            # Variant 2: entire thing is base64
            decoded = _b64_decode_safe(rest)
            if "@" not in decoded:
                return None
            _, hostport = decoded.split("@", 1)

        # Handle IPv6
        if hostport.startswith("["):
            bracket_end = hostport.find("]")
            if bracket_end != -1:
                host = hostport[1:bracket_end]
                rest_port = hostport[bracket_end + 1:]
                if rest_port.startswith(":"):
                    port = int(rest_port[1:]) if rest_port[1:].isdigit() else 0
                else:
                    port = 0
            else:
                return None
        elif ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0

        # Validation
        if not host or not _is_valid_port(port):
            logger.warning(f"Invalid ss config: host={host}, port={port}")
            return None

        if not name:
            name = f"ss-{host}"
        
        return {
            "name": name,
            "protocol": "shadowsocks",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {},
            "advanced_params": {},
            "notes": None,
        }
    except Exception as e:
        logger.debug(f"Failed to parse ss URI: {e}")
        return None

def _parse_trojan(uri: str) -> Optional[dict[str, Any]]:
    """Parse trojan://uuid@host:port URI with advanced parameters."""
    try:
        rest = uri[len("trojan://"):]
        
        # Fragment for name
        name = None
        if "#" in rest:
            rest, frag = rest.rsplit("#", 1)
            name = unquote(frag)
        
        # Strip query
        query_str = ""
        if "?" in rest:
            rest, query_str = rest.split("?", 1)
        
        # uuid@host:port
        if "@" not in rest:
            return None
        
        uuid_, hostport = rest.split("@", 1)
        
        # Handle IPv6
        if hostport.startswith("["):
            bracket_end = hostport.find("]")
            if bracket_end != -1:
                host = hostport[1:bracket_end]
                rest_port = hostport[bracket_end + 1:]
                if rest_port.startswith(":"):
                    port = int(rest_port[1:]) if rest_port[1:].isdigit() else 0
                else:
                    port = 0
            else:
                return None
        elif ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0
        
        # Parse query
        params = parse_qs(query_str)
        sni = params.get("sni", [""])[0]
        alpn = params.get("alpn", [""])[0]
        
        # Validation
        if not host or not _is_valid_port(port):
            logger.warning(f"Invalid trojan config: host={host}, port={port}")
            return None
        
        if not name:
            name = f"trojan-{host}"
        
        return {
            "name": name,
            "protocol": "trojan",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {"uuid": uuid_} if uuid_ else {},
            "advanced_params": {
                "sni": sni,
                "alpn": alpn,
            },
            "notes": None,
        }
    except Exception as e:
        logger.debug(f"Failed to parse trojan URI: {e}")
        return None

def _parse_hysteria2(uri: str) -> Optional[dict[str, Any]]:
    """Parse hysteria2://uuid@host:port?query URI."""
    try:
        rest = uri[len("hysteria2://"):]
        
        # Fragment for name
        name = None
        if "#" in rest:
            rest, frag = rest.rsplit("#", 1)
            name = unquote(frag)
        
        # Strip query
        query_str = ""
        if "?" in rest:
            rest, query_str = rest.split("?", 1)
        
        # uuid@host:port or just host:port
        if "@" in rest:
            password, hostport = rest.split("@", 1)
        else:
            password = ""
            hostport = rest
        
        # Handle IPv6
        if hostport.startswith("["):
            bracket_end = hostport.find("]")
            if bracket_end != -1:
                host = hostport[1:bracket_end]
                rest_port = hostport[bracket_end + 1:]
                if rest_port.startswith(":"):
                    port = int(rest_port[1:]) if rest_port[1:].isdigit() else 0
                else:
                    port = 0
            else:
                return None
        elif ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0
        
        # Parse query
        params = parse_qs(query_str)
        sni = params.get("sni", [""])[0]
        insecure = params.get("insecure", ["0"])[0]
        obfs = params.get("obfs", [""])[0]
        obfs_password = params.get("obfs-password", [""])[0]
        
        # Validation
        if not host or not _is_valid_port(port):
            logger.warning(f"Invalid hysteria2 config: host={host}, port={port}")
            return None
        
        if not name:
            name = f"hysteria2-{host}"
        
        return {
            "name": name,
            "protocol": "hysteria2",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {"password": password} if password else {},
            "advanced_params": {
                "sni": sni,
                "insecure": insecure,
                "obfs": obfs,
                "obfs-password": obfs_password,
            },
            "notes": f"obfs={obfs}" if obfs else None,
        }
    except Exception as e:
        logger.debug(f"Failed to parse hysteria2 URI: {e}")
        return None

def _parse_tuic(uri: str) -> Optional[dict[str, Any]]:
    """Parse tuic://uuid:password@host:port?query URI."""
    try:
        rest = uri[len("tuic://"):]
        
        # Fragment for name
        name = None
        if "#" in rest:
            rest, frag = rest.rsplit("#", 1)
            name = unquote(frag)
        
        # Strip query
        query_str = ""
        if "?" in rest:
            rest, query_str = rest.split("?", 1)
        
        # uuid:password@host:port
        if "@" not in rest:
            return None
        
        userinfo, hostport = rest.split("@", 1)
        
        # Parse uuid:password
        if ":" in userinfo:
            uuid_, password = userinfo.split(":", 1)
        else:
            uuid_ = userinfo
            password = ""
        
        # Handle IPv6
        if hostport.startswith("["):
            bracket_end = hostport.find("]")
            if bracket_end != -1:
                host = hostport[1:bracket_end]
                rest_port = hostport[bracket_end + 1:]
                if rest_port.startswith(":"):
                    port = int(rest_port[1:]) if rest_port[1:].isdigit() else 0
                else:
                    port = 0
            else:
                return None
        elif ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0
        
        # Parse query
        params = parse_qs(query_str)
        sni = params.get("sni", [""])[0]
        alpn = params.get("alpn", [""])[0]
        congestion_control = params.get("congestion_control", [""])[0]
        
        # Validation
        if not host or not _is_valid_port(port):
            logger.warning(f"Invalid tuic config: host={host}, port={port}")
            return None
        
        if not name:
            name = f"tuic-{host}"
        
        return {
            "name": name,
            "protocol": "tuic",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {"uuid": uuid_} if uuid_ else {},
            "advanced_params": {
                "sni": sni,
                "alpn": alpn,
                "congestion_control": congestion_control,
            },
            "notes": f"congestion={congestion_control}" if congestion_control else None,
        }
    except Exception as e:
        logger.debug(f"Failed to parse tuic URI: {e}")
        return None

# ── URI dispatch ───────────────────────────────────────────────────────

_URI_PARSERS = {
    "vmess://": _parse_vmess,
    "vless://": _parse_vless,
    "ss://": _parse_ss,
    "trojan://": _parse_trojan,
    "hysteria2://": _parse_hysteria2,
    "tuic://": _parse_tuic,
}

def _parse_uri_line(line: str) -> Optional[dict[str, Any]]:
    """Try to parse a single URI line with the appropriate parser."""
    line = line.strip()
    for prefix, parser in _URI_PARSERS.items():
        if line.startswith(prefix):
            result = parser(line)
            return result
    return None

# ── WireGuard parser ──────────────────────────────────────────────────

def _parse_wireguard(content: str) -> list[dict[str, Any]]:
    """Parse WireGuard config with [Peer] blocks and IPv6 support."""
    profiles: list[dict[str, Any]] = []
    lines = content.splitlines()

    # Find all [Peer] sections
    peer_starts: list[int] = []
    for i, line in enumerate(lines):
        if line.strip().lower() == "[peer]":
            peer_starts.append(i)

    if not peer_starts:
        return []

    for idx, start in enumerate(peer_starts):
        end = peer_starts[idx + 1] if idx + 1 < len(peer_starts) else len(lines)
        section = lines[start + 1 : end]

        endpoint_host = None
        endpoint_port = None
        public_key = None
        allowed_ips = None

        for sline in section:
            stripped = sline.strip()
            if stripped.startswith("#") or stripped.startswith(";"):
                continue
            if "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip().lower()
            value = value.strip()

            if key == "endpoint":
                # Parse host:port (may be [ipv6]:port)
                if value.startswith("["):
                    # IPv6: [::1]:port
                    bracket_end = value.find("]")
                    if bracket_end != -1:
                        endpoint_host = value[1:bracket_end]
                        rest = value[bracket_end + 1:]
                        if rest.startswith(":") and rest[1:].isdigit():
                            endpoint_port = int(rest[1:])
                else:
                    if ":" in value:
                        h, p = value.rsplit(":", 1)
                        endpoint_host = h
                        endpoint_port = int(p) if p.isdigit() else None
                    else:
                        endpoint_host = value
            elif key == "publickey":
                public_key = value
            elif key == "allowedips":
                allowed_ips = value

        # Get name from preceding comment line
        name = None
        for j in range(start - 1, -1, -1):
            prev = lines[j].strip()
            if prev.startswith("#") or prev.startswith(";"):
                name = prev.lstrip("#; ").strip()
                break
            elif prev == "" or prev.startswith("["):
                break

        if not name:
            name = f"WireGuard-{endpoint_host or 'unknown'}"

        # Validation
        if endpoint_host and not _is_valid_host(endpoint_host):
            logger.warning(f"Invalid WireGuard host: {endpoint_host}")
            continue
        
        if endpoint_port and not _is_valid_port(endpoint_port):
            logger.warning(f"Invalid WireGuard port: {endpoint_port}")
            continue

        fp_data = {}
        if public_key:
            fp_data["public_key"] = public_key

        notes_parts = []
        if allowed_ips:
            notes_parts.append(f"AllowedIPs={allowed_ips}")

        profiles.append({
            "name": name,
            "protocol": "wireguard",
            "server_host": endpoint_host,
            "server_port": endpoint_port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": fp_data,
            "advanced_params": {},
            "notes": "; ".join(notes_parts) if notes_parts else None,
        })

    return profiles

# ── OpenVPN parser ────────────────────────────────────────────────────

def _parse_openvpn(content: str) -> list[dict[str, Any]]:
    """Parse OpenVPN config with 'remote' directives."""
    profiles: list[dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("remote "):
            continue

        parts = stripped.split()
        if len(parts) < 2:
            continue

        host = parts[1]
        port = None
        proto = "udp"

        if len(parts) >= 3:
            try:
                port = int(parts[2])
            except ValueError:
                proto = parts[2]
        if len(parts) >= 4:
            proto = parts[3]

        # Get name from preceding comment
        name = None
        for j in range(i - 1, -1, -1):
            prev = lines[j].strip()
            if prev.startswith("#") or prev.startswith(";"):
                name = prev.lstrip("#; ").strip()
                break
            elif prev == "" or not prev.startswith("#"):
                break

        if not name:
            name = f"OpenVPN-{host}"

        # Validation
        if not _is_valid_host(host):
            logger.warning(f"Invalid OpenVPN host: {host}")
            continue
        
        if port and not _is_valid_port(port):
            logger.warning(f"Invalid OpenVPN port: {port}")
            continue

        profiles.append({
            "name": name,
            "protocol": "openvpn",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {},
            "advanced_params": {"proto": proto},
            "notes": f"proto={proto}",
        })

    return profiles

# ── Base64 subscription blob detection ────────────────────────────────

def _is_base64_blob(content: str) -> bool:
    """Heuristic: content is a single long base64 line or multiple lines
    that decode to URI-prefixed text."""
    lines = [l.strip() for l in content.strip().splitlines() if l.strip()]
    if not lines:
        return False

    # If any line starts with a URI scheme, it's already plain text
    for line in lines:
        for prefix in _URI_PARSERS:
            if line.startswith(prefix):
                return False

    # If any line contains [Peer] or remote, it's WG/OVPN
    if "[Peer]" in content or "[peer]" in content:
        return False
    if re.search(r'^\s*remote\s+', content, re.MULTILINE):
        return False

    # Try decoding the first non-empty line
    first = lines[0]
    decoded = _b64_decode_safe(first)
    if not decoded:
        return False

    # Check if decoded text contains URI prefixes
    for prefix in _URI_PARSERS:
        if prefix in decoded:
            return True

    return False

def _decode_base64_blob(content: str) -> str:
    """Decode a base64 subscription blob into plain text."""
    # Try decoding the entire content as one blob
    stripped = content.strip()
    # Remove whitespace (some subscription files have line breaks inside b64)
    compact = re.sub(r'\s+', '', stripped)
    decoded = _b64_decode_safe(compact)
    if decoded:
        return decoded

    # Try line-by-line
    lines = stripped.splitlines()
    decoded_parts = []
    for line in lines:
        d = _b64_decode_safe(line.strip())
        if d:
            decoded_parts.append(d)
    return "\n".join(decoded_parts)

# ── Main entry point ──────────────────────────────────────────────────

def parse_config(content: str, source_type: str) -> list[dict[str, Any]]:
    """Parse VPN configuration text into a list of profile dicts.

    Args:
        content:      Raw text fetched from the source URL.
        source_type:  One of "github", "url", "manual".

    Returns:
        List of dicts with keys:
            name, protocol, server_host, server_port, country_code,
            fingerprint_data, advanced_params, notes

    Never raises on malformed input; returns whatever could be parsed.
    """
    if not content or not content.strip():
        return []

    results: list[dict[str, Any]] = []

    try:
        # ── Step 1: Check for base64 subscription blob ────────────────────
        if _is_base64_blob(content):
            decoded = _decode_base64_blob(content)
            if decoded:
                content = decoded
                logger.info(f"Decoded base64 subscription blob ({len(decoded)} chars)")

        # ── Step 2: Parse URI lines (vmess, vless, ss, trojan, hysteria2, tuic) ─
        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parsed = _parse_uri_line(line)
            if parsed:
                results.append(parsed)

        # ── Step 3: WireGuard [Peer] blocks ──────────────────────────────
        if "[Peer]" in content or "[peer]" in content:
            wg_profiles = _parse_wireguard(content)
            results.extend(wg_profiles)

        # ── Step 4: OpenVPN 'remote' directives ──────────────────────────
        if re.search(r'^\s*remote\s+', content, re.MULTILINE):
            ovpn_profiles = _parse_openvpn(content)
            results.extend(ovpn_profiles)

        logger.info(f"Parsed {len(results)} profiles from {source_type} source")

    except Exception as e:
        logger.error(f"Error parsing config: {e}")

    return results
