"""ERROR-PANEL — Config parser service.

Multi-format VPN configuration parser supporting:
  - WireGuard [Peer] blocks
  - OpenVPN "remote" directives
  - Base64 subscription blobs (vmess://, vless://, ss://, trojan:// URIs)
  - Direct URI lines (vmess://, vless://, ss://, trojan://)

Never raises on malformed input; returns whatever could be parsed,
possibly an empty list.
"""

import base64
import hashlib
import json
import re
from typing import Any, Optional
from urllib.parse import unquote, urlparse, parse_qs

# ── Country name/code mapping (25+ common countries) ─────────────────────────

COUNTRY_MAP: dict[str, str] = {
    # Full names → ISO 3166-1 alpha-2
    "germany": "DE", "deutschland": "DE",
    "iran": "IR",
    "netherlands": "NL", "holland": "NL",
    "united states": "US", "usa": "US", "america": "US",
    "united kingdom": "GB", "britain": "GB", "england": "GB", "uk": "GB",
    "france": "FR",
    "canada": "CA",
    "sweden": "SE",
    "finland": "FI",
    "austria": "AT",
    "switzerland": "CH",
    "turkey": "TR", "turkiye": "TR",
    "united arab emirates": "AE", "uae": "AE",
    "japan": "JP",
    "singapore": "SG",
    "australia": "AU",
    "brazil": "BR",
    "india": "IN",
    "russia": "RU",
    "south korea": "KR", "korea": "KR",
    "china": "CN",
    "poland": "PL",
    "romania": "RO",
    "ukraine": "UA",
    "spain": "ES",
    "italy": "IT",
    "denmark": "DK",
    "norway": "NO",
    "belgium": "BE",
    "ireland": "IE",
    "portugal": "PT",
    "czech republic": "CZ", "czechia": "CZ",
    "hungary": "HU",
    "argentina": "AR",
    "mexico": "MX",
    "indonesia": "ID",
    "thailand": "TH",
    "vietnam": "VN",
    "philippines": "PH",
    "malaysia": "MY",
    "taiwan": "TW",
    "hong kong": "HK",
    "israel": "IL",
    "egypt": "EG",
    "south africa": "ZA",
    "nigeria": "NG",
    "kenya": "KE",
}

# Also map 2-letter codes to themselves for pass-through
for _code in list(set(COUNTRY_MAP.values())):
    COUNTRY_MAP[_code.lower()] = _code


def extract_country_code(text: str) -> Optional[str]:
    """Scan text for country names or 2-letter codes; return ISO alpha-2 or None."""
    low = text.lower()
    for name, code in COUNTRY_MAP.items():
        if name in low:
            return code
    # Check for standalone 2-letter country codes (e.g., "DE" in "DE-Frankfurt")
    m = re.search(r'\b([A-Za-z]{2})\b', text)
    if m:
        candidate = m.group(1).upper()
        if candidate.lower() in COUNTRY_MAP:
            return COUNTRY_MAP[candidate.lower()]
    return None


# ── Base64 helpers ───────────────────────────────────────────────────────────

def _b64_decode_safe(s: str) -> str:
    """Decode base64 with padding fix. Returns empty string on failure."""
    try:
        # Fix padding
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return ""


# ── URI Parsers ──────────────────────────────────────────────────────────────

def _parse_vmess(uri: str) -> Optional[dict[str, Any]]:
    """Parse vmess://base64_json URI.

    Fields: ps (name), add (host), port, id (uuid), net, type.
    Protocol: "vmess". UUID stored in fingerprint_data (not secret).
    """
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
        return {
            "name": name,
            "protocol": "vmess",
            "server_host": host or None,
            "server_port": port or None,
            "country_code": extract_country_code(name),
            "fingerprint_data": {"uuid": uuid_, "net": net} if uuid_ else {},
            "notes": f"net={net}",
        }
    except Exception:
        return None


def _parse_vless(uri: str) -> Optional[dict[str, Any]]:
    """Parse vless://uuid@host:port?query URI.

    Protocol: "vless". UUID stored in fingerprint_data.
    """
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
        # host:port
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0
        # Parse query for type/security
        params = parse_qs(query_str)
        net_type = params.get("type", ["tcp"])[0]
        if not name:
            name = f"vless-{host}"
        return {
            "name": name,
            "protocol": "vless",
            "server_host": host or None,
            "server_port": port or None,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {"uuid": uuid_} if uuid_ else {},
            "notes": f"net={net_type}",
        }
    except Exception:
        return None


def _parse_ss(uri: str) -> Optional[dict[str, Any]]:
    """Parse ss:// SIP002 URI (both variants).

    Variant 1: ss://base64(method:password)@host:port#name
    Variant 2: ss://base64(method:password@host:port)#name
    Protocol: "shadowsocks". Password is NOT stored.
    """
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
            # Decode userinfo to get method (we don't store the password)
            _userinfo = _b64_decode_safe(userinfo_enc)
        else:
            # Variant 2: entire thing is base64
            decoded = _b64_decode_safe(rest)
            if "@" not in decoded:
                return None
            _, hostport = decoded.split("@", 1)

        # host:port
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0

        if not name:
            name = f"ss-{host}"
        return {
            "name": name,
            "protocol": "shadowsocks",
            "server_host": host or None,
            "server_port": port or None,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {},
            "notes": None,
        }
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[dict[str, Any]]:
    """Parse trojan://uuid@host:port URI.

    Protocol: "trojan". UUID stored in fingerprint_data.
    """
    try:
        rest = uri[len("trojan://"):]
        # Fragment for name
        name = None
        if "#" in rest:
            rest, frag = rest.rsplit("#", 1)
            name = unquote(frag)
        # Strip query
        if "?" in rest:
            rest, _ = rest.split("?", 1)
        # uuid@host:port
        if "@" not in rest:
            return None
        uuid_, hostport = rest.split("@", 1)
        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 0
        else:
            host = hostport
            port = 0
        if not name:
            name = f"trojan-{host}"
        return {
            "name": name,
            "protocol": "trojan",
            "server_host": host or None,
            "server_port": port or None,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {"uuid": uuid_} if uuid_ else {},
            "notes": None,
        }
    except Exception:
        return None


# ── URI dispatch ─────────────────────────────────────────────────────────────

_URI_PARSERS = {
    "vmess://": _parse_vmess,
    "vless://": _parse_vless,
    "ss://": _parse_ss,
    "trojan://": _parse_trojan,
}


def _parse_uri_line(line: str) -> Optional[dict[str, Any]]:
    """Try to parse a single URI line with the appropriate parser."""
    for prefix, parser in _URI_PARSERS.items():
        if line.strip().startswith(prefix):
            result = parser(line.strip())
            return result
    return None


# ── WireGuard parser ────────────────────────────────────────────────────────

def _parse_wireguard(content: str) -> list[dict[str, Any]]:
    """Parse WireGuard config with [Peer] blocks.

    One profile per [Peer]. Extracts:
      - Endpoint host:port
      - PublicKey (stored in fingerprint_data, NOT as secret)
      - AllowedIPs
      - Name from preceding comment line or "WireGuard-<host>"
    """
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
            "notes": "; ".join(notes_parts) if notes_parts else None,
        })

    return profiles


# ── OpenVPN parser ──────────────────────────────────────────────────────────

def _parse_openvpn(content: str) -> list[dict[str, Any]]:
    """Parse OpenVPN config with "remote" directives.

    One profile per "remote" line. Extracts host, port, proto.
    Name from preceding comment or "OpenVPN-<host>".
    """
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

        profiles.append({
            "name": name,
            "protocol": "openvpn",
            "server_host": host,
            "server_port": port,
            "country_code": extract_country_code(name or ""),
            "fingerprint_data": {},
            "notes": f"proto={proto}",
        })

    return profiles


# ── Base64 subscription blob detection ──────────────────────────────────────

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


# ── Main entry point ────────────────────────────────────────────────────────

def parse_config(content: str, source_type: str) -> list[dict[str, Any]]:
    """Parse VPN configuration text into a list of profile dicts.

    Args:
        content:      Raw text fetched from the source URL.
        source_type:  One of "github", "url", "manual".

    Returns:
        List of dicts with keys:
            name, protocol, server_host, server_port, country_code,
            fingerprint_data, notes

    Never raises on malformed input; returns whatever could be parsed,
    possibly an empty list.
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

        # ── Step 2: Parse URI lines (vmess, vless, ss, trojan) ───────────
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

        # ── Step 4: OpenVPN "remote" directives ──────────────────────────
        if re.search(r'^\s*remote\s+', content, re.MULTILINE):
            ovpn_profiles = _parse_openvpn(content)
            results.extend(ovpn_profiles)

    except Exception:
        # Never raise — return whatever was collected so far
        pass

    return results
