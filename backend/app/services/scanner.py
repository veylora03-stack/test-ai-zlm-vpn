"""ERROR-PANEL — Enhanced Security Scanner.

Static security scanner with protocol-specific checks and reduced false-positives.
Optimized regex patterns for better accuracy.
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Profile, SecurityScan, Source
from .audit import log_action
from backend.core.logger import logger

# ── Helper functions ───────────────────────────────────────────────────

def _is_private_ip(host: str) -> bool:
    """Check if host is a private/localhost IP address."""
    if not host:
        return False
    
    private_patterns = [
        r'^127\.',           # 127.0.0.0/8 (localhost)
        r'^10\.',            # 10.0.0.0/8
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # 172.16.0.0/12
        r'^192\.168\.',      # 192.168.0.0/16
        r'^169\.254\.',      # 169.254.0.0/16 (link-local)
        r'^::1$',            # ::1 (IPv6 localhost)
        r'^fe80:',           # fe80::/10 (IPv6 link-local)
        r'^fc',              # fc00::/7 (IPv6 unique local)
        r'^fd',              # fd00::/8 (IPv6 unique local)
        r'^localhost$',      # localhost
        r'^0\.0\.0\.0$',     # 0.0.0.0
    ]
    
    host_lower = host.lower()
    for pattern in private_patterns:
        if re.match(pattern, host_lower):
            return True
    
    return False

def _is_suspicious_port(port: Optional[int]) -> bool:
    """Check if port number is suspicious."""
    if port is None:
        return False
    
    suspicious_ports = [
        22,    # SSH (unusual for VPN)
        23,    # Telnet
        25,    # SMTP
        135,   # MS RPC
        139,   # NetBIOS
        445,   # SMB
        1433,  # MSSQL
        1521,  # Oracle
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        27017, # MongoDB
    ]
    
    return port in suspicious_ports

def _read_raw_config(config_ref: Optional[str]) -> str:
    """Read raw config text from file reference."""
    if not config_ref:
        return ""
    
    try:
        from backend.core.paths import RAW_DIR
        file_path = RAW_DIR / config_ref
        if file_path.exists():
            return file_path.read_text(encoding="utf-8")
    except Exception as e:
        logger.debug(f"Failed to read raw config: {e}")
    
    return ""

# ── Static checks ─────────────────────────────────────────────────────

def _check_private_key_exposed(raw_text: str, protocol: str) -> Optional[dict]:
    """Weight 35: Private key exposed in config text."""
    # WireGuard private key
    if protocol == "wireguard":
        if re.search(r'^\s*PrivateKey\s*=\s*[A-Za-z0-9+/=]{40,}', raw_text, re.MULTILINE):
            return {"code": "private_key_exposed", "weight": 35,
                    "message": "WireGuard private key found in config text"}
    
    # OpenVPN/RSA private key
    if re.search(r'-----BEGIN (?:RSA )?PRIVATE KEY-----', raw_text):
        return {"code": "private_key_exposed", "weight": 35,
                "message": "RSA private key found in config"}
    
    return None

def _check_inline_credentials(raw_text: str) -> Optional[dict]:
    """Weight 25: Inline credentials in config."""
    # OpenVPN auth-user-pass
    if re.search(r'<auth-user-pass>', raw_text):
        return {"code": "inline_credentials", "weight": 25,
                "message": "Inline auth-user-pass credentials in OpenVPN config"}
    
    # URL with embedded credentials (user:pass@)
    if re.search(r'://[^/\s:]+:[^/\s@]+@', raw_text):
        return {"code": "inline_credentials", "weight": 25,
                "message": "URL with embedded credentials (user:pass@) found"}
    
    return None

def _check_exec_directives(raw_text: str, protocol: str) -> Optional[dict]:
    """Weight 30: Dangerous execution directives in OpenVPN."""
    if protocol != "openvpn":
        return None
    
    checks = [
        (r'^\s*up\s+\S+', "OpenVPN 'up' directive executes external command"),
        (r'^\s*down\s+\S+', "OpenVPN 'down' directive executes external command"),
        (r'^\s*script-security\s+[2-9]', "OpenVPN 'script-security' >= 2 may allow code execution"),
        (r'^\s*plugin\s+\S+', "OpenVPN 'plugin' directive loads external module"),
        (r'^\s*cd\s+\S+', "OpenVPN 'cd' directive changes working directory"),
    ]
    
    for pattern, message in checks:
        if re.search(pattern, raw_text, re.MULTILINE):
            return {"code": "exec_directives", "weight": 30, "message": message}
    
    return None

def _check_allow_insecure(raw_text: str, protocol: str) -> Optional[dict]:
    """Weight 25: Insecure TLS/connection settings."""
    # VLess/Trojan/Hysteria2 specific checks
    if protocol in ["vless", "trojan", "hysteria2", "tuic"]:
        if re.search(r'allowInsecure["\s]*[:=]\s*["\']?true', raw_text, re.IGNORECASE):
            return {"code": "allow_insecure", "weight": 25,
                    "message": "allowInsecure=true found -- TLS verification disabled"}
        
        if re.search(r'insecure["\s]*[:=]\s*["\']?1', raw_text, re.IGNORECASE):
            return {"code": "allow_insecure", "weight": 25,
                    "message": "insecure=1 found -- security checks disabled"}
    
    # General skip-cert-verify
    if "skip-cert-verify" in raw_text.lower():
        return {"code": "allow_insecure", "weight": 25,
                "message": "skip-cert-verify found -- certificate verification skipped"}
    
    return None

def _check_no_tls_verify(raw_text: str, protocol: str) -> Optional[dict]:
    """Weight 15: Missing TLS verification in OpenVPN only."""
    if protocol != "openvpn":
        return None
    
    has_client = "client" in raw_text or "remote " in raw_text
    if not has_client:
        return None
    
    has_remote_cert_tls = bool(re.search(r'^\s*remote-cert-tls', raw_text, re.MULTILINE))
    has_verify = bool(re.search(r'^\s*verify-', raw_text, re.MULTILINE))
    has_ca = bool(re.search(r'^\s*ca\s+', raw_text, re.MULTILINE)) or "<ca>" in raw_text
    
    if not has_remote_cert_tls and not has_verify:
        return {"code": "no_tls_verify", "weight": 15,
                "message": "OpenVPN client missing remote-cert-tls or verify directive"}
    
    if not has_ca:
        return {"code": "no_tls_verify", "weight": 15,
                "message": "OpenVPN client missing CA certificate"}
    
    return None

def _check_weak_cipher(raw_text: str, protocol: str) -> Optional[dict]:
    """Weight 15: Weak cryptographic cipher/method."""
    if protocol not in ["openvpn", "shadowsocks"]:
        return None
    
    # OpenVPN weak ciphers
    if protocol == "openvpn":
        weak_ciphers = [
            (r'\bcipher\s+DES\b', "DES cipher detected (weak)"),
            (r'\bcipher\s+RC4\b', "RC4 cipher detected (weak)"),
            (r'\bcipher\s+BF-CBC\b', "BF-CBC cipher detected (weak)"),
            (r'\bcipher\s+none\b', "No cipher specified (insecure)"),
            (r'\bauth\s+MD5\b', "MD5 auth detected (weak)"),
        ]
        
        for pattern, message in weak_ciphers:
            if re.search(pattern, raw_text, re.IGNORECASE):
                return {"code": "weak_cipher", "weight": 15, "message": message}
    
    # Shadowsocks weak methods
    if protocol == "shadowsocks":
        if re.search(r':(rc4|rc4-md5|table|salsa20|chacha20):', raw_text, re.IGNORECASE):
            return {"code": "weak_cipher", "weight": 15,
                    "message": "Weak Shadowsocks encryption method detected"}
    
    return None

def _check_http_endpoint(raw_text: str, protocol: str) -> Optional[dict]:
    """Weight 15: HTTP (non-HTTPS) endpoint addresses in sensitive contexts."""
    # Only flag HTTP in contexts where it's actually suspicious
    # Don't flag http:// in comments or documentation
    
    # Check for HTTP URLs in actual config directives (not comments)
    lines = raw_text.splitlines()
    for line in lines:
        line_stripped = line.strip()
        
        # Skip comments
        if line_stripped.startswith('#') or line_stripped.startswith(';'):
            continue
        
        # Check for HTTP URLs in actual config (not just any text)
        if re.search(r'http://[^\s\'"<>]+', line_stripped):
            # But allow HTTP in certain contexts (like OCSP stapling URLs)
            if not re.search(r'(ocsp|crl|ca)\s+http://', line_stripped, re.IGNORECASE):
                return {"code": "http_endpoint", "weight": 15,
                        "message": "HTTP (non-HTTPS) endpoint found in config directive"}
    
    return None

def _check_localhost_or_private(profile: Profile) -> Optional[dict]:
    """Weight 20: Server host is localhost or private IP."""
    if _is_private_ip(profile.server_host or ""):
        return {"code": "localhost_or_private_remote", "weight": 20,
                "message": f"Server host '{profile.server_host}' is a private/localhost address"}
    return None

def _check_suspicious_port(profile: Profile) -> Optional[dict]:
    """Weight 5: Suspicious port number."""
    if _is_suspicious_port(profile.server_port):
        return {"code": "suspicious_port", "weight": 5,
                "message": f"Suspicious port number: {profile.server_port}"}
    return None

def _check_low_reputation_source(source: Optional[Source]) -> Optional[dict]:
    """Weight up to 20: Source has low reputation or suspicious status."""
    if source is None:
        return None
    
    weight = 0
    reasons = []
    
    if source.reputation_score < 40:
        weight += 20
        reasons.append("reputation < 40")
    elif source.reputation_score < 60:
        weight += 10
        reasons.append("reputation < 60")
    
    if source.status == "suspicious":
        weight += 10
        reasons.append("source status is suspicious")
    
    weight = min(weight, 20)
    
    if weight > 0:
        return {"code": "low_reputation_source", "weight": weight,
                "message": f"Low trust source ({', '.join(reasons)})"}
    
    return None

# ── Main scan function ────────────────────────────────────────────────

async def scan_profile(db: AsyncSession, profile: Profile) -> dict:
    """Run static security scan on a profile.

    Args:
        db: Async database session.
        profile: The Profile ORM object to scan.

    Returns:
        Dict with keys: scan_id, risk_score, risk_level, warnings, recommendation
    """
    # Read raw config text
    raw_text = _read_raw_config(profile.config_ref)
    protocol = profile.protocol or ""

    # Load source for reputation check
    source = None
    if profile.source_id:
        src_result = await db.execute(select(Source).where(Source.id == profile.source_id))
        source = src_result.scalar_one_or_none()

    # Run all static checks
    warnings: list[dict] = []

    checks = [
        _check_private_key_exposed(raw_text, protocol),
        _check_inline_credentials(raw_text),
        _check_exec_directives(raw_text, protocol),
        _check_allow_insecure(raw_text, protocol),
        _check_no_tls_verify(raw_text, protocol),
        _check_weak_cipher(raw_text, protocol),
        _check_http_endpoint(raw_text, protocol),
        _check_localhost_or_private(profile),
        _check_suspicious_port(profile),
        _check_low_reputation_source(source),
    ]

    for warning in checks:
        if warning is not None:
            warnings.append(warning)

    # Compute risk score (capped at 100)
    risk_score = min(sum(w["weight"] for w in warnings), 100)

    # Determine risk level
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Determine recommendation
    if risk_level == "critical":
        recommendation = "block"
    elif risk_level in ("medium", "high"):
        recommendation = "review"
    else:
        recommendation = "approve"

    # Persist SecurityScan row
    scan = SecurityScan(
        profile_id=profile.id,
        scanned_at=datetime.now(timezone.utc),
        risk_score=risk_score,
        risk_level=risk_level,
        warnings_json=json.dumps(warnings),
        recommendation=recommendation,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Update profile risk_score
    profile.risk_score = risk_score
    await db.flush()

    # Audit log
    await log_action(
        db, "scan", "profile", profile.id,
        {"risk_score": risk_score, "risk_level": risk_level, "recommendation": recommendation},
    )

    logger.info(f"Scanned profile {profile.id}: risk={risk_score} ({risk_level}), recommendation={recommendation}")

    return {
        "scan_id": scan.id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "warnings": warnings,
        "recommendation": recommendation,
    }
