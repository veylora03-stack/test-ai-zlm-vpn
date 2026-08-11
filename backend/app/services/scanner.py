"""ERROR-PANEL — Security Scanner Service.

Static analysis of VPN config profiles for risk scoring.
NEVER executes config content, NEVER opens connections, NEVER stores secrets.
"""

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Profile, SecurityScan, Source
from ..services.audit import log_action


# ── Private IP detection ────────────────────────────────────────────────────

def _is_private_ip(host: str) -> bool:
    """Check if a hostname is localhost or a private/LAN IP address."""
    if not host:
        return False
    low = host.lower()
    if low in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # Not an IP address -- check common private prefixes
        if low.startswith("127.") or low.startswith("10."):
            return True
        if low.startswith("192.168."):
            return True
        if low.startswith("172."):
            parts = low.split(".")
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return True
                except ValueError:
                    pass
        return False


def _is_suspicious_port(port: Optional[int]) -> bool:
    """Check if a port number is suspicious."""
    if port is None:
        return False
    SUSPICIOUS_PORTS = {23, 25, 4444, 31337}
    if port in SUSPICIOUS_PORTS:
        return True
    if port < 1024 and port not in (443, 80):
        return True
    return False


# ── Raw config file reader ─────────────────────────────────────────────────

def _read_raw_config(config_ref: Optional[str]) -> str:
    """Read raw config text from the file path stored in config_ref."""
    if not config_ref:
        return ""
    try:
        if os.path.isfile(config_ref):
            with open(config_ref, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
    except Exception:
        pass
    return ""


# ── Static checks ───────────────────────────────────────────────────────────

def _check_private_key_exposed(raw_text: str) -> Optional[dict]:
    """Weight 35: Private key exposed in config text."""
    if re.search(r'^\s*PrivateKey\s*=\s*\S+', raw_text, re.MULTILINE):
        return {"code": "private_key_exposed", "weight": 35,
                "message": "WireGuard private key found in config text"}
    if re.search(r'<key>.*?BEGIN (?:RSA )?PRIVATE KEY', raw_text, re.DOTALL):
        return {"code": "private_key_exposed", "weight": 35,
                "message": "RSA private key found in OpenVPN config"}
    return None


def _check_inline_credentials(raw_text: str) -> Optional[dict]:
    """Weight 25: Inline credentials in config."""
    if re.search(r'<auth-user-pass>', raw_text):
        return {"code": "inline_credentials", "weight": 25,
                "message": "Inline auth-user-pass credentials in OpenVPN config"}
    if re.search(r'://[^/\s]+:[^/\s]+@', raw_text):
        return {"code": "inline_credentials", "weight": 25,
                "message": "URL with embedded credentials (user:pass@) found"}
    return None


def _check_exec_directives(raw_text: str) -> Optional[dict]:
    """Weight 30: Dangerous execution directives in OpenVPN."""
    checks = [
        (r'^\s*up\s+', "OpenVPN 'up' directive executes external command"),
        (r'^\s*down\s+', "OpenVPN 'down' directive executes external command"),
        (r'^\s*script-security\s+', "OpenVPN 'script-security' directive may allow code execution"),
        (r'^\s*plugin\s+', "OpenVPN 'plugin' directive loads external module"),
        (r'^\s*cd\s+', "OpenVPN 'cd' directive changes working directory"),
    ]
    for pattern, message in checks:
        if re.search(pattern, raw_text, re.MULTILINE):
            return {"code": "exec_directives", "weight": 30, "message": message}
    return None


def _check_allow_insecure(raw_text: str) -> Optional[dict]:
    """Weight 25: Insecure TLS/connection settings."""
    if re.search(r'allowInsecure["\s]*[:=]\s*true', raw_text, re.IGNORECASE):
        return {"code": "allow_insecure", "weight": 25,
                "message": "allowInsecure=true found -- TLS verification disabled"}
    if "skip-cert-verify" in raw_text.lower():
        return {"code": "allow_insecure", "weight": 25,
                "message": "skip-cert-verify found -- certificate verification skipped"}
    if re.search(r'insecure["\s]*[:=]\s*true', raw_text, re.IGNORECASE):
        return {"code": "allow_insecure", "weight": 25,
                "message": "insecure=true found -- security checks disabled"}
    return None


def _check_no_tls_verify(raw_text: str) -> Optional[dict]:
    """Weight 15: Missing TLS verification in OpenVPN."""
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


def _check_weak_cipher(raw_text: str) -> Optional[dict]:
    """Weight 15: Weak cryptographic cipher/method."""
    weak_ciphers = ["DES", "RC4", "BF-CBC", "none"]
    for cipher in weak_ciphers:
        if re.search(rf'\b{re.escape(cipher)}\b', raw_text, re.IGNORECASE):
            return {"code": "weak_cipher", "weight": 15,
                    "message": f"Weak cipher/method '{cipher}' detected"}
    return None


def _check_http_endpoint(raw_text: str) -> Optional[dict]:
    """Weight 15: HTTP (non-HTTPS) endpoint addresses."""
    if re.search(r'http://[^\s]+', raw_text):
        return {"code": "http_endpoint", "weight": 15,
                "message": "HTTP (non-HTTPS) endpoint address found in config"}
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


# ── Main scan function ──────────────────────────────────────────────────────

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

    # Load source for reputation check
    source = None
    if profile.source_id:
        src_result = await db.execute(select(Source).where(Source.id == profile.source_id))
        source = src_result.scalar_one_or_none()

    # Run all static checks
    warnings: list[dict] = []

    checks = [
        _check_private_key_exposed(raw_text),
        _check_inline_credentials(raw_text),
        _check_exec_directives(raw_text),
        _check_allow_insecure(raw_text),
        _check_no_tls_verify(raw_text),
        _check_weak_cipher(raw_text),
        _check_http_endpoint(raw_text),
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

    return {
        "scan_id": scan.id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "warnings": warnings,
        "recommendation": recommendation,
    }
