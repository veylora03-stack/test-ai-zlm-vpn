"""ERROR-PANEL — Enhanced Deduplication Service.

Fingerprint-based duplicate detection with improved algorithm.
Uses multiple components for stronger fingerprinting.
"""

import hashlib
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Profile
from backend.core.logger import logger

def fingerprint(cfg: dict) -> str:
    """Compute a dedup fingerprint for a parsed config dict.

    Enhanced algorithm uses multiple components for stronger fingerprinting:
    - protocol
    - server_host (normalized)
    - server_port
    - uuid or public_key (from fingerprint_data)
    - advanced security parameters (publicKey for Reality, etc.)
    
    Components are sorted and lowercased for stable hashing.

    Args:
        cfg: A dict as returned by parse_config(), with keys like
             name, protocol, server_host, server_port, fingerprint_data, advanced_params.

    Returns:
        Hex SHA-256 hash string.
    """
    protocol = (cfg.get("protocol") or "").lower()
    host = (cfg.get("server_host") or "").lower()
    port = str(cfg.get("server_port") or "")

    # Extract identifiers from fingerprint_data
    fp_data = cfg.get("fingerprint_data") or {}
    uuid_ = (fp_data.get("uuid") or "").lower()
    public_key = (fp_data.get("public_key") or "").lower()
    password = (fp_data.get("password") or "").lower()  # For Hysteria2

    # Extract advanced security parameters
    adv_params = cfg.get("advanced_params") or {}
    adv_public_key = (adv_params.get("publicKey") or adv_params.get("public_key") or "").lower()
    
    # Combine all public keys (Reality, WireGuard, etc.)
    all_keys = [public_key, adv_public_key] if any([public_key, adv_public_key]) else []
    combined_key = "|".join(sorted(set(filter(None, all_keys))))

    # Build components list
    components = [
        protocol,
        host,
        port,
        uuid_,
        combined_key,
        password,
    ]
    
    # Filter empty components and sort for stability
    components = sorted(filter(None, components))
    
    raw = "|".join(components)
    hash_value = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    
    logger.debug(f"Generated fingerprint: {hash_value[:16]}... for {protocol}://{host}:{port}")
    
    return hash_value

async def find_duplicate(
    db: AsyncSession, fp: str
) -> Optional[Profile]:
    """Find an existing profile with the given fingerprint.

    Args:
        db: Async database session.
        fp: Fingerprint hex string.

    Returns:
        The matching Profile ORM object, or None if no duplicate found.
    """
    result = await db.execute(
        select(Profile).where(Profile.fingerprint == fp).limit(1)
    )
    duplicate = result.scalar_one_or_none()
    
    if duplicate:
        logger.info(f"Found duplicate profile: {duplicate.id} (fingerprint: {fp[:16]}...)")
    
    return duplicate
