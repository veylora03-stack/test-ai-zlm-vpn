"""ERROR-PANEL — Deduplication service.

Fingerprint-based duplicate detection for imported VPN profiles.
Fingerprint = SHA-256 of (protocol|server_host|server_port|uuid_or_publickey),
sorted, lowercased.
"""

import hashlib
import json
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Profile


def fingerprint(cfg: dict) -> str:
    """Compute a dedup fingerprint for a parsed config dict.

    The fingerprint is SHA-256 of the sorted, lowercased concatenation of:
      protocol, server_host, server_port, and the UUID or public key
      from fingerprint_data.

    Args:
        cfg: A dict as returned by parse_config(), with keys like
             name, protocol, server_host, server_port, fingerprint_data.

    Returns:
        Hex SHA-256 hash string.
    """
    protocol = (cfg.get("protocol") or "").lower()
    host = (cfg.get("server_host") or "").lower()
    port = str(cfg.get("server_port") or "")

    # Extract UUID or public_key from fingerprint_data
    fp_data = cfg.get("fingerprint_data") or {}
    uuid_ = (fp_data.get("uuid") or "").lower()
    public_key = (fp_data.get("public_key") or "").lower()

    # Sort all non-empty components for stable hash
    components = sorted(filter(None, [protocol, host, port, uuid_, public_key]))
    raw = "|".join(components)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
    return result.scalar_one_or_none()
