"""ERROR-PANEL — Audit logging service.

Provides an async helper to record actions in the audit_logs table.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AuditLog


async def log_action(
    db: AsyncSession,
    action: str,
    entity_type: str,
    entity_id: int,
    details: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """Write an entry to the audit_logs table.

    Args:
        db: The async database session.
        action: What happened (e.g. "create", "update", "delete").
        entity_type: The type of entity (e.g. "source", "profile").
        entity_id: The primary key of the affected entity.
        details: Optional dict of extra info; stored as JSON.

    Returns:
        The created AuditLog ORM instance (flushed, not committed).
    """
    entry = AuditLog(
        created_at=datetime.now(timezone.utc),
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details_json=json.dumps(details) if details else None,
    )
    db.add(entry)
    await db.flush()
    return entry
