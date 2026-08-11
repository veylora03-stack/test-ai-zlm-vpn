"""ERROR-PANEL — API: Source Sync.

POST /api/sources/{source_id}/sync

Integrates the real parser (Phase 5) and dedup service.
For each parsed config, computes a fingerprint; if a profile with the
same fingerprint already exists, the profile is skipped (duplicate).
"""

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..models import Profile, Source
from ..services.audit import log_action
from ..services.dedup import fingerprint, find_duplicate
from ..services.fetcher import FetchError, SchemeError, SizeError, fetch_source
from ..services.parser import parse_config
from ..services.scanner import scan_profile

router = APIRouter(prefix="/api", tags=["sync"])

# Raw config storage directory
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW_DIR = os.path.join(_BASE_DIR, "data", "raw")


@router.post("/sources/{source_id}/sync")
async def sync_source(source_id: int, db: AsyncSession = Depends(get_db)):
    """Fetch the source URL, save raw content, parse configs, create profiles (with dedup)."""
    # ── Load source ────────────────────────────────────────────────────
    result = await db.execute(select(Source).where(Source.id == source_id))
    source = result.scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    if source.status == "blocked":
        raise HTTPException(status_code=409, detail="Source is blocked and cannot be synced")

    if not source.url:
        raise HTTPException(status_code=400, detail="Source has no URL to fetch")

    # ── Fetch ──────────────────────────────────────────────────────────
    try:
        fetched = await fetch_source(source.url)
    except SchemeError as exc:
        source.last_error = str(exc)
        await db.commit()
        raise HTTPException(status_code=400, detail=str(exc))
    except SizeError as exc:
        source.last_error = str(exc)
        await db.commit()
        raise HTTPException(status_code=400, detail=str(exc))
    except FetchError as exc:
        source.last_error = str(exc)
        await db.commit()
        raise HTTPException(status_code=502, detail=str(exc))

    # ── Save raw content to disk ───────────────────────────────────────
    os.makedirs(RAW_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    raw_filename = f"source_{source_id}_{timestamp}.txt"
    raw_path = os.path.join(RAW_DIR, raw_filename)
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(fetched["content"])

    # ── Parse configs ──────────────────────────────────────────────────
    parsed = parse_config(fetched["content"], source.type)

    # ── Create profiles (quarantined by default, with dedup) ───────────
    imported_count = 0
    duplicates = 0
    for cfg in parsed:
        # Compute fingerprint for dedup
        fp = fingerprint(cfg)

        # Check for existing duplicate
        existing = await find_duplicate(db, fp)
        if existing is not None:
            duplicates += 1
            continue

        profile = Profile(
            source_id=source.id,
            name=cfg.get("name", "unknown"),
            protocol=cfg.get("protocol", "wireguard"),
            server_host=cfg.get("server_host"),
            server_port=cfg.get("server_port"),
            country_code=cfg.get("country_code"),
            status="quarantined",
            fingerprint=fp,
            config_ref=raw_path,
            notes=cfg.get("notes"),
        )
        db.add(profile)
        imported_count += 1

    if imported_count > 0:
        await db.flush()

    # ── Auto-scan each newly imported profile ──────────────────────────
    # Get all profiles created in this sync (they share raw_path as config_ref)
    if imported_count > 0:
        new_profiles_result = await db.execute(
            select(Profile)
            .where(Profile.source_id == source.id, Profile.config_ref == raw_path)
        )
        for new_profile in new_profiles_result.scalars().all():
            try:
                await scan_profile(db, new_profile)
            except Exception:
                pass  # Scan failure should not block sync

    # ── Update source on success ───────────────────────────────────────
    source.last_sync_at = datetime.now(timezone.utc)
    source.last_error = None
    source.status = "active"
    await db.flush()

    # ── Audit ──────────────────────────────────────────────────────────
    await log_action(
        db, "sync", "source", source.id,
        {
            "bytes": fetched["bytes"],
            "sha256": fetched["sha256"],
            "imported_count": imported_count,
            "duplicates": duplicates,
            "raw_path": raw_path,
        },
    )

    return {
        "fetched_bytes": fetched["bytes"],
        "sha256": fetched["sha256"],
        "raw_path": raw_path,
        "imported_count": imported_count,
        "duplicates": duplicates,
    }
