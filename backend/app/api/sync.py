"""
ERROR-PANEL — API: Source Sync.
POST /api/sources/{source_id}/sync
Integrates the real parser and dedup service.
For each parsed config, computes a fingerprint; if a profile with the
same fingerprint already exists, the profile is skipped (duplicate).

CRITICAL FIX: Tracks newly created profile IDs to ensure auto-scan
executes on every imported profile. Previous code queried by
config_ref path mismatch, resulting in 0 scans.
"""
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db, AsyncSessionLocal
from ..models import Profile, Source
from ..services.audit import log_action
from ..services.dedup import fingerprint, find_duplicate
from ..services.fetcher import FetchError, FetchSSRFError, SchemeError, SizeError, fetch_source
from ..services.parser import parse_config
from ..services.scanner import scan_profile
from backend.core.paths import RAW_DIR
from backend.core.logger import logger

router = APIRouter(prefix="/api", tags=["sync"])

MAX_SOURCES = 100


@router.post("/sources/{source_id}/sync")
async def sync_source(source_id: int, db: AsyncSession = Depends(get_db)):
    """
    Fetch the source URL, save raw content, parse configs, create
    profiles (with dedup), and auto-scan each new profile.
    
    Transaction is managed by get_db() — no manual commits.
    Error state persistence uses a separate session to avoid
    rollback conflicts.
    """
    # ── Enforce source limit efficiently ──────────────────────
    count_result = await db.execute(select(func.count(Source.id)))
    if count_result.scalar() >= MAX_SOURCES:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum source limit ({MAX_SOURCES}) reached"
        )

    # ── Load source ───────────────────────────────────────────
    result = await db.execute(select(Source).where(Source.id == source_id))
    source = result.scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    if source.status == "blocked":
        raise HTTPException(
            status_code=409,
            detail="Source is blocked and cannot be synced"
        )
    if not source.url:
        raise HTTPException(
            status_code=400,
            detail="Source has no URL to fetch"
        )

    # ── Fetch ─────────────────────────────────────────────────
    try:
        fetched = await fetch_source(source.url)
    except (SchemeError, SizeError, FetchSSRFError) as exc:
        await _persist_source_error(source_id, str(exc))
        raise HTTPException(status_code=400, detail=str(exc))
    except FetchError as exc:
        await _persist_source_error(source_id, str(exc))
        raise HTTPException(status_code=502, detail=str(exc))

    # ── Save raw content to disk ──────────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    raw_filename = f"source_{source_id}_{timestamp}.txt"
    raw_path = RAW_DIR / raw_filename
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(fetched["content"], encoding="utf-8")

    # ── Parse configs ─────────────────────────────────────────
    parsed = parse_config(fetched["content"], source.type)

    # ── Create profiles (quarantined by default, with dedup) ──
    imported_count = 0
    duplicates = 0
    new_profile_ids: list[int] = []  # Track IDs for auto-scan

    for cfg in parsed:
        fp = fingerprint(cfg)
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
            config_ref=raw_filename,  # Store relative filename, not absolute path
            notes=cfg.get("notes"),
        )
        db.add(profile)
        await db.flush()  # Flush to get auto-generated ID
        new_profile_ids.append(profile.id)
        imported_count += 1

    # ── Auto-scan each newly imported profile ─────────────────
    # CRITICAL FIX: Query by tracked IDs, not by config_ref path
    for profile_id in new_profile_ids:
        result = await db.execute(
            select(Profile).where(Profile.id == profile_id)
        )
        new_profile = result.scalar_one_or_none()
        if new_profile:
            try:
                await scan_profile(db, new_profile)
            except Exception as e:
                logger.warning(f"Scan failed for profile {profile_id}: {e}")
                # Scan failure does not block sync

    # ── Update source on success ──────────────────────────────
    source.last_sync_at = datetime.now(timezone.utc)
    source.last_error = None
    source.status = "active"

    # ── Audit ─────────────────────────────────────────────────
    await log_action(
        db, "sync", "source", source.id,
        {
            "bytes": fetched["bytes"],
            "sha256": fetched["sha256"],
            "imported_count": imported_count,
            "duplicates": duplicates,
            "raw_filename": raw_filename,
        },
    )

    return {
        "fetched_bytes": fetched["bytes"],
        "sha256": fetched["sha256"],
        "raw_filename": raw_filename,
        "imported_count": imported_count,
        "duplicates": duplicates,
    }


async def _persist_source_error(source_id: int, error_msg: str):
    """
    Persist error state to source record using a separate session.
    
    This is necessary because get_db() will rollback the main
    transaction when HTTPException is raised. Using a separate
    session ensures the error state is saved regardless.
    """
    async with AsyncSessionLocal() as error_session:
        try:
            result = await error_session.execute(
                select(Source).where(Source.id == source_id)
            )
            source = result.scalar_one_or_none()
            if source:
                source.last_error = error_msg
                await error_session.commit()
        except Exception as e:
            logger.error(f"Failed to persist source error: {e}")
