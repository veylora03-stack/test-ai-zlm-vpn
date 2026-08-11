"""ERROR-PANEL — API: Quarantine + Security Scanner.

GET  /api/quarantine/               — list quarantined/pending_review profiles with latest_scan
POST /api/quarantine/{id}/approve   — approve (status -> approved)
POST /api/quarantine/{id}/reject    — reject  (status -> blocked)
POST /api/quarantine/{id}/block     — block   (status -> blocked, risk_score -> 100)
POST /api/security/scan/{profile_id}  — run scanner on demand
GET  /api/security/scans/{profile_id} — scan history newest first
"""

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..models import Profile, SecurityScan
from ..schemas import ProfileResponse, SecurityScanResponse
from ..services.audit import log_action
from ..services.scanner import scan_profile

router = APIRouter(prefix="/api", tags=["quarantine", "security"])


# ── Quarantine list (with embedded latest_scan) ─────────────────────────────

@router.get("/quarantine/")
async def list_quarantine(db: AsyncSession = Depends(get_db)):
    """List profiles with status quarantined or pending_review, newest first.

    Each item includes a 'latest_scan' dict with risk_score, risk_level,
    warnings (parsed list), and recommendation from the most recent scan.
    """
    result = await db.execute(
        select(Profile)
        .where(Profile.status.in_(["quarantined", "pending_review"]))
        .order_by(Profile.id.desc())
    )
    profiles = result.scalars().all()

    items = []
    for p in profiles:
        # Get latest scan
        scan_result = await db.execute(
            select(SecurityScan)
            .where(SecurityScan.profile_id == p.id)
            .order_by(SecurityScan.id.desc())
            .limit(1)
        )
        latest_scan_obj = scan_result.scalar_one_or_none()

        latest_scan = None
        if latest_scan_obj:
            warnings_list = []
            if latest_scan_obj.warnings_json:
                try:
                    warnings_list = json.loads(latest_scan_obj.warnings_json)
                except (json.JSONDecodeError, TypeError):
                    warnings_list = []
            latest_scan = {
                "risk_score": latest_scan_obj.risk_score,
                "risk_level": latest_scan_obj.risk_level,
                "warnings": warnings_list,
                "recommendation": latest_scan_obj.recommendation,
            }

        items.append({
            "id": p.id,
            "source_id": p.source_id,
            "name": p.name,
            "protocol": p.protocol,
            "server_host": p.server_host,
            "server_port": p.server_port,
            "country_code": p.country_code,
            "status": p.status,
            "risk_score": p.risk_score,
            "duplicate_of": p.duplicate_of,
            "fingerprint": p.fingerprint,
            "config_ref": p.config_ref,
            "notes": p.notes,
            "created_at": p.created_at,
            "updated_at": p.updated_at,
            "latest_scan": latest_scan,
        })

    return items


# ── Quarantine actions ──────────────────────────────────────────────────────

@router.post("/quarantine/{profile_id}/approve", response_model=ProfileResponse)
async def approve_quarantine(profile_id: int, db: AsyncSession = Depends(get_db)):
    """Approve a quarantined profile (status -> approved)."""
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile.status = "approved"
    await db.flush()
    await db.refresh(profile)
    await log_action(db, "approve", "profile", profile.id, {"new_status": "approved"})
    return profile


@router.post("/quarantine/{profile_id}/reject", response_model=ProfileResponse)
async def reject_quarantine(profile_id: int, db: AsyncSession = Depends(get_db)):
    """Reject a quarantined profile (status -> blocked)."""
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile.status = "blocked"
    await db.flush()
    await db.refresh(profile)
    await log_action(db, "reject", "profile", profile.id, {"new_status": "blocked"})
    return profile


@router.post("/quarantine/{profile_id}/block", response_model=ProfileResponse)
async def block_quarantine(profile_id: int, db: AsyncSession = Depends(get_db)):
    """Block a quarantined profile (status -> blocked, risk_score -> 100)."""
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile.status = "blocked"
    profile.risk_score = 100
    await db.flush()
    await db.refresh(profile)
    await log_action(db, "block", "profile", profile.id, {"new_status": "blocked", "risk_score": 100})
    return profile


# ── Security Scanner endpoints ──────────────────────────────────────────────

@router.post("/security/scan/{profile_id}")
async def scan_profile_endpoint(profile_id: int, db: AsyncSession = Depends(get_db)):
    """Run security scanner on a profile on demand."""
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    scan_result = await scan_profile(db, profile)
    return scan_result


@router.get("/security/scans/{profile_id}", response_model=list[SecurityScanResponse])
async def get_scan_history(profile_id: int, db: AsyncSession = Depends(get_db)):
    """Get scan history for a profile, newest first."""
    result = await db.execute(
        select(SecurityScan)
        .where(SecurityScan.profile_id == profile_id)
        .order_by(SecurityScan.id.desc())
    )
    return result.scalars().all()
