"""ERROR-PANEL — API: Network Tests & Metrics.

POST /api/tests/run/{profile_id}    — run tester, persist Metric row, audit "test"
GET  /api/metrics?profile_id=        — metric history newest first
POST /api/metrics                    — manual speed submission; audit "metric_manual"
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..models import Metric, Profile
from ..schemas import ManualMetricCreate, MetricResponse
from ..services.audit import log_action
from ..services.tester import test_profile

router = APIRouter(prefix="/api", tags=["tests", "metrics"])


@router.post("/tests/run/{profile_id}", response_model=MetricResponse)
async def run_test(profile_id: int, db: AsyncSession = Depends(get_db)):
    """Run TCP connect latency test on a profile, persist Metric row."""
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Run the tester (pass db for settings integration)
    test_result = await test_profile(profile, db=db)

    # Create Metric row
    metric = Metric(
        profile_id=profile.id,
        checked_at=datetime.now(timezone.utc),
        ping_ms=test_result.get("ping_ms"),
        packet_loss_pct=test_result.get("packet_loss_pct"),
        jitter_ms=test_result.get("jitter_ms"),
        download_mbps=None,  # Not measured by TCP connect test
        upload_mbps=None,    # Not measured by TCP connect test
        error_message=test_result.get("error"),
    )
    db.add(metric)
    await db.flush()
    await db.refresh(metric)

    # Audit log
    await log_action(
        db, "test", "profile", profile.id,
        {
            "ping_ms": test_result.get("ping_ms"),
            "reachable": test_result.get("reachable"),
            "packet_loss_pct": test_result.get("packet_loss_pct"),
        },
    )

    return metric


@router.get("/metrics", response_model=list[MetricResponse])
async def get_metrics(
    profile_id: int = Query(..., description="Filter by profile ID"),
    db: AsyncSession = Depends(get_db),
):
    """Get metric history for a profile, newest first."""
    result = await db.execute(
        select(Metric)
        .where(Metric.profile_id == profile_id)
        .order_by(Metric.id.desc())
    )
    return result.scalars().all()


@router.post("/metrics", response_model=MetricResponse, status_code=201)
async def submit_manual_metrics(
    body: ManualMetricCreate,
    db: AsyncSession = Depends(get_db),
):
    """Submit manual speed metrics for a profile.

    Rationale: Real download/upload measurement requires an active VPN
    connection which this panel never establishes automatically (no-auto-connect
    principle). Manual entry preserves the ranking formula completeness.
    """
    # Verify profile exists
    result = await db.execute(select(Profile).where(Profile.id == body.profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    metric = Metric(
        profile_id=body.profile_id,
        checked_at=datetime.now(timezone.utc),
        ping_ms=body.ping_ms,
        packet_loss_pct=0.0,
        jitter_ms=0.0,
        download_mbps=body.download_mbps,
        upload_mbps=body.upload_mbps,
        error_message=None,
    )
    db.add(metric)
    await db.flush()
    await db.refresh(metric)

    # Audit log
    await log_action(
        db, "metric_manual", "profile", body.profile_id,
        {
            "download_mbps": body.download_mbps,
            "upload_mbps": body.upload_mbps,
            "ping_ms": body.ping_ms,
        },
    )

    return metric
