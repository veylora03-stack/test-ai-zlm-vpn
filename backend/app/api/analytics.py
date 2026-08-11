"""ERROR-PANEL — API: Analytics & Ranking.

GET /api/ranking/top?metric=score&limit=10  — top profiles by metric
GET /api/analytics/overview                  — analytics overview
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..models import Metric, Profile, Source
from ..services.ranker import top_profiles

router = APIRouter(prefix="/api", tags=["analytics", "ranking"])


@router.get("/ranking/top")
async def get_ranking_top(
    metric: str = Query("score", description="Metric: ping|download|upload|score"),
    limit: int = Query(10, description="Max results", ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Return top profiles ranked by the given metric."""
    results = await top_profiles(db, metric=metric, limit=limit)
    return results


@router.get("/analytics/overview")
async def get_analytics_overview(db: AsyncSession = Depends(get_db)):
    """Return analytics overview: counts, averages, trends."""

    # Counts by status
    status_result = await db.execute(
        select(Profile.status, func.count(Profile.id))
        .group_by(Profile.status)
    )
    counts_by_status = {row[0]: row[1] for row in status_result.all()}

    # Counts by protocol
    protocol_result = await db.execute(
        select(Profile.protocol, func.count(Profile.id))
        .group_by(Profile.protocol)
    )
    counts_by_protocol = {row[0]: row[1] for row in protocol_result.all()}

    # Sources total and active
    sources_total_result = await db.execute(select(func.count(Source.id)))
    sources_total = sources_total_result.scalar() or 0

    sources_active_result = await db.execute(
        select(func.count(Source.id)).where(Source.status == "active")
    )
    sources_active = sources_active_result.scalar() or 0

    # Quarantined count
    quarantined_result = await db.execute(
        select(func.count(Profile.id))
        .where(Profile.status.in_(["quarantined", "pending_review"]))
    )
    quarantined_count = quarantined_result.scalar() or 0

    # Average risk score
    avg_risk_result = await db.execute(
        select(func.avg(Profile.risk_score))
    )
    avg_risk = avg_risk_result.scalar()
    avg_risk = round(avg_risk, 2) if avg_risk is not None else 0.0

    # Ping trend: last 20 metric rows
    ping_trend_result = await db.execute(
        select(Metric.checked_at, Metric.ping_ms)
        .where(Metric.ping_ms.isnot(None))
        .order_by(Metric.id.desc())
        .limit(20)
    )
    ping_trend = [
        {"checked_at": row[0].isoformat() if row[0] else None, "ping_ms": row[1]}
        for row in ping_trend_result.all()
    ]
    # Reverse so it's chronological (oldest first)
    ping_trend.reverse()

    return {
        "counts_by_status": counts_by_status,
        "counts_by_protocol": counts_by_protocol,
        "sources_total": sources_total,
        "sources_active": sources_active,
        "quarantined_count": quarantined_count,
        "avg_risk": avg_risk,
        "ping_trend": ping_trend,
    }
