"""ERROR-PANEL — Ranking Engine Service.

Computes composite scores for VPN profiles using the formula:
  score = w_dl*download_norm + w_ul*upload_norm + w_ping*ping_norm
        + w_stab*stability_norm + w_sec*security_norm

Weights are read from the settings table (key "ranking_weights").
If not present, defaults to {download:0.35, upload:0.20, ping:0.20,
stability:0.15, security:0.10}.

Normalizations:
  download_norm = min(dl / 200, 1)
  upload_norm   = min(ul / 100, 1)
  ping_norm     = max(0, 1 - avg_ping / 1000)
  stability_norm = max(0, 1 - packet_loss / 100) * (1 - min(jitter / 200, 1))
  security_norm = 1 - risk_score / 100

Missing metric values count as 0.
Eligible profiles: status in ("approved", "tested") only.
"""

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Metric, Profile, Settings

# Default weights (used if settings table is empty or missing key)
DEFAULT_WEIGHTS = {
    "download": 0.35, "upload": 0.20,
    "ping": 0.20, "stability": 0.15, "security": 0.10,
}


async def _get_weights(db: AsyncSession) -> dict:
    """Load ranking weights from settings table."""
    result = await db.execute(
        select(Settings).where(Settings.key == "ranking_weights")
    )
    row = result.scalar_one_or_none()
    if row:
        try:
            return json.loads(row.value)
        except (json.JSONDecodeError, TypeError):
            pass
    return DEFAULT_WEIGHTS


def compute_score(
    download_mbps: float | None,
    upload_mbps: float | None,
    ping_ms: float | None,
    packet_loss_pct: float | None,
    jitter_ms: float | None,
    risk_score: int,
    weights: dict | None = None,
) -> float:
    """Compute the composite ranking score for a profile.

    Missing values (None) are treated as 0.

    Args:
        weights: Optional dict with keys download, upload, ping,
                 stability, security. Defaults to DEFAULT_WEIGHTS.

    Returns:
        Float score in [0, 1].
    """
    w = weights or DEFAULT_WEIGHTS

    dl = download_mbps if download_mbps is not None else 0.0
    ul = upload_mbps if upload_mbps is not None else 0.0
    ping = ping_ms if ping_ms is not None else 0.0
    loss = packet_loss_pct if packet_loss_pct is not None else 0.0
    jitter = jitter_ms if jitter_ms is not None else 0.0

    download_norm = min(dl / 200.0, 1.0)
    upload_norm = min(ul / 100.0, 1.0)
    ping_norm = max(0.0, 1.0 - ping / 1000.0)
    stability_norm = max(0.0, 1.0 - loss / 100.0) * (1.0 - min(jitter / 200.0, 1.0))
    security_norm = 1.0 - risk_score / 100.0

    score = (
        w.get("download", 0.35) * download_norm
        + w.get("upload", 0.20) * upload_norm
        + w.get("ping", 0.20) * ping_norm
        + w.get("stability", 0.15) * stability_norm
        + w.get("security", 0.10) * security_norm
    )
    return round(score, 6)


async def top_profiles(
    db: AsyncSession,
    metric: str = "score",
    limit: int = 10,
) -> list[dict]:
    """Return top profiles ranked by the given metric.

    Args:
        db: Async database session.
        metric: One of "ping", "download", "upload", "score".
        limit: Maximum number of profiles to return.

    Returns:
        List of dicts with profile fields plus computed score/metrics.
    """
    # Load weights from settings
    weights = await _get_weights(db)

    # Get eligible profiles
    result = await db.execute(
        select(Profile)
        .where(Profile.status.in_(["approved", "tested"]))
        .order_by(Profile.id)
    )
    profiles = result.scalars().all()

    if not profiles:
        return []

    # Build ranking data
    ranked: list[dict] = []
    for p in profiles:
        # Get latest metric
        metric_result = await db.execute(
            select(Metric)
            .where(Metric.profile_id == p.id)
            .order_by(Metric.id.desc())
            .limit(1)
        )
        latest_metric = metric_result.scalar_one_or_none()

        dl = latest_metric.download_mbps if latest_metric else None
        ul = latest_metric.upload_mbps if latest_metric else None
        ping = latest_metric.ping_ms if latest_metric else None
        loss = latest_metric.packet_loss_pct if latest_metric else None
        jitter = latest_metric.jitter_ms if latest_metric else None

        score = compute_score(dl, ul, ping, loss, jitter, p.risk_score, weights)

        entry = {
            "id": p.id,
            "name": p.name,
            "protocol": p.protocol,
            "server_host": p.server_host,
            "server_port": p.server_port,
            "country_code": p.country_code,
            "status": p.status,
            "risk_score": p.risk_score,
            "score": score,
            "download_mbps": dl,
            "upload_mbps": ul,
            "ping_ms": ping,
            "packet_loss_pct": loss,
            "jitter_ms": jitter,
        }
        ranked.append(entry)

    # Sort by metric
    if metric == "ping":
        # Lower ping is better; only consider profiles with a ping value
        ranked = [r for r in ranked if r["ping_ms"] is not None]
        ranked.sort(key=lambda r: r["ping_ms"])
    elif metric == "download":
        ranked.sort(key=lambda r: r["download_mbps"] or 0, reverse=True)
    elif metric == "upload":
        ranked.sort(key=lambda r: r["upload_mbps"] or 0, reverse=True)
    else:  # score
        ranked.sort(key=lambda r: r["score"], reverse=True)

    return ranked[:limit]
