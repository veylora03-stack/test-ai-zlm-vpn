"""ERROR-PANEL — API: Settings & Logs.

GET  /api/settings           — return all settings as one dict
PATCH /api/settings          — partial update with validation
GET  /api/logs?limit=100     — audit logs newest first
POST /api/backup             — copy SQLite to backups dir
GET  /api/export?format=json — full JSON dump
GET  /api/export?format=csv  — CSV of profiles
"""

import csv
import io
import json
import os
import shutil
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..models import AuditLog, Metric, Profile, Settings, Source
from ..schemas import AuditLogResponse
from ..services.audit import log_action

router = APIRouter(prefix="/api", tags=["settings", "logs", "backup", "export"])


# ── Settings ──────────────────────────────────────────────────────────────────

async def _load_settings_dict(db: AsyncSession) -> dict:
    """Load all settings as a plain dict with JSON-parsed values."""
    result = await db.execute(select(Settings))
    rows = result.scalars().all()
    out = {}
    for row in rows:
        try:
            out[row.key] = json.loads(row.value)
        except (json.JSONDecodeError, TypeError):
            out[row.key] = row.value
    return out


@router.get("/settings")
async def get_settings(db: AsyncSession = Depends(get_db)):
    """Return all settings as one dict."""
    return await _load_settings_dict(db)


@router.patch("/settings")
async def update_settings(
    body: dict,
    db: AsyncSession = Depends(get_db),
):
    """Partial update of settings with validation.

    Validation rules:
    - ranking_weights: each weight > 0, sum within 0.001 of 1.0
    - test_attempts: 1..10
    - test_timeout: 1..30
    - test_concurrency: 1..10
    - auto_refresh_seconds: 5..300
    """
    errors = []

    if "ranking_weights" in body:
        weights = body["ranking_weights"]
        if not isinstance(weights, dict):
            errors.append("ranking_weights must be an object")
        else:
            required_keys = {"download", "upload", "ping", "stability", "security"}
            if set(weights.keys()) != required_keys:
                errors.append(f"ranking_weights must have keys {sorted(required_keys)}")
            else:
                vals = list(weights.values())
                if any(not isinstance(v, (int, float)) or v <= 0 for v in vals):
                    errors.append("All weights must be positive numbers")
                elif abs(sum(vals) - 1.0) > 0.001:
                    errors.append(f"Weights must sum to 1.0 (got {sum(vals):.4f})")

    if "test_attempts" in body:
        v = body["test_attempts"]
        if not isinstance(v, int) or v < 1 or v > 10:
            errors.append("test_attempts must be integer 1..10")

    if "test_timeout" in body:
        v = body["test_timeout"]
        if not isinstance(v, (int, float)) or v < 1 or v > 30:
            errors.append("test_timeout must be number 1..30")

    if "test_concurrency" in body:
        v = body["test_concurrency"]
        if not isinstance(v, int) or v < 1 or v > 10:
            errors.append("test_concurrency must be integer 1..10")

    if "auto_refresh_seconds" in body:
        v = body["auto_refresh_seconds"]
        if not isinstance(v, int) or v < 5 or v > 300:
            errors.append("auto_refresh_seconds must be integer 5..300")

    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors))

    # Persist each provided key
    for key, value in body.items():
        json_value = json.dumps(value)
        result = await db.execute(select(Settings).where(Settings.key == key))
        row = result.scalar_one_or_none()
        if row:
            row.value = json_value
        else:
            db.add(Settings(key=key, value=json_value))

    await db.flush()

    # Audit
    await log_action(db, "settings_update", "settings", 0, {"updated_keys": list(body.keys())})

    return await _load_settings_dict(db)


# ── Logs ──────────────────────────────────────────────────────────────────────

@router.get("/logs", response_model=list[AuditLogResponse])
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Return audit logs newest first."""
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    )
    return result.scalars().all()


# ── Backup ────────────────────────────────────────────────────────────────────

@router.post("/backup")
async def create_backup(db: AsyncSession = Depends(get_db)):
    """Copy the SQLite database file into backend/data/backups/."""
    from backend.core.paths import DB_PATH

    backup_dir = os.path.join(os.path.dirname(DB_PATH), "backups")
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_name = f"error_{timestamp}.db"
    backup_path = os.path.join(backup_dir, backup_name)

    if not os.path.exists(DB_PATH):
        raise HTTPException(status_code=500, detail="Database file not found")

    shutil.copy2(DB_PATH, backup_path)

    await log_action(db, "backup", "system", 0, {"path": backup_path})

    return {"path": backup_path, "filename": backup_name}


# ── Export ────────────────────────────────────────────────────────────────────

@router.get("/export")
async def export_data(
    format: str = Query("json", description="Export format: json or csv"),
    db: AsyncSession = Depends(get_db),
):
    """Export data. JSON: full dump. CSV: profiles only."""
    if format == "json":
        # Sources
        src_result = await db.execute(select(Source))
        sources = src_result.scalars().all()
        sources_data = []
        for s in sources:
            sources_data.append({
                "id": s.id, "name": s.name, "type": s.type, "url": s.url,
                "status": s.status, "reputation_score": s.reputation_score,
                "last_sync_at": s.last_sync_at.isoformat() if s.last_sync_at else None,
                "last_error": s.last_error, "notes": s.notes,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "updated_at": s.updated_at.isoformat() if s.updated_at else None,
            })

        # Profiles
        prof_result = await db.execute(select(Profile))
        profiles = prof_result.scalars().all()
        profiles_data = []
        for p in profiles:
            profiles_data.append({
                "id": p.id, "source_id": p.source_id, "name": p.name,
                "protocol": p.protocol, "server_host": p.server_host,
                "server_port": p.server_port, "country_code": p.country_code,
                "status": p.status, "risk_score": p.risk_score,
                "fingerprint": p.fingerprint,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "updated_at": p.updated_at.isoformat() if p.updated_at else None,
            })

        # Metrics
        met_result = await db.execute(select(Metric))
        metrics = met_result.scalars().all()
        metrics_data = []
        for m in metrics:
            metrics_data.append({
                "id": m.id, "profile_id": m.profile_id,
                "checked_at": m.checked_at.isoformat() if m.checked_at else None,
                "ping_ms": m.ping_ms, "packet_loss_pct": m.packet_loss_pct,
                "jitter_ms": m.jitter_ms, "download_mbps": m.download_mbps,
                "upload_mbps": m.upload_mbps, "error_message": m.error_message,
            })

        return {"sources": sources_data, "profiles": profiles_data, "metrics": metrics_data}

    elif format == "csv":
        # CSV of profiles only — no secret material in profiles
        prof_result = await db.execute(select(Profile))
        profiles = prof_result.scalars().all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "name", "protocol", "server_host", "server_port",
            "country_code", "status", "risk_score", "fingerprint", "created_at",
        ])
        for p in profiles:
            writer.writerow([
                p.id, p.name, p.protocol, p.server_host or "",
                p.server_port or "", p.country_code or "", p.status,
                p.risk_score, p.fingerprint or "",
                p.created_at.isoformat() if p.created_at else "",
            ])

        return PlainTextResponse(
            content=output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=profiles.csv"},
        )

    else:
        raise HTTPException(status_code=400, detail="format must be json or csv")

