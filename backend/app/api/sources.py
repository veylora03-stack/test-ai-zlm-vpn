"""ERROR-PANEL — API: Sources CRUD.

GET    /api/sources/       — list all sources
POST   /api/sources/       — create a source
GET    /api/sources/{id}   — get source by id
PATCH  /api/sources/{id}   — update source
DELETE /api/sources/{id}   — delete source
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..models import Source
from ..schemas import SourceCreate, SourceResponse, SourceUpdate
from ..services.audit import log_action

router = APIRouter(prefix="/api/sources", tags=["sources"])


@router.get("/", response_model=list[SourceResponse])
async def list_sources(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Source).order_by(Source.id))
    return result.scalars().all()


@router.post("/", response_model=SourceResponse, status_code=201)
async def create_source(body: SourceCreate, db: AsyncSession = Depends(get_db)):
    source = Source(**body.model_dump())
    db.add(source)
    await db.flush()
    await db.refresh(source)
    await log_action(db, "create", "source", source.id, {"name": source.name, "type": source.type})
    return source


@router.get("/{source_id}", response_model=SourceResponse)
async def get_source(source_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Source).where(Source.id == source_id))
    source = result.scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    return source


@router.patch("/{source_id}", response_model=SourceResponse)
async def update_source(
    source_id: int, body: SourceUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Source).where(Source.id == source_id))
    source = result.scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(source, field, value)

    await db.flush()
    await db.refresh(source)
    await log_action(db, "update", "source", source.id, {"updated_fields": list(update_data.keys())})
    return source


@router.delete("/{source_id}", status_code=204)
async def delete_source(source_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Source).where(Source.id == source_id))
    source = result.scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")

    await log_action(db, "delete", "source", source.id, {"name": source.name})
    await db.delete(source)
    await db.flush()
    return None
