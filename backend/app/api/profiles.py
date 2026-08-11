"""ERROR-PANEL — API: Profiles CRUD with filters.

GET    /api/profiles/       — list profiles (filters: status, protocol, search)
POST   /api/profiles/       — create a profile
GET    /api/profiles/{id}   — get profile by id
PATCH  /api/profiles/{id}   — update profile
DELETE /api/profiles/{id}   — delete profile
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..models import Profile
from ..schemas import ProfileCreate, ProfileResponse, ProfileUpdate
from ..services.audit import log_action

router = APIRouter(prefix="/api/profiles", tags=["profiles"])


@router.get("/", response_model=list[ProfileResponse])
async def list_profiles(
    status: str | None = Query(None, description="Filter by profile status"),
    protocol: str | None = Query(None, description="Filter by protocol"),
    search: str | None = Query(None, description="Search in profile name (case-insensitive)"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Profile).order_by(Profile.id)

    if status is not None:
        stmt = stmt.where(Profile.status == status)
    if protocol is not None:
        stmt = stmt.where(Profile.protocol == protocol)
    if search is not None:
        stmt = stmt.where(Profile.name.ilike(f"%{search}%"))

    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/", response_model=ProfileResponse, status_code=201)
async def create_profile(body: ProfileCreate, db: AsyncSession = Depends(get_db)):
    profile = Profile(**body.model_dump())
    db.add(profile)
    await db.flush()
    await db.refresh(profile)
    await log_action(
        db,
        "create",
        "profile",
        profile.id,
        {"name": profile.name, "protocol": profile.protocol, "status": profile.status},
    )
    return profile


@router.get("/{profile_id}", response_model=ProfileResponse)
async def get_profile(profile_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.patch("/{profile_id}", response_model=ProfileResponse)
async def update_profile(
    profile_id: int, body: ProfileUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(profile, field, value)

    await db.flush()
    await db.refresh(profile)
    await log_action(
        db,
        "update",
        "profile",
        profile.id,
        {"updated_fields": list(update_data.keys())},
    )
    return profile


@router.delete("/{profile_id}", status_code=204)
async def delete_profile(profile_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    await log_action(db, "delete", "profile", profile.id, {"name": profile.name})
    await db.delete(profile)
    await db.flush()
    return None
