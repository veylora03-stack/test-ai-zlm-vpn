"""ERROR-PANEL — Async SQLAlchemy database configuration.

Uses aiosqlite driver for local-first SQLite storage.
Database file: backend/data/error.db
"""

import os
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

# Resolve database path relative to this file so it works regardless of CWD
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DB_DIR = os.path.join(_BASE_DIR, "data")
_DB_PATH = os.path.join(_DB_DIR, "error.db")

# Ensure the data directory exists
os.makedirs(_DB_DIR, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{_DB_PATH}"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency that yields an async database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_tables() -> None:
    """Create all tables if they do not exist (run on app startup)."""
    # Import models to register them with Base.metadata
    import backend.app.models  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def seed_settings_defaults() -> None:
    """Seed default settings if the settings table is empty."""
    import json
    from .models import Settings

    DEFAULTS = {
        "ranking_weights": json.dumps({
            "download": 0.35, "upload": 0.20,
            "ping": 0.20, "stability": 0.15, "security": 0.10,
        }),
        "test_attempts": "4",
        "test_timeout": "5.0",
        "test_concurrency": "5",
        "auto_refresh_seconds": "30",
    }

    async with async_session() as session:
        for key, value in DEFAULTS.items():
            result = await session.execute(
                __import__("sqlalchemy").select(Settings).where(Settings.key == key)
            )
            if result.scalar_one_or_none() is None:
                session.add(Settings(key=key, value=value))
        await session.commit()
