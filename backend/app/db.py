"""ERROR-PANEL — Async SQLAlchemy database configuration.

Uses aiosqlite driver for local-first SQLite storage.
Database file: backend/data/error_panel.db (centralized via core.paths)
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from backend.core.paths import DB_PATH, DATA_DIR
from backend.core.logger import logger

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Use the centralized DB_PATH from core.paths
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

logger.info(f"Database initialized at: {DB_PATH}")

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    connect_args={
        "timeout": 30.0,
        "check_same_thread": False,
    }
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

class Base(DeclarativeBase):
    pass

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()

async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def close_db():
    await engine.dispose()
