from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings
from .models import Base


engine = create_async_engine(f"sqlite+aiosqlite:///{settings.db_path}", future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def session_scope():
    async with SessionLocal() as session:
        yield session


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session
