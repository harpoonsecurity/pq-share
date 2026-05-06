from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings
from .models import Base


engine = create_async_engine(f"sqlite+aiosqlite:///{settings.db_path}", future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


# Lightweight in-place migrations. Each entry is (table, column, full DDL fragment).
# SQLite supports ADD COLUMN, so introducing a nullable column on an existing
# table is safe and idempotent. New tables are still created via metadata.create_all.
_PENDING_COLUMNS: list[tuple[str, str, str]] = [
    ("files", "suite_json",       "TEXT"),
    ("users", "pub_secp384r1",    "BLOB"),
    ("users", "pub_ecdsap384",    "BLOB"),
    ("users", "pub_mlkem1024",    "BLOB"),
    ("users", "pub_mldsa87",      "BLOB"),
    ("users", "wrapped_recovery_key", "BLOB"),
]


async def _apply_column_additions(conn) -> None:
    for table, column, ddl in _PENDING_COLUMNS:
        rows = await conn.execute(text(f"PRAGMA table_info({table})"))
        existing = {row[1] for row in rows.fetchall()}
        if column not in existing:
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _apply_column_additions(conn)


@asynccontextmanager
async def session_scope():
    async with SessionLocal() as session:
        yield session


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session
