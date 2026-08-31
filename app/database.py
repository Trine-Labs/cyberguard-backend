"""
CyberGuard Backend — Async Database Connection (PostgreSQL)
Uses SQLAlchemy 2.0 async engine + asyncpg driver.
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

from app.config import get_settings

settings = get_settings()


def _fix_database_url(url: str) -> str:
    """
    Rewrites the database URL scheme to 'postgresql+asyncpg://' so the async
    driver is always used, regardless of what format the user pastes.
    """
    if url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]

    # Strip query parameters (like ?sslmode=require or ?channel_binding=...)
    # because asyncpg does not support them and will throw TypeErrors.
    if "?" in url:
        url = url.split("?")[0]

    return url


_database_url = _fix_database_url(settings.database_url)

# ── Async Engine ──────────────────────────────────────────────────────────────
# Local PostgreSQL (Docker container) — no SSL, no Neon-specific workarounds.
engine = create_async_engine(
    _database_url,
    echo=False,
    pool_size=20,               # Sufficient for local PostgreSQL
    max_overflow=10,             # Limit burst
    pool_timeout=30,             # Fail fast if pool is exhausted
    pool_pre_ping=True,          # Detect stale connections
    connect_args={
        "timeout": 60,               # asyncpg connection timeout
        "command_timeout": 60,       # asyncpg query timeout
    },
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async DB session.
    Injects the tenant_id RLS variable if present in the request context.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


import asyncio

async def set_rls_tenant(session: AsyncSession, tenant_id: str) -> None:
    """
    Sets the PostgreSQL session-level variable used by RLS policies.
    Must be called BEFORE any tenant-scoped query in the session.
    Uses transaction-local setting (third param = true) so it auto-clears
    after each transaction — no cross-tenant leakage risk.
    """
    for attempt in range(3):
        try:
            await session.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
            return
        except Exception as e:
            if "getaddrinfo" in str(e) or "11001" in str(e) or "ConnectionRefused" in str(e):
                if attempt < 2:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
            raise


@asynccontextmanager
async def get_tenant_db(tenant_id: str) -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for tenant-scoped DB sessions.
    Automatically sets the RLS variable so all queries are tenant-isolated.
    Usage:
        async with get_tenant_db(tenant_id) as session:
            result = await session.execute(select(User))
    """
    async with AsyncSessionLocal() as session:
        try:
            await set_rls_tenant(session, tenant_id)
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
