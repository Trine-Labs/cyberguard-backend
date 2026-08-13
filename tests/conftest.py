"""
CyberGuard Backend Test Infrastructure & Fixtures (conftest.py)
"""
import uuid
import pytest
import pytest_asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from sqlalchemy.pool import NullPool

from app.main import app
from app.database import AsyncSessionLocal, _database_url
from app.models.tenant import Tenant
from app.models.user import User
from app.services.auth_service import create_access_token, hash_password

from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend

from app.dependencies import get_db

import app.database as app_db

FastAPICache.init(InMemoryBackend(), prefix="fastapi-cache-test")

test_engine = create_async_engine(_database_url, poolclass=NullPool)
TestSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

app_db.engine = test_engine
app_db.AsyncSessionLocal = TestSessionLocal

async def _override_get_db():
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

app.dependency_overrides[get_db] = _override_get_db


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Yields an isolated AsyncSession for database test operations.
    Rolls back uncommitted changes upon test completion.
    """
    async with TestSessionLocal() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()


@pytest_asyncio.fixture(scope="function")
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """
    Async HTTP client for FastAPI endpoint integration testing.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def test_tenant_data(db_session: AsyncSession):
    """
    Creates a temporary test Tenant and Admin User in the database,
    returning token, tenant_id, and user_id.
    """
    tenant_name = f"TestCorp_{uuid.uuid4().hex[:6]}"
    domain = f"testcorp_{uuid.uuid4().hex[:6]}.com"
    user_email = f"admin@{domain}"
    
    tenant = Tenant(
        org_name=tenant_name,
        contact_email=user_email,
        status="active"
    )
    db_session.add(tenant)
    await db_session.flush()
    user = User(
        tenant_id=tenant.id,
        email=user_email,
        hashed_password=hash_password("TestPassword123!"),
        role="admin",
        is_active=True,
        is_totp_verified=True
    )
    db_session.add(user)
    await db_session.commit()

    token = create_access_token(
        user_id=str(user.id),
        tenant_id=str(tenant.id),
        role=user.role
    )

    return {
        "tenant": tenant,
        "user": user,
        "tenant_id": tenant.id,
        "user_id": user.id,
        "token": token,
        "domain": domain,
        "headers": {"Authorization": f"Bearer {token}"}
    }
