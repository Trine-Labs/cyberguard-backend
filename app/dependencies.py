"""FastAPI dependency injection — auth guard, DB session, tenant context."""
import uuid
from typing import Optional
from dataclasses import dataclass
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import AsyncSessionLocal, set_rls_tenant
from app.services.auth_service import decode_token
from app.models.user import User
from app.models.tenant import Tenant


security = HTTPBearer()


async def get_db():
    """Plain DB session without RLS (for auth endpoints before tenant is known)."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# TokenUser alias for backward compatibility across routers
TokenUser = User


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_db),
) -> User:
    """
    Auth guard: validates JWT token signature, then verifies that the user
    account and their organization tenant exist and are active in the database.
    If the account or organization has been deleted or suspended, raises 401.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication credentials are invalid, expired, or account no longer exists.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(credentials.credentials)
        user_id: str = payload.get("sub")
        tenant_id: str = payload.get("tenant_id")
        if not user_id or not tenant_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # 1. Fetch user from DB and check active status
    user_res = await session.execute(
        select(User).where(User.id == uuid.UUID(user_id))
    )
    user = user_res.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception

    # 2. Fetch tenant and verify it still exists and is not suspended
    tenant_res = await session.execute(
        select(Tenant).where(Tenant.id == uuid.UUID(tenant_id))
    )
    tenant = tenant_res.scalar_one_or_none()
    if tenant is None or tenant.status == "suspended":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your organization account has been removed or suspended.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Set RLS for this tenant
    await set_rls_tenant(session, str(tenant.id))

    return user


async def get_current_user_full(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_db),
) -> User:
    """
    Heavier auth guard that fetches the full User row from DB.
    Use this ONLY when you need fields not in the JWT (e.g. is_active check,
    totp_secret, last_login_at). Most endpoints should use get_current_user.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication credentials are invalid or expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(credentials.credentials)
        user_id: str = payload.get("sub")
        tenant_id: str = payload.get("tenant_id")
        if not user_id or not tenant_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Set RLS context for this session
    await set_rls_tenant(session, tenant_id)

    # Fetch and validate user
    result = await session.execute(
        select(User).where(User.id == uuid.UUID(user_id))
    )
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    if not user.is_totp_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA setup is required. Please complete TOTP verification.",
        )

    return user


async def get_current_tenant(
    current_user: TokenUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> Tenant:
    """Fetch the tenant record for the authenticated user."""
    await set_rls_tenant(session, current_user.tenant_id)
    result = await session.execute(
        select(Tenant).where(Tenant.id == current_user.tenant_id)
    )
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found.",
        )
    return tenant


def require_admin(current_user: TokenUser = Depends(get_current_user)) -> TokenUser:
    """Restrict endpoint to admin role only."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )
    return current_user


def get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP from request headers, respecting reverse proxies."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None
