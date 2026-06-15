"""
CyberGuard — Auth Router
Endpoints: register, TOTP setup verification, login (2-step), token refresh.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import AsyncSessionLocal, set_rls_tenant
from app.dependencies import get_db, get_client_ip
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.auth import (
    RegisterRequest, RegisterResponse,
    TOTPVerifyRequest,
    LoginRequest, LoginStep1Response,
    LoginTOTPRequest, TokenResponse,
    RefreshTokenRequest,
)
from app.services.auth_service import (
    hash_password, verify_password,
    generate_totp_secret, generate_totp_qr_base64,
    verify_totp_code,
    create_access_token, create_refresh_token, decode_token,
    validate_corporate_email,
)
from app.services.audit_service import log_action, AuditAction
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    payload: RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    Step 1 of 2 for account creation.
    Creates tenant + user, generates TOTP secret, returns QR code.
    Account is NOT usable until TOTP is verified via /verify-totp.
    """
    # Enforce corporate email
    if not validate_corporate_email(payload.email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Public email providers are not permitted. "
                "Please use your corporate email address."
            ),
        )
    
    # Check for duplicate email
    existing = await session.execute(
        select(User).where(User.email == payload.email.lower())
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )
    
    # Create tenant
    tenant = Tenant(org_name=payload.org_name.strip())
    session.add(tenant)
    await session.flush()  # Get tenant.id before user insert
    
    # Generate TOTP secret
    totp_secret = generate_totp_secret()
    
    # Create user
    user = User(
        tenant_id=tenant.id,
        email=payload.email.lower().strip(),
        hashed_password=hash_password(payload.password),
        totp_secret=totp_secret,
        is_totp_enabled=True,
        is_totp_verified=False,
        role="admin",
    )
    session.add(user)
    await session.flush()
    
    # Set RLS context for audit log
    await set_rls_tenant(session, str(tenant.id))
    
    # Log the event
    await log_action(
        session=session,
        tenant_id=tenant.id,
        actor_user_id=user.id,
        action=AuditAction.USER_REGISTERED,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        metadata={"email": payload.email, "org_name": payload.org_name},
    )
    
    # Generate QR code
    qr_code = generate_totp_qr_base64(email=user.email, secret=totp_secret)
    
    return RegisterResponse(
        user_id=str(user.id),
        tenant_id=str(tenant.id),
        email=user.email,
        totp_secret=totp_secret,
        totp_qr_code=qr_code,
    )


@router.post("/verify-totp", status_code=200)
async def verify_totp_setup(
    payload: TOTPVerifyRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    Step 2 of registration: Verify the TOTP code scanned from QR.
    Marks the user as fully activated.
    """
    user = await session.get(User, uuid.UUID(payload.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    if user.is_totp_verified:
        raise HTTPException(status_code=409, detail="TOTP already verified for this account.")
    
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP is not configured for this user.")
    
    if not verify_totp_code(secret=user.totp_secret, code=payload.code):
        # Set RLS before audit log
        await set_rls_tenant(session, str(user.tenant_id))
        await log_action(
            session=session,
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action=AuditAction.USER_TOTP_FAILED,
            ip_address=get_client_ip(request),
            metadata={"step": "setup_verification"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code. Please check your authenticator app and try again.",
        )
    
    # Mark as verified
    user.is_totp_verified = True
    
    await set_rls_tenant(session, str(user.tenant_id))
    await log_action(
        session=session,
        tenant_id=user.tenant_id,
        actor_user_id=user.id,
        action=AuditAction.USER_TOTP_VERIFIED,
        ip_address=get_client_ip(request),
    )
    
    return {"message": "MFA successfully activated. You may now log in."}


@router.post("/login", response_model=LoginStep1Response)
async def login_step1(
    payload: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    Login Step 1: Validate email + password.
    Returns a temporary user_id for the TOTP challenge step.
    Does NOT issue a JWT yet.
    """
    result = await session.execute(
        select(User).where(User.email == payload.email.lower())
    )
    user = result.scalar_one_or_none()
    
    # Constant-time comparison to prevent user enumeration
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been suspended.",
        )
    
    if not user.is_totp_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please complete MFA setup before logging in.",
        )
    
    return LoginStep1Response(user_id=str(user.id))


@router.post("/login/totp", response_model=TokenResponse)
async def login_step2_totp(
    payload: LoginTOTPRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    Login Step 2: Verify TOTP code.
    Issues JWT access + refresh tokens upon success.
    """
    user = await session.get(User, uuid.UUID(payload.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    if not verify_totp_code(secret=user.totp_secret, code=payload.code):
        await set_rls_tenant(session, str(user.tenant_id))
        await log_action(
            session=session,
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action=AuditAction.USER_LOGIN_FAILED,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"reason": "invalid_totp"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authenticator code.",
        )
    
    # Issue tokens
    access_token = create_access_token(
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
        role=user.role,
    )
    refresh_token, _ = create_refresh_token(
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
    )
    
    # Update last login
    user.last_login_at = datetime.now(timezone.utc)
    
    await set_rls_tenant(session, str(user.tenant_id))
    await log_action(
        session=session,
        tenant_id=user.tenant_id,
        actor_user_id=user.id,
        action=AuditAction.USER_LOGIN_SUCCESS,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )
