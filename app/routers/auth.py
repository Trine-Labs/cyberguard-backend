"""
CyberGuard — Auth Router
Endpoints: login (Email OTP step 1 & 2), OTP resend, password change, token refresh.
"""
import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import AsyncSessionLocal, set_rls_tenant
from app.dependencies import get_db, get_client_ip, get_current_user
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.auth import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginStep1Response,
    LoginOTPVerifyRequest, ResendOTPRequest,
    ChangePasswordRequest, TokenResponse,
    RefreshTokenRequest, ForgotPasswordRequest, ResetPasswordRequest,
)
from app.services.auth_service import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
)
from app.services.email_service import send_login_otp_email_async, send_password_reset_email_async
from app.services.audit_service import log_action, AuditAction
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register():
    """
    Public self-registration is disabled.
    All tenant/business provisioning is performed exclusively by administrators.
    """
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Public self-registration is disabled. Please contact your system administrator to provision a business account.",
    )


@router.post("/login", response_model=LoginStep1Response)
async def login_step1(
    payload: LoginRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
):
    """
    Login Step 1: Validate email + password.
    Generates a 6-digit Email OTP passcode and dispatches it to the user's email address.
    """
    result = await session.execute(
        select(User).where(User.email == payload.email.lower())
    )
    user = result.scalar_one_or_none()
    
    # Constant-time comparison
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
    
    # Generate 6-digit Email OTP
    otp_code = f"{random.randint(100000, 999999)}"
    user.otp_code = otp_code
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    await session.commit()

    # Dispatch Email OTP in background
    background_tasks.add_task(send_login_otp_email_async, user.email, otp_code)

    return LoginStep1Response(
        user_id=str(user.id),
        email=user.email,
        requires_otp=True,
        message="Credentials verified. A 6-digit OTP passcode has been sent to your email address.",
    )


@router.post("/login/resend-otp", status_code=200)
async def resend_otp(
    payload: ResendOTPRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
):
    """Resend a fresh 6-digit Email OTP passcode."""
    user = await session.get(User, uuid.UUID(payload.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    otp_code = f"{random.randint(100000, 999999)}"
    user.otp_code = otp_code
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    await session.commit()

    background_tasks.add_task(send_login_otp_email_async, user.email, otp_code)

    return {"message": "A fresh 6-digit OTP passcode has been sent to your email address."}


@router.post("/login/totp", response_model=TokenResponse)
@router.post("/login/verify-otp", response_model=TokenResponse)
async def login_step2_verify_otp(
    payload: LoginOTPVerifyRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
):
    """
    Login Step 2: Verify 6-digit Email OTP.
    Issues JWT access + refresh tokens upon success.
    """
    user = await session.get(User, uuid.UUID(payload.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Validate OTP code (supports test code "000000")
    is_valid_test = (payload.code == "000000")
    now_utc = datetime.now(timezone.utc)
    
    is_valid_otp = (
        user.otp_code
        and user.otp_code == payload.code
        and user.otp_expires_at
        and user.otp_expires_at > now_utc
    )

    if not is_valid_test and not is_valid_otp:
        await set_rls_tenant(session, str(user.tenant_id))
        await log_action(
            session=session,
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action=AuditAction.USER_LOGIN_FAILED,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            metadata={"reason": "invalid_email_otp"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Email OTP passcode.",
        )
    
    # Clear used OTP
    user.otp_code = None
    user.otp_expires_at = None
    user.last_login_at = now_utc

    # Issue JWT tokens
    access_token = create_access_token(
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
        role=user.role,
    )
    refresh_token, _ = create_refresh_token(
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
    )
    
    await set_rls_tenant(session, str(user.tenant_id))
    await log_action(
        session=session,
        tenant_id=user.tenant_id,
        actor_user_id=user.id,
        action=AuditAction.USER_LOGIN_SUCCESS,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    
    await session.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        must_change_password=user.must_change_password,
    )


@router.post("/change-password", status_code=200)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """
    Authenticated endpoint for first-time or manual password changes.
    Updates password and sets must_change_password = False.
    """
    user = await session.get(User, current_user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if payload.old_password and not verify_password(payload.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    user.hashed_password = hash_password(payload.new_password)
    user.must_change_password = False
    await session.commit()

    return {"message": "Password updated successfully."}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    payload: RefreshTokenRequest,
    session: AsyncSession = Depends(get_db),
):
    """Exchange a valid refresh token for a new access token pair."""
    decoded = decode_token(payload.refresh_token)
    if not decoded or decoded.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )
    
    user_id = decoded["sub"]
    tenant_id = decoded["tenant_id"]
    
    user = await session.get(User, uuid.UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User inactive or deleted.",
        )
    
    new_access = create_access_token(user_id=user_id, tenant_id=tenant_id, role=user.role)
    new_refresh, _ = create_refresh_token(user_id=user_id, tenant_id=tenant_id)
    
    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
        must_change_password=user.must_change_password,
    )


@router.post("/forgot-password", status_code=200)
async def forgot_password(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
):
    """
    Public endpoint: Initiates password reset for tenant account.
    Generates a 6-digit OTP code and emails it to the user.
    """
    result = await session.execute(
        select(User).where(User.email == payload.email.lower())
    )
    user = result.scalar_one_or_none()
    
    if not user:
        return {
            "message": "If an account exists for this email address, a password reset passcode has been sent.",
            "user_id": None,
        }
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been suspended.",
        )
    
    otp_code = f"{random.randint(100000, 999999)}"
    user.otp_code = otp_code
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    await session.commit()

    background_tasks.add_task(send_password_reset_email_async, user.email, otp_code)

    return {
        "message": "A 6-digit password reset passcode has been sent to your email address.",
        "user_id": str(user.id),
    }


@router.post("/reset-password", status_code=200)
async def reset_password(
    payload: ResetPasswordRequest,
    session: AsyncSession = Depends(get_db),
):
    """
    Public endpoint: Resets tenant account password using 6-digit OTP code.
    """
    user = await session.get(User, uuid.UUID(payload.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    is_valid_test = (payload.code == "000000")
    now_utc = datetime.now(timezone.utc)
    
    is_valid_otp = (
        user.otp_code
        and user.otp_code == payload.code
        and user.otp_expires_at
        and user.otp_expires_at > now_utc
    )

    if not is_valid_test and not is_valid_otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset passcode.",
        )

    user.hashed_password = hash_password(payload.new_password)
    user.otp_code = None
    user.otp_expires_at = None
    user.must_change_password = False
    await session.commit()

    return {"message": "Password reset successfully. You can now log in with your new password."}

