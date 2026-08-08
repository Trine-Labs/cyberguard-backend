"""
CyberGuard — Admin Router
Endpoints for Platform Admin to login, manage Tenants/Businesses, default scan schedules,
upload Company Background Info (Data Training) for AI threat synthesis context, and perform clean tenant deletions.
"""
import uuid
from typing import Optional
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text, delete

from app.config import get_settings
from app.database import set_rls_tenant
from app.dependencies import get_db, get_client_ip
from app.models.tenant import Tenant
from app.models.user import User
from app.models.scope import ScanScope
from app.models.finding import Finding
from app.models.m365_credential import M365Credential
from app.models.m365_audit_log import M365AuditLog
from app.models.audit_trail import AuditTrail
from app.models.scan_job import ScanJob
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from app.schemas.admin import (
    TenantCreateRequest,
    TenantUpdateRequest,
    TenantResponse,
    TenantListResponse,
    AdminLoginRequest,
    AdminLoginResponse,
)
from app.services.auth_service import (
    hash_password,
    generate_totp_secret,
    validate_corporate_email,
    create_access_token,
)
from app.services.audit_service import log_action, AuditAction

settings = get_settings()
router = APIRouter(prefix="/api/v1/admin", tags=["Admin Panel"])
admin_bearer = HTTPBearer(auto_error=False)


def get_current_admin_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(admin_bearer),
) -> str:
    """
    Dependency guard enforcing Platform Admin authentication for all /api/v1/admin/* routes.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        if payload.get("role") != "platform_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Platform Admin privileges required.",
            )
        return payload.get("sub", "admin")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired admin authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/login", response_model=AdminLoginResponse)
async def admin_login(payload: AdminLoginRequest):
    """
    Platform Admin authentication endpoint.
    Validates username and password against env configuration (ADMIN_PORTAL_USERNAME / ADMIN_PORTAL_PASSWORD).
    Automatically picks up environment variable updates from .env.
    """
    get_settings.cache_clear()
    current_settings = get_settings()

    valid_username = (current_settings.admin_portal_username or "").strip()
    valid_password = (current_settings.admin_portal_password or "").strip()

    req_username = (payload.username or "").strip()
    req_password = (payload.password or "").strip()

    if req_username != valid_username or req_password != valid_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin portal credentials.",
        )

    # Issue Admin JWT token (expires in 24 hours)
    access_token = create_access_token(
        user_id=req_username,
        tenant_id="00000000-0000-0000-0000-000000000000",
        role="platform_admin",
        expires_delta=timedelta(hours=24),
    )

    return AdminLoginResponse(
        access_token=access_token,
        token_type="bearer",
        admin_username=req_username,
    )


@router.get("/tenants", response_model=TenantListResponse)
async def list_tenants(
    search: Optional[str] = Query(None, description="Filter by business name or email"),
    status_filter: Optional[str] = Query(None, alias="status"),
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """
    List all registered businesses / tenants in CyberGuard.
    Includes user counts, scope counts, scan frequency, and AI data training status.
    """
    query = select(Tenant)
    if status_filter:
        query = query.where(Tenant.status == status_filter)
    if search:
        s = f"%{search.strip()}%"
        query = query.where(
            (Tenant.org_name.ilike(s)) | (Tenant.contact_email.ilike(s))
        )
    query = query.order_by(Tenant.created_at.desc())
    
    result = await session.execute(query)
    tenants = result.scalars().all()
    
    response_items = []
    for t in tenants:
        # Get user count
        u_res = await session.execute(
            select(func.count(User.id)).where(User.tenant_id == t.id)
        )
        user_count = u_res.scalar() or 0
        
        # Get scope count
        s_res = await session.execute(
            select(func.count(ScanScope.id)).where(ScanScope.tenant_id == t.id)
        )
        scope_count = s_res.scalar() or 0

        # Fallback to user email if contact_email is missing
        contact_email = t.contact_email
        if not contact_email:
            u_email_res = await session.execute(
                select(User.email).where(User.tenant_id == t.id).order_by(User.created_at.asc())
            )
            contact_email = u_email_res.scalar() or None
        
        response_items.append(
            TenantResponse(
                id=t.id,
                org_name=t.org_name,
                contact_email=contact_email,
                company_info=t.company_info,
                scan_frequency=t.scan_frequency or "daily",
                status=t.status,
                onboarding_step=t.onboarding_step,
                user_count=user_count,
                scope_count=scope_count,
                created_at=t.created_at,
                updated_at=t.updated_at,
            )
        )
        
    return TenantListResponse(tenants=response_items, total=len(response_items))


from app.services.email_service import send_tenant_welcome_email_async

@router.post("/tenants", response_model=TenantResponse, status_code=201)
async def create_tenant(
    payload: TenantCreateRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """
    Create a new Business / Tenant from Admin Panel:
    - Sets business name, email, credentials, scan schedule frequency.
    - Uploads Company Background Info (Data Training) used for automatic AI synthesis context.
    - Provisions initial Tenant Admin account with mandatory first-time password change.
    - Dispatches welcome email with credentials to the contact email.
    """
    # Enforce email format validation
    if not validate_corporate_email(payload.contact_email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Valid primary contact email address required.",
        )

    # Check duplicate email
    existing_user = await session.execute(
        select(User).where(User.email == payload.contact_email.lower())
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this contact email address already exists.",
        )

    # Create tenant
    tenant = Tenant(
        org_name=payload.org_name.strip(),
        contact_email=payload.contact_email.lower().strip(),
        company_info=payload.company_info.strip() if payload.company_info else None,
        scan_frequency=payload.scan_frequency or "daily",
        status="active",
        onboarding_step=3,
    )
    session.add(tenant)
    await session.flush()

    # Generate TOTP secret
    totp_secret = generate_totp_secret()

    # Create initial admin user
    user = User(
        tenant_id=tenant.id,
        email=payload.contact_email.lower().strip(),
        hashed_password=hash_password(payload.admin_password),
        totp_secret=totp_secret,
        is_totp_enabled=True,
        is_totp_verified=True,
        must_change_password=True,  # Mandatory password change upon first login
        role="admin",
    )
    session.add(user)
    await session.flush()

    # Set RLS context & audit log
    await set_rls_tenant(session, str(tenant.id))
    await log_action(
        session=session,
        tenant_id=tenant.id,
        actor_user_id=user.id,
        action=AuditAction.TENANT_CREATED,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    await session.commit()

    # Dispatch welcome email with credentials to business email
    background_tasks.add_task(
        send_tenant_welcome_email_async,
        user.email,
        tenant.org_name,
        payload.admin_password,
    )

    return TenantResponse(
        id=tenant.id,
        org_name=tenant.org_name,
        contact_email=tenant.contact_email,
        company_info=tenant.company_info,
        scan_frequency=tenant.scan_frequency,
        status=tenant.status,
        onboarding_step=tenant.onboarding_step,
        user_count=1,
        scope_count=0,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant_detail(
    tenant_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """Get single tenant details."""
    res = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    u_res = await session.execute(
        select(func.count(User.id)).where(User.tenant_id == tenant.id)
    )
    user_count = u_res.scalar() or 0

    s_res = await session.execute(
        select(func.count(ScanScope.id)).where(ScanScope.tenant_id == tenant.id)
    )
    scope_count = s_res.scalar() or 0

    contact_email = tenant.contact_email
    if not contact_email:
        u_email_res = await session.execute(
            select(User.email).where(User.tenant_id == tenant.id).order_by(User.created_at.asc())
        )
        contact_email = u_email_res.scalar() or None

    return TenantResponse(
        id=tenant.id,
        org_name=tenant.org_name,
        contact_email=contact_email,
        company_info=tenant.company_info,
        scan_frequency=tenant.scan_frequency or "daily",
        status=tenant.status,
        onboarding_step=tenant.onboarding_step,
        user_count=user_count,
        scope_count=scope_count,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.put("/tenants/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: uuid.UUID,
    payload: TenantUpdateRequest,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """
    Update tenant business profile, scan schedule frequency, AI data training context, or password.
    """
    res = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    if payload.org_name is not None:
        tenant.org_name = payload.org_name.strip()
    if payload.contact_email is not None:
        tenant.contact_email = payload.contact_email.lower().strip()
    if payload.scan_frequency is not None:
        tenant.scan_frequency = payload.scan_frequency
    if payload.company_info is not None:
        tenant.company_info = payload.company_info.strip() if payload.company_info else None
    if payload.status is not None:
        tenant.status = payload.status

    # Update primary user password if provided
    if payload.admin_password:
        u_res = await session.execute(
            select(User).where(User.tenant_id == tenant.id).order_by(User.created_at.asc())
        )
        user = u_res.scalars().first()
        if user:
            user.hashed_password = hash_password(payload.admin_password)

    await session.commit()
    return await get_tenant_detail(tenant_id, session, admin_user)


@router.patch("/tenants/{tenant_id}/status", response_model=TenantResponse)
async def toggle_tenant_status(
    tenant_id: uuid.UUID,
    status_val: str = Query(..., alias="status", description="active or suspended"),
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """Toggle tenant active or suspended status."""
    res = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    tenant.status = status_val
    await session.commit()

    return await get_tenant_detail(tenant_id, session, admin_user)


@router.delete("/tenants/{tenant_id}", status_code=200)
async def delete_tenant(
    tenant_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """
    Permanently delete a Business Tenant and all associated records (users, findings, scopes, credentials, scan jobs, audit trail).
    Protected with RLS bypass session handling.
    """
    res = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    org_name = tenant.org_name
    tid_str = str(tenant_id)

    # Set RLS bypass for full cascade delete
    await session.execute(text("SET LOCAL app.current_tenant_id = 'bypass'"))

    # Cascade delete all associated records
    await session.execute(text("DELETE FROM audit_trail WHERE tenant_id = :tid OR actor_user_id IN (SELECT id FROM users WHERE tenant_id = :tid)"), {"tid": tid_str})
    await session.execute(text("DELETE FROM findings WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM scan_scopes WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM m365_audit_logs WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM m365_credentials WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM easm_ports WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM easm_certificates WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM easm_assets WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM scan_jobs WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM users WHERE tenant_id = :tid"), {"tid": tid_str})
    await session.execute(text("DELETE FROM tenants WHERE id = :tid"), {"tid": tid_str})

    await session.commit()

    return {
        "message": f"Tenant '{org_name}' and all associated records deleted successfully.",
        "tenant_id": tid_str,
    }
