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
from sqlalchemy import select, func, text, delete, and_, or_

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
    TenantStatsResponse,
    AdminLoginRequest,
    AdminLoginResponse,
    AdminScopeCreateRequest,
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
    # Compute global stats across all tenants (unfiltered)
    all_tenants_res = await session.execute(select(Tenant.status))
    all_statuses = all_tenants_res.scalars().all()
    stats = TenantStatsResponse(
        total_tenants=len(all_statuses),
        active_tenants=sum(1 for s in all_statuses if s == "active"),
        onboarding_tenants=sum(1 for s in all_statuses if s == "onboarding"),
        suspended_tenants=sum(1 for s in all_statuses if s == "suspended"),
    )

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
                default_language=getattr(t, "default_language", "en") or "en",
                status=t.status,
                onboarding_step=t.onboarding_step,
                user_count=user_count,
                scope_count=scope_count,
                created_at=t.created_at,
                updated_at=t.updated_at,
            )
        )
        
    return TenantListResponse(tenants=response_items, total=len(response_items), stats=stats)


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
    - Sets business name, email, credentials, scan schedule frequency, default language.
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

    # Create tenant initialized in onboarding state at Step 1
    tenant = Tenant(
        org_name=payload.org_name.strip(),
        contact_email=payload.contact_email.lower().strip(),
        company_info=payload.company_info.strip() if payload.company_info else None,
        scan_frequency=payload.scan_frequency or "daily",
        default_language=(payload.default_language or "en").lower().strip(),
        status="onboarding",
        onboarding_step=1,
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
        default_language=tenant.default_language or "en",
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
        default_language=getattr(tenant, "default_language", "en") or "en",
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
    Update tenant business profile, scan schedule frequency, AI data training context, default language, or password.
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
    if payload.default_language is not None:
        tenant.default_language = payload.default_language.lower().strip()
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


@router.get("/tenants/{tenant_id}/overview")
async def get_admin_tenant_overview(
    tenant_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """
    Returns complete security profile and telemetry for an organization:
    - Metadata (org_name, email, status, schedule, AI data context)
    - Active findings matrix & vulnerabilities
    - Discovered EASM attack surface assets & subdomains
    - Configured scan scope domains
    - Recent scan jobs and telemetry
    """
    await session.execute(text("SET LOCAL app.current_tenant_id = 'bypass'"))

    res = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    tid_str = str(tenant_id)

    # 1. Fetch scopes
    scopes_res = await session.execute(
        select(ScanScope).where(ScanScope.tenant_id == tenant_id).order_by(ScanScope.created_at.desc())
    )
    scopes = [
        {
            "id": str(s.id),
            "type": s.type,
            "value": s.value,
            "verified": s.verified,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scopes_res.scalars().all()
    ]

    # 2. Fetch EASM assets
    assets_res = await session.execute(
        select(EasmAsset).where(EasmAsset.tenant_id == tenant_id).order_by(EasmAsset.hostname.asc())
    )
    assets_list = []
    for a in assets_res.scalars().all():
        import json
        tech_list = []
        for item in (a.tech_stack or []):
            try:
                obj = json.loads(item)
                tech_list.append(f"{obj['name']} {obj.get('version', '')}".strip())
            except Exception:
                tech_list.append(item)

        assets_list.append({
            "id": str(a.id),
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "http_status": a.http_status,
            "asset_type": a.asset_type,
            "tech_stack": tech_list,
            "sec_headers_grade": a.sec_headers_grade,
            "cve_count": a.cve_count or 0,
            "is_exposed_admin": a.is_exposed_admin,
            "discovered_at": a.discovered_at.isoformat() if a.discovered_at else None,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        })

    # 3. Fetch Findings
    findings_res = await session.execute(
        select(Finding).where(Finding.tenant_id == tenant_id).order_by(Finding.created_at.desc())
    )
    findings_list = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_res.scalars().all():
        sev = (f.severity or "medium").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        findings_list.append({
            "id": str(f.id),
            "issue_type": f.issue_type,
            "severity": f.severity,
            "status": f.status,
            "entity": f.entity,
            "source": f.source,
            "evidence": f.evidence or {},
            "tags": f.tags or [],
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    # 4. Fetch Scan Jobs
    jobs_res = await session.execute(
        select(ScanJob).where(ScanJob.tenant_id == tenant_id).order_by(ScanJob.created_at.desc()).limit(15)
    )
    jobs_list = []
    for j in jobs_res.scalars().all():
        meta = j.metadata_ or {}
        duration = 0
        if j.started_at:
            end_t = j.completed_at if j.completed_at else datetime.now(timezone.utc)
            duration = max(0, int((end_t - j.started_at).total_seconds()))
        jobs_list.append({
            "id": str(j.id),
            "job_type": j.job_type,
            "status": j.status,
            "duration_seconds": duration,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "targets": meta.get("targets", []),
            "error_message": j.error_message,
        })

    # Fallback to user email if contact_email is missing
    contact_email = tenant.contact_email
    if not contact_email:
        u_email_res = await session.execute(
            select(User.email).where(User.tenant_id == tenant.id).order_by(User.created_at.asc())
        )
        contact_email = u_email_res.scalar() or None

    return {
        "tenant": {
            "id": tid_str,
            "org_name": tenant.org_name,
            "contact_email": contact_email,
            "company_info": tenant.company_info,
            "scan_frequency": tenant.scan_frequency or "daily",
            "default_language": getattr(tenant, "default_language", "en") or "en",
            "status": tenant.status,
            "onboarding_step": tenant.onboarding_step,
            "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
        },
        "stats": {
            "total_findings": len(findings_list),
            "critical_findings": sev_counts["critical"],
            "high_findings": sev_counts["high"],
            "medium_findings": sev_counts["medium"],
            "low_findings": sev_counts["low"],
            "total_assets": len(assets_list),
            "total_scopes": len(scopes),
            "last_scan_at": jobs_list[0]["created_at"] if jobs_list else None,
        },
        "scopes": scopes,
        "assets": assets_list,
        "findings": findings_list,
        "scan_jobs": jobs_list,
    }


@router.post("/tenants/{tenant_id}/scopes", status_code=201)
async def add_admin_tenant_scope(
    tenant_id: uuid.UUID,
    payload: AdminScopeCreateRequest,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """Add a new domain scan scope to a business tenant from Platform Admin."""
    await session.execute(text("SET LOCAL app.current_tenant_id = 'bypass'"))

    res = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    domain_val = payload.value.strip().lower()
    if domain_val.startswith("https://"):
        domain_val = domain_val[8:]
    elif domain_val.startswith("http://"):
        domain_val = domain_val[7:]
    domain_val = domain_val.rstrip("/")

    # Check duplicate
    existing = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.tenant_id == tenant_id,
                ScanScope.value == domain_val,
                ScanScope.type == payload.type,
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Scope '{domain_val}' already exists for this tenant.")

    new_scope = ScanScope(
        tenant_id=tenant_id,
        type=payload.type,
        value=domain_val,
        verified=True,
    )
    session.add(new_scope)
    await session.commit()

    return {
        "id": str(new_scope.id),
        "type": new_scope.type,
        "value": new_scope.value,
        "verified": new_scope.verified,
        "created_at": new_scope.created_at.isoformat() if new_scope.created_at else None,
    }


@router.delete("/tenants/{tenant_id}/scopes/{scope_id}", status_code=200)
async def delete_admin_tenant_scope(
    tenant_id: uuid.UUID,
    scope_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """Delete a domain scan scope from a business tenant."""
    await session.execute(text("SET LOCAL app.current_tenant_id = 'bypass'"))

    res = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.id == scope_id,
                ScanScope.tenant_id == tenant_id,
            )
        )
    )
    scope = res.scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found for this tenant.")

    await session.delete(scope)
    await session.commit()

    return {"message": f"Scope '{scope.value}' removed successfully.", "scope_id": str(scope_id)}


@router.post("/tenants/{tenant_id}/scan", status_code=200)
async def trigger_admin_tenant_scan(
    tenant_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """
    Trigger dedicated EASM perimeter scan for a specific business tenant from Platform Admin.
    Reads configured scan scopes and automatically launches the EASM discovery pipeline.
    """
    from app.services.easm_scanner import run_easm_scan

    await session.execute(text("SET LOCAL app.current_tenant_id = 'bypass'"))

    res = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    tid_str = str(tenant_id)

    # 1. Fetch tenant domain scopes
    scopes_res = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.tenant_id == tenant_id,
                ScanScope.type == "domain",
            )
        )
    )
    scopes = scopes_res.scalars().all()
    domain_targets = [s.value.strip().lower() for s in scopes if s.value and s.value.strip()]

    # 2. Fallback: If no explicit scope, check existing discovered assets for root domain
    if not domain_targets:
        assets_res = await session.execute(
            select(EasmAsset.hostname).where(EasmAsset.tenant_id == tenant_id).limit(10)
        )
        for h in assets_res.scalars().all():
            parts = h.strip().lower().split('.')
            if len(parts) >= 2:
                base_d = ".".join(parts[-2:])
                if base_d not in domain_targets:
                    domain_targets.append(base_d)
                    new_scope = ScanScope(
                        tenant_id=tenant_id,
                        type="domain",
                        value=base_d,
                        verified=True,
                    )
                    session.add(new_scope)
        if domain_targets:
            await session.commit()

    # 3. Fallback: Corporate email domain
    if not domain_targets and tenant.contact_email and "@" in tenant.contact_email:
        email_domain = tenant.contact_email.split("@")[-1].strip().lower()
        blocked_domains = [d.strip().lower() for d in settings.blocked_email_domains.split(",") if d.strip()]
        if email_domain not in blocked_domains:
            domain_targets = [email_domain]
            new_scope = ScanScope(
                tenant_id=tenant_id,
                type="domain",
                value=email_domain,
                verified=True,
            )
            session.add(new_scope)
            await session.commit()

    if not domain_targets:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot scan '{tenant.org_name}': No target domains configured. Please click on this organization and add a domain scope (e.g. somathes.ma or somathes.com).",
        )

    job_id = uuid.uuid4()
    background_tasks.add_task(run_easm_scan, tid_str, domain_targets, None, job_id)

    return {
        "message": f"Dedicated EASM perimeter scan started for '{tenant.org_name}'.",
        "tenant_id": tid_str,
        "job_id": str(job_id),
        "targets": domain_targets,
    }


@router.get("/scan-jobs")
async def get_admin_global_scan_jobs(
    limit: int = 100,
    offset: int = 0,
    tenant_id: Optional[str] = Query(None),
    job_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    session: AsyncSession = Depends(get_db),
    admin_user: str = Depends(get_current_admin_user),
):
    """
    Returns global scan jobs across ALL tenants for Platform Admins.
    Supports multi-tenant filtering, sorting, searching, and summary stats.
    """
    await session.execute(text("SET LOCAL app.current_tenant_id = 'bypass'"))

    tenants_res = await session.execute(
        select(Tenant.id, Tenant.org_name, Tenant.contact_email).order_by(Tenant.org_name)
    )
    tenants_list = [
        {"id": str(t.id), "org_name": t.org_name, "contact_email": t.contact_email}
        for t in tenants_res.all()
    ]

    query = select(ScanJob, Tenant.org_name, Tenant.contact_email).outerjoin(
        Tenant, ScanJob.tenant_id == Tenant.id
    )

    if tenant_id and tenant_id != "all":
        try:
            t_uuid = uuid.UUID(tenant_id)
            query = query.where(ScanJob.tenant_id == t_uuid)
        except ValueError:
            pass

    if job_type and job_type != "all":
        query = query.where(ScanJob.job_type == job_type)

    if status and status != "all":
        query = query.where(ScanJob.status == status)

    if sort_by == "duration":
        sort_col = (ScanJob.completed_at - ScanJob.started_at)
    elif sort_by == "status":
        sort_col = ScanJob.status
    elif sort_by == "tenant_name":
        sort_col = Tenant.org_name
    else:
        sort_col = ScanJob.created_at

    if sort_order == "asc":
        query = query.order_by(sort_col.asc().nulls_last())
    else:
        query = query.order_by(sort_col.desc().nulls_last())

    result = await session.execute(query.limit(limit).offset(offset))
    rows = result.all()

    all_summary_res = await session.execute(
        select(
            func.count(ScanJob.id).label("total_scans"),
            func.count(func.nullif(ScanJob.status != 'completed', True)).label("completed_scans"),
            func.count(func.nullif(ScanJob.status != 'failed', True)).label("failed_scans"),
            func.count(func.nullif(~ScanJob.status.in_(['running', 'queued']), True)).label("active_scans"),
            func.count(func.distinct(ScanJob.tenant_id)).label("unique_tenants_scanned"),
            func.max(ScanJob.completed_at).label("last_scan_at")
        )
    )
    sum_row = all_summary_res.one()

    formatted_jobs = []
    for job, org_name, contact_email in rows:
        meta = job.metadata_ or {}
        duration = 0
        if job.started_at:
            end_t = job.completed_at if job.completed_at else datetime.now(timezone.utc)
            duration = max(0, int((end_t - job.started_at).total_seconds()))

        label_map = {
            "easm": "EASM Perimeter Scan",
            "m365": "Microsoft 365 Identity Sync",
            "baseline": "Security Baseline Audit",
        }

        formatted_jobs.append({
            "id": str(job.id),
            "tenant_id": str(job.tenant_id) if job.tenant_id else None,
            "tenant_name": org_name or "Unknown Tenant",
            "contact_email": contact_email or "N/A",
            "job_type": job.job_type,
            "job_type_label": label_map.get(job.job_type, job.job_type.upper()),
            "status": job.status,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "duration_seconds": duration,
            "error_message": job.error_message,
            "targets": meta.get("targets", []),
            "metadata": meta,
        })

    return {
        "jobs": formatted_jobs,
        "total": len(formatted_jobs),
        "tenants": tenants_list,
        "summary": {
            "total_scans": sum_row.total_scans or 0,
            "completed_scans": sum_row.completed_scans or 0,
            "failed_scans": sum_row.failed_scans or 0,
            "active_scans": sum_row.active_scans or 0,
            "unique_tenants_scanned": sum_row.unique_tenants_scanned or 0,
            "last_scan_at": sum_row.last_scan_at.isoformat() if sum_row.last_scan_at else None,
        }
    }
