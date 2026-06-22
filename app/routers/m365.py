"""
CyberGuard — Microsoft 365 Router
Endpoints: initiate OAuth consent, handle callback, vault token, status.
"""
import asyncio
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.dependencies import get_db, get_current_user, require_admin
from app.database import set_rls_tenant
from app.models.user import User
from app.models.tenant import Tenant
from app.models.m365_credential import M365Credential
from app.models.scan_job import ScanJob
from app.models.scope import ScanScope
from app.services.m365_service import build_admin_consent_url, exchange_code_for_tokens
from app.services.crypto_service import encrypt_token, EncryptedBlob
from app.services.audit_service import log_action, AuditAction
from app.services.easm_scanner import run_easm_scan
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/v1/m365", tags=["Microsoft 365"])

# In-memory state store for OAuth CSRF protection
# In production, use Redis: state -> tenant_id mapping with TTL
_oauth_state_store: dict[str, str] = {}


@router.get("/connect")
async def initiate_m365_connect(
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Generate the Microsoft Admin Consent URL.
    Returns the URL for the frontend to redirect to.
    The 'state' parameter prevents CSRF and ties the callback to this tenant.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    # Generate a secure random state token (CSRF protection)
    state = secrets.token_urlsafe(32)
    
    # Store state -> tenant_id mapping (TTL: 10 minutes)
    # TODO Phase 2: Move to Redis with TTL
    _oauth_state_store[state] = str(current_user.tenant_id)
    
    consent_url = build_admin_consent_url(state=state)
    
    await log_action(
        session=session,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action=AuditAction.M365_CONNECT_INITIATED,
    )
    
    return {"consent_url": consent_url}


@router.get("/callback")
async def m365_oauth_callback(
    request: Request,
    background_tasks: BackgroundTasks,
    code: str = Query(None, description="Authorization code from Microsoft"),
    state: str = Query(None, description="CSRF state token"),
    error: str = Query(None, description="OAuth error code"),
    error_description: str = Query(None, description="Human-readable error"),
    admin_consent: str = Query(None, description="Admin consent flag from Microsoft"),
    tenant: str = Query(None, alias="tenant", description="Microsoft tenant ID"),
    session: AsyncSession = Depends(get_db),
):
    """
    Microsoft redirects here after the admin grants/denies consent.
    Exchanges the authorization code for tokens, encrypts and vaults the refresh token.
    """
    # Handle OAuth errors
    if error:
        return RedirectResponse(
            url=f"{settings.frontend_url}/onboarding/m365?error={error}&description={error_description}"
        )
    
    # Validate state (CSRF check)
    if not state or state not in _oauth_state_store:
        return RedirectResponse(
            url=f"{settings.frontend_url}/onboarding/m365?error=invalid_state"
        )
    
    tenant_id = _oauth_state_store.pop(state)  # Consume state (one-time use)
    
    if not code:
        return RedirectResponse(
            url=f"{settings.frontend_url}/onboarding/m365?error=no_code"
        )
    
    try:
        # Exchange authorization code for tokens (server-to-server)
        token_data = await exchange_code_for_tokens(authorization_code=code)
        
        refresh_token_plaintext = token_data["refresh_token"]
        granted_scopes = token_data.get("scope", "").split()
        ms_tenant_id = tenant or "common"
        
        # Encrypt the refresh token immediately
        blob = encrypt_token(
            plaintext=refresh_token_plaintext,
            tenant_id=tenant_id,
        )
        
        # Zero out plaintext from memory (best effort in Python)
        del refresh_token_plaintext
        
        # Set RLS for this tenant
        await set_rls_tenant(session, tenant_id)
        
        # Upsert M365 credential record
        existing_result = await session.execute(
            select(M365Credential).where(M365Credential.tenant_id == tenant_id)
        )
        existing_cred = existing_result.scalar_one_or_none()
        
        if existing_cred:
            # Update existing credential
            existing_cred.encrypted_refresh_token = blob.ciphertext
            existing_cred.kms_key_id = blob.kms_key_id
            existing_cred.ms_tenant_id = ms_tenant_id
            existing_cred.granted_scopes = granted_scopes
            existing_cred.token_status = "active"
            existing_cred.connected_at = datetime.now(timezone.utc)
            existing_cred.revoked_at = None
        else:
            # Create new credential
            cred = M365Credential(
                tenant_id=tenant_id,
                ms_tenant_id=ms_tenant_id,
                encrypted_refresh_token=blob.ciphertext,
                kms_key_id=blob.kms_key_id,
                granted_scopes=granted_scopes,
                token_status="active",
            )
            session.add(cred)
        
        # Update tenant onboarding step
        db_tenant = await session.get(Tenant, tenant_id)
        if db_tenant and db_tenant.onboarding_step < 3:
            db_tenant.onboarding_step = 3
        
        # Queue baseline scan job
        scan_job = ScanJob(
            tenant_id=tenant_id,
            job_type="baseline",
            status="queued",
            metadata_={"triggered_by": "m365_onboarding"},
        )
        session.add(scan_job)
        
        # Advance onboarding step to 4 (done)
        if db_tenant:
            db_tenant.onboarding_step = 4
            db_tenant.status = "active"
        
        await log_action(
            session=session,
            tenant_id=tenant_id,
            action=AuditAction.M365_CONNECTED,
            metadata={"ms_tenant_id": ms_tenant_id, "scopes": granted_scopes},
        )
        
        await log_action(
            session=session,
            tenant_id=tenant_id,
            action=AuditAction.BASELINE_SCAN_QUEUED,
            metadata={"job_type": "baseline"},
        )
        
        await session.commit()

        # Trigger EASM scan for all verified domain scopes
        scopes_result = await session.execute(
            select(ScanScope).where(
                and_(
                    ScanScope.tenant_id == tenant_id,
                    ScanScope.type == "domain",
                )
            )
        )
        scope_values = [s.value for s in scopes_result.scalars().all()]
        if scope_values:
            background_tasks.add_task(run_easm_scan, tenant_id, scope_values)

    except ValueError as e:
        return RedirectResponse(
            url=f"{settings.frontend_url}/onboarding/m365?error=vault_failed&description={str(e)}"
        )
    except Exception as e:
        return RedirectResponse(
            url=f"{settings.frontend_url}/onboarding/m365?error=connection_failed&description={str(e)}"
        )
    
    # Redirect to dashboard on success
    return RedirectResponse(
        url=f"{settings.frontend_url}/dashboard?onboarding=complete&m365=connected"
    )


@router.get("/status")
async def get_m365_status(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Return the M365 connection status for the current tenant."""
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    result = await session.execute(
        select(M365Credential).where(
            M365Credential.tenant_id == current_user.tenant_id
        )
    )
    cred = result.scalar_one_or_none()
    
    if not cred:
        return {"connected": False, "status": None}
    
    return {
        "connected": cred.token_status == "active",
        "status": cred.token_status,
        "ms_tenant_id": cred.ms_tenant_id,
        "granted_scopes": cred.granted_scopes,
        "connected_at": cred.connected_at.isoformat() if cred.connected_at else None,
    }


@router.get("/hub")
async def get_m365_hub_state(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Return the M365 Hub state from the database. Trigger scan if empty."""
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    result = await session.execute(
        select(M365Credential).where(
            M365Credential.tenant_id == current_user.tenant_id
        )
    )
    cred = result.scalar_one_or_none()
    
    if not cred:
        return {"tenant_id": str(current_user.tenant_id), "users": [], "directory_roles": [], "ca_policies": [], "mfa_details": [], "oauth2_grants": [], "service_principals": [], "findings": []}
        
    state = cred.hub_state
    
    # If state is missing, trigger a background task to fetch it immediately
    if not state:
        from app.tasks.m365_scanner import run_m365_scan_background
        background_tasks.add_task(run_m365_scan_background, str(current_user.tenant_id))
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "users": [],
            "directory_roles": [],
            "ca_policies": [],
            "mfa_details": [],
            "oauth2_grants": [],
            "service_principals": [],
            "findings": []
        }
        
    return state


@router.delete("/disconnect")
async def disconnect_m365(
    request: Request,
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """
    Mark the M365 credential as revoked.
    Stops all future polling. Admin must re-authorize to reconnect.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))
    
    result = await session.execute(
        select(M365Credential).where(
            M365Credential.tenant_id == current_user.tenant_id
        )
    )
    cred = result.scalar_one_or_none()
    
    if not cred:
        raise HTTPException(status_code=404, detail="No M365 connection found.")
    
    cred.token_status = "revoked"
    cred.revoked_at = datetime.now(timezone.utc)
    
    await log_action(
        session=session,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action=AuditAction.M365_TOKEN_REVOKED,
        metadata={"ms_tenant_id": cred.ms_tenant_id},
    )
    
    return {"message": "Microsoft 365 connection has been disconnected."}

@router.post("/sync")
async def sync_m365_hub_state(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Manually trigger a rescan of the M365 environment.
    """
    await set_rls_tenant(session, str(current_user.tenant_id))
    result = await session.execute(
        select(M365Credential).where(M365Credential.tenant_id == current_user.tenant_id)
    )
    cred = result.scalar_one_or_none()
    
    if not cred or cred.token_status != "active":
        raise HTTPException(status_code=400, detail="M365 not connected or token expired.")
        
    from app.tasks.m365_scanner import run_m365_scan_background
    background_tasks.add_task(run_m365_scan_background, str(current_user.tenant_id))
    
    return {"status": "sync_started"}
