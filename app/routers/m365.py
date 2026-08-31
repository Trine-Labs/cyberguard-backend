"""
CyberGuard — Microsoft 365 Router
Endpoints: initiate OAuth consent, handle callback, vault token, status.
"""
import asyncio
import secrets
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete

from app.dependencies import get_db, get_current_user, require_admin
from app.database import set_rls_tenant
from app.models.user import User
from app.models.tenant import Tenant
from app.models.m365_credential import M365Credential
from app.models.scan_job import ScanJob
from app.models.scope import ScanScope
from app.models.finding import Finding
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

# Human readable descriptions for all possible Microsoft Graph scopes
_GRAPH_SCOPE_DESCRIPTIONS = {
    "User.Read.All": {
        "title": "User.Read.All",
        "description_en": "Read user profiles, account status, and sign-in activity",
        "description_fr": "Lire les profils utilisateurs, l'état des comptes et l'activité de connexion",
        "category": "Identity & Directory",
    },
    "Policy.Read.All": {
        "title": "Policy.Read.All",
        "description_en": "Read Conditional Access and security policies",
        "description_fr": "Lire les politiques d'accès conditionnel et de sécurité",
        "category": "Security Policies",
    },
    "RoleManagement.Read.All": {
        "title": "RoleManagement.Read.All",
        "description_en": "Read administrative and directory role assignments (Entra ID)",
        "description_fr": "Lire les affectations de rôles administratifs (Entra ID)",
        "category": "Privilege & Governance",
    },
    "AuditLog.Read.All": {
        "title": "AuditLog.Read.All",
        "description_en": "Read sign-in logs for stale account and threat detection",
        "description_fr": "Lire les journaux de connexion pour la détection des comptes inactifs et menaces",
        "category": "Audit & Compliance",
    },
    "Directory.Read.All": {
        "title": "Directory.Read.All",
        "description_en": "Enumerate directory objects, groups, and application registrations",
        "description_fr": "Énumérer les objets d'annuaire, groupes et applications",
        "category": "Identity & Directory",
    },
    "UserAuthenticationMethod.Read.All": {
        "title": "UserAuthenticationMethod.Read.All",
        "description_en": "Read MFA registration states and authentication methods",
        "description_fr": "Lire l'état d'enregistrement MFA et les méthodes d'authentification",
        "category": "Authentication",
    },
    "IdentityRiskyUser.Read.All": {
        "title": "IdentityRiskyUser.Read.All",
        "description_en": "Read Identity Protection risk detections and compromised users",
        "description_fr": "Lire les détections de risque Identity Protection et utilisateurs compromis",
        "category": "Threat Protection",
    },
    "Reports.Read.All": {
        "title": "Reports.Read.All",
        "description_en": "Read tenant security and usage summary reports",
        "description_fr": "Lire les rapports récapitulatifs de sécurité et d'utilisation",
        "category": "Reporting",
    },
    "DeviceManagementManagedDevices.Read.All": {
        "title": "DeviceManagementManagedDevices.Read.All",
        "description_en": "Read Intune / MDM managed device security compliance",
        "description_fr": "Lire la conformité de sécurité des appareils gérés Intune / MDM",
        "category": "Device Security",
    },
    "MailboxSettings.Read": {
        "title": "MailboxSettings.Read",
        "description_en": "Read mailbox security and external auto-forwarding rules",
        "description_fr": "Lire la sécurité des boîtes aux lettres et règles de redirection externe",
        "category": "Email Security",
    },
    "SharePointTenantSettings.Read.All": {
        "title": "SharePointTenantSettings.Read.All",
        "description_en": "Read external sharing and SharePoint tenant security configurations",
        "description_fr": "Lire les configurations de partage externe et sécurité SharePoint",
        "category": "Collaboration Security",
    },
    "offline_access": {
        "title": "offline_access",
        "description_en": "Maintain encrypted tokens for automated background posture scans",
        "description_fr": "Maintenir des jetons chiffrés pour les analyses de posture continues",
        "category": "Connectivity",
    },
}


@router.get("/permissions")
async def get_m365_required_permissions():
    """
    Returns the real, dynamically parsed list of Microsoft Graph OAuth scopes
    configured in the backend system along with human-readable descriptions.
    """
    raw_scopes = settings.m365_scopes.split()
    permissions = []
    for raw in raw_scopes:
        clean_name = raw.replace("https://graph.microsoft.com/", "").strip()
        info = _GRAPH_SCOPE_DESCRIPTIONS.get(clean_name, {
            "title": clean_name,
            "description_en": f"Read-only access for {clean_name}",
            "description_fr": f"Accès en lecture seule pour {clean_name}",
            "category": "Graph API",
        })
        permissions.append({
            "scope": clean_name,
            "title": info["title"],
            "description_en": info["description_en"],
            "description_fr": info["description_fr"],
            "category": info["category"],
        })
    return {"permissions": permissions}


@router.get("/connect")
async def get_m365_connect_url(
    source: Optional[str] = Query("onboarding", description="Source flow: onboarding or settings"),
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
    _oauth_state_store[state] = {
        "tenant_id": str(current_user.tenant_id),
        "source": source or "onboarding",
    }
    
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
    
    state_entry = _oauth_state_store.pop(state)  # Consume state (one-time use)
    if isinstance(state_entry, dict):
        tenant_id = state_entry.get("tenant_id")
        source = state_entry.get("source", "onboarding")
    else:
        tenant_id = state_entry
        source = "onboarding"
    
    if not code:
        err_dest = "/onboarding/m365" if source == "onboarding" else "/dashboard/settings?tab=m365"
        return RedirectResponse(
            url=f"{settings.frontend_url}{err_dest}?error=no_code"
        )
    
    is_onboarding_flow = source == "onboarding"

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
        
        # Check tenant status
        db_tenant = await session.get(Tenant, tenant_id)
        if db_tenant and (db_tenant.onboarding_step < 4 or db_tenant.status == "onboarding"):
            is_onboarding_flow = True

        if is_onboarding_flow and db_tenant:
            # Advance to Step 3 (Environment Setup & Scan Status screen)
            db_tenant.onboarding_step = 3
            db_tenant.status = "onboarding"
        
        # Queue baseline scan job
        scan_job = ScanJob(
            tenant_id=tenant_id,
            job_type="baseline",
            status="queued",
            metadata_={"triggered_by": "m365_onboarding" if is_onboarding_flow else "m365_settings"},
        )
        session.add(scan_job)
        
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
        err_dest = "/onboarding/m365" if is_onboarding_flow else "/dashboard/settings?tab=m365"
        return RedirectResponse(
            url=f"{settings.frontend_url}{err_dest}?error=vault_failed&description={str(e)}"
        )
    except Exception as e:
        err_dest = "/onboarding/m365" if is_onboarding_flow else "/dashboard/settings?tab=m365"
        return RedirectResponse(
            url=f"{settings.frontend_url}{err_dest}?error=connection_failed&description={str(e)}"
        )
    
    # If onboarding, redirect to /onboarding/status; if from settings, redirect to /dashboard/m365
    if is_onboarding_flow:
        return RedirectResponse(
            url=f"{settings.frontend_url}/onboarding/status?m365=connected"
        )
    else:
        return RedirectResponse(
            url=f"{settings.frontend_url}/dashboard/m365?m365=connected"
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
        return {"connected": False, "status": None, "last_sync_at": None}
        
    hub = cred.hub_state or {}
    last_sync_at = hub.get("timestamp") or (cred.last_used_at.isoformat() if cred.last_used_at else (cred.connected_at.isoformat() if cred.connected_at else None))

    return {
        "connected": cred.token_status == "active",
        "status": cred.token_status,
        "ms_tenant_id": cred.ms_tenant_id,
        "granted_scopes": cred.granted_scopes,
        "connected_at": cred.connected_at.isoformat() if cred.connected_at else None,
        "last_sync_at": last_sync_at,
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
    
    # Delete all SSPM findings related to M365 when disconnected
    await session.execute(
        delete(Finding).where(
            and_(
                Finding.tenant_id == current_user.tenant_id,
                Finding.source == "m365"
            )
        )
    )
    
    await log_action(
        session=session,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action=AuditAction.M365_TOKEN_REVOKED,
        metadata={"ms_tenant_id": cred.ms_tenant_id},
    )
    
    await session.commit()
    
    return {"message": "Microsoft 365 connection has been disconnected and related findings cleared."}

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
    
    try:
        from fastapi_cache import FastAPICache
        await FastAPICache.clear()
    except Exception:
        pass

    return {"status": "sync_started"}
