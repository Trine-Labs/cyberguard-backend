"""M365 Scanner Celery Task"""
import asyncio
import logging
from datetime import datetime
from app.worker import celery_app
from app.database import AsyncSessionLocal
from app.models.m365_credential import M365Credential
from app.models.finding import Finding
from app.services.m365_service import refresh_access_token
from app.services.m365_graph_client import M365GraphClient
from app.services.rules_engine import run_all_rules, get_admin_user_ids
from app.services.findings_service import upsert_m365_findings
from app.services.crypto_service import decrypt_token, EncryptedBlob
from app.config import get_settings
from sqlalchemy import select

logger = logging.getLogger(__name__)
settings = get_settings()

async def _process_tenant(session, cred: M365Credential):
    try:
        blob = EncryptedBlob(ciphertext=cred.encrypted_refresh_token, kms_key_id=cred.kms_key_id)
        refresh_token_plaintext = decrypt_token(blob)
        
        token_data = await refresh_access_token(refresh_token_plaintext)
        access_token = token_data.get("access_token")

        if not access_token:
            logger.error(f"Failed to refresh token for tenant {cred.tenant_id}")
            return

        client = M365GraphClient(cred.tenant_id, access_token, session)
        try:
            grants = await client.get_oauth2_permission_grants()
            service_principals = await client.get_service_principals()
            users = await client.get_users()
            directory_roles = await client.get_directory_roles()
            ca_policies = await client.get_conditional_access_policies()
            mfa_details = await client.get_mfa_details()
            
            # Fetch mailbox rules for admins to save API calls
            admin_ids = get_admin_user_ids(directory_roles)
            admin_users = [u for u in users if u.get("id") in admin_ids]
            mailbox_rules = await client.get_mailbox_rules(admin_users)

            # Get domains from tenant or use placeholder/empty for MVP
            verified_domains = [] 

            findings = run_all_rules(
                users=users,
                directory_roles=directory_roles,
                mfa_details=mfa_details,
                ca_policies=ca_policies,
                grants=grants,
                service_principals=service_principals,
                mailbox_rules=mailbox_rules,
                verified_domains=verified_domains
            )
            
            await upsert_m365_findings(session, cred.tenant_id, findings)
            
            # --- Aggregate Hub State ---
            hub_state = {
                "tenant_id": str(cred.tenant_id),
                "timestamp": datetime.utcnow().isoformat(),
                "users": users,
                "directory_roles": directory_roles,
                "ca_policies": ca_policies,
                "mfa_details": mfa_details,
                "oauth2_grants": grants,
                "service_principals": service_principals,
                "findings": [f for f in findings if f["severity"] in ["high", "critical"]]
            }
            
            cred.hub_state = hub_state
            await session.commit()
            # ---------------------------
            
            logger.info(f"Successfully scanned M365 for tenant {cred.tenant_id}")
        finally:
            await client.close()

    except ValueError as ve:
        if "revoked or expired" in str(ve):
            logger.warning(f"Refresh token expired/revoked for tenant {cred.tenant_id}. Marking status as expired.")
            cred.token_status = "expired"
            await session.commit()
        else:
            logger.error(f"Value error scanning tenant {cred.tenant_id}: {ve}")
    except Exception as e:
        logger.error(f"Error scanning tenant {cred.tenant_id}: {e}")

async def run_m365_scan_background(tenant_id: str):
    """Wrapper to run a scan for a specific tenant in a background task with its own DB session."""
    logger.info(f"Starting background M365 scanner task for tenant {tenant_id}.")
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(M365Credential).where(M365Credential.tenant_id == tenant_id)
        )
        cred = result.scalar_one_or_none()
        if cred and cred.token_status == "active":
            await _process_tenant(session, cred)
    logger.info(f"Completed background M365 scanner task for tenant {tenant_id}.")

async def _scan_all_tenants_async():
    """Async implementation to scan all tenants."""
    logger.info("Starting M365 scanner task.")
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(M365Credential).where(M365Credential.token_status == "active")
        )
        creds = result.scalars().all()
        for cred in creds:
            await _process_tenant(session, cred)
    logger.info("Completed M365 scanner task.")

@celery_app.task
def scan_all_tenants():
    """
    Periodic task to scan M365 tenants for illicit consent grants.
    """
    asyncio.run(_scan_all_tenants_async())
