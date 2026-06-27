"""M365 Scanner Background Task"""
import asyncio
import logging
from datetime import datetime
from app.worker import celery_app
from app.database import AsyncSessionLocal
from app.models.m365_credential import M365Credential
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
        # Decrypt refresh token and obtain a fresh access token
        blob = EncryptedBlob(ciphertext=cred.encrypted_refresh_token, kms_key_id=cred.kms_key_id)
        refresh_token_plaintext = decrypt_token(blob)
        token_data = await refresh_access_token(refresh_token_plaintext)
        access_token = token_data.get("access_token")

        if not access_token:
            logger.error(f"Failed to refresh access token for tenant {cred.tenant_id}")
            return

        client = M365GraphClient(cred.tenant_id, access_token, session)
        try:
            # ── Core identity data ─────────────────────────────────────────
            users = await client.get_users()
            guest_accounts = await client.get_guest_accounts()
            directory_roles = await client.get_directory_roles()
            ca_policies = await client.get_conditional_access_policies()
            mfa_details = await client.get_mfa_details(users=users)

            # ── OAuth & app permissions ────────────────────────────────────
            grants = await client.get_oauth2_permission_grants()
            service_principals = await client.get_service_principals()
            app_role_assignments = await client.get_app_role_assignments()

            # ── Tenant configuration ───────────────────────────────────────
            verified_domains = await client.get_verified_domains()
            audit_log_status = await client.get_audit_log_status()
            sharepoint_settings = await client.get_sharepoint_settings()

            # ── Identity Protection & Privileged Access ────────────────────
            risky_users = await client.get_risky_users()
            pim_assignments = await client.get_pim_eligible_assignments()

            # ── Mailbox rules — all members (rate-limited per-user) ────────
            admin_ids = get_admin_user_ids(directory_roles)
            # Prioritise admins but scan all users for BEC coverage
            admin_users = [u for u in users if u.get("id") in admin_ids]
            non_admin_users = [u for u in users if u.get("id") not in admin_ids]
            # Admins first, then the rest — total list deduplicated by ordering
            all_users_ordered = admin_users + non_admin_users
            mailbox_rules = await client.get_mailbox_rules(all_users_ordered)

            # ── Run detection engine ───────────────────────────────────────
            findings = run_all_rules(
                users=users,
                directory_roles=directory_roles,
                mfa_details=mfa_details,
                ca_policies=ca_policies,
                grants=grants,
                service_principals=service_principals,
                mailbox_rules=mailbox_rules,
                verified_domains=verified_domains,
                guest_accounts=guest_accounts,
                app_role_assignments=app_role_assignments,
                audit_log_status=audit_log_status,
                sharepoint_settings=sharepoint_settings,
                risky_users=risky_users,
                pim_assignments=pim_assignments,
            )

            await upsert_m365_findings(session, cred.tenant_id, findings)

            # ── Store hub snapshot ─────────────────────────────────────────
            hub_state = {
                "tenant_id": str(cred.tenant_id),
                "timestamp": datetime.utcnow().isoformat(),
                "users": users,
                "guest_accounts": guest_accounts,
                "directory_roles": directory_roles,
                "ca_policies": ca_policies,
                "mfa_details": mfa_details,
                "oauth2_grants": grants,
                "service_principals": service_principals,
                "app_role_assignments": app_role_assignments,
                "verified_domains": verified_domains,
                "audit_log_status": audit_log_status,
                "sharepoint_settings": sharepoint_settings,
                "risky_users": risky_users,
                "pim_assignments": pim_assignments,
                "findings": [f for f in findings if f["severity"] in ("high", "critical")],
            }

            cred.hub_state = hub_state
            await session.commit()

            logger.info(
                f"M365 scan complete for tenant {cred.tenant_id}: "
                f"{len(users)} users, {len(guest_accounts)} guests, "
                f"{len(findings)} findings"
            )

        finally:
            await client.close()

    except ValueError as ve:
        if "revoked or expired" in str(ve):
            logger.warning(
                f"Refresh token revoked/expired for tenant {cred.tenant_id}. Marking as expired."
            )
            cred.token_status = "expired"
            await session.commit()
        else:
            logger.error(f"ValueError scanning tenant {cred.tenant_id}: {ve}")
    except Exception as e:
        logger.error(f"Unhandled error scanning tenant {cred.tenant_id}: {e}", exc_info=True)


async def run_m365_scan_background(tenant_id: str):
    """Run a full M365 scan for a single tenant in a background FastAPI task."""
    logger.info(f"Starting M365 background scan for tenant {tenant_id}")
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(M365Credential).where(M365Credential.tenant_id == tenant_id)
        )
        cred = result.scalar_one_or_none()
        if cred and cred.token_status == "active":
            await _process_tenant(session, cred)
        else:
            logger.warning(f"No active M365 credential for tenant {tenant_id} — scan skipped")
    logger.info(f"Completed M365 background scan for tenant {tenant_id}")


async def _scan_all_tenants_async():
    """Scan all active M365 tenants sequentially."""
    logger.info("Starting M365 scan across all tenants")
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(M365Credential).where(M365Credential.token_status == "active")
        )
        creds = result.scalars().all()
        logger.info(f"Found {len(creds)} active M365 tenants to scan")
        for cred in creds:
            await _process_tenant(session, cred)
    logger.info("Completed M365 scan across all tenants")


@celery_app.task
def scan_all_tenants():
    """Celery task: scan all active M365 tenants."""
    asyncio.run(_scan_all_tenants_async())
