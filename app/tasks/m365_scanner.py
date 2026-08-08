"""M365 Scanner Background Task"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from app.worker import celery_app
from app.database import AsyncSessionLocal
from app.models.m365_credential import M365Credential
from app.models.tenant import Tenant
from app.services.m365_service import refresh_access_token
from app.services.m365_graph_client import M365GraphClient
from app.services.rules_engine import run_all_rules, get_admin_user_ids
from app.services.findings_service import upsert_m365_findings
from app.services.crypto_service import decrypt_token, EncryptedBlob
from app.config import get_settings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)
settings = get_settings()

# Map admin-panel scan_frequency values to seconds
FREQUENCY_TO_SECONDS: dict[str, int] = {
    "hourly":       1 * 3600,
    "two_hours":    2 * 3600,
    "three_hours":  3 * 3600,
    "six_hours":    6 * 3600,
    "twice_daily": 12 * 3600,
    "daily":       24 * 3600,
    "weekly":      7 * 24 * 3600,
}


def _is_scan_due(cred: M365Credential, tenant: Tenant) -> bool:
    """
    Return True if the tenant's M365 scan is due based on their configured
    scan_frequency and the timestamp of the last scan stored in hub_state.
    """
    freq = getattr(tenant, "scan_frequency", "daily") or "daily"
    interval_seconds = FREQUENCY_TO_SECONDS.get(freq, 24 * 3600)

    hub = cred.hub_state or {}
    last_scan_str = hub.get("timestamp")
    if not last_scan_str:
        return True  # Never scanned → scan now

    try:
        last_scan_dt = datetime.fromisoformat(last_scan_str)
        # Make timezone-aware if naive
        if last_scan_dt.tzinfo is None:
            last_scan_dt = last_scan_dt.replace(tzinfo=timezone.utc)
        seconds_since = (datetime.now(timezone.utc) - last_scan_dt).total_seconds()
        return seconds_since >= interval_seconds
    except Exception:
        return True  # Unparseable timestamp → scan to be safe


async def _process_tenant(session: AsyncSession, cred: M365Credential):
    try:
        # Decrypt refresh token and obtain a fresh access token
        blob = EncryptedBlob(ciphertext=cred.encrypted_refresh_token, kms_key_id=cred.kms_key_id)
        refresh_token_plaintext = decrypt_token(blob)
        token_data = await refresh_access_token(refresh_token_plaintext)
        access_token = token_data.get("access_token")
        new_refresh_token = token_data.get("refresh_token")

        if not access_token:
            logger.error(f"Failed to refresh access token for tenant {cred.tenant_id}")
            return

        # If Microsoft returned a rotated refresh token, update it in DB immediately
        if new_refresh_token and new_refresh_token != refresh_token_plaintext:
            from app.services.crypto_service import encrypt_token
            new_blob = encrypt_token(new_refresh_token)
            cred.encrypted_refresh_token = new_blob.ciphertext
            cred.kms_key_id = new_blob.kms_key_id
            cred.updated_at = datetime.now(timezone.utc)
            await session.commit()

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

            # ── Endpoint protection (Intune / Defender) ───────────────────────
            managed_devices = await client.get_managed_devices()

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
                managed_devices=managed_devices,
            )

            await upsert_m365_findings(session, cred.tenant_id, findings)

            # ── Store hub snapshot ─────────────────────────────────────────
            hub_state = {
                "tenant_id": str(cred.tenant_id),
                "timestamp": datetime.now(timezone.utc).isoformat(),
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
                "managed_devices": managed_devices,
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
    """
    Scan active M365 & EASM tenants, but only if their configured scan_frequency
    interval has elapsed since the last scan. This prevents over-scanning tenants
    that have a weekly or daily schedule when checked hourly.
    """
    logger.info("Starting scheduled scan check across all tenants")
    async with AsyncSessionLocal() as session:
        # 1. M365 Scheduled Scans
        result = await session.execute(
            select(M365Credential, Tenant)
            .join(Tenant, M365Credential.tenant_id == Tenant.id)
            .where(M365Credential.token_status == "active")
        )
        rows = result.all()

        due_tenants = []
        skipped = 0
        for cred, tenant in rows:
            if _is_scan_due(cred, tenant):
                due_tenants.append(cred)
            else:
                freq = getattr(tenant, "scan_frequency", "daily")
                logger.info(
                    f"[M365] Skipping tenant {cred.tenant_id} "
                    f"(scan_frequency={freq}, not yet due)"
                )
                skipped += 1

        logger.info(
            f"[M365] {len(due_tenants)} tenant(s) due for scan, "
            f"{skipped} skipped (not yet due)"
        )
        for cred in due_tenants:
            await _process_tenant(session, cred)

        # 2. EASM Scheduled Scans
        from app.models.scope import ScanScope
        from app.models.scan_job import ScanJob
        from app.services.easm_scanner import run_easm_scan
        from sqlalchemy import and_

        all_tenants_res = await session.execute(
            select(Tenant).where(Tenant.status == "active")
        )
        active_tenants = all_tenants_res.scalars().all()

        for t in active_tenants:
            freq = getattr(t, "scan_frequency", "daily") or "daily"
            interval_seconds = FREQUENCY_TO_SECONDS.get(freq, 24 * 3600)

            # Fetch scope values
            scopes_res = await session.execute(
                select(ScanScope.value).where(
                    and_(ScanScope.tenant_id == t.id, ScanScope.type == "domain")
                )
            )
            scope_values = [s for s in scopes_res.scalars().all()]
            if not scope_values:
                continue

            # Check last EASM scan job
            last_job_res = await session.execute(
                select(ScanJob).where(
                    and_(ScanJob.tenant_id == t.id, ScanJob.job_type == "easm")
                ).order_by(ScanJob.created_at.desc()).limit(1)
            )
            last_job = last_job_res.scalar_one_or_none()

            easm_due = True
            if last_job and (last_job.completed_at or last_job.started_at):
                last_time = last_job.completed_at or last_job.started_at
                if last_time.tzinfo is None:
                    last_time = last_time.replace(tzinfo=timezone.utc)
                seconds_since = (datetime.now(timezone.utc) - last_time).total_seconds()
                if seconds_since < interval_seconds:
                    easm_due = False

            if easm_due:
                logger.info(f"[EASM Scheduled] Triggering automated scan for tenant {t.id} (frequency={freq})")
                try:
                    await run_easm_scan(str(t.id), scope_values)
                except Exception as e:
                    logger.error(f"[EASM Scheduled] Failed to run EASM scan for tenant {t.id}: {e}")
            else:
                logger.info(f"[EASM Scheduled] Tenant {t.id} scan not yet due (frequency={freq})")

    logger.info("Completed scheduled scan check across all tenants")


@celery_app.task
def scan_all_tenants():
    """Celery task: scan M365 and EASM tenants that are due per their scan_frequency setting."""
    asyncio.run(_scan_all_tenants_async())
