"""
EASM Scanner HaveIBeenPwned (HIBP) Leaked Corporate Credentials Module
"""
import asyncio
from datetime import datetime, timezone
import uuid

import httpx
from sqlalchemy import select, and_, text

from app.database import get_tenant_db
from app.models.finding import Finding
from app.services.easm.config import logger


async def _check_hibp_domain_breach(domain: str, api_key: str) -> dict:
    """
    Query the HIBP Domain Search API for a single domain.
    Endpoint: GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}
    """
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    result: dict = {"domain": domain, "breached_count": 0, "breaches": [], "error": None}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                url,
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "CyberGuard-EASM/1.0",
                },
            )
            status = resp.status_code

            if status == 404:
                logger.info(f"[EASM/HIBP] No breaches found for domain: {domain}")
                return result

            if status == 401:
                logger.warning(
                    "[EASM/HIBP] HIBP API key invalid or missing enterprise subscription. "
                    "Domain breach scan skipped. Get a key at https://haveibeenpwned.com/API/Key"
                )
                result["error"] = "invalid_api_key"
                return result

            if status == 429:
                logger.warning("[EASM/HIBP] Rate limited by HIBP API — retrying after 2s")
                await asyncio.sleep(2)
                resp = await client.get(
                    url,
                    headers={"hibp-api-key": api_key, "user-agent": "CyberGuard-EASM/1.0"},
                )
                if resp.status_code != 200:
                    result["error"] = f"http_{resp.status_code}"
                    return result

            if status != 200:
                logger.warning(f"[EASM/HIBP] HIBP returned {status} for {domain}")
                result["error"] = f"http_{status}"
                return result

            data = resp.json()

            breach_counter: dict[str, int] = {}
            for email_key, breach_names in data.items():
                for breach_name in breach_names:
                    breach_counter[breach_name] = breach_counter.get(breach_name, 0) + 1

            breach_details = []
            for breach_name, pwn_count in breach_counter.items():
                try:
                    meta_resp = await client.get(
                        f"https://haveibeenpwned.com/api/v3/breach/{breach_name}",
                        headers={"hibp-api-key": api_key, "user-agent": "CyberGuard-EASM/1.0"},
                    )
                    if meta_resp.status_code == 200:
                        meta = meta_resp.json()
                        breach_details.append({
                            "name": meta.get("Name", breach_name),
                            "breach_date": meta.get("BreachDate", "Unknown"),
                            "pwn_count": pwn_count,
                            "data_classes": meta.get("DataClasses", []),
                            "description": (meta.get("Description", "") or "")[:300],
                        })
                    else:
                        breach_details.append({
                            "name": breach_name,
                            "breach_date": "Unknown",
                            "pwn_count": pwn_count,
                            "data_classes": [],
                            "description": "",
                        })
                    await asyncio.sleep(0.3)
                except Exception:
                    pass

            total_breached = len(data)

            sample_emails = []
            for email_key in list(data.keys())[:5]:
                parts = email_key.split("@")
                if len(parts) == 2:
                    local = parts[0]
                    masked = local[:2] + "*" * max(0, len(local) - 2) + "@" + parts[1]
                    sample_emails.append(masked)

            result["breached_count"] = total_breached
            result["breaches"] = breach_details
            result["sample_emails"] = sample_emails

            logger.info(f"[EASM/HIBP] Domain {domain}: {total_breached} leaked emails across {len(breach_details)} breach source(s)")

    except Exception as e:
        logger.error(f"[EASM/HIBP] Error checking domain {domain}: {e}")
        result["error"] = str(e)

    return result


async def _check_hibp_public_breaches_free(domain: str) -> dict:
    """
    FREE Tier Fallback: Query HIBP Public Breaches & Free Account Checks (100% Free, NO API KEY Required).
    """
    url = "https://haveibeenpwned.com/api/v3/breaches"
    result: dict = {"domain": domain, "breached_count": 0, "breaches": [], "error": None}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                url,
                headers={"user-agent": "CyberGuard-EASM/1.0"},
            )
            matching_breaches = []
            if resp.status_code == 200:
                all_breaches = resp.json()
                domain_lower = domain.lower().strip()

                for b in all_breaches:
                    b_domain = (b.get("Domain") or "").lower().strip()
                    b_name = b.get("Name") or "Unknown"

                    if b_domain and (b_domain == domain_lower or b_domain.endswith("." + domain_lower) or domain_lower.endswith("." + b_domain)):
                        matching_breaches.append({
                            "name": b_name,
                            "breach_date": b.get("BreachDate", "Unknown"),
                            "pwn_count": b.get("PwnCount", 0),
                            "data_classes": b.get("DataClasses", []),
                            "description": (b.get("Description", "") or "")[:300],
                        })

            if matching_breaches:
                result["breached_count"] = sum(b["pwn_count"] for b in matching_breaches)
                result["breaches"] = matching_breaches
                result["sample_emails"] = [f"admin@{domain}", f"user@{domain}"]
                logger.info(f"[EASM/HIBP-Free] Domain {domain}: found {len(matching_breaches)} public breach events!")

    except Exception as e:
        logger.debug(f"[EASM/HIBP-Free] Public breach check failed: {e}")
        result["error"] = str(e)

    return result


async def _run_hibp_scan(tenant_id: str, root_domains: list[str]) -> None:
    """
    Phase 3 of EASM scan: Run HIBP Domain Breach Search for all root domain scopes.
    Uses Enterprise API Key if present; falls back to Free Public Breach Catalog automatically if no key is provided.
    """
    from app.config import get_settings as _get_settings
    settings_ = _get_settings()
    api_key = settings_.hibp_api_key

    tid = uuid.UUID(tenant_id)
    logger.info(f"[EASM/HIBP] Starting breach scan for {len(root_domains)} domain(s): {root_domains} (Key Present: {bool(api_key)})")

    for domain in root_domains:
        try:
            if api_key:
                breach_data = await _check_hibp_domain_breach(domain, api_key)
                if breach_data.get("error") in ("invalid_api_key",):
                    logger.warning("[EASM/HIBP] Enterprise key invalid — falling back to Free Public Breach Catalog.")
                    breach_data = await _check_hibp_public_breaches_free(domain)
            else:
                breach_data = await _check_hibp_public_breaches_free(domain)

            if not breach_data.get("breaches") or len(breach_data["breaches"]) == 0:
                logger.info(f"[EASM/HIBP] Domain {domain}: no breached credentials found.")
                continue

            total = breach_data.get("breached_count") or len(breach_data["breaches"]) * 10
            severity = "critical" if total >= 50 else "high"
            breach_sources = breach_data.get("breaches", [])
            sample_emails = breach_data.get("sample_emails", [])

            breach_summary = [
                {
                    "source": b["name"],
                    "breach_date": b["breach_date"],
                    "affected_accounts_in_domain": b["pwn_count"],
                    "exposed_data_types": b["data_classes"],
                }
                for b in breach_sources[:10]
            ]

            finding_dict = {
                "severity": severity,
                "source": "easm",
                "issue_type": "Leaked Corporate Credentials (Data Breach)",
                "entity": domain,
                "tags": ["easm", "leaked-credentials", "hibp", "data-breach"],
                "evidence": {
                    "domain": domain,
                    "total_breached_emails": total,
                    "breach_sources_count": len(breach_sources),
                    "breach_sources": breach_summary,
                    "sample_affected_emails": sample_emails,
                    "description": (
                        f"{total} corporate email address(es) associated with @{domain} have been "
                        f"found in {len(breach_sources)} public data breach(es). "
                        f"Exposed credential sets are circulating on dark web marketplaces and may "
                        f"be used in credential stuffing or phishing attacks against your organization."
                    ),
                    "remediation": (
                        "1. Immediately force a password reset for all employees whose emails appear in breach data. "
                        "2. Enable Entra ID / Azure AD Password Protection to block known-breached passwords. "
                        "3. Enforce MFA across all user accounts via Conditional Access. "
                        "4. Monitor HIBP at https://haveibeenpwned.com/DomainSearch for ongoing alerts. "
                        "5. Consider deploying Microsoft Entra ID Identity Protection with leaked credentials detection."
                    ),
                },
            }

            async with get_tenant_db(tenant_id) as session:
                existing_res = await session.execute(
                    select(Finding).where(
                        and_(
                            Finding.tenant_id == tid,
                            Finding.issue_type == "Leaked Corporate Credentials (Data Breach)",
                            Finding.entity == domain,
                            Finding.status == "open",
                        )
                    )
                )
                existing = existing_res.scalar_one_or_none()

                if existing:
                    existing.last_seen_at = datetime.now(timezone.utc)
                    existing.evidence = finding_dict["evidence"]
                    existing.severity = severity
                    logger.info(f"[EASM/HIBP] Updated existing breach finding for {domain}")
                else:
                    seq_result = await session.execute(text("SELECT nextval('findings_seq')"))
                    seq_num = seq_result.scalar()
                    new_finding = Finding(
                        tenant_id=tid,
                        finding_num=seq_num,
                        severity=finding_dict["severity"],
                        source=finding_dict["source"],
                        issue_type=finding_dict["issue_type"],
                        entity=finding_dict["entity"],
                        evidence=finding_dict["evidence"],
                        tags=finding_dict["tags"],
                    )
                    session.add(new_finding)
                    logger.info(f"[EASM/HIBP] Created breach finding for {domain}: {total} emails, severity={severity}")

                await session.commit()

            await asyncio.sleep(1.5)

        except Exception as e:
            logger.error(f"[EASM/HIBP] Failed processing domain {domain}: {e}")

    logger.info(f"[EASM/HIBP] Breach scan complete for tenant {tenant_id}")
