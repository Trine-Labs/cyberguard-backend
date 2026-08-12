"""Findings Upsert and Resolution Logic"""
import uuid
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.models.finding import Finding

async def upsert_m365_findings(
    session: AsyncSession, 
    tenant_id: uuid.UUID, 
    new_findings: List[Dict[str, Any]]
):
    """
    Deterministic upsert logic for M365 findings.
    Matches existing findings by entity and issue_type.
    Re-opens resolved findings if detected again, or resolves missing ones.
    """
    # Fetch existing M365 findings for the tenant (both open and resolved)
    result = await session.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.source == "m365"
        )
    )
    existing_all = result.scalars().all()
    existing_map = {f"{f.issue_type}::{f.entity}": f for f in existing_all}
    open_map = {f"{f.issue_type}::{f.entity}": f for f in existing_all if f.status == "open"}
    
    # Track which findings are currently active in this scan pass
    active_keys = set()
    
    for nf in new_findings:
        key = f"{nf['issue_type']}::{nf['entity']}"
        active_keys.add(key)
        
        if key in existing_map:
            # Update last_seen and re-open if previously resolved
            existing = existing_map[key]
            existing.last_seen_at = datetime.utcnow()
            existing.status = "open"
            existing.resolved_at = None
            updated_ev = dict(nf["evidence"] or {})
            if existing.evidence and "ai_synthesis" in existing.evidence and "ai_synthesis" not in updated_ev:
                updated_ev["ai_synthesis"] = existing.evidence["ai_synthesis"]
            existing.evidence = updated_ev
        else:
            # Insert new finding
            from sqlalchemy import text as _text
            seq_result = await session.execute(_text("SELECT nextval('findings_seq')"))
            seq_num = seq_result.scalar()
            
            finding = Finding(
                tenant_id=tenant_id,
                finding_num=seq_num,
                severity=nf["severity"],
                source="m365",
                issue_type=nf["issue_type"],
                entity=nf["entity"],
                evidence=nf["evidence"],
                tags=nf["tags"]
            )
            session.add(finding)
            
    PHISHING_TAGS = {"phishing_simulation", "identity_risk", "human_factor", "credential_harvesting"}
    PHISHING_TYPES = {
        "Phishing Simulation Failure (Employee Compromise Risk)",
        "Critical Employee Security Risk (Awareness Score Below 50)",
        "Credential Harvesting Failure (High Risk Compromise)",
    }

    # Resolve open findings that are no longer present in this scan pass
    for key, existing in open_map.items():
        if key not in active_keys:
            # DO NOT auto-resolve phishing simulation findings during M365 tenant scan passes
            has_phishing_tag = any(t in PHISHING_TAGS for t in (existing.tags or []))
            if existing.issue_type in PHISHING_TYPES or has_phishing_tag:
                continue

            existing.status = "resolved"
            existing.resolved_at = datetime.utcnow()
            
    await session.commit()

    try:
        from fastapi_cache import FastAPICache
        await FastAPICache.clear()
    except Exception:
        pass


async def reverify_and_purge_false_positives(session: AsyncSession, tenant_id: uuid.UUID) -> int:
    """
    Scans existing open findings for the tenant and resolves false positives and duplicates:
    1. Deduplication of identical (source, issue_type, entity) findings.
    2. Unresolvable / Dead subdomains (DNS lookup fails).
    3. Catch-all / Soft-404 path reflection findings.
    4. Redirect false positives (cross-domain, cross-path stem, or SSO/login redirects).
    5. Poor Security Headers / Missing SSL on catch-all or unresolvable hosts.
    Returns count of resolved false positive findings.
    """
    import urllib.parse
    from app.services.easm_scanner import _resolve_ip, _get_catch_all_details, _HTTP_CLIENT
    
    result = await session.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.status == "open"
        )
    )
    open_findings = result.scalars().all()
    resolved_count = 0
    
    # ── Deduplication ──────────────────────────────────────────────────────────
    seen_keys = set()
    unique_findings = []
    for f in open_findings:
        key = (f.source, (f.issue_type or "").strip(), (f.entity or "").strip())
        if key in seen_keys:
            f.status = "resolved"
            f.resolved_at = datetime.utcnow()
            resolved_count += 1
        else:
            seen_keys.add(key)
            unique_findings.append(f)
            
    host_dns_cache = {}
    host_catch_all_cache = {}
    
    for f in unique_findings:
        if f.source != "ext_scanner":
            continue
            
        hostname = (f.evidence or {}).get("hostname") or f.entity.split(":")[0]
        if not hostname or hostname.startswith("127.") or hostname == "localhost":
            continue
            
        # Skip special entities
        if hostname.startswith("Policy:") or hostname.startswith("User:") or hostname.startswith("Mailbox:") or hostname.startswith("App:"):
            continue

        # Check DNS resolution
        if hostname not in host_dns_cache:
            host_dns_cache[hostname] = await _resolve_ip(hostname)
        ip = host_dns_cache[hostname]
        
        # Rule 1: Host does not resolve -> false positive!
        if not ip:
            f.status = "resolved"
            f.resolved_at = datetime.utcnow()
            resolved_count += 1
            continue
            
        # Check catch-all details
        if hostname not in host_catch_all_cache:
            details = await _get_catch_all_details(f"https://{hostname}")
            if not details:
                details = await _get_catch_all_details(f"http://{hostname}")
            host_catch_all_cache[hostname] = details
        catch_all_details = host_catch_all_cache[hostname]
        is_catch_all = catch_all_details is not None
        
        # Rule 2: Poor Security Headers / Missing SSL Certificate on catch-all servers -> resolve!
        if is_catch_all and f.issue_type in ("Poor Security Headers", "Missing SSL Certificate"):
            f.status = "resolved"
            f.resolved_at = datetime.utcnow()
            resolved_count += 1
            continue

        # Rule 2b: Purge pure INFO noise & individual header/CVE log spam
        issue_type_lower = (f.issue_type or "").lower()
        if (
            f.severity == "info"
            or f.issue_type == "Poor Security Headers"
            or issue_type_lower.startswith("verified cross-origin-")
            or issue_type_lower.startswith("verified permissions-")
            or issue_type_lower.startswith("verified content-security-")
            or issue_type_lower.startswith("verified strict-transport-")
            or issue_type_lower.startswith("verified x-")
            or issue_type_lower.startswith("vulnerability cve-")
        ):
            f.status = "resolved"
            f.resolved_at = datetime.utcnow()
            resolved_count += 1
            continue
            
        # Rule 3: Sensitive path finding on catch-all / soft-404 / redirect host -> re-verify
        if f.issue_type.startswith("Exposed Sensitive File"):
            target_url = (f.evidence or {}).get("url") or (f.evidence or {}).get("matched_at")
            if target_url and isinstance(target_url, str) and target_url.startswith("http"):
                try:
                    resp = await _HTTP_CLIENT.get(target_url, timeout=4.0)
                    
                    if resp.status_code not in (200, 206):
                        f.status = "resolved"
                        f.resolved_at = datetime.utcnow()
                        resolved_count += 1
                        continue

                    # Redirect Guardrails
                    if resp.history:
                        parsed_init = urllib.parse.urlparse(str(resp.history[0].url))
                        parsed_final = urllib.parse.urlparse(str(resp.url))

                        # Cross domain redirect
                        if parsed_init.netloc != parsed_final.netloc:
                            f.status = "resolved"
                            f.resolved_at = datetime.utcnow()
                            resolved_count += 1
                            continue

                        # Cross path redirect
                        init_path = parsed_init.path.rstrip('/')
                        final_path = parsed_final.path.rstrip('/')
                        if init_path and final_path and init_path != final_path:
                            f.status = "resolved"
                            f.resolved_at = datetime.utcnow()
                            resolved_count += 1
                            continue

                    # Login / SSO redirect
                    final_url_lower = str(resp.url).lower()
                    if any(lg in final_url_lower for lg in ["/wp-login", "/login", "/sso/", "/openid-connect", "/oauth/authorize", "page-not-found"]):
                        path = (f.evidence or {}).get("path") or ""
                        if not path.startswith("/wp-login") and not path.startswith("/login"):
                            f.status = "resolved"
                            f.resolved_at = datetime.utcnow()
                            resolved_count += 1
                            continue

                    body_text = resp.text
                    if "captcha" in body_text.lower() and "challenge" in body_text.lower():
                        f.status = "resolved"
                        f.resolved_at = datetime.utcnow()
                        resolved_count += 1
                        continue
                        
                    content_type = resp.headers.get("Content-Type", "").lower()
                    is_html = "text/html" in content_type or body_text.strip().lower().startswith(("<!doctype html", "<html"))
                    
                    if is_catch_all and is_html:
                        if catch_all_details:
                            c_len = catch_all_details.get("body_len", len(catch_all_details["content"]))
                            if abs(len(resp.content) - c_len) < max(100, c_len * 0.05):
                                f.status = "resolved"
                                f.resolved_at = datetime.utcnow()
                                resolved_count += 1
                                continue
                                
                        path = (f.evidence or {}).get("path") or ""
                        matched_kw = (f.evidence or {}).get("matched_keyword") or ""
                        
                        clean_body = body_text
                        for tok in [target_url, path, path.lstrip("/"), path.split("/")[-1]]:
                            if tok and len(tok) >= 3:
                                clean_body = clean_body.replace(tok, "").replace(tok.lower(), "")
                                
                        if matched_kw and matched_kw.lower() not in clean_body.lower():
                            f.status = "resolved"
                            f.resolved_at = datetime.utcnow()
                            resolved_count += 1
                            continue
                except Exception:
                    f.status = "resolved"
                    f.resolved_at = datetime.utcnow()
                    resolved_count += 1
                    continue
                    
    if resolved_count > 0:
        await session.commit()
    return resolved_count

