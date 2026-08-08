"""
EASM Scanner Finding Generation & Database Upsert Module
"""
from datetime import datetime, timezone
from typing import Optional
import uuid

from sqlalchemy import select, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.models.finding import Finding
from app.models.scope import ScanScope
from app.services.easm.config import _is_ip, logger


async def _generate_findings(
    tenant_id: uuid.UUID,
    hostname: str,
    http_result: dict,
    cert_info: Optional[dict],
    open_risky_ports: list[tuple[int, str, str]],  # [(port, service, risk)]
    sensitive_paths: list[dict],
    email_security: dict,
    is_exposed_admin: bool,
    cve_data: list[dict],
    nuclei_data: list[dict],
    asset_criticality: str,
    session: AsyncSession,
) -> None:
    """
    Auto-generate findings for security issues found during EASM scan.
    Deduplicates by entity+issue_type before inserting.
    Adjusts severity based on asset criticality and includes real CVEs.
    """
    scopes_res = await session.execute(
        select(ScanScope).where(
            and_(
                ScanScope.tenant_id == tenant_id,
                ScanScope.type == "domain"
            )
        )
    )
    domain_scopes = [s.value.lower().strip() for s in scopes_res.scalars().all()]

    def _get_base_domain(hn: str, scopes: list[str]) -> str:
        hn_lower = hn.lower().strip()
        if _is_ip(hn_lower):
            return hn_lower

        matching_scopes = []
        for d in scopes:
            if hn_lower == d or hn_lower.endswith("." + d):
                matching_scopes.append(d)
        if matching_scopes:
            return max(matching_scopes, key=len)

        parts = hn_lower.split('.')
        if len(parts) >= 2:
            if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "edu", "gov", "ac"):
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return hn_lower

    base_domain = _get_base_domain(hostname, domain_scopes)

    findings_to_create = []

    def _adjust_severity(base_sev: str) -> str:
        levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        rev_levels = {v: k for k, v in levels.items()}
        val = levels.get(base_sev, 2)
        if asset_criticality in ("critical", "high"):
            val = min(4, val + 1)
        elif asset_criticality == "low":
            val = max(0, val - 1)
        return rev_levels.get(val, base_sev)

    # Verified Findings (Layer 2 - Active Nuclei Verification)
    for result in nuclei_data:
        if (result.get("severity") or "").lower() == "info":
            continue
        findings_to_create.append({
            "severity": _adjust_severity(result.get("severity", "high")),
            "source": "ext_scanner",
            "issue_type": f"Verified {result.get('cve_id', 'Vulnerability')}",
            "entity": hostname,
            "tags": ["Verified", "Nuclei"],
            "evidence": {
                "hostname": hostname,
                "confidence": 95,
                "description": result.get("description"),
                "extracted_results": result.get("extracted_results")
            },
        })

    # Host Unreachable / Dead DNS Guardrail
    if not http_result.get("status") and not cert_info and not open_risky_ports and not sensitive_paths:
        logger.info(f"[EASM] Skipping findings generation for unreachable host: {hostname}")
        return

    # Missing SSL Certificate
    if not cert_info and http_result.get("status") and not http_result.get("is_catch_all"):
        findings_to_create.append({
            "severity": _adjust_severity("high"),
            "source": "ext_scanner",
            "issue_type": "Missing SSL Certificate",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "description": "The server responded to HTTP requests but no valid TLS certificate could be extracted. The server is likely lacking SSL configuration or port 443 is inaccessible.",
            },
        })
    elif cert_info and cert_info.get("issuer") == "Missing" and not http_result.get("is_catch_all"):
        findings_to_create.append({
            "severity": _adjust_severity("high"),
            "source": "ext_scanner",
            "issue_type": "Missing SSL Certificate",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "description": "The server responded to HTTP requests but no valid TLS certificate could be extracted. The server is likely lacking SSL configuration or port 443 is inaccessible.",
            },
        })

    # Expired TLS certificate
    elif cert_info and cert_info["is_expired"]:
        findings_to_create.append({
            "severity": _adjust_severity("medium"),
            "source": "ext_scanner",
            "issue_type": "Expired SSL Certificate",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "issuer": cert_info["issuer"],
                "expired_on": cert_info["valid_to"].isoformat(),
                "days_overdue": abs(cert_info["days_to_expiry"]),
            },
        })

    # Certificate expiring soon (< 30 days)
    if cert_info and not cert_info["is_expired"] and 0 < cert_info["days_to_expiry"] <= 30:
        findings_to_create.append({
            "severity": _adjust_severity("low"),
            "source": "ext_scanner",
            "issue_type": "SSL Certificate Expiring Soon",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "issuer": cert_info["issuer"],
                "expires_on": cert_info["valid_to"].isoformat(),
                "days_remaining": cert_info["days_to_expiry"],
            },
        })

    # Self-signed certificate
    if cert_info and cert_info["is_self_signed"]:
        findings_to_create.append({
            "severity": "medium",
            "source": "ext_scanner",
            "issue_type": "Self-Signed SSL Certificate",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "issuer": cert_info["issuer"],
            },
        })

    # Hostname mismatch
    if cert_info and cert_info.get("is_mismatch"):
        findings_to_create.append({
            "severity": _adjust_severity("medium"),
            "source": "ext_scanner",
            "issue_type": "SSL Certificate Hostname Mismatch",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "subject": cert_info["subject"],
                "sans": cert_info["sans"],
                "description": "The server returned an SSL certificate that does not cover this hostname.",
            },
        })

    # Poor security headers
    if http_result.get("status") and http_result.get("sec_headers_grade") in ("D", "F") and not http_result.get("is_catch_all"):
        grade = http_result.get("sec_headers_grade", "D")
        score = http_result.get("sec_headers_score", 45 if grade == "D" else 25)
        missing_list = http_result.get("missing_headers") or ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"]

        missing_formatted = [
            h.replace("content-security-policy", "Content-Security-Policy")
             .replace("strict-transport-security", "Strict-Transport-Security")
             .replace("x-frame-options", "X-Frame-Options")
             .replace("x-content-type-options", "X-Content-Type-Options")
             .replace("referrer-policy", "Referrer-Policy")
             .replace("permissions-policy", "Permissions-Policy")
            for h in missing_list
        ]
        missing_str = ", ".join(missing_formatted)

        header_sev = "medium" if (grade == "F" or "content-security-policy" in missing_list or "strict-transport-security" in missing_list) else "low"

        findings_to_create.append({
            "severity": header_sev,
            "source": "ext_scanner",
            "issue_type": f"Insecure HTTP Security Headers (Missing: {missing_str})",
            "entity": base_domain,
            "evidence": {
                "hostname": hostname,
                "score": score,
                "grade": grade,
                "missing_headers": missing_formatted,
                "missing_headers_summary": missing_str,
                "description": f"Security headers posture score for {hostname} is {score}/100 (Grade {grade}). Missing headers: {missing_str}.",
                "remediation": f"1. Configure missing headers on your web server: {missing_str}.\n2. Implement Content-Security-Policy (CSP) to restrict unauthorized script execution.\n3. Enable Strict-Transport-Security (HSTS) with max-age >= 31536000.",
            },
        })

    # Risky open ports
    for port, service, risk in open_risky_ports:
        findings_to_create.append({
            "severity": _adjust_severity(risk),
            "source": "ext_scanner",
            "issue_type": f"Exposed {service} Port",
            "entity": f"{hostname}:{port}",
            "evidence": {
                "hostname": hostname,
                "port": port,
                "service": service,
                "internet_facing": True,
            },
        })

    # Sensitive paths
    for sp in sensitive_paths:
        findings_to_create.append({
            "severity": _adjust_severity(sp.get("severity", "critical")),
            "source": "ext_scanner",
            "issue_type": f"Exposed Sensitive File: {sp['type']}",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "url": sp["url"],
                "path": sp["path"],
                "matched_keyword": sp["matched_keyword"],
                "internet_facing": True,
            },
        })

    # Exposed admin panel
    if is_exposed_admin:
        findings_to_create.append({
            "severity": _adjust_severity("high"),
            "source": "ext_scanner",
            "issue_type": "Exposed Admin Panel",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "matched_keyword": any(kw in hostname for kw in ["admin", "portal", "manage", "cpanel", "wp-admin", "phpmyadmin"]),
                "internet_facing": True,
                "note": "Admin-named hostname is publicly reachable on the internet.",
            },
        })

    # Email Security (SPF / DMARC)
    if not _is_ip(hostname):
        if not email_security.get("dmarc"):
            findings_to_create.append({
                "severity": _adjust_severity("medium"),
                "source": "ext_scanner",
                "issue_type": "Missing DMARC Record",
                "entity": base_domain,
                "evidence": {
                    "hostname": hostname,
                    "affected_subdomains": [hostname],
                    "description": "No DMARC record was found, making the domain vulnerable to email spoofing.",
                },
            })
        elif email_security.get("dmarc_policy") == "none":
            findings_to_create.append({
                "severity": _adjust_severity("low"),
                "source": "ext_scanner",
                "issue_type": "DMARC Policy is 'None'",
                "entity": base_domain,
                "evidence": {
                    "hostname": hostname,
                    "dmarc_record": email_security["dmarc"],
                    "affected_subdomains": [hostname],
                    "description": "DMARC is configured but the policy is set to 'none', meaning spoofed emails are not blocked.",
                },
            })

        if not email_security.get("spf"):
            findings_to_create.append({
                "severity": _adjust_severity("medium"),
                "source": "ext_scanner",
                "issue_type": "Missing SPF Record",
                "entity": base_domain,
                "evidence": {
                    "hostname": hostname,
                    "affected_subdomains": [hostname],
                    "description": "No SPF record was found, allowing unauthorized senders to forge emails from this domain.",
                },
            })

    unique_findings_map = {}
    for f in findings_to_create:
        key = (f["entity"], f["issue_type"])
        if key not in unique_findings_map:
            unique_findings_map[key] = f
        else:
            existing_f = unique_findings_map[key]
            ex_results = existing_f["evidence"].get("extracted_results")
            new_results = f["evidence"].get("extracted_results")
            if new_results:
                if not ex_results:
                    existing_f["evidence"]["extracted_results"] = new_results
                else:
                    if not isinstance(ex_results, list):
                        ex_results = [ex_results]
                    if not isinstance(new_results, list):
                        new_results = [new_results]

                    combined = list(set([str(x) for x in ex_results] + [str(x) for x in new_results]))
                    existing_f["evidence"]["extracted_results"] = combined

    for f in unique_findings_map.values():
        existing = await session.execute(
            select(Finding).where(
                and_(
                    Finding.tenant_id == tenant_id,
                    Finding.entity == f["entity"],
                    Finding.issue_type == f["issue_type"],
                )
            )
        )
        existing_row = existing.scalars().first()
        if existing_row:
            existing_row.last_seen_at = datetime.now(timezone.utc)
            if existing_row.status == "resolved":
                existing_row.status = "open"

            consolidated_issues = (
                "Poor Security Headers",
                "Missing DMARC Record",
                "DMARC Policy is 'None'",
                "Missing SPF Record"
            )
            if f["issue_type"] in consolidated_issues:
                current_evidence = dict(existing_row.evidence or {})
                affected = list(current_evidence.get("affected_subdomains") or [])
                new_subs = f["evidence"].get("affected_subdomains") or []

                for ns in new_subs:
                    if ns not in affected:
                        affected.append(ns)

                current_evidence["affected_subdomains"] = affected

                if f["issue_type"] == "Poor Security Headers":
                    current_evidence["grade"] = "F" if (current_evidence.get("grade") == "F" or f["evidence"].get("grade") == "F") else "D"

                existing_row.evidence = current_evidence
                flag_modified(existing_row, "evidence")

                sev_hierarchy = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                existing_sev = existing_row.severity
                new_sev = f["severity"]
                if sev_hierarchy.get(new_sev, 0) > sev_hierarchy.get(existing_sev, 0):
                    existing_row.severity = new_sev
        else:
            seq_result = await session.execute(text("SELECT nextval('findings_seq')"))
            seq_num = seq_result.scalar()
            session.add(Finding(
                tenant_id=tenant_id,
                finding_num=seq_num,
                severity=f["severity"],
                source=f["source"],
                issue_type=f["issue_type"],
                entity=f["entity"],
                tags=f.get("tags", []),
                evidence=f["evidence"],
                status="open",
            ))
