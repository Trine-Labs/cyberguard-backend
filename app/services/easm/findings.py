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


async def _generate_subdomain_info_finding(
    tenant_id: uuid.UUID,
    root_domain: str,
    subdomains: list[str],
    session: AsyncSession,
) -> None:
    """Auto-generate attack surface inventory info finding for enumerated subdomains."""
    sub_count = len(subdomains)
    issue_type = f"Discovered Subdomains ({sub_count} Active Hosts)"

    existing = await session.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == tenant_id,
                Finding.entity == root_domain,
                Finding.issue_type == issue_type,
            )
        )
    )
    existing_row = existing.scalars().first()
    evidence_payload = {
        "root_domain": root_domain,
        "subdomains_count": sub_count,
        "subdomains_sample": subdomains[:50],
        "description": f"External perimeter reconnaissance mapped {sub_count} active subdomain hostname(s) associated with {root_domain}.",
    }

    if existing_row:
        existing_row.last_seen_at = datetime.now(timezone.utc)
        existing_row.evidence = evidence_payload
        flag_modified(existing_row, "evidence")
    else:
        seq_result = await session.execute(text("SELECT nextval('findings_seq')"))
        seq_num = seq_result.scalar()
        session.add(Finding(
            tenant_id=tenant_id,
            finding_num=seq_num,
            severity="info",
            source="ext_scanner",
            issue_type=issue_type,
            entity=root_domain,
            tags=["Info", "Attack Surface", "Subdomains", "DNS"],
            evidence=evidence_payload,
            status="open",
        ))


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
    all_open_ports: Optional[list[tuple[int, str, str]]] = None,
    geoip_info: Optional[dict] = None,
) -> None:
    """
    Auto-generate findings for security issues & informational telemetry found during EASM scan.
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

    # Consolidated High-Impact Version-Specific CVE Findings
    # Group by detected component name + version (e.g. "Apache 2.4.49")
    if cve_data:
        tech_cve_groups: dict[str, list[dict]] = {}
        for cve in cve_data:
            cve_sev = (cve.get("severity") or "high").lower()
            if cve_sev not in ("high", "critical") and float(cve.get("cvss_score", 0)) < 7.0:
                continue

            tech_label = cve.get("tech_name")
            if not tech_label:
                continue

            if tech_label not in tech_cve_groups:
                tech_cve_groups[tech_label] = []
            tech_cve_groups[tech_label].append(cve)

        for tech_name, cves in tech_cve_groups.items():
            if not cves:
                continue

            max_score = max([float(c.get("cvss_score", 7.0)) for c in cves])
            base_severity = "critical" if max_score >= 9.0 else "high"

            cve_list_summary = []
            cve_ids = []
            for c in cves[:5]:  # Top 5 high-severity CVEs
                cid = c.get("cve_id", "Unknown CVE")
                cve_ids.append(cid)
                cve_list_summary.append({
                    "cve_id": cid,
                    "cvss_score": c.get("cvss_score", 7.5),
                    "severity": c.get("severity", "high"),
                    "description": c.get("description", "")
                })

            cve_str = ", ".join(cve_ids[:3])
            issue_title = f"Outdated Component: {tech_name} ({len(cves)} Vulnerabilities: {cve_str})"

            findings_to_create.append({
                "severity": _adjust_severity(base_severity),
                "source": "ext_scanner",
                "issue_type": issue_title,
                "entity": hostname,
                "tags": ["CVE", "Outdated Software", tech_name.split()[0]],
                "evidence": {
                    "hostname": hostname,
                    "component": tech_name,
                    "vulnerability_count": len(cves),
                    "top_cvss_score": max_score,
                    "cves": cve_list_summary,
                    "description": f"Identified outdated {tech_name} installation exposing {len(cves)} known high/critical vulnerabilities ({cve_str}).",
                    "remediation": f"Upgrade {tech_name} to the latest supported stable vendor release."
                }
            })

    # Host Unreachable / Dead DNS Guardrail
    if not http_result.get("status") and not cert_info and not open_risky_ports and not sensitive_paths and not cve_data and not is_exposed_admin:
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
    ADMIN_KEYWORDS = ["admin", "portal", "manage", "cpanel", "whm", "webmin", "wp-admin", "phpmyadmin", "kibana", "grafana", "dashboard"]
    UTILITY_EXCLUSIONS = {"autodiscover", "autoconfig", "mail", "email", "smtp", "imap", "pop", "pop3", "webdisk", "ftp", "ns1", "ns2", "relay"}

    first_part = hostname.split('.')[0].lower()
    if is_exposed_admin and first_part not in UTILITY_EXCLUSIONS:
        matched_kw = [kw for kw in ADMIN_KEYWORDS if kw in hostname.lower()]
        findings_to_create.append({
            "severity": _adjust_severity("high"),
            "source": "ext_scanner",
            "issue_type": "Exposed Admin Panel",
            "entity": hostname,
            "evidence": {
                "hostname": hostname,
                "matched_keyword": matched_kw[0] if matched_kw else "Admin Interface",
                "internet_facing": True,
                "note": f"Administrative control panel or portal ({matched_kw[0] if matched_kw else 'Admin'}) is publicly reachable on the internet.",
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

        # ── Informational Telemetry: Email Security Baseline (Enforced) ───
        if email_security.get("dmarc") and email_security.get("dmarc_policy") in ("reject", "quarantine") and email_security.get("spf"):
            pol_cap = str(email_security.get("dmarc_policy", "enforced")).capitalize()
            findings_to_create.append({
                "severity": "info",
                "source": "ext_scanner",
                "issue_type": f"Email Security: SPF & DMARC Enforced ({pol_cap})",
                "entity": base_domain,
                "tags": ["Info", "Email Security", "DMARC", "SPF"],
                "evidence": {
                    "domain": base_domain,
                    "dmarc_policy": email_security.get("dmarc_policy"),
                    "dmarc_record": email_security.get("dmarc"),
                    "spf_record": email_security.get("spf"),
                    "description": f"Domain {base_domain} enforces email spoofing protections via active SPF and DMARC ({email_security.get('dmarc_policy')}) records.",
                },
            })

    # ── Informational Telemetry: Active SSL/TLS Certificate Baseline ─────────
    if cert_info and not cert_info.get("is_expired") and not cert_info.get("is_self_signed") and not cert_info.get("is_mismatch") and cert_info.get("issuer") != "Missing" and cert_info.get("days_to_expiry", 0) > 30:
        valid_to_val = cert_info.get("valid_to")
        valid_to_str = valid_to_val.isoformat() if hasattr(valid_to_val, "isoformat") else str(valid_to_val)
        ca_name = cert_info.get("issuer", "Trusted CA")
        findings_to_create.append({
            "severity": "info",
            "source": "ext_scanner",
            "issue_type": f"Active SSL Certificate ({ca_name})",
            "entity": hostname,
            "tags": ["Info", "TLS", "Certificate"],
            "evidence": {
                "hostname": hostname,
                "issuer": cert_info.get("issuer"),
                "valid_to": valid_to_str,
                "days_remaining": cert_info.get("days_to_expiry"),
                "sans_count": len(cert_info.get("sans", [])),
                "sans": cert_info.get("sans", [])[:10],
                "description": f"Verified active SSL/TLS certificate issued by {cert_info.get('issuer')} covering {hostname} with {cert_info.get('days_to_expiry')} days remaining.",
            },
        })

    # ── Informational Telemetry: Web Technology Stack Fingerprint ────────────
    if http_result.get("tech_stack"):
        tech_list = http_result.get("tech_stack", [])
        tech_names = [t.get("name") for t in tech_list if t.get("name")]
        if tech_names:
            tech_summary_str = ", ".join(tech_names[:5])
            findings_to_create.append({
                "severity": "info",
                "source": "ext_scanner",
                "issue_type": f"Web Tech Stack: {tech_summary_str}",
                "entity": hostname,
                "tags": ["Info", "Technology Stack", "Fingerprint"],
                "evidence": {
                    "hostname": hostname,
                    "tech_count": len(tech_list),
                    "technologies": tech_list,
                    "tech_summary": tech_summary_str,
                    "description": f"Fingerprinted {len(tech_list)} web application technologies on {hostname}: {tech_summary_str}.",
                },
            })

    # ── Informational Telemetry: Perimeter Port Exposure Baseline ────────────
    if all_open_ports:
        port_summary = ", ".join([f"{s} ({p})" for p, s, _ in all_open_ports[:6]])
        port_count_label = f"{len(all_open_ports)} Active Services" if len(all_open_ports) > 1 else "1 Active Service"
        findings_to_create.append({
            "severity": "info",
            "source": "ext_scanner",
            "issue_type": f"Open Network Ports: {port_count_label}",
            "entity": hostname,
            "tags": ["Info", "Port Discovery", "Perimeter Baseline"],
            "evidence": {
                "hostname": hostname,
                "open_ports_count": len(all_open_ports),
                "ports": [{"port": p, "service": s, "risk_level": r} for p, s, r in all_open_ports],
                "ports_summary": port_summary,
                "description": f"Detected {len(all_open_ports)} active network service port(s) on {hostname}: {port_summary}.",
            },
        })

    # ── Informational Telemetry: Infrastructure & Hosting Routing ────────────
    if geoip_info and (geoip_info.get("provider") or geoip_info.get("location")):
        prov = geoip_info.get("provider") or "Cloud Infrastructure"
        loc = geoip_info.get("location") or "Global"
        findings_to_create.append({
            "severity": "info",
            "source": "ext_scanner",
            "issue_type": f"Hosting Provider: {prov} ({loc})",
            "entity": hostname,
            "tags": ["Info", "Infrastructure", "GeoIP"],
            "evidence": {
                "hostname": hostname,
                "provider": prov,
                "location": loc,
                "description": f"Host {hostname} is hosted on infrastructure managed by {prov} in region {loc}.",
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
