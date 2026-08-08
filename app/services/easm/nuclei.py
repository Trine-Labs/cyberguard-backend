"""
EASM Scanner Nuclei DAST Vulnerability Scan Phase
"""
from datetime import datetime, timezone
import gc
import json
from urllib.parse import urlparse
import uuid

from sqlalchemy import select, and_, text

from app.database import get_tenant_db
from app.models.easm import EasmAsset, EasmPort
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.services.easm.config import logger
from app.services.easm.probes import _crawl_links, _analyze_javascript
from app.services.verification_engine import NucleiVerificationEngine


async def _run_nuclei_phase(tenant_id: str, domains: list[str], modules: list[str] | None = None, job_id: uuid.UUID | None = None) -> tuple[int, int]:
    """
    Phase 2 of the EASM scan: Run Nuclei vulnerability scanning.
    Runs AFTER all assets have been discovered and stored in the DB.
    Scans in batches of hostnames to balance speed and low memory usage under 512MB.
    Returns (ok_count, fail_count).
    """
    from app.services.easm.scanner import _is_job_cancelled

    do_vuln = not modules or "vuln" in modules
    if not do_vuln:
        return (0, 0)

    engine = NucleiVerificationEngine()
    if not engine.nuclei_bin.exists():
        logger.warning("[EASM/Nuclei] Nuclei binary not found, skipping vulnerability scan phase")
        return (0, 0)

    tid = uuid.UUID(tenant_id)
    ok_count = 0
    fail_count = 0

    logger.info(f"[EASM/Nuclei] Starting vulnerability scan phase for {len(domains)} host(s)")

    def _extract_hostname(matched_at: str, fallback: str) -> str:
        if not matched_at:
            return fallback
        try:
            parsed = urlparse(matched_at)
            host = parsed.hostname
            if host:
                return host.lower().strip()
        except Exception:
            pass
        return fallback

    NUCLEI_BATCH_SIZE = 10
    batches = [domains[i:i + NUCLEI_BATCH_SIZE] for i in range(0, len(domains), NUCLEI_BATCH_SIZE)]

    for batch_idx, batch_domains in enumerate(batches):
        if await _is_job_cancelled(tenant_id, job_id):
            logger.info(f"[EASM/Nuclei] Scan job {job_id} cancelled by user. Exiting Nuclei phase batch {batch_idx + 1}.")
            break

        if job_id:
            try:
                async with get_tenant_db(tenant_id) as session:
                    result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
                    j = result.scalar_one_or_none()
                    if j:
                        if j.status in ("failed", "completed"):
                            logger.info(f"[EASM/Nuclei] Scan job {job_id} cancelled or finished. Exiting progress update.")
                            break
                        meta = dict(j.metadata_ or {})
                        meta["phase"] = "vuln"
                        meta["vuln_total"] = len(domains)
                        meta["vuln_completed"] = ok_count
                        meta["vuln_failed"] = fail_count
                        j.metadata_ = meta
                        await session.commit()
            except Exception as e:
                logger.warning(f"[EASM/Nuclei] Could not update scan job progress metadata: {e}")

        batch_targets = set()
        batch_tech_tags = set()
        asset_info_map = {}  # hostname -> {"criticality": str}

        try:
            async with get_tenant_db(tenant_id) as session:
                for hostname in batch_domains:
                    result = await session.execute(
                        select(EasmAsset).where(
                            and_(
                                EasmAsset.tenant_id == tid,
                                EasmAsset.hostname == hostname,
                            )
                        )
                    )
                    asset = result.scalar_one_or_none()
                    if not asset:
                        continue

                    asset_info_map[hostname] = {
                        "criticality": asset.asset_criticality or "medium",
                        "findings_found": 0
                    }

                    for t in (asset.tech_stack or []):
                        try:
                            obj = json.loads(t) if isinstance(t, str) else t
                            if obj.get("name"):
                                batch_tech_tags.add(obj["name"].lower().replace(" ", "-"))
                        except (json.JSONDecodeError, TypeError):
                            pass

                    port_result = await session.execute(
                        select(EasmPort).where(
                            and_(
                                EasmPort.tenant_id == tid,
                                EasmPort.asset_id == asset.id,
                            )
                        )
                    )
                    ports = port_result.scalars().all()

                    web_urls = set()
                    for p in ports:
                        if p.service in ("HTTP", "HTTP-Alt", "HTTPS", "HTTPS-Alt"):
                            scheme = "https" if "HTTPS" in p.service else "http"
                            port_num = p.port
                            if (scheme == "https" and port_num == 443) or (scheme == "http" and port_num == 80):
                                web_urls.add(f"{scheme}://{hostname}")
                            else:
                                web_urls.add(f"{scheme}://{hostname}:{port_num}")

                    if not web_urls and asset.http_status:
                        web_urls.add(f"https://{hostname}")
                        web_urls.add(f"http://{hostname}")

                    for w in web_urls:
                        batch_targets.add(w)

                    finding_result = await session.execute(
                        select(Finding).where(
                            and_(
                                Finding.tenant_id == tid,
                                Finding.entity == hostname,
                                Finding.issue_type.like("Exposed Sensitive File:%")
                            )
                        )
                    )
                    for f in finding_result.scalars().all():
                        if f.evidence and f.evidence.get("url"):
                            batch_targets.add(f.evidence.get("url"))

                    for w_url in web_urls:
                        crawled_paths = await _crawl_links(w_url)
                        js_paths = await _analyze_javascript(w_url)

                        valid_dast_targets = []
                        sensitive_exts = {".bak", ".env", ".yml", ".yaml", ".sql", ".db", ".sqlite", ".log", ".kdbx", ".pem", ".key", ".config"}
                        for cp in crawled_paths.union(js_paths):
                            if cp.endswith("/"):
                                batch_targets.add(f"{w_url.rstrip('/')}{cp}")
                                continue

                            if any(cp.lower().endswith(ext) for ext in sensitive_exts):
                                issue_type = f"Exposed Sensitive File: Config/Backup ({cp.split('/')[-1]})"
                                existing = await session.execute(
                                    select(Finding).where(
                                        and_(
                                            Finding.tenant_id == tid,
                                            Finding.entity == hostname,
                                            Finding.issue_type == issue_type
                                        )
                                    )
                                )
                                existing_row = existing.scalars().first()
                                if existing_row:
                                    existing_row.last_seen_at = datetime.now(timezone.utc)
                                    if existing_row.status == "resolved":
                                        existing_row.status = "open"
                                    continue

                                seq_result = await session.execute(text("SELECT nextval('findings_seq')"))
                                seq_num = seq_result.scalar()
                                session.add(Finding(
                                    tenant_id=tid,
                                    finding_num=seq_num,
                                    severity="high",
                                    source="ext_scanner",
                                    issue_type=issue_type,
                                    entity=hostname,
                                    tags=["Verified", "Crawler"],
                                    evidence={
                                        "hostname": hostname,
                                        "confidence": 95,
                                        "description": f"An organically crawled file with a sensitive extension was discovered: {w_url.rstrip('/')}{cp}",
                                        "url": f"{w_url.rstrip('/')}{cp}",
                                    },
                                    status="open"
                                ))
                                if hostname in asset_info_map:
                                    asset_info_map[hostname]["findings_found"] = asset_info_map[hostname].get("findings_found", 0) + 1

                            if "#" in cp:
                                continue
                            static_exts = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map"}
                            if any(cp.lower().endswith(ext) for ext in static_exts):
                                continue
                            valid_dast_targets.append(cp)

                        valid_dast_targets.sort(key=lambda x: 0 if "/api" in x or "/rest" in x else 1)
                        for cp in valid_dast_targets[:5]:
                            batch_targets.add(f"{w_url.rstrip('/')}{cp}")
        except Exception as e:
            logger.error(f"[EASM/Nuclei] Error loading batch assets: {e}")
            fail_count += len(batch_domains)
            continue

        if not batch_targets:
            logger.info(f"[EASM/Nuclei] Batch {batch_idx + 1} has no open web targets. Skipping.")
            ok_count += len(batch_domains)
            continue

        try:
            targets_list = list(batch_targets)
            tags_list = list(batch_tech_tags)
            logger.info(f"[EASM/Nuclei] Batch {batch_idx + 1}/{len(batches)}: Scanning {len(batch_domains)} host(s) via {len(targets_list)} URLs. Tech tags: {tags_list}")

            raw_nuclei_data = await engine.verify(targets_list, tags=tags_list)

            nuclei_findings = []
            seen_issues = set()
            for n in raw_nuclei_data:
                t_id = str(n.get("template_id", "")).lower()
                n_sev = str(n.get("severity", "")).lower()
                if (
                    "wappalyzer" in t_id
                    or n_sev == "info"
                    or any(h in t_id for h in ("security-header", "cross-origin", "permissions-policy", "x-permitted"))
                ):
                    continue

                matched_at = n.get("matched_at", "")
                finding_host = _extract_hostname(matched_at, batch_domains[0]) if batch_domains else ""
                if not finding_host:
                    continue

                issue_type = f"Verified {n.get('cve_id', 'Vulnerability')}"
                key = (finding_host, issue_type)

                if key in seen_issues:
                    continue

                seen_issues.add(key)
                n["_resolved_host"] = finding_host
                nuclei_findings.append(n)

            if nuclei_findings:
                async with get_tenant_db(tenant_id) as session:
                    for result_item in nuclei_findings:
                        t_id = str(result_item.get("template_id", "")).lower()
                        finding_host = result_item.get("_resolved_host", "")
                        logger.info(f"[EASM/Nuclei] Mapped finding {t_id} to host {finding_host}")

                        host_info = asset_info_map.get(finding_host, {"criticality": "medium"})
                        asset_criticality = host_info.get("criticality", "medium")

                        def _adjust_severity(base_sev: str) -> str:
                            levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                            rev_levels = {v: k for k, v in levels.items()}
                            val = levels.get(base_sev, 2)
                            if asset_criticality in ("critical", "high"):
                                val = min(4, val + 1)
                            elif asset_criticality == "low":
                                val = max(0, val - 1)
                            return rev_levels.get(val, base_sev)

                        issue_type = f"Verified {result_item.get('cve_id', 'Vulnerability')}"

                        existing = await session.execute(
                            select(Finding).where(
                                and_(
                                    Finding.tenant_id == tid,
                                    Finding.entity == finding_host,
                                    Finding.issue_type == issue_type,
                                )
                            )
                        )
                        existing_row = existing.scalars().first()
                        if existing_row:
                            logger.info(f"[EASM/Nuclei] Deduplicating existing finding {issue_type} for {finding_host}")
                            existing_row.last_seen_at = datetime.now(timezone.utc)
                            if existing_row.status == "resolved":
                                existing_row.status = "open"

                            current_evidence = dict(existing_row.evidence or {})
                            matched_urls = current_evidence.get("matched_at", [])
                            if isinstance(matched_urls, str):
                                matched_urls = [matched_urls]
                            elif not isinstance(matched_urls, list):
                                matched_urls = []

                            new_match = result_item.get("matched_at")
                            if new_match and new_match not in matched_urls:
                                matched_urls.append(new_match)
                                current_evidence["matched_at"] = matched_urls
                                existing_row.evidence = current_evidence
                                from sqlalchemy.orm.attributes import flag_modified
                                flag_modified(existing_row, "evidence")
                            continue

                        seq_result = await session.execute(text("SELECT nextval('findings_seq')"))
                        seq_num = seq_result.scalar()

                        logger.info(f"[EASM/Nuclei] Adding new finding {issue_type} for {finding_host} with severity {result_item.get('severity')}")
                        session.add(Finding(
                            tenant_id=tid,
                            finding_num=seq_num,
                            severity=_adjust_severity(result_item.get("severity", "high")),
                            source="ext_scanner",
                            issue_type=issue_type,
                            entity=finding_host,
                            tags=["Verified", "Nuclei"],
                            evidence={
                                "hostname": finding_host,
                                "confidence": 95,
                                "description": result_item.get("description"),
                                "extracted_results": result_item.get("extracted_results"),
                                "matched_at": result_item.get("matched_at"),
                                "template_id": result_item.get("template_id"),
                            },
                        ))

                        if finding_host in asset_info_map:
                            asset_info_map[finding_host]["findings_found"] = asset_info_map[finding_host].get("findings_found", 0) + 1

                    for hname, info in asset_info_map.items():
                        findings_count = info.get("findings_found", 0)
                        if findings_count > 0:
                            result = await session.execute(
                                select(EasmAsset).where(
                                    and_(
                                        EasmAsset.tenant_id == tid,
                                        EasmAsset.hostname == hname,
                                    )
                                )
                            )
                            asset_row = result.scalar_one_or_none()
                            if asset_row:
                                asset_row.cve_count = (asset_row.cve_count or 0) + findings_count
                                asset_row.updated_at = datetime.now(timezone.utc)

                    await session.commit()

            ok_count += len(batch_domains)
            logger.info(f"[EASM/Nuclei] Batch {batch_idx + 1} done. Found {len(nuclei_findings)} verified vulnerabilities across {len(batch_domains)} hosts.")
        except Exception as e:
            logger.error(f"[EASM/Nuclei] Batch {batch_idx + 1} scan failed: {e}")
            fail_count += len(batch_domains)

        gc.collect()

    logger.info(f"[EASM/Nuclei] Phase complete: {ok_count} ok, {fail_count} failed")
    return (ok_count, fail_count)
