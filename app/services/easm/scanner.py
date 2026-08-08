"""
EASM Scanner Core Orchestration & Execution Service
"""
import asyncio
from datetime import datetime, timezone
import gc
import ipaddress
import json
import uuid

from sqlalchemy import select, and_

from app.database import get_tenant_db
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from app.models.scan_job import ScanJob
from app.services.easm.config import (
    _GLOBAL_SCAN_SEM,
    _HTTP_CLIENT,
    COMMON_PORTS,
    RISKY_PORTS,
    _get_tenant_lock,
    _is_cidr,
    _is_ip,
    logger,
)
from app.services.easm.findings import _generate_findings
from app.services.easm.hibp import _run_hibp_scan
from app.services.easm.nuclei import _run_nuclei_phase
from app.services.easm.probes import (
    _calculate_cve_data,
    _check_email_security,
    _detect_tech_stack,
    _grade_security_headers,
    _probe_http,
    _probe_sensitive_paths,
    _probe_tls,
    _resolve_geoip,
    _resolve_ip,
    _scan_port,
    _test_catch_all,
)
from app.services.easm.subdomain import _enumerate_subdomains


async def scan_domain(
    tenant_id: uuid.UUID,
    hostname: str,
    modules: list[str] | None = None
) -> None:
    """
    Full EASM scan for a single hostname.
    Runs all probes concurrently and stores results.
    Gated by _GLOBAL_SCAN_SEM to prevent resource exhaustion.
    """
    async with _GLOBAL_SCAN_SEM:
        await _scan_domain_inner(tenant_id, hostname, modules)


async def _scan_domain_inner(
    tenant_id: uuid.UUID,
    hostname: str,
    modules: list[str] | None = None
) -> None:
    """Inner implementation of scan_domain, runs under the global semaphore."""
    logger.info(f"[EASM] Scanning {hostname} for tenant {tenant_id}")

    async def dummy_http(): return {}
    async def dummy_tls(): return None

    do_web = not modules or "web" in modules
    do_ports = not modules or "ports" in modules

    http_task = asyncio.create_task(_probe_http(hostname) if do_web else dummy_http())
    tls_task = asyncio.create_task(_probe_tls(hostname) if do_web else dummy_tls())
    ip_task = asyncio.create_task(_resolve_ip(hostname))

    sem = asyncio.Semaphore(50)

    async def _guarded_port(host, port, timeout=1.5):
        async with sem:
            return await _scan_port(host, port, timeout)

    active_ports = COMMON_PORTS if do_ports else []
    if do_ports and hostname in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        active_ports = [p for p in COMMON_PORTS if p[0] not in (3000, 3001, 8000)]

    port_tasks = {
        (port, svc, risk): asyncio.create_task(_guarded_port(hostname, port))
        for port, svc, risk in active_ports
    }

    http_result = await http_task
    cert_info = await tls_task
    ip_address = await ip_task
    port_results = {k: await v for k, v in port_tasks.items()}

    geoip_info = await _resolve_geoip(ip_address)
    is_catch_all = http_result.get("is_catch_all", False)

    open_web_urls = set()
    if http_result.get("final_url"):
        open_web_urls.add(http_result["final_url"])

    for (port, svc, risk), is_open in port_results.items():
        if is_open and svc in ("HTTP", "HTTP-Alt", "HTTPS", "HTTPS-Alt"):
            scheme = "https" if "HTTPS" in svc else "http"
            open_web_urls.add(f"{scheme}://{hostname}:{port}")

    sensitive_findings = []
    if do_web:
        all_tech = {json.dumps(t, sort_keys=True) for t in http_result.get("tech_stack", [])}
        for web_url in open_web_urls:
            if web_url != http_result.get("final_url"):
                try:
                    resp = await _HTTP_CLIENT.get(web_url)
                    techs = _detect_tech_stack(str(resp.url), dict(resp.headers), resp.text)
                    for t in techs:
                        all_tech.add(json.dumps(t, sort_keys=True))

                    if not http_result.get("status"):
                        http_result["status"] = resp.status_code
                        http_result["sec_headers_grade"] = _grade_security_headers(dict(resp.headers))
                        http_result["final_url"] = str(resp.url)
                        http_result["is_catch_all"] = await _test_catch_all(web_url)
                except Exception:
                    pass

            is_catch = await _test_catch_all(web_url)
            findings = await _probe_sensitive_paths(web_url, is_catch_all=is_catch)
            sensitive_findings.extend(findings)

        http_result["tech_stack"] = [json.loads(t) for t in all_tech]

    do_email = (not modules or "email" in modules) and not _is_ip(hostname)
    email_security = await _check_email_security(hostname) if do_email else {}

    is_admin = any(kw in hostname for kw in ["admin", "portal", "manage", "cpanel", "wp-admin", "phpmyadmin"])
    http_status = http_result.get("status")
    tech_stack = http_result.get("tech_stack", [])
    grade = http_result.get("sec_headers_grade", "unknown")

    criticality = "unknown"
    if any(w in hostname for w in ["prod", "api", "app", "www", "main"]):
        criticality = "high"
    elif any(w in hostname for w in ["dev", "test", "staging", "qa"]):
        criticality = "low"
    elif is_admin:
        criticality = "critical"
    else:
        criticality = "medium"

    do_vuln = not modules or "vuln" in modules

    async def dummy_cve(): return []
    cve_data = await (_calculate_cve_data(tech_stack) if do_vuln else dummy_cve())

    nuclei_data = []
    cve_count = len(cve_data)

    async with get_tenant_db(str(tenant_id)) as session:
        # ── Upsert easm_assets ──────────────────────────────────────────────────
        existing_asset = await session.execute(
            select(EasmAsset).where(
                and_(
                    EasmAsset.tenant_id == tenant_id,
                    EasmAsset.hostname == hostname,
                )
            )
        )
        asset = existing_asset.scalar_one_or_none()

        if asset:
            asset.ip_address = ip_address
            asset.http_status = http_status
            asset.tech_stack = [json.dumps(t) for t in tech_stack]
            asset.sec_headers_grade = grade
            asset.cve_count = cve_count
            asset.is_catch_all = is_catch_all
            asset.is_exposed_admin = is_admin
            asset.asset_criticality = criticality
            asset.last_seen_at = datetime.now(timezone.utc)
            asset.updated_at = datetime.now(timezone.utc)
        else:
            asset = EasmAsset(
                tenant_id=tenant_id,
                hostname=hostname,
                ip_address=ip_address,
                http_status=http_status,
                asset_type="admin" if is_admin else "web",
                tech_stack=[json.dumps(t) for t in tech_stack],
                sec_headers_grade=grade,
                cve_count=cve_count,
                is_catch_all=is_catch_all,
                is_exposed_admin=is_admin,
                asset_criticality=criticality,
                status="active",
            )
            session.add(asset)
        await session.flush()

        # ── Upsert easm_certificates ────────────────────────────────────────────
        if cert_info:
            existing_cert = await session.execute(
                select(EasmCertificate).where(
                    and_(
                        EasmCertificate.tenant_id == tenant_id,
                        EasmCertificate.hostname == hostname,
                    )
                )
            )
            cert_row = existing_cert.scalar_one_or_none()
            if cert_row:
                cert_row.issuer = cert_info["issuer"]
                cert_row.valid_from = cert_info["valid_from"]
                cert_row.valid_to = cert_info["valid_to"]
                cert_row.is_expired = cert_info["is_expired"]
                cert_row.is_self_signed = cert_info["is_self_signed"]
                cert_row.is_mismatch = cert_info.get("is_mismatch", False)
                cert_row.days_to_expiry = cert_info["days_to_expiry"]
                cert_row.sans = cert_info["sans"]
                cert_row.updated_at = datetime.now(timezone.utc)
            else:
                session.add(EasmCertificate(
                    tenant_id=tenant_id,
                    hostname=hostname,
                    issuer=cert_info["issuer"],
                    subject=cert_info["subject"],
                    fingerprint=None,
                    valid_from=cert_info["valid_from"],
                    valid_to=cert_info["valid_to"],
                    is_expired=cert_info["is_expired"],
                    is_self_signed=cert_info["is_self_signed"],
                    is_mismatch=cert_info.get("is_mismatch", False),
                    days_to_expiry=cert_info["days_to_expiry"],
                    sans=cert_info["sans"],
                ))

        # ── Upsert easm_ports ───────────────────────────────────────────────────
        risky_open: list[tuple[int, str, str]] = []
        for (port, svc, risk), is_open in port_results.items():
            if not is_open:
                continue
            is_risky = port in RISKY_PORTS
            if is_risky:
                risky_open.append((port, svc, risk))

            existing_port = await session.execute(
                select(EasmPort).where(
                    and_(
                        EasmPort.tenant_id == tenant_id,
                        EasmPort.ip_address == ip_address,
                        EasmPort.port == port,
                    )
                )
            )
            port_row = existing_port.scalar_one_or_none()
            if port_row:
                port_row.last_seen_at = datetime.now(timezone.utc)
                port_row.is_risky = is_risky
                if geoip_info["provider"]:
                    port_row.provider = geoip_info["provider"]
                if geoip_info["location"]:
                    port_row.location = geoip_info["location"]
            else:
                session.add(EasmPort(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    ip_address=ip_address or "0.0.0.0",
                    port=port,
                    protocol="tcp",
                    service=svc,
                    banner=None,
                    provider=geoip_info.get("provider"),
                    location=geoip_info.get("location"),
                    risk_level=risk,
                    is_risky=is_risky,
                ))

        # ── Auto-generate findings ───────────────────────────────────────────
        try:
            await _generate_findings(
                tenant_id, hostname, http_result, cert_info, risky_open,
                sensitive_findings, email_security, is_admin, cve_data, nuclei_data, criticality, session
            )
        except Exception as e:
            logger.warning(f"[EASM] Finding generation error for {hostname}: {e}")

        await session.flush()
        logger.info(f"[EASM] Done {hostname}: status={http_status} grade={grade} ports={len(risky_open)} risky admin={is_admin}")


async def _is_job_cancelled(tenant_id: str, job_id: uuid.UUID | None) -> bool:
    if not job_id:
        return False
    try:
        async with get_tenant_db(tenant_id) as session:
            result = await session.execute(select(ScanJob.status).where(ScanJob.id == job_id))
            row = result.first()
            if row and row[0] in ("failed", "completed"):
                return True
    except Exception as e:
        logger.warning(f"[EASM] Error checking scan job cancel status: {e}")
    return False


async def run_easm_scan(tenant_id: str, scope_values: list[str], modules: list[str] | None = None) -> None:
    """
    Main entry point: scan all domains in the tenant's scope.
    Called as a background task after onboarding or manual rescan.
    Creates a ScanJob record and updates its status throughout.
    """
    tid = uuid.UUID(tenant_id)

    job_id: uuid.UUID | None = None
    try:
        async with get_tenant_db(tenant_id) as session:
            job = ScanJob(
                tenant_id=tid,
                job_type="easm",
                status="queued",
                started_at=datetime.now(timezone.utc),
                metadata_={
                    "targets": scope_values,
                    "modules": modules,
                    "all_hosts": [],
                    "total": 0,
                    "completed": 0,
                    "failed": 0,
                    "subdomains_found": 0,
                },
            )
            session.add(job)
            await session.commit()
            job_id = job.id
    except Exception as e:
        logger.error(f"[EASM] Could not create queued ScanJob: {e}")

    lock = _get_tenant_lock(tenant_id)
    if lock.locked():
        logger.info(f"[EASM] Scan already running for tenant {tenant_id}, queuing this scan...")

    async with lock:
        try:
            await _run_easm_scan_inner(tenant_id, scope_values, passed_job_id=job_id, modules=modules)
        except Exception as e:
            logger.error(f"[EASM] Scan job {job_id} failed with unexpected error: {e}")
            if job_id:
                try:
                    async with get_tenant_db(tenant_id) as session:
                        result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
                        job = result.scalar_one_or_none()
                        if job and job.status in ("queued", "running"):
                            job.status = "failed"
                            await session.commit()
                except Exception as inner_e:
                    logger.error(f"[EASM] Could not mark job {job_id} as failed: {inner_e}")


async def _run_easm_scan_inner(tenant_id: str, scope_values: list[str], passed_job_id: uuid.UUID | None = None, modules: list[str] | None = None) -> None:
    """Inner implementation of run_easm_scan, runs under the per-tenant guard."""
    tid = uuid.UUID(tenant_id)
    root_domains = [s for s in scope_values if not _is_cidr(s)]
    cidrs = [s for s in scope_values if _is_cidr(s)]
    logger.info(f"[EASM] Starting scan for tenant {tenant_id}, {len(root_domains)} domain(s), {len(cidrs)} CIDR(s)")

    ip_targets: list[str] = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.num_addresses == 1:
                ip_targets.append(str(net.network_address))
            else:
                for ip in net.hosts():
                    ip_targets.append(str(ip))
        except ValueError:
            pass

    all_domains: list[str] = []
    subdomain_map: dict[str, list[str]] = {}

    for root in root_domains:
        if not modules or "subdomains" in modules:
            subs = await _enumerate_subdomains(root)
        else:
            subs = []
        hosts = list({root} | set(subs))
        subdomain_map[root] = hosts
        all_domains.extend(hosts)
        logger.info(f"[EASM] {root}: {len(subs)} subdomains discovered → {len(hosts)} total hosts")

    seen: set[str] = set()
    domains: list[str] = []
    for d in all_domains:
        if d not in seen:
            seen.add(d)
            domains.append(d)

    for ip in ip_targets:
        if ip not in seen:
            seen.add(ip)
            domains.append(ip)

    total_subdomains = len(all_domains) - len(root_domains)

    job_id: uuid.UUID | None = passed_job_id
    try:
        async with get_tenant_db(tenant_id) as session:
            if job_id:
                result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
                job = result.scalar_one_or_none()
                if job:
                    job.status = "running"
                    job.metadata_ = {
                        "targets": scope_values,
                        "all_hosts": domains,
                        "total": len(domains),
                        "completed": 0,
                        "failed": 0,
                        "subdomains_found": total_subdomains,
                        "current_step": "subdomain_enum",
                        "step_label": f"Discovered {total_subdomains} subdomains across targets",
                    }
                    await session.commit()
            else:
                job = ScanJob(
                    tenant_id=tid,
                    job_type="easm",
                    status="running",
                    started_at=datetime.now(timezone.utc),
                    metadata_={
                        "targets": scope_values,
                        "all_hosts": domains,
                        "total": len(domains),
                        "completed": 0,
                        "failed": 0,
                        "subdomains_found": total_subdomains,
                        "current_step": "subdomain_enum",
                        "step_label": f"Discovered {total_subdomains} subdomains across targets",
                    },
                )
                session.add(job)
                await session.flush()
                job_id = job.id
                logger.info(f"[EASM] Created scan job {job_id} ── {len(domains)} hosts to scan")
    except Exception as e:
        logger.warning(f"[EASM] Could not update/create scan job record: {e}")

    completed = 0
    failed = 0
    BATCH_SIZE = 10

    async def _worker(domain_to_scan: str):
        try:
            await scan_domain(tid, domain_to_scan, modules)
            return (domain_to_scan, True)
        except Exception as e:
            logger.error(f"[EASM] Failed to scan {domain_to_scan}: {e}")
            return (domain_to_scan, False)

    for i in range(0, len(domains), BATCH_SIZE):
        if await _is_job_cancelled(tenant_id, job_id):
            logger.info(f"[EASM] Scan job {job_id} cancelled by user. Exiting discovery loop.")
            return

        batch = domains[i:i + BATCH_SIZE]
        logger.info(f"[EASM] Scanning batch {i // BATCH_SIZE + 1}/{(len(domains) + BATCH_SIZE - 1) // BATCH_SIZE}: {len(batch)} host(s)")

        tasks = [asyncio.create_task(_worker(d)) for d in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                failed += 1
            elif isinstance(result, tuple) and result[1]:
                completed += 1
            else:
                failed += 1

        if job_id:
            try:
                async with get_tenant_db(tenant_id) as session:
                    result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
                    j = result.scalar_one_or_none()
                    if j:
                        if j.status in ("failed", "completed"):
                            logger.info(f"[EASM] Scan job {job_id} cancelled or finished. Exiting progress update.")
                            return
                        j.metadata_ = {
                            "targets": scope_values,
                            "all_hosts": domains,
                            "total": len(domains),
                            "completed": completed,
                            "failed": failed,
                            "subdomains_found": total_subdomains,
                            "current_step": "probing_ports_web",
                            "step_label": f"Probing ports, HTTP headers & web tech stack ({completed}/{len(domains)} hosts done)",
                        }
                        await session.commit()
            except Exception:
                pass

        gc.collect()

    logger.info(f"[EASM] Asset discovery complete for tenant {tenant_id}: {completed} ok, {failed} failed, {total_subdomains} subdomains found")

    if await _is_job_cancelled(tenant_id, job_id):
        logger.info(f"[EASM] Scan job {job_id} cancelled by user. Skipping Nuclei phase.")
        return

    nuclei_ok = 0
    nuclei_fail = 0
    try:
        if job_id:
            async with get_tenant_db(tenant_id) as session:
                result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
                j = result.scalar_one_or_none()
                if j:
                    j.metadata_ = {
                        **(j.metadata_ or {}),
                        "phase": "vuln",
                        "current_step": "vulnerability_scan",
                        "step_label": "Running DAST & CVE vulnerability analysis (Nuclei engine)",
                    }
                    await session.commit()

        nuclei_ok, nuclei_fail = await _run_nuclei_phase(tenant_id, domains, modules, job_id=job_id)
    except Exception as e:
        logger.error(f"[EASM] Nuclei phase failed: {e}")

    if job_id:
        try:
            async with get_tenant_db(tenant_id) as session:
                result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
                j = result.scalar_one_or_none()
                if j:
                    if j.status in ("failed", "completed"):
                        logger.info(f"[EASM] Scan job {job_id} was cancelled or finished. Not overwriting status.")
                        return
                    j.status = "completed" if (completed > 0 or failed == 0) else "failed"
                    j.completed_at = datetime.now(timezone.utc)
                    j.metadata_ = {
                        "targets": scope_values,
                        "all_hosts": domains,
                        "total": len(domains),
                        "completed": completed,
                        "failed": failed,
                        "subdomains_found": total_subdomains,
                        "nuclei_scanned": nuclei_ok,
                        "nuclei_failed": nuclei_fail,
                        "current_step": "completed",
                        "step_label": "Scan finished & findings updated",
                    }
                    if j.status == "completed":
                        j.error_message = None
                    else:
                        j.error_message = f"All {failed} host(s) failed to scan"
                    await session.commit()
        except Exception as e:
            logger.warning(f"[EASM] Could not update scan job: {e}")

    logger.info(f"[EASM] Scan fully complete for tenant {tenant_id}: {completed} ok, {failed} failed, nuclei={nuclei_ok}/{nuclei_ok+nuclei_fail}")

    if not modules or "hibp" in modules or "credentials" in modules:
        try:
            await _run_hibp_scan(tenant_id, root_domains)
        except Exception as e:
            logger.error(f"[EASM/HIBP] Breach scan phase failed: {e}")
