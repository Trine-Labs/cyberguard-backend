"""
CyberGuard -- Findings Router
Unified security findings from all sources (M365 + EASM scanner).
Reads from the findings table (populated by easm_scanner + m365 checks).
"""
import io
import time
import asyncio
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, and_, or_, cast, String, case
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi_cache.decorator import cache
from app.cache_utils import tenant_key_builder
from pydantic import BaseModel

from app.dependencies import get_db, get_current_user, require_admin
from app.database import set_rls_tenant, get_tenant_db
from app.models.user import User
from app.models.finding import Finding
from app.models.tenant import Tenant

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "finding_id": f.human_id,
        "severity": f.severity,
        "source": f.source,
        "issue_type": f.issue_type,
        "entity": f.entity,
        "status": f.status,
        "evidence": f.evidence or {},
        "tags": f.tags or [],
        "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
        "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
    }


class StatusUpdateRequest(BaseModel):
    status: str  # open | resolved | accepted_risk | false_positive


class AIAnalystRequest(BaseModel):
    industry_context: Optional[str] = "Moroccan Banking Sector"
    top_n: Optional[int] = 20


@router.get("")
async def list_findings(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    """Paginated, filterable findings list from DB."""
    t0 = time.time()
    await set_rls_tenant(session, str(current_user.tenant_id))

    q = select(Finding).where(Finding.tenant_id == current_user.tenant_id)

    if severity and severity != "all":
        q = q.where(Finding.severity == severity)
    if source and source != "all":
        q = q.where(Finding.source == source)
    if status and status != "all":
        q = q.where(Finding.status == status)
    if search:
        q = q.where(
            or_(
                Finding.issue_type.ilike(f"%{search}%"),
                Finding.entity.ilike(f"%{search}%"),
            )
        )

    async def fetch_total():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            return await db.scalar(select(func.count(Finding.id)).where(q.whereclause)) or 0

    async def fetch_counts():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            counts_q = select(cast(Finding.severity, String), func.count()).where(
                and_(Finding.tenant_id == current_user.tenant_id, Finding.status == "open")
            ).group_by(cast(Finding.severity, String))
            res = await db.execute(counts_q)
            return {row[0]: row[1] for row in res.all()}

    async def fetch_page():
        async with get_tenant_db(str(current_user.tenant_id)) as db:
            severity_order = case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                (Finding.severity == "info", 4),
                else_=5,
            )
            page_q = q.order_by(
                severity_order,
                Finding.created_at.desc()
            ).offset((page - 1) * per_page).limit(per_page)
            res = await db.execute(page_q)
            return res.scalars().all()

    total, sev_map, findings = await asyncio.gather(
        fetch_total(),
        fetch_counts(),
        fetch_page()
    )
    open_count = sum(sev_map.values())
    
    ret = {
        "findings": [_finding_to_dict(f) for f in findings],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
        "summary": {
            "critical": sev_map.get("critical", 0),
            "high": sev_map.get("high", 0),
            "medium": sev_map.get("medium", 0),
            "open": open_count,
        },
    }
    return ret


@router.get("/ai-analyst/latest")
async def get_latest_ai_analyst_synthesis(
    current_user: User = Depends(get_current_user),
):
    """Retrieve saved executive AI synthesis for the current tenant if available."""
    from app.services.ai_analyst import get_latest_executive_synthesis
    latest = get_latest_executive_synthesis(str(current_user.tenant_id))
    if not latest:
        return {"synthesis": None}
    return {"synthesis": latest}


@router.post("/ai-analyst/synthesize")
async def synthesize_ai_analyst(
    body: Optional[AIAnalystRequest] = None,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """
    Module 5: AI Analyst Layer
    Takes deterministic Findings for the tenant, strips PII, embeds tenant profile background info (data training context),
    and generates an executive-ready English synthesis with strict DB finding ID validation.
    Persists synthesis for the tenant.
    """
    from app.services.ai_analyst import run_ai_analyst_pipeline, save_executive_synthesis
    from app.models.tenant import Tenant

    await set_rls_tenant(session, str(current_user.tenant_id))

    # Fetch Tenant profile info
    t_res = await session.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = t_res.scalar_one_or_none()

    company_info = tenant.company_info if (tenant and tenant.company_info) else ""
    org_name = tenant.org_name if tenant else "Enterprise Business"
    industry_ctx = f"{org_name} Profile Context" if company_info else f"{org_name} Security Baseline"

    top_n = body.top_n if (body and body.top_n) else 20

    # Fetch top findings for the tenant ordered by severity
    q = (
        select(Finding)
        .where(and_(Finding.tenant_id == current_user.tenant_id, Finding.status == "open"))
        .order_by(Finding.severity, Finding.created_at.desc())
        .limit(top_n)
    )
    result = await session.execute(q)
    findings_orm = result.scalars().all()
    findings_data = [_finding_to_dict(f) for f in findings_orm]

    try:
        synthesis = await run_ai_analyst_pipeline(
            findings=findings_data,
            industry_context=industry_ctx,
            company_info=company_info,
            org_name=org_name,
        )
        save_executive_synthesis(str(current_user.tenant_id), synthesis)
        return synthesis
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Analyst execution failed: {str(e)}")


@router.post("/{finding_id}/synthesize")
async def synthesize_single_finding(
    finding_id: str,
    force: bool = Query(False),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """
    Generate dynamic context-aware AI synthesis for a single security finding
    and save the result directly into finding.evidence['ai_synthesis'] in PostgreSQL.
    If an AI synthesis already exists and force=False, returns the cached database record instantly.
    """
    from app.services.ai_analyst import run_single_finding_ai_synthesis
    from sqlalchemy.orm.attributes import flag_modified
    from fastapi_cache import FastAPICache

    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == current_user.tenant_id,
                or_(
                    cast(Finding.id, String) == finding_id,
                    Finding.human_id == finding_id,
                )
            )
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # ── Return cached DB synthesis if already generated and force=False ──────────
    existing_synthesis = finding.evidence.get("ai_synthesis") if (finding.evidence and isinstance(finding.evidence, dict)) else None
    if not force and existing_synthesis:
        return {
            "message": "AI synthesis retrieved from database cache",
            "finding_id": str(finding.id),
            "ai_synthesis": existing_synthesis,
            "finding": _finding_to_dict(finding),
        }

    from app.models.tenant import Tenant
    t_res = await session.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    current_tenant = t_res.scalar_one_or_none()
    company_info = current_tenant.company_info if current_tenant else ""

    finding_dict = _finding_to_dict(finding)
    synthesis_result = await run_single_finding_ai_synthesis(
        finding=finding_dict,
        industry_context="Enterprise Security Baseline",
        company_info=company_info or ""
    )

    new_evidence = dict(finding.evidence or {})
    new_evidence["ai_synthesis"] = synthesis_result
    finding.evidence = new_evidence
    flag_modified(finding, "evidence")
    finding.updated_at = datetime.now(timezone.utc)

    await session.commit()
    await session.refresh(finding)

    try:
        await FastAPICache.clear()
    except Exception:
        pass

    return {
        "message": "AI synthesis generated and saved",
        "finding_id": str(finding.id),
        "ai_synthesis": synthesis_result,
        "finding": _finding_to_dict(finding),
    }


@router.post("/{finding_id}/synthesize/preview")
async def synthesize_single_finding_preview(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """
    Ephemeral AI synthesis — generates and returns the result WITHOUT saving to DB.
    Used for instant on-open synthesis in the UI (transient, not persisted).
    """
    from app.services.ai_analyst import run_single_finding_ai_synthesis
    from app.models.tenant import Tenant

    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == current_user.tenant_id,
                or_(
                    cast(Finding.id, String) == finding_id,
                    Finding.human_id == finding_id,
                )
            )
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    t_res = await session.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    current_tenant = t_res.scalar_one_or_none()
    company_info = current_tenant.company_info if current_tenant else ""

    finding_dict = _finding_to_dict(finding)
    synthesis_result = await run_single_finding_ai_synthesis(
        finding=finding_dict,
        industry_context="Enterprise Security Baseline",
        company_info=company_info or ""
    )

    return {
        "finding_id": str(finding.id),
        "ai_synthesis": synthesis_result,
    }




@router.get("/export/pdf")
async def export_findings_pdf(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status (open/resolved/all)"),
):
    """
    Generate and stream a full security audit PDF report for the tenant.
    Includes all findings sorted by severity, with evidence details.
    """
    from app.services.pdf_service import generate_audit_pdf

    await set_rls_tenant(session, str(current_user.tenant_id))

    # Fetch tenant name
    tenant = await session.get(Tenant, current_user.tenant_id)
    org_name = tenant.org_name if tenant else "Unknown Organisation"

    # Fetch all findings (no pagination — full export)
    q = select(Finding).where(Finding.tenant_id == current_user.tenant_id)
    if status and status != "all":
        q = q.where(Finding.status == status)
    q = q.order_by(Finding.severity, Finding.created_at.desc())

    result = await session.execute(q)
    findings_orm = result.scalars().all()

    findings_data = [_finding_to_dict(f) for f in findings_orm]

    # Generate PDF in a thread pool to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    pdf_bytes = await loop.run_in_executor(
        None,
        lambda: generate_audit_pdf(org_name=org_name, findings=findings_data)
    )

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    filename = f"cyberguard_audit_{org_name.lower().replace(' ', '_')}_{ts}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{finding_id}")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Get a single finding's full details including evidence blob."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    result = await session.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == current_user.tenant_id,
                Finding.id == finding_id,
            )
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_to_dict(finding)


@router.patch("/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    body: StatusUpdateRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    """Update finding status. Persisted to DB & clears cached metrics."""
    from fastapi_cache import FastAPICache

    await set_rls_tenant(session, str(current_user.tenant_id))

    valid_statuses = {"open", "resolved", "accepted_risk", "false_positive"}
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

    result = await session.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == current_user.tenant_id,
                or_(
                    cast(Finding.id, String) == finding_id,
                    Finding.human_id == finding_id,
                )
            )
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = body.status
    if body.status == "resolved":
        finding.resolved_at = datetime.now(timezone.utc)
    else:
        finding.resolved_at = None
    finding.updated_at = datetime.now(timezone.utc)

    await session.commit()
    await session.refresh(finding)

    # Invalidate cached endpoints so UI immediately gets fresh DB metrics
    try:
        await FastAPICache.clear()
    except Exception:
        pass

    return {
        "message": f"Status updated to '{body.status}'",
        "finding_id": str(finding.id),
        "status": finding.status,
    }
