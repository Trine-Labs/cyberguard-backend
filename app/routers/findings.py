"""
CyberGuard -- Findings Router
Unified security findings from all sources (M365 + EASM scanner).
Reads from the findings table (populated by easm_scanner + m365 checks).
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi_cache.decorator import cache
from app.cache_utils import tenant_key_builder
from pydantic import BaseModel

from app.dependencies import get_db, get_current_user, require_admin
from app.database import set_rls_tenant
from app.models.user import User
from app.models.finding import Finding

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


@router.get("")
@cache(expire=60, key_builder=tenant_key_builder)
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
    import time
    print("\n--- FINDINGS API DEBUG ---")
    t0 = time.time()
    await set_rls_tenant(session, str(current_user.tenant_id))
    print(f"[Debug] set_rls_tenant took {time.time() - t0:.4f}s")

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

    import asyncio
    from app.database import get_tenant_db
    from sqlalchemy import cast, String

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
            from sqlalchemy import case
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

    t_gather = time.time()
    total, sev_map, findings = await asyncio.gather(
        fetch_total(),
        fetch_counts(),
        fetch_page()
    )
    print(f"[Debug] Scatter-Gather execution took {time.time() - t_gather:.4f}s")
    open_count = sum(sev_map.values())
    
    t4 = time.time()
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
    print(f"[Debug] serialization took {time.time() - t4:.4f}s")
    print(f"[Debug] TOTAL API execution took {time.time() - t0:.4f}s")
    return ret


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
    current_user: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
):
    """Update finding status. Persisted to DB."""
    await set_rls_tenant(session, str(current_user.tenant_id))

    valid_statuses = {"open", "resolved", "accepted_risk", "false_positive"}
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

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

    from datetime import datetime, timezone
    finding.status = body.status
    if body.status == "resolved":
        finding.resolved_at = datetime.now(timezone.utc)
    finding.updated_at = datetime.now(timezone.utc)

    return {"message": f"Status updated to '{body.status}'", "finding_id": str(finding.id)}
