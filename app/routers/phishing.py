"""
CyberGuard — Phishing Simulation & Employee Awareness Router
"""
import uuid
from typing import List, Optional
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.services import phishing_service

router = APIRouter(prefix="/api/v1/phishing", tags=["Phishing Simulation"])


class TargetEmployeeInput(BaseModel):
    email: EmailStr
    name: Optional[str] = None


class CreateCampaignPayload(BaseModel):
    title: str
    template_type: str = "password_reset"
    targets: List[TargetEmployeeInput]


@router.post("/campaigns", status_code=201)
async def create_phishing_campaign(
    payload: CreateCampaignPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.targets:
        raise HTTPException(status_code=400, detail="At least one target email is required.")
    
    target_dicts = [{"email": t.email, "name": t.name or t.email.split("@")[0].capitalize()} for t in payload.targets]
    
    campaign = await phishing_service.launch_phishing_campaign(
        session=db,
        tenant_id=current_user.tenant_id,
        title=payload.title,
        template_type=payload.template_type,
        target_employees=target_dicts
    )

    return {
        "message": f"Phishing campaign '{campaign.title}' launched successfully to {len(target_dicts)} targets.",
        "campaign_id": str(campaign.id),
        "total_targets": campaign.total_targets,
    }


@router.get("/campaigns")
async def list_phishing_campaigns(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    campaigns = await phishing_service.get_tenant_campaigns(db, current_user.tenant_id)
    return {
        "campaigns": [
            {
                "id": str(c.id),
                "title": c.title,
                "email_subject": c.email_subject,
                "template_type": c.template_type,
                "status": c.status,
                "total_targets": c.total_targets,
                "clicks_count": c.clicks_count,
                "click_rate": round((c.clicks_count / c.total_targets * 100), 1) if c.total_targets > 0 else 0.0,
                "launched_at": c.launched_at.isoformat(),
            }
            for c in campaigns
        ]
    }


@router.get("/scores")
async def list_employee_security_scores(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scores = await phishing_service.get_tenant_employee_scores(db, current_user.tenant_id)
    return {
        "employee_scores": [
            {
                "id": str(s.id),
                "employee_email": s.employee_email,
                "employee_name": s.employee_name,
                "department": s.department,
                "current_score": s.current_score,
                "risk_tier": s.risk_tier,
                "simulations_received": s.simulations_received,
                "simulations_clicked": s.simulations_clicked,
                "simulations_reported": s.simulations_reported,
                "last_phished_at": s.last_phished_at.isoformat() if s.last_phished_at else None,
            }
            for s in scores
        ]
    }


@router.get("/public/track")
async def track_phishing_click(
    t: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Public tracking endpoint executed when an employee clicks a simulated phishing link in an email.
    Captures click metrics, reduces employee score, logs Finding, and redirects to /phished educational page.
    """
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    res = await phishing_service.record_phishing_click(db, t, ip, user_agent)
    
    redirect_url = f"https://cyberguardsystem.online/phished?token={t}"
    if res:
        redirect_url += f"&name={res['employee_name']}&score={res['current_score']}&penalty={res['score_penalty']}"

    return RedirectResponse(url=redirect_url, status_code=302)
