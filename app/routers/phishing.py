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
                "targets": [
                    {
                        "id": str(t.id),
                        "employee_email": t.employee_email,
                        "employee_name": t.employee_name,
                        "status": t.status,
                        "sent_at": t.sent_at.isoformat(),
                        "clicked_at": t.clicked_at.isoformat() if t.clicked_at else None,
                        "ip_address": t.ip_address,
                        "user_agent": t.user_agent,
                        "score_penalty": t.score_penalty,
                    }
                    for t in (c.targets or [])
                ],
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


class SubmitCredentialsRequest(BaseModel):
    token: str

class QuizRewardRequest(BaseModel):
    token: str


@router.get("/public/track")
async def track_phishing_click(
    t: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Public tracking endpoint executed when an employee clicks a simulated phishing link in an email.
    Captures click metrics, reduces employee score, logs Finding, and redirects to realistic fake landing page.
    """
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    res = await phishing_service.record_phishing_click(db, t, ip, user_agent)
    
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from app.models.phishing import PhishingTarget, PhishingCampaign
    target_res = await db.execute(
        select(PhishingTarget)
        .options(selectinload(PhishingTarget.campaign))
        .where(PhishingTarget.tracking_token == t)
    )
    target = target_res.scalar_one_or_none()
    template_type = target.campaign.template_type if (target and target.campaign) else "password_reset"

    base_domain = "https://cyberguardsystem.online"
    if template_type == "password_reset":
        redirect_url = f"{base_domain}/phish/login?t={t}"
    elif template_type == "urgent_invoice":
        redirect_url = f"{base_domain}/phish/invoice?t={t}"
    elif template_type == "hr_policy_update":
        redirect_url = f"{base_domain}/phish/hr?t={t}"
    else:
        redirect_url = f"{base_domain}/phished?token={t}"

    if res:
        redirect_url += f"&name={res['employee_name']}&score={res['current_score']}&penalty={res['score_penalty']}"

    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/public/submit-credentials")
async def submit_phishing_credentials(
    req: SubmitCredentialsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    res = await phishing_service.record_credential_submission(db, req.token, ip, user_agent)
    if not res:
        raise HTTPException(status_code=404, detail="Invalid phishing token.")

    return {
        "message": "Credentials captured in simulation.",
        "redirect_url": f"https://cyberguardsystem.online/phished?token={req.token}&name={res['employee_name']}&score={res['current_score']}&penalty=40"
    }


@router.post("/public/quiz-reward")
async def reward_quiz_points_endpoint(
    req: QuizRewardRequest,
    db: AsyncSession = Depends(get_db),
):
    res = await phishing_service.reward_quiz_points(db, req.token)
    if not res:
        raise HTTPException(status_code=404, detail="Invalid phishing tracking token.")
    return res
