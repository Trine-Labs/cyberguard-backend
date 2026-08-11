"""
CyberGuard — Phishing Simulation & Employee Security Awareness Service
"""
import uuid
import secrets
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
from sqlalchemy.orm import selectinload

from app.models.phishing import PhishingCampaign, PhishingTarget, EmployeeSecurityScore
from app.models.finding import Finding
from app.services.email_service import send_email_async
from app.config import get_settings

settings = get_settings()


TEMPLATES: Dict[str, Dict[str, str]] = {
    "password_reset": {
        "subject": "Urgent: Microsoft 365 Password Expiration Notice",
        "sender_name": "Microsoft 365 Security Team",
        "body_html": """
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h2 style="color: #d9534f;">Microsoft 365 Password Expiration Notice</h2>
            <p>Hello <strong>{employee_name}</strong>,</p>
            <p>Your Microsoft 365 organization password is scheduled to expire in <strong>4 hours</strong>.</p>
            <p>To prevent immediate interruption to your Outlook, Teams, and cloud documents, please verify your credentials below:</p>
            <div style="margin: 25px 0;">
                <a href="{tracking_url}" style="background-color: #0078d4; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Keep Current Password & Verify Identity</a>
            </div>
            <p style="font-size: 12px; color: #777;">Reference Code: MS-SEC-{token_short}</p>
            <p style="font-size: 11px; color: #999;">Microsoft Security Operations Center &copy; 2026</p>
        </div>
        """
    },
    "urgent_invoice": {
        "subject": "Action Required: Outstanding Vendor Invoice #INV-88942",
        "sender_name": "Accounts Payable Department",
        "body_html": """
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h3 style="color: #222;">Pending Payment Notice: Invoice #INV-88942</h3>
            <p>Dear <strong>{employee_name}</strong>,</p>
            <p>Please review the attached invoice payment request for service period Q3. Late fees will incur if payment is not authorized today.</p>
            <div style="margin: 25px 0;">
                <a href="{tracking_url}" style="background-color: #2e7d32; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Review & Authorize Payment Voucher</a>
            </div>
            <p style="font-size: 12px; color: #777;">Secure Voucher ID: VOUCH-{token_short}</p>
        </div>
        """
    },
    "hr_policy_update": {
        "subject": "Mandatory: Updated Employee Handbook & Work Policy Signature",
        "sender_name": "Corporate Human Resources",
        "body_html": """
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h3 style="color: #1565c0;">Company HR Policy Update</h3>
            <p>Hi <strong>{employee_name}</strong>,</p>
            <p>All employees are required to acknowledge the revised Remote Work & Security Guidelines Policy.</p>
            <div style="margin: 25px 0;">
                <a href="{tracking_url}" style="background-color: #1565c0; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Sign & Acknowledge Updated Policy</a>
            </div>
            <p style="font-size: 11px; color: #999;">Human Resources Compliance Portal</p>
        </div>
        """
    }
}


def _compute_risk_tier(score: int) -> str:
    if score >= 80:
        return "low_risk"
    elif score >= 50:
        return "medium_risk"
    else:
        return "high_risk"


async def get_or_create_employee_score(session: AsyncSession, tenant_id: uuid.UUID, email: str, name: str) -> EmployeeSecurityScore:
    res = await session.execute(
        select(EmployeeSecurityScore).where(
            EmployeeSecurityScore.tenant_id == tenant_id,
            EmployeeSecurityScore.employee_email == email.lower()
        )
    )
    score_obj = res.scalar_one_or_none()
    if not score_obj:
        score_obj = EmployeeSecurityScore(
            tenant_id=tenant_id,
            employee_email=email.lower(),
            employee_name=name,
            current_score=100,
            risk_tier="low_risk",
            simulations_received=0,
            simulations_clicked=0,
            simulations_reported=0
        )
        session.add(score_obj)
        await session.commit()
    return score_obj


async def launch_phishing_campaign(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    title: str,
    template_type: str,
    target_employees: List[Dict[str, str]]
) -> PhishingCampaign:
    tmpl = TEMPLATES.get(template_type, TEMPLATES["password_reset"])
    
    campaign = PhishingCampaign(
        tenant_id=tenant_id,
        title=title,
        email_subject=tmpl["subject"],
        sender_name=tmpl["sender_name"],
        sender_email="simulation@cyberguardsystem.online",
        template_type=template_type,
        status="active",
        total_targets=len(target_employees),
        clicks_count=0
    )
    session.add(campaign)
    await session.flush()

    for emp in target_employees:
        email = emp["email"].lower()
        name = emp.get("name", email.split("@")[0].capitalize())
        token = secrets.token_urlsafe(32)

        target = PhishingTarget(
            campaign_id=campaign.id,
            tenant_id=tenant_id,
            employee_email=email,
            employee_name=name,
            tracking_token=token,
            status="sent",
            score_penalty=25
        )
        session.add(target)

        # Update employee score record
        emp_score = await get_or_create_employee_score(session, tenant_id, email, name)
        emp_score.simulations_received += 1

        # Dispatch email
        tracking_url = f"https://cyberguardsystem.online/api/v1/phishing/public/track?t={token}"
        body = tmpl["body_html"].format(
            employee_name=name,
            tracking_url=tracking_url,
            token_short=token[:8]
        )
        try:
            await send_email_async(
                to_email=email,
                subject=tmpl["subject"],
                html_content=body,
                from_name=tmpl["sender_name"]
            )
        except Exception as e:
            pass

    await session.commit()
    return campaign


async def record_phishing_click(
    session: AsyncSession,
    token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    res = await session.execute(
        select(PhishingTarget).where(PhishingTarget.tracking_token == token)
    )
    target = res.scalar_one_or_none()
    if not target:
        return None

    first_click = target.status != "clicked"
    target.status = "clicked"
    target.clicked_at = datetime.now(timezone.utc)
    target.ip_address = ip_address
    target.user_agent = user_agent

    # Increment campaign click count
    res_camp = await session.execute(
        select(PhishingCampaign).where(PhishingCampaign.id == target.campaign_id)
    )
    campaign = res_camp.scalar_one_or_none()
    if campaign and first_click:
        campaign.clicks_count += 1

    # Update employee score and risk tier
    emp_score = await get_or_create_employee_score(session, target.tenant_id, target.employee_email, target.employee_name)
    if first_click:
        emp_score.simulations_clicked += 1
        emp_score.current_score = max(0, emp_score.current_score - target.score_penalty)
        emp_score.risk_tier = _compute_risk_tier(emp_score.current_score)
        emp_score.last_phished_at = datetime.now(timezone.utc)

        # Automatically log a Security Finding in the database
        from sqlalchemy import text as _text
        seq_res = await session.execute(_text("SELECT nextval('findings_seq')"))
        seq_num = seq_res.scalar()

        finding = Finding(
            tenant_id=target.tenant_id,
            finding_num=seq_num,
            severity="high",
            source="m365",
            issue_type="Phishing Simulation Failure (Employee Compromise Risk)",
            entity=target.employee_email,
            evidence={
                "employee_name": target.employee_name,
                "campaign_title": campaign.title if campaign else "Phishing Simulation",
                "clicked_at": datetime.now(timezone.utc).isoformat(),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "score_penalty": target.score_penalty,
                "new_score": emp_score.current_score,
            },
            tags=["phishing_simulation", "identity_risk", "human_factor"]
        )
        session.add(finding)

        # When employee score drops below 50, automatically create a CRITICAL severity finding
        if emp_score.current_score < 50:
            seq_res_crit = await session.execute(_text("SELECT nextval('findings_seq')"))
            seq_num_crit = seq_res_crit.scalar()

            crit_finding = Finding(
                tenant_id=target.tenant_id,
                finding_num=seq_num_crit,
                severity="critical",
                source="m365",
                issue_type="Critical Employee Security Risk (Awareness Score Below 50)",
                entity=target.employee_email,
                evidence={
                    "employee_name": target.employee_name,
                    "employee_email": target.employee_email,
                    "current_score": emp_score.current_score,
                    "risk_tier": emp_score.risk_tier,
                    "simulations_received": emp_score.simulations_received,
                    "simulations_clicked": emp_score.simulations_clicked,
                    "reason": "Employee security awareness score dropped below 50 due to phishing simulation clicks.",
                    "last_phished_at": datetime.now(timezone.utc).isoformat(),
                },
                tags=["phishing_simulation", "critical_human_risk", "vulnerable_identity"]
            )
            session.add(crit_finding)

    await session.commit()

    return {
        "employee_name": target.employee_name,
        "employee_email": target.employee_email,
        "campaign_title": campaign.title if campaign else "Phishing Simulation",
        "current_score": emp_score.current_score,
        "score_penalty": target.score_penalty,
        "risk_tier": emp_score.risk_tier,
    }


async def get_tenant_campaigns(session: AsyncSession, tenant_id: uuid.UUID) -> List[PhishingCampaign]:
    res = await session.execute(
        select(PhishingCampaign)
        .options(selectinload(PhishingCampaign.targets))
        .where(PhishingCampaign.tenant_id == tenant_id)
        .order_by(PhishingCampaign.created_at.desc())
    )
    return res.scalars().all()


async def get_tenant_employee_scores(session: AsyncSession, tenant_id: uuid.UUID) -> List[EmployeeSecurityScore]:
    res = await session.execute(
        select(EmployeeSecurityScore).where(EmployeeSecurityScore.tenant_id == tenant_id).order_by(EmployeeSecurityScore.current_score.asc())
    )
    return res.scalars().all()
