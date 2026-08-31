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
        "subject": "Action Required: Microsoft 365 Password Expiration Alert",
        "sender_name": "Microsoft 365 Security Team",
        "body_html": """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="margin: 0; padding: 24px; background-color: #f4f5f7; font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 4px; border: 1px solid #e1dfdd; box-shadow: 0 2px 8px rgba(0,0,0,0.06);">
                <tr>
                    <td style="padding: 32px 40px 24px 40px;">
                        <!-- Microsoft Header -->
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 24px;">
                            <tr>
                                <td style="vertical-align: middle;">
                                    <table role="presentation" border="0" cellpadding="0" cellspacing="0">
                                        <tr>
                                            <td style="width: 10px; height: 10px; background-color: #f25022;"></td>
                                            <td style="width: 2px;"></td>
                                            <td style="width: 10px; height: 10px; background-color: #7fba00;"></td>
                                        </tr>
                                        <tr><td colspan="3" style="height: 2px;"></td></tr>
                                        <tr>
                                            <td style="width: 10px; height: 10px; background-color: #00a4ef;"></td>
                                            <td style="width: 2px;"></td>
                                            <td style="width: 10px; height: 10px; background-color: #ffb900;"></td>
                                        </tr>
                                    </table>
                                </td>
                                <td style="vertical-align: middle; padding-left: 10px;">
                                    <span style="font-size: 18px; font-weight: 600; color: #737373; letter-spacing: -0.3px;">Microsoft 365 Security</span>
                                </td>
                            </tr>
                        </table>

                        <h2 style="color: #1b1b1b; font-size: 20px; font-weight: 600; margin: 0 0 16px 0; line-height: 1.3;">
                            Your organization password expires today
                        </h2>
                        
                        <p style="color: #323130; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                            Hello <strong>{employee_name}</strong>,
                        </p>
                        <p style="color: #323130; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
                            Your Microsoft 365 organization account password will expire in <strong>4 hours</strong>. To maintain uninterrupted access to your Outlook inbox, Microsoft Teams, OneDrive files, and corporate cloud resources, please retain your current credentials below:
                        </p>

                        <!-- Call to Action -->
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 28px 0;">
                            <tr>
                                <td style="border-radius: 2px; background-color: #0067b8; text-align: center;">
                                    <a href="{tracking_url}" style="background-color: #0067b8; border: 1px solid #0067b8; border-radius: 2px; color: #ffffff; display: inline-block; font-size: 14px; font-weight: 600; padding: 12px 28px; text-decoration: none; box-sizing: border-box;">
                                        Keep Current Password &amp; Retain Access
                                    </a>
                                </td>
                            </tr>
                        </table>

                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f8f9fa; border-radius: 4px; padding: 12px 16px; margin-top: 20px; border-left: 3px solid #0067b8;">
                            <tr>
                                <td style="font-size: 12px; color: #605e5c; line-height: 1.5;">
                                    <strong>Tenant Security Notice:</strong> If no action is taken before expiration, your active session tokens will be revoked and multi-factor re-enrollment will be enforced.
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="background-color: #f3f2f1; padding: 20px 40px; border-top: 1px solid #edebe9; font-size: 11px; color: #605e5c; line-height: 1.5;">
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                            <tr>
                                <td>
                                    Reference Ticket: <strong>MS-SEC-{token_short}</strong><br>
                                    Microsoft Security Operations Center &bull; Identity &amp; Access Governance
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
    },
    "urgent_invoice": {
        "subject": "Action Required: Outstanding Vendor Invoice #INV-88942 Authorization",
        "sender_name": "Accounts Payable Department",
        "body_html": """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="margin: 0; padding: 24px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 6px; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                <tr>
                    <td style="padding: 32px 36px;">
                        <div style="font-size: 18px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">Accounts Payable Electronic Voucher System</div>
                        <div style="font-size: 12px; color: #64748b; margin-bottom: 24px;">Urgent Payment Authorization Request &bull; Invoice #INV-88942</div>

                        <p style="color: #334155; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                            Dear <strong>{employee_name}</strong>,
                        </p>
                        <p style="color: #334155; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
                            An electronic invoice voucher requires your immediate sign-off prior to the end-of-month accounting settlement cycle:
                        </p>

                        <!-- Invoice Summary Box -->
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 24px;">
                            <tr>
                                <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #64748b;">Vendor:</td>
                                <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; font-weight: 600; color: #0f172a;">Global Enterprise Cloud Services</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #64748b;">Amount Due:</td>
                                <td style="padding: 12px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; font-weight: 600; color: #0f172a;">$14,850.00 USD</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 16px; font-size: 13px; color: #64748b;">Due Date:</td>
                                <td style="padding: 12px 16px; font-size: 13px; font-weight: 600; color: #dc2626;">Immediate (Pending Approval)</td>
                            </tr>
                        </table>

                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 24px 0;">
                            <tr>
                                <td style="border-radius: 6px; background-color: #0284c7; text-align: center;">
                                    <a href="{tracking_url}" style="background-color: #0284c7; border: 1px solid #0284c7; border-radius: 6px; color: #ffffff; display: inline-block; font-size: 14px; font-weight: 600; padding: 12px 28px; text-decoration: none;">
                                        Review &amp; Authorize Payment Voucher
                                    </a>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="background-color: #f8fafc; padding: 16px 36px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8;">
                        Voucher Security Key: VOUCH-{token_short} &bull; Corporate Finance &amp; Accounting Operations
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
    },
    "hr_policy_update": {
        "subject": "Mandatory: Updated Corporate Security & Remote Work Policy Signature",
        "sender_name": "Corporate Human Resources",
        "body_html": """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="margin: 0; padding: 24px; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 6px; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                <tr>
                    <td style="padding: 32px 36px;">
                        <div style="font-size: 18px; font-weight: 700; color: #1e3a8a; margin-bottom: 4px;">Human Resources Compliance Portal</div>
                        <div style="font-size: 12px; color: #64748b; margin-bottom: 24px;">Annual Policy Acknowledgment &bull; Mandatory for All Staff</div>

                        <p style="color: #334155; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                            Hi <strong>{employee_name}</strong>,
                        </p>
                        <p style="color: #334155; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
                            The updated <strong>2026 Remote Work, Data Privacy, and Information Security Policy</strong> has been published. All employees must review and digitally sign the policy acknowledgment within 24 hours.
                        </p>

                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 24px 0;">
                            <tr>
                                <td style="border-radius: 6px; background-color: #2563eb; text-align: center;">
                                    <a href="{tracking_url}" style="background-color: #2563eb; border: 1px solid #2563eb; border-radius: 6px; color: #ffffff; display: inline-block; font-size: 14px; font-weight: 600; padding: 12px 28px; text-decoration: none;">
                                        Sign &amp; Acknowledge Updated Policy
                                    </a>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="background-color: #f8fafc; padding: 16px 36px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8;">
                        HR Compliance Reference: HR-POL-{token_short} &bull; Workday People Operations
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
    },
    "it_helpdesk_ticket": {
        "subject": "Action Required: Scheduled VPN & Single Sign-On Re-Verification",
        "sender_name": "Global IT Security Operations",
        "body_html": """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="margin: 0; padding: 24px; background-color: #0b132b; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; margin: 0 auto; background-color: #1c2541; border-radius: 6px; border: 1px solid #3a506b; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
                <tr>
                    <td style="padding: 32px 36px;">
                        <div style="font-size: 18px; font-weight: 700; color: #6fffe9; margin-bottom: 4px;">Corporate IT Security Gateway</div>
                        <div style="font-size: 12px; color: #a5a5a5; margin-bottom: 24px;">Security Audit Incident &bull; Ticket #IT-99201</div>

                        <p style="color: #e0e1dd; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                            Hello <strong>{employee_name}</strong>,
                        </p>
                        <p style="color: #e0e1dd; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
                            As part of our scheduled zero-trust security audit, all active corporate VPN profiles and Single Sign-On (SSO) tokens must be re-verified to maintain access to corporate internal networks and development environments.
                        </p>

                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 24px 0;">
                            <tr>
                                <td style="border-radius: 4px; background-color: #5bc0be; text-align: center;">
                                    <a href="{tracking_url}" style="background-color: #5bc0be; border: 1px solid #5bc0be; border-radius: 4px; color: #0b132b; display: inline-block; font-size: 14px; font-weight: 700; padding: 12px 28px; text-decoration: none;">
                                        Authenticate VPN &amp; SSO Access
                                    </a>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="background-color: #151d32; padding: 16px 36px; border-top: 1px solid #3a506b; font-size: 11px; color: #6c757d;">
                        Global IT Infrastructure Operations &bull; Ticket #IT-99201 &bull; 256-bit TLS Gateway
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
    },
    "cloud_storage_shared": {
        "subject": "Encrypted Document Shared: Q3 Financial Audit & Executive Compensation Review.pdf",
        "sender_name": "Cloud Document Security Vault",
        "body_html": """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="margin: 0; padding: 24px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 6px; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                <tr>
                    <td style="padding: 32px 36px;">
                        <div style="font-size: 18px; font-weight: 700; color: #1e293b; margin-bottom: 4px;">Secure Cloud Document Share</div>
                        <div style="font-size: 12px; color: #64748b; margin-bottom: 24px;">Encrypted Corporate Vault &bull; Restricted Distribution</div>

                        <p style="color: #334155; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                            Dear <strong>{employee_name}</strong>,
                        </p>
                        <p style="color: #334155; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
                            A confidential audit report, <strong>Q3_Executive_Audit_&amp;_Compensation.pdf (4.2 MB)</strong>, has been shared with your corporate account. Sign in with your work identity credentials to decrypt and view the document.
                        </p>

                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 24px 0;">
                            <tr>
                                <td style="border-radius: 6px; background-color: #2563eb; text-align: center;">
                                    <a href="{tracking_url}" style="background-color: #2563eb; border: 1px solid #2563eb; border-radius: 6px; color: #ffffff; display: inline-block; font-size: 14px; font-weight: 600; padding: 12px 28px; text-decoration: none;">
                                        Decrypt &amp; Access Shared Document
                                    </a>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="background-color: #f8fafc; padding: 16px 36px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8;">
                        Protected by Secure Cloud Storage Encryption &bull; Document Vault #DOC-{token_short}
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
    },
    "payroll_direct_deposit": {
        "subject": "Urgent Notice: Direct Deposit Remuneration Verification Required",
        "sender_name": "Workday Payroll Operations",
        "body_html": """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
        <body style="margin: 0; padding: 24px; background-color: #f0fdf4; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 6px; border: 1px solid #bbf7d0; box-shadow: 0 4px 12px rgba(16,185,129,0.08);">
                <tr>
                    <td style="padding: 32px 36px;">
                        <div style="font-size: 18px; font-weight: 700; color: #065f46; margin-bottom: 4px;">Workday Payroll &amp; Remuneration</div>
                        <div style="font-size: 12px; color: #047857; margin-bottom: 24px;">Banking Direct Deposit Compliance Audit</div>

                        <p style="color: #374151; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                            Hi <strong>{employee_name}</strong>,
                        </p>
                        <p style="color: #374151; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
                            An automated security verification is required for your active direct deposit banking details prior to the upcoming salary disbursement cycle. Please authenticate your employee credentials to confirm your bank routing info.
                        </p>

                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 24px 0;">
                            <tr>
                                <td style="border-radius: 6px; background-color: #059669; text-align: center;">
                                    <a href="{tracking_url}" style="background-color: #059669; border: 1px solid #059669; border-radius: 6px; color: #ffffff; display: inline-block; font-size: 14px; font-weight: 600; padding: 12px 28px; text-decoration: none;">
                                        Sign In &amp; Confirm Direct Deposit
                                    </a>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="background-color: #ecfdf5; padding: 16px 36px; border-top: 1px solid #bbf7d0; font-size: 11px; color: #6b7280;">
                        Workday Payroll Operations &bull; Direct Deposit Banking Compliance &bull; Ref: PAY-{token_short}
                    </td>
                </tr>
            </table>
        </body>
        </html>
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

async def _upsert_finding(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    issue_type: str,
    entity: str,
    severity: str,
    source: str,
    evidence: Dict[str, Any],
    tags: List[str]
) -> Finding:
    from sqlalchemy import func
    res = await session.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            func.lower(Finding.entity) == entity.lower(),
            Finding.issue_type == issue_type
        ).order_by(Finding.created_at.desc())
    )
    existing = res.scalars().first()

    now = datetime.now(timezone.utc)
    if existing:
        existing.status = "open"
        existing.severity = severity
        existing.last_seen_at = now
        existing.resolved_at = None
        existing.evidence = evidence
        existing.tags = tags
        existing.updated_at = now
        return existing
    else:
        from sqlalchemy import text as _text
        seq_res = await session.execute(_text("SELECT nextval('findings_seq')"))
        seq_num = seq_res.scalar()
        finding = Finding(
            tenant_id=tenant_id,
            finding_num=seq_num,
            severity=severity,
            source=source,
            issue_type=issue_type,
            entity=entity.lower(),
            evidence=evidence,
            tags=tags
        )
        session.add(finding)
        return finding


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

        # Upsert Security Finding (updates existing finding if present)
        await _upsert_finding(
            session=session,
            tenant_id=target.tenant_id,
            issue_type="Phishing Simulation Failure (Employee Compromise Risk)",
            entity=target.employee_email,
            severity="high",
            source="human_risk",
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

        # When employee score drops below 75, upsert CRITICAL severity finding
        if emp_score.current_score < 75:
            await _upsert_finding(
                session=session,
                tenant_id=target.tenant_id,
                issue_type="Critical Employee Security Risk (Awareness Score Below 75)",
                entity=target.employee_email,
                severity="critical",
                source="human_risk",
                evidence={
                    "employee_name": target.employee_name,
                    "employee_email": target.employee_email,
                    "current_score": emp_score.current_score,
                    "risk_tier": emp_score.risk_tier,
                    "simulations_received": emp_score.simulations_received,
                    "simulations_clicked": emp_score.simulations_clicked,
                    "reason": "Employee security awareness score dropped below 75 due to phishing simulation clicks.",
                    "last_phished_at": datetime.now(timezone.utc).isoformat(),
                },
                tags=["phishing_simulation", "critical_human_risk", "vulnerable_identity"]
            )

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


async def record_credential_submission(
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

    first_submission = target.status != "submitted_credentials"
    target.status = "submitted_credentials"
    target.submitted_credentials_at = datetime.now(timezone.utc)
    if ip_address:
        target.ip_address = ip_address
    if user_agent:
        target.user_agent = user_agent

    emp_score = await get_or_create_employee_score(session, target.tenant_id, target.employee_email, target.employee_name)
    if first_submission:
        emp_score.current_score = max(0, emp_score.current_score - 15)
        emp_score.risk_tier = _compute_risk_tier(emp_score.current_score)
        emp_score.last_phished_at = datetime.now(timezone.utc)

        # Upsert Credential Harvesting Failure Finding (updates existing finding if present)
        await _upsert_finding(
            session=session,
            tenant_id=target.tenant_id,
            issue_type="Credential Harvesting Failure (High Risk Compromise)",
            entity=target.employee_email,
            severity="critical",
            source="human_risk",
            evidence={
                "employee_name": target.employee_name,
                "submitted_at": datetime.now(timezone.utc).isoformat(),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "score_penalty": 15,
                "new_score": emp_score.current_score,
            },
            tags=["phishing_simulation", "credential_harvesting", "critical_human_factor"]
        )

        # Also trigger Critical Employee Security Risk if score drops below 75
        if emp_score.current_score < 75:
            await _upsert_finding(
                session=session,
                tenant_id=target.tenant_id,
                issue_type="Critical Employee Security Risk (Awareness Score Below 75)",
                entity=target.employee_email,
                severity="critical",
                source="human_risk",
                evidence={
                    "employee_name": target.employee_name,
                    "employee_email": target.employee_email,
                    "current_score": emp_score.current_score,
                    "risk_tier": emp_score.risk_tier,
                    "simulations_received": emp_score.simulations_received,
                    "simulations_clicked": emp_score.simulations_clicked,
                    "reason": "Employee security awareness score dropped below 75 due to phishing simulation clicks.",
                    "last_phished_at": datetime.now(timezone.utc).isoformat(),
                },
                tags=["phishing_simulation", "critical_human_risk", "vulnerable_identity"]
            )

    await session.commit()
    return {
        "employee_name": target.employee_name,
        "employee_email": target.employee_email,
        "current_score": emp_score.current_score,
        "risk_tier": emp_score.risk_tier,
    }


async def reward_quiz_points(
    session: AsyncSession,
    token: str
) -> Optional[Dict[str, Any]]:
    res = await session.execute(
        select(PhishingTarget).where(PhishingTarget.tracking_token == token)
    )
    target = res.scalar_one_or_none()
    if not target:
        return None

    emp_score = await get_or_create_employee_score(session, target.tenant_id, target.employee_email, target.employee_name)
    
    if not target.quiz_reward_applied:
        target.quiz_reward_applied = True
        emp_score.current_score = min(100, emp_score.current_score + 5)
        emp_score.risk_tier = _compute_risk_tier(emp_score.current_score)
        await session.commit()

    return {
        "employee_name": target.employee_name,
        "employee_email": target.employee_email,
        "new_score": emp_score.current_score,
        "risk_tier": emp_score.risk_tier,
        "reward_applied": True
    }


async def reset_employee_score(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    employee_email: str
) -> Optional[EmployeeSecurityScore]:
    from sqlalchemy import func
    from app.models.finding import Finding

    res = await session.execute(
        select(EmployeeSecurityScore).where(
            EmployeeSecurityScore.tenant_id == tenant_id,
            EmployeeSecurityScore.employee_email == employee_email
        )
    )
    score_obj = res.scalar_one_or_none()
    if not score_obj:
        return None

    score_obj.current_score = 100
    score_obj.risk_tier = "low_risk"
    score_obj.simulations_clicked = 0
    score_obj.simulations_reported = 0

    # Automatically resolve all open security findings for this employee
    findings_res = await session.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            func.lower(Finding.entity) == employee_email.lower(),
            Finding.status != "resolved"
        )
    )
    open_findings = findings_res.scalars().all()

    now = datetime.now(timezone.utc)
    for f in open_findings:
        f.status = "resolved"
        f.resolved_at = now
        f.updated_at = now

    await session.commit()
    await session.refresh(score_obj)
    return score_obj


async def get_employee_activity_details(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    employee_email: str
) -> Dict[str, Any]:
    from sqlalchemy.orm import selectinload

    score_res = await session.execute(
        select(EmployeeSecurityScore).where(
            EmployeeSecurityScore.tenant_id == tenant_id,
            EmployeeSecurityScore.employee_email == employee_email
        )
    )
    score_obj = score_res.scalar_one_or_none()

    target_res = await session.execute(
        select(PhishingTarget)
        .options(selectinload(PhishingTarget.campaign))
        .where(
            PhishingTarget.tenant_id == tenant_id,
            PhishingTarget.employee_email == employee_email
        )
        .order_by(PhishingTarget.sent_at.desc())
    )
    targets = target_res.scalars().all()

    history = []
    total_credentials_entered = 0
    total_clicks = 0

    for t in targets:
        is_compromised = (
            t.status in ("clicked", "submitted_credentials") or
            t.clicked_at is not None or
            t.submitted_credentials_at is not None
        )
        
        events = []
        if t.sent_at:
            events.append({
                "type": "sent",
                "label": "Simulation Lure Dispatched",
                "timestamp": t.sent_at.isoformat(),
                "severity": "info",
                "details": f"Email lure dispatched for campaign '{t.campaign.title if t.campaign else 'Simulation'}'"
            })

        if t.clicked_at:
            total_clicks += 1
            events.append({
                "type": "clicked",
                "label": "Clicked Phishing Link",
                "timestamp": t.clicked_at.isoformat(),
                "severity": "warning",
                "ip_address": t.ip_address or "Unknown",
                "user_agent": t.user_agent or "Unknown Browser",
                "penalty": t.score_penalty,
                "details": f"Simulation link opened from IP {t.ip_address or 'Unknown'}"
            })

        if t.submitted_credentials_at:
            total_credentials_entered += 1
            events.append({
                "type": "submitted_credentials",
                "label": "Entered Password / Credentials on Cloned Page",
                "timestamp": t.submitted_credentials_at.isoformat(),
                "severity": "critical",
                "ip_address": t.ip_address or "Unknown",
                "user_agent": t.user_agent or "Unknown Browser",
                "penalty": 40,
                "details": f"Credential harvesting vulnerability confirmed from IP {t.ip_address or 'Unknown'}"
            })

        if t.quiz_reward_applied:
            events.append({
                "type": "quiz_reward",
                "label": "Completed Remediation Micro-Quiz",
                "timestamp": (
                    t.submitted_credentials_at.isoformat() if t.submitted_credentials_at
                    else (t.clicked_at.isoformat() if t.clicked_at else t.sent_at.isoformat())
                ),
                "severity": "success",
                "details": "Successfully completed instant educational awareness training (+5 score restored)"
            })

        primary_action = (
            "submitted_credentials" if (t.submitted_credentials_at or t.status == "submitted_credentials")
            else ("clicked" if (t.clicked_at or t.status == "clicked") else "safe")
        )
        primary_timestamp = t.submitted_credentials_at or t.clicked_at or t.sent_at

        history.append({
            "target_id": str(t.id),
            "campaign_id": str(t.campaign_id),
            "campaign_title": t.campaign.title if t.campaign else "Phishing Simulation",
            "template_type": t.campaign.template_type if t.campaign else "password_reset",
            "status": t.status,
            "action": primary_action,
            "is_compromised": is_compromised,
            "event_timestamp": primary_timestamp.isoformat() if primary_timestamp else None,
            "sent_at": t.sent_at.isoformat() if t.sent_at else None,
            "clicked_at": t.clicked_at.isoformat() if t.clicked_at else None,
            "submitted_credentials_at": t.submitted_credentials_at.isoformat() if t.submitted_credentials_at else None,
            "quiz_reward_applied": t.quiz_reward_applied,
            "ip_address": t.ip_address,
            "user_agent": t.user_agent,
            "score_penalty": t.score_penalty if primary_action != "safe" else 0,
            "events": events
        })

    return {
        "employee": {
            "name": score_obj.employee_name if score_obj else (targets[0].employee_name if targets else employee_email.split("@")[0].capitalize()),
            "email": employee_email,
            "department": score_obj.department if score_obj else "General",
            "current_score": score_obj.current_score if score_obj else 100,
            "risk_tier": score_obj.risk_tier if score_obj else "low_risk",
            "simulations_received": score_obj.simulations_received if score_obj else len(targets),
            "simulations_clicked": score_obj.simulations_clicked if score_obj else total_clicks,
            "simulations_reported": score_obj.simulations_reported if score_obj else 0,
            "credentials_entered_count": total_credentials_entered,
            "last_phished_at": score_obj.last_phished_at.isoformat() if (score_obj and score_obj.last_phished_at) else None,
        },
        "history": history
    }


async def get_target_details_by_token(
    session: AsyncSession,
    token: str
) -> Optional[Dict[str, Any]]:
    res = await session.execute(
        select(PhishingTarget).where(PhishingTarget.tracking_token == token)
    )
    target = res.scalar_one_or_none()
    if not target:
        return None

    emp_score = await get_or_create_employee_score(session, target.tenant_id, target.employee_email, target.employee_name)

    return {
        "employee_name": target.employee_name,
        "employee_email": target.employee_email,
        "current_score": emp_score.current_score,
        "score_penalty": target.score_penalty,
        "risk_tier": emp_score.risk_tier,
        "status": target.status,
        "quiz_reward_applied": target.quiz_reward_applied,
    }
