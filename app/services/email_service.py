"""
CyberGuard — Email Service
Handles dispatching Email OTP passcodes and Business Onboarding Welcome Credentials emails via SMTP.
Includes fallbacks for local developer logging when SMTP is unconfigured.
"""
import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from app.config import get_settings

settings = get_settings()


def _build_otp_html(otp_code: str) -> str:
    """Build responsive HTML template for Email OTP Verification."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0F0F0F; color: #E2E8F0; margin: 0; padding: 24px; }}
        .container {{ max-width: 520px; margin: 0 auto; background: #141414; border: 1px solid #262626; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .brand {{ text-align: center; margin-bottom: 24px; }}
        .brand-title {{ font-size: 22px; font-weight: 800; color: #FFFFFF; letter-spacing: -0.5px; }}
        .brand-accent {{ color: #D4342A; }}
        .otp-box {{ background: #1A1A1A; border: 1px solid #333333; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0; }}
        .otp-code {{ font-family: 'JetBrains Mono', Consolas, monospace; font-size: 36px; font-weight: 800; color: #D4342A; letter-spacing: 8px; margin: 0; }}
        .notice {{ font-size: 13px; color: #A3A3A3; line-height: 1.6; text-align: center; margin-top: 16px; }}
        .footer {{ text-align: center; margin-top: 32px; font-size: 12px; color: #737373; border-top: 1px solid #262626; padding-top: 16px; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="brand">
          <div class="brand-title">Cyber<span class="brand-accent">Guard</span></div>
          <div style="font-size: 12px; color: #A3A3A3; margin-top: 4px;">Enterprise Security Authentication</div>
        </div>
        
        <h2 style="font-size: 18px; margin-bottom: 8px; text-align: center; color: #FFFFFF;">Email Verification Passcode</h2>
        <p style="font-size: 14px; color: #A3A3A3; text-align: center; margin: 0 0 20px;">Use the 6-digit One-Time Passcode (OTP) below to complete your identity verification.</p>
        
        <div class="otp-box">
          <div class="otp-code">{otp_code}</div>
        </div>
        
        <div class="notice">
          This passcode is valid for <strong>10 minutes</strong>. If you did not initiate this login request, please contact your security administrator immediately.
        </div>
        
        <div class="footer">
          CyberGuard Continuous Threat & Attack Surface Management Platform
        </div>
      </div>
    </body>
    </html>
    """


def _build_welcome_html(org_name: str, contact_email: str, temp_password: str, login_url: str) -> str:
    """Build responsive HTML template for New Business Provisioning Welcome email."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0F0F0F; color: #E2E8F0; margin: 0; padding: 24px; }}
        .container {{ max-width: 560px; margin: 0 auto; background: #141414; border: 1px solid #262626; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .brand {{ text-align: center; margin-bottom: 24px; }}
        .brand-title {{ font-size: 24px; font-weight: 800; color: #FFFFFF; letter-spacing: -0.5px; }}
        .brand-accent {{ color: #D4342A; }}
        .card {{ background: #1A1A1A; border: 1px solid #333333; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .cred-item {{ margin-bottom: 12px; font-size: 14px; }}
        .cred-label {{ color: #A3A3A3; font-weight: 500; display: block; font-size: 12px; text-transform: uppercase; margin-bottom: 2px; }}
        .cred-value {{ font-family: monospace; font-size: 15px; color: #FFFFFF; background: #0F0F0F; padding: 6px 12px; border-radius: 4px; border: 1px solid #262626; display: inline-block; word-break: break-all; }}
        .btn {{ display: inline-block; background: #D4342A; color: #FFFFFF !important; text-decoration: none; font-weight: 600; font-size: 14px; padding: 12px 28px; border-radius: 6px; text-align: center; margin-top: 16px; }}
        .warning-badge {{ background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.25); color: #EAB308; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin-top: 20px; line-height: 1.5; }}
        .footer {{ text-align: center; margin-top: 32px; font-size: 12px; color: #737373; border-top: 1px solid #262626; padding-top: 16px; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="brand">
          <div class="brand-title">Cyber<span class="brand-accent">Guard</span></div>
          <div style="font-size: 12px; color: #A3A3A3; margin-top: 4px;">Enterprise Security Portal Provisioned</div>
        </div>

        <h2 style="font-size: 20px; color: #FFFFFF; margin-bottom: 8px;">Welcome to CyberGuard, {org_name}!</h2>
        <p style="font-size: 14px; color: #A3A3A3; line-height: 1.6; margin: 0 0 16px;">
          Your enterprise business workspace has been successfully provisioned on the CyberGuard Security Monitoring Platform.
        </p>

        <div class="card">
          <div style="font-size: 13px; font-weight: 700; color: #D4342A; text-transform: uppercase; margin-bottom: 14px; letter-spacing: 0.5px;">
            Primary Admin Access Credentials
          </div>

          <div class="cred-item">
            <span class="cred-label">Login URL</span>
            <div style="font-size: 13px; color: #3B82F6;">{login_url}</div>
          </div>

          <div class="cred-item">
            <span class="cred-label">Contact / Admin Email</span>
            <div class="cred-value">{contact_email}</div>
          </div>

          <div class="cred-item">
            <span class="cred-label">Temporary Initial Password</span>
            <div class="cred-value">{temp_password}</div>
          </div>

          <div style="text-align: center; margin-top: 20px;">
            <a href="{login_url}" class="btn">Sign In to Business Workspace</a>
          </div>
        </div>

        <div class="warning-badge">
          <strong>Mandatory First-Time Security Requirement:</strong> Upon logging in for the first time, you will be prompted to set a permanent password.
        </div>

        <div class="footer">
          CyberGuard Continuous Security & Threat Operations
        </div>
      </div>
    </body>
    </html>
    """


def send_raw_email(to_email: str, subject: str, html_content: str) -> bool:
    """Synchronous SMTP email sender."""
    st = get_settings()
    smtp_user = st.smtp_user or ""
    smtp_pass = st.smtp_password or ""
    from_email = st.smtp_from_email or smtp_user or "noreply@cyberguard.io"
    from_name = st.smtp_from_name or "CyberGuard Security"

    # Fallback to terminal logging if SMTP credentials are unconfigured
    if not smtp_user or not smtp_pass:
        print("\n" + "="*60)
        print(f" [EMAIL DISPATCH LOG — LOCAL DEV FALLBACK]")
        print(f" To: {to_email}")
        print(f" Subject: {subject}")
        print("="*60 + "\n")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(st.smtp_host, st.smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, [to_email], msg.as_string())
        
        print(f"[EMAIL SERVICE] Email successfully dispatched to {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL SERVICE ERROR] Failed to send email to {to_email}: {e}")
        return False


async def send_login_otp_email_async(to_email: str, otp_code: str):
    """Dispatch Email OTP passcode asynchronously in background."""
    print(f"\n[EMAIL OTP] Passcode for {to_email}: ===> {otp_code} <===\n")
    html = _build_otp_html(otp_code)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_raw_email, to_email, "CyberGuard — Your Email OTP Passcode", html)


async def send_tenant_welcome_email_async(to_email: str, org_name: str, temp_password: str, login_url: Optional[str] = None):
    """Dispatch Business Welcome & Credentials email asynchronously in background."""
    st = get_settings()
    target_url = login_url or f"{st.frontend_url}/auth/login"
    print(f"\n[WELCOME EMAIL] Credentials for {org_name} ({to_email}) -> Pass: {temp_password}\n")
    html = _build_welcome_html(org_name, to_email, temp_password, target_url)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_raw_email, to_email, f"Welcome to CyberGuard — Account Provisioned for {org_name}", html)


async def send_email_async(to_email: str, subject: str, html_content: str, from_name: Optional[str] = None):
    """Dispatch custom email asynchronously in background executor."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_raw_email, to_email, subject, html_content)
