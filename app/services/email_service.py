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
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>CyberGuard Verification Code</title>
      <style>
        body {{
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          background-color: #0B0B0C;
          color: #E4E4E7;
          margin: 0;
          padding: 32px 16px;
          -webkit-font-smoothing: antialiased;
        }}
        .wrapper {{
          max-width: 540px;
          margin: 0 auto;
          background-color: #131315;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 4px;
          padding: 36px 32px;
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
        }}
        .brand {{
          display: flex;
          align-items: center;
          margin-bottom: 28px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.06);
          padding-bottom: 20px;
        }}
        .brand-title {{
          font-size: 20px;
          font-weight: 700;
          color: #FFFFFF;
          letter-spacing: -0.3px;
        }}
        .brand-accent {{
          color: #F97316;
        }}
        .brand-badge {{
          display: inline-block;
          margin-left: 10px;
          background: rgba(249, 115, 22, 0.12);
          border: 1px solid rgba(249, 115, 22, 0.3);
          color: #F97316;
          font-size: 10px;
          font-weight: 700;
          padding: 2px 8px;
          border-radius: 4px;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }}
        .headline {{
          font-size: 18px;
          font-weight: 600;
          color: #F4F4F6;
          margin: 0 0 8px 0;
        }}
        .subtext {{
          font-size: 13px;
          color: #A1A1AA;
          line-height: 1.6;
          margin: 0 0 24px 0;
        }}
        .otp-container {{
          background-color: #171719;
          border: 1px solid rgba(249, 115, 22, 0.35);
          border-radius: 4px;
          padding: 24px 16px;
          text-align: center;
          margin: 24px 0;
          box-shadow: inset 0 0 20px rgba(249, 115, 22, 0.04);
        }}
        .otp-label {{
          font-size: 11px;
          font-weight: 600;
          color: #71717A;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          margin-bottom: 8px;
        }}
        .otp-digits {{
          font-family: 'JetBrains Mono', Consolas, 'Courier New', monospace;
          font-size: 38px;
          font-weight: 700;
          color: #F97316;
          letter-spacing: 12px;
          margin: 0;
          padding-left: 12px;
        }}
        .security-notice {{
          background-color: rgba(255, 255, 255, 0.03);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-left: 3px solid #F97316;
          border-radius: 4px;
          padding: 12px 14px;
          font-size: 12px;
          color: #A1A1AA;
          line-height: 1.5;
          margin-top: 24px;
        }}
        .footer {{
          margin-top: 32px;
          border-top: 1px solid rgba(255, 255, 255, 0.06);
          padding-top: 20px;
          font-size: 11px;
          color: #52525B;
          line-height: 1.5;
          text-align: center;
        }}
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="brand">
          <span class="brand-title">Cyber<span class="brand-accent">Guard</span></span>
          <span class="brand-badge">AUTHENTICATION</span>
        </div>
        
        <h1 class="headline">One-Time Verification Passcode</h1>
        <p class="subtext">Use the 6-digit verification passcode below to authorize your identity request.</p>
        
        <div class="otp-container">
          <div class="otp-label">Security Verification Code</div>
          <div class="otp-digits">{otp_code}</div>
        </div>
        
        <div class="security-notice">
          <strong>Security Advisory:</strong> This passcode expires in <strong>10 minutes</strong>. Never share this code with anyone. CyberGuard security personnel will never ask for your authentication codes.
        </div>
        
        <div class="footer">
          CyberGuard Continuous Threat Operations & Attack Surface Management<br>
          Automated Security Intelligence Platform
        </div>
      </div>
    </body>
    </html>
    """


def _build_welcome_html(org_name: str, contact_email: str, temp_password: str, login_url: str) -> str:
    """Build responsive HTML template for New Business Provisioning Welcome email."""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to CyberGuard</title>
      <style>
        body {{
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          background-color: #0B0B0C;
          color: #E4E4E7;
          margin: 0;
          padding: 32px 16px;
          -webkit-font-smoothing: antialiased;
        }}
        .wrapper {{
          max-width: 560px;
          margin: 0 auto;
          background-color: #131315;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 4px;
          padding: 36px 32px;
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
        }}
        .brand {{
          display: flex;
          align-items: center;
          margin-bottom: 28px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.06);
          padding-bottom: 20px;
        }}
        .brand-title {{
          font-size: 20px;
          font-weight: 700;
          color: #FFFFFF;
          letter-spacing: -0.3px;
        }}
        .brand-accent {{
          color: #F97316;
        }}
        .brand-badge {{
          display: inline-block;
          margin-left: 10px;
          background: rgba(34, 197, 94, 0.1);
          border: 1px solid rgba(34, 197, 94, 0.3);
          color: #22C55E;
          font-size: 10px;
          font-weight: 700;
          padding: 2px 8px;
          border-radius: 4px;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }}
        .headline {{
          font-size: 19px;
          font-weight: 600;
          color: #F4F4F6;
          margin: 0 0 8px 0;
        }}
        .subtext {{
          font-size: 13px;
          color: #A1A1AA;
          line-height: 1.6;
          margin: 0 0 24px 0;
        }}
        .cred-card {{
          background-color: #171719;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 4px;
          padding: 22px 20px;
          margin: 20px 0;
        }}
        .cred-header {{
          font-size: 11px;
          font-weight: 700;
          color: #F97316;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          margin-bottom: 16px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          padding-bottom: 8px;
        }}
        .cred-row {{
          margin-bottom: 14px;
        }}
        .cred-label {{
          font-size: 11px;
          font-weight: 600;
          color: #71717A;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-bottom: 4px;
          display: block;
        }}
        .cred-value {{
          font-family: 'JetBrains Mono', Consolas, monospace;
          font-size: 13px;
          color: #F4F4F6;
          background-color: #262626;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 4px;
          padding: 8px 12px;
          display: block;
          word-break: break-all;
        }}
        .btn-container {{
          text-align: center;
          margin-top: 24px;
        }}
        .btn {{
          display: inline-block;
          background-color: #F97316;
          color: #FFFFFF !important;
          text-decoration: none;
          font-weight: 600;
          font-size: 13px;
          padding: 12px 30px;
          border-radius: 4px;
          letter-spacing: 0.02em;
          box-shadow: 0 4px 14px rgba(249, 115, 22, 0.35);
        }}
        .requirement-box {{
          background-color: rgba(234, 179, 8, 0.08);
          border: 1px solid rgba(234, 179, 8, 0.25);
          border-radius: 4px;
          padding: 12px 14px;
          font-size: 12px;
          color: #EAB308;
          line-height: 1.5;
          margin-top: 20px;
        }}
        .footer {{
          margin-top: 32px;
          border-top: 1px solid rgba(255, 255, 255, 0.06);
          padding-top: 20px;
          font-size: 11px;
          color: #52525B;
          line-height: 1.5;
          text-align: center;
        }}
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="brand">
          <span class="brand-title">Cyber<span class="brand-accent">Guard</span></span>
          <span class="brand-badge">TENANT PROVISIONED</span>
        </div>
        
        <h1 class="headline">Workspace Provisioned for {org_name}</h1>
        <p class="subtext">
          Your enterprise organization workspace has been deployed on the CyberGuard Security Platform. You may now access your tenant console and configure your perimeter attack surface scopes.
        </p>
        
        <div class="cred-card">
          <div class="cred-header">Primary Administrator Credentials</div>
          
          <div class="cred-row">
            <span class="cred-label">Console Access Endpoint</span>
            <div style="font-size: 12px; color: #38BDF8; word-break: break-all; font-family: 'JetBrains Mono', monospace;">
              {login_url}
            </div>
          </div>
          
          <div class="cred-row">
            <span class="cred-label">Admin Email Account</span>
            <span class="cred-value">{contact_email}</span>
          </div>
          
          <div class="cred-row" style="margin-bottom: 0;">
            <span class="cred-label">Temporary Access Password</span>
            <span class="cred-value">{temp_password}</span>
          </div>
          
          <div class="btn-container">
            <a href="{login_url}" class="btn">Sign In to Business Console</a>
          </div>
        </div>
        
        <div class="requirement-box">
          <strong>Mandatory First-Time Security Requirement:</strong> Upon first login, you will be required to change your temporary password and configure MFA for tenant compliance.
        </div>
        
        <div class="footer">
          CyberGuard Continuous Threat Operations & Attack Surface Management<br>
          Automated Security Intelligence Platform
        </div>
      </div>
    </body>
    </html>
    """


def _build_password_reset_html(otp_code: str) -> str:
    """Build responsive HTML template for Password Reset Passcode."""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>CyberGuard Password Reset Request</title>
      <style>
        body {{
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          background-color: #0B0B0C;
          color: #E4E4E7;
          margin: 0;
          padding: 32px 16px;
          -webkit-font-smoothing: antialiased;
        }}
        .wrapper {{
          max-width: 540px;
          margin: 0 auto;
          background-color: #131315;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 4px;
          padding: 36px 32px;
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
        }}
        .brand {{
          display: flex;
          align-items: center;
          margin-bottom: 28px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.06);
          padding-bottom: 20px;
        }}
        .brand-title {{
          font-size: 20px;
          font-weight: 700;
          color: #FFFFFF;
          letter-spacing: -0.3px;
        }}
        .brand-accent {{
          color: #F97316;
        }}
        .brand-badge {{
          display: inline-block;
          margin-left: 10px;
          background: rgba(239, 68, 68, 0.12);
          border: 1px solid rgba(239, 68, 68, 0.3);
          color: #EF4444;
          font-size: 10px;
          font-weight: 700;
          padding: 2px 8px;
          border-radius: 4px;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }}
        .headline {{
          font-size: 18px;
          font-weight: 600;
          color: #F4F4F6;
          margin: 0 0 8px 0;
        }}
        .subtext {{
          font-size: 13px;
          color: #A1A1AA;
          line-height: 1.6;
          margin: 0 0 24px 0;
        }}
        .otp-container {{
          background-color: #171719;
          border: 1px solid rgba(249, 115, 22, 0.35);
          border-radius: 4px;
          padding: 24px 16px;
          text-align: center;
          margin: 24px 0;
          box-shadow: inset 0 0 20px rgba(249, 115, 22, 0.04);
        }}
        .otp-label {{
          font-size: 11px;
          font-weight: 600;
          color: #71717A;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          margin-bottom: 8px;
        }}
        .otp-digits {{
          font-family: 'JetBrains Mono', Consolas, 'Courier New', monospace;
          font-size: 38px;
          font-weight: 700;
          color: #F97316;
          letter-spacing: 12px;
          margin: 0;
          padding-left: 12px;
        }}
        .security-notice {{
          background-color: rgba(255, 255, 255, 0.03);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-left: 3px solid #EF4444;
          border-radius: 4px;
          padding: 12px 14px;
          font-size: 12px;
          color: #A1A1AA;
          line-height: 1.5;
          margin-top: 24px;
        }}
        .footer {{
          margin-top: 32px;
          border-top: 1px solid rgba(255, 255, 255, 0.06);
          padding-top: 20px;
          font-size: 11px;
          color: #52525B;
          line-height: 1.5;
          text-align: center;
        }}
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="brand">
          <span class="brand-title">Cyber<span class="brand-accent">Guard</span></span>
          <span class="brand-badge">PASSWORD RESET</span>
        </div>
        
        <h1 class="headline">Password Reset Authorization Code</h1>
        <p class="subtext">Use the 6-digit passcode below to authorize your CyberGuard password reset request.</p>
        
        <div class="otp-container">
          <div class="otp-label">Password Reset Code</div>
          <div class="otp-digits">{otp_code}</div>
        </div>
        
        <div class="security-notice">
          <strong>Security Notice:</strong> This reset code expires in <strong>15 minutes</strong>. If you did not request a password reset, please contact your security operations team immediately to audit your account.
        </div>
        
        <div class="footer">
          CyberGuard Continuous Threat Operations & Attack Surface Management<br>
          Automated Security Intelligence Platform
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
    from_email = st.smtp_from_email or smtp_user or "noreply@cyberguardsystem.online"
    from_name = st.smtp_from_name or "CyberGuard Enterprise Security"

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
    await loop.run_in_executor(None, send_raw_email, to_email, "CyberGuard — Your Verification Passcode", html)


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


async def send_password_reset_email_async(to_email: str, otp_code: str):
    """Dispatch Password Reset OTP passcode asynchronously in background."""
    print(f"\n[PASSWORD RESET OTP] Code for {to_email}: ===> {otp_code} <===\n")
    html = _build_password_reset_html(otp_code)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_raw_email, to_email, "CyberGuard — Password Reset Request", html)
