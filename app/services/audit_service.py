"""
CyberGuard — Audit Trail Service
Provides a clean interface for logging immutable action records.
"""
import uuid
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit_trail import AuditTrail


# Action constants — prevents typos across the codebase
class AuditAction:
    USER_REGISTERED = "USER_REGISTERED"
    USER_LOGIN_SUCCESS = "USER_LOGIN_SUCCESS"
    USER_LOGIN_FAILED = "USER_LOGIN_FAILED"
    USER_TOTP_SETUP = "USER_TOTP_SETUP"
    USER_TOTP_VERIFIED = "USER_TOTP_VERIFIED"
    USER_TOTP_FAILED = "USER_TOTP_FAILED"
    SCOPE_ADDED = "SCOPE_ADDED"
    SCOPE_VERIFY_ATTEMPTED = "SCOPE_VERIFY_ATTEMPTED"
    SCOPE_VERIFIED = "SCOPE_VERIFIED"
    SCOPE_VERIFY_FAILED = "SCOPE_VERIFY_FAILED"
    M365_CONNECT_INITIATED = "M365_CONNECT_INITIATED"
    M365_CONNECTED = "M365_CONNECTED"
    M365_CONNECT_FAILED = "M365_CONNECT_FAILED"
    M365_TOKEN_REVOKED = "M365_TOKEN_REVOKED"
    BASELINE_SCAN_QUEUED = "BASELINE_SCAN_QUEUED"
    REPORT_EXPORTED = "REPORT_EXPORTED"


async def log_action(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    action: str,
    actor_user_id: Optional[uuid.UUID] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """
    Write an immutable audit log entry.
    
    Uses the RLS-bypassed system_admin role for writing audit entries,
    since the RLS context may not be set during system-initiated events.
    
    Args:
        session: Active DB session (should have RLS context set).
        tenant_id: The tenant this event belongs to.
        action: Action constant from AuditAction class.
        actor_user_id: The user who performed the action (None for system events).
        ip_address: Client IP (from request headers).
        user_agent: Client user agent string.
        metadata: Additional context (JSON-serializable dict).
    """
    entry = AuditTrail(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata_=metadata or {},
    )
    session.add(entry)
    # Note: commit is handled by the session context manager (get_db)
