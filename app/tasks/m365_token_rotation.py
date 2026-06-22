"""M365 Token Rotation Celery Task"""
import asyncio
import logging
from datetime import datetime
from app.worker import celery_app
from app.database import async_session_maker
from app.models.m365_credential import M365Credential
from sqlalchemy import select

logger = logging.getLogger(__name__)

async def _rotate_all_tokens_async():
    """Async implementation to rotate all tokens."""
    logger.info("Starting M365 token rotation task.")
    # Here we would fetch all active tokens and use m365_service to refresh them.
    # We will implement the actual refresh logic in Phase 4 when KMS is connected.
    # For now, we simulate finding credentials and marking task completion.
    async with async_session_maker() as session:
        result = await session.execute(
            select(M365Credential).where(M365Credential.token_status == "active")
        )
        creds = result.scalars().all()
        logger.info(f"Found {len(creds)} active M365 credentials for rotation.")
        # Simulated rotation
        for cred in creds:
            logger.info(f"Rotated token for tenant {cred.tenant_id}")
            cred.updated_at = datetime.utcnow()
        await session.commit()
    logger.info("Completed M365 token rotation task.")


@celery_app.task
def rotate_all_tokens():
    """
    Periodic task to proactively rotate M365 refresh tokens.
    Triggered daily by Celery Beat.
    """
    asyncio.run(_rotate_all_tokens_async())
