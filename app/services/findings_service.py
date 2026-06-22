"""Findings Upsert and Resolution Logic"""
import uuid
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.models.finding import Finding

async def upsert_m365_findings(
    session: AsyncSession, 
    tenant_id: uuid.UUID, 
    new_findings: List[Dict[str, Any]]
):
    """
    Deterministic upsert logic for M365 findings.
    Matches existing findings by entity and issue_type.
    Marks resolved if finding no longer exists in new_findings.
    """
    # Fetch existing open M365 findings for the tenant
    result = await session.execute(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.source == "m365",
            Finding.status == "open"
        )
    )
    existing_open = result.scalars().all()
    
    # Map existing open findings by a unique composite key
    existing_map = {f"{f.issue_type}::{f.entity}": f for f in existing_open}
    
    # Track which findings are still active
    active_keys = set()
    
    for nf in new_findings:
        key = f"{nf['issue_type']}::{nf['entity']}"
        active_keys.add(key)
        
        if key in existing_map:
            # Update last_seen
            existing = existing_map[key]
            existing.last_seen_at = datetime.utcnow()
            existing.evidence = nf["evidence"]
        else:
            # Insert new
            from sqlalchemy import text as _text
            seq_result = await session.execute(_text("SELECT nextval('findings_seq')"))
            seq_num = seq_result.scalar()
            
            finding = Finding(
                tenant_id=tenant_id,
                finding_num=seq_num,
                severity=nf["severity"],
                source="m365",
                issue_type=nf["issue_type"],
                entity=nf["entity"],
                evidence=nf["evidence"],
                tags=nf["tags"]
            )
            session.add(finding)
            
    # Resolve findings that are no longer present
    for key, existing in existing_map.items():
        if key not in active_keys:
            existing.status = "resolved"
            existing.resolved_at = datetime.utcnow()
            
    await session.commit()
