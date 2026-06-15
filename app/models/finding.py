"""
CyberGuard — Finding SQLAlchemy Model
Unified security findings from all scan sources.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text,
    ForeignKey, ARRAY, Enum as PgEnum
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    finding_num = Column(Integer, nullable=False)  # auto from sequence, becomes FIN-{num}
    severity = Column(
        PgEnum("critical", "high", "medium", "low", "info", name="finding_severity"),
        nullable=False
    )
    source = Column(
        PgEnum("m365", "ext_scanner", "manual", name="finding_source"),
        nullable=False
    )
    issue_type = Column(String(255), nullable=False)
    entity = Column(String(512), nullable=False)
    status = Column(
        PgEnum("open", "resolved", "accepted_risk", "false_positive", name="finding_status"),
        nullable=False, default="open"
    )
    evidence = Column(JSONB, nullable=False, default=dict)
    tags = Column(ARRAY(Text), nullable=False, default=list)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    @property
    def human_id(self) -> str:
        """Stable human-readable finding identifier: FIN-1042"""
        return f"FIN-{self.finding_num}"
