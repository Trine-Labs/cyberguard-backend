"""
CyberGuard — Phishing Simulation & Employee Security Awareness Models
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, DateTime, Integer, String, Text, ForeignKey, Enum as PgEnum
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class PhishingCampaign(Base):
    __tablename__ = "phishing_campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    title = Column(String(255), nullable=False)
    email_subject = Column(String(255), nullable=False)
    sender_name = Column(String(255), nullable=False)
    sender_email = Column(String(255), nullable=False)
    template_type = Column(String(50), nullable=False, default="password_reset")
    status = Column(String(50), nullable=False, default="active")  # active, completed
    total_targets = Column(Integer, nullable=False, default=0)
    clicks_count = Column(Integer, nullable=False, default=0)
    launched_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    targets = relationship("PhishingTarget", back_populates="campaign", cascade="all, delete-orphan")


class PhishingTarget(Base):
    __tablename__ = "phishing_targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(
        UUID(as_uuid=True), ForeignKey("phishing_campaigns.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    tenant_id = Column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    employee_email = Column(String(255), nullable=False, index=True)
    employee_name = Column(String(255), nullable=False)
    tracking_token = Column(String(64), nullable=False, unique=True, index=True)
    status = Column(String(50), nullable=False, default="sent")  # sent, opened, clicked, reported
    sent_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    clicked_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    score_penalty = Column(Integer, nullable=False, default=25)

    campaign = relationship("PhishingCampaign", back_populates="targets")


class EmployeeSecurityScore(Base):
    __tablename__ = "employee_security_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    employee_email = Column(String(255), nullable=False, index=True)
    employee_name = Column(String(255), nullable=False)
    department = Column(String(100), nullable=True, default="General")
    current_score = Column(Integer, nullable=False, default=100)  # 0 to 100
    risk_tier = Column(String(50), nullable=False, default="low_risk")  # low_risk, medium_risk, high_risk
    simulations_received = Column(Integer, nullable=False, default=0)
    simulations_clicked = Column(Integer, nullable=False, default=0)
    simulations_reported = Column(Integer, nullable=False, default=0)
    last_phished_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
