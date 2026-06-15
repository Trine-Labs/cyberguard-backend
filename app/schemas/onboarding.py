"""Pydantic schemas for onboarding endpoints."""
from typing import List, Optional
from pydantic import BaseModel, field_validator
from app.services.dns_service import validate_domain_format, validate_cidr_format


class ScopeItem(BaseModel):
    type: str    # 'domain' | 'cidr'
    value: str

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in ("domain", "cidr"):
            raise ValueError("type must be 'domain' or 'cidr'.")
        return v

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip().lower()


class AddScopeRequest(BaseModel):
    scopes: List[ScopeItem]

    @field_validator("scopes")
    @classmethod
    def at_least_one_domain(cls, v: List[ScopeItem]) -> List[ScopeItem]:
        if not v:
            raise ValueError("At least one scope item is required.")
        domains = [s for s in v if s.type == "domain"]
        if not domains:
            raise ValueError("At least one root domain is required.")
        return v


class ScopeItemResponse(BaseModel):
    id: str
    type: str
    value: str
    verified: bool
    verification_token: Optional[str]
    verified_at: Optional[str]

    class Config:
        from_attributes = True


class AddScopeResponse(BaseModel):
    scopes: List[ScopeItemResponse]
    message: str


class VerifyScopeResponse(BaseModel):
    scope_id: str
    domain: str
    verified: bool
    message: str
    attempts: int


class OnboardingStatusResponse(BaseModel):
    tenant_id: str
    onboarding_step: int
    status: str
    scopes: List[ScopeItemResponse]
    m365_connected: bool
    checklist: dict
