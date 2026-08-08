from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
import uuid

class TenantCreateRequest(BaseModel):
    org_name: str = Field(..., min_length=2, max_length=255, description="Business or Tenant Name")
    contact_email: EmailStr = Field(..., description="Primary Contact Email")
    admin_password: str = Field(..., min_length=8, description="Initial Admin User Password")
    scan_frequency: str = Field("daily", description="Scan schedule: hourly, two_hours, three_hours, six_hours, twice_daily, daily, weekly")
    company_info: Optional[str] = Field(None, description="Data Training background context for AI synthesis")

class TenantUpdateRequest(BaseModel):
    org_name: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    scan_frequency: Optional[str] = None
    company_info: Optional[str] = None
    status: Optional[str] = None  # active, suspended, onboarding
    admin_password: Optional[str] = None

class TenantResponse(BaseModel):
    id: uuid.UUID
    org_name: str
    contact_email: Optional[str] = None
    company_info: Optional[str] = None
    scan_frequency: str
    status: str
    onboarding_step: int
    user_count: int = 0
    scope_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class TenantListResponse(BaseModel):
    tenants: List[TenantResponse]
    total: int


class AdminLoginRequest(BaseModel):
    username: str = Field(..., description="Platform Admin Username")
    password: str = Field(..., description="Platform Admin Password")


class AdminLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    admin_username: str

