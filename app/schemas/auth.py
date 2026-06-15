"""Pydantic schemas for authentication endpoints."""
import re
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator, model_validator


class RegisterRequest(BaseModel):
    org_name: str
    email: EmailStr
    password: str

    @field_validator("org_name")
    @classmethod
    def org_name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Organization name must be at least 2 characters.")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character.")
        return v


class RegisterResponse(BaseModel):
    user_id: str
    tenant_id: str
    email: str
    totp_secret: str       # Raw secret (for manual entry in authenticator app)
    totp_qr_code: str      # data: URI PNG of QR code


class TOTPVerifyRequest(BaseModel):
    user_id: str
    code: str              # 6-digit TOTP code

    @field_validator("code")
    @classmethod
    def code_is_digits(cls, v: str) -> str:
        if not v.isdigit() or len(v) != 6:
            raise ValueError("TOTP code must be exactly 6 digits.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginStep1Response(BaseModel):
    """Returned after password check passes. Frontend prompts TOTP."""
    user_id: str
    requires_totp: bool = True
    message: str = "Password verified. Please enter your authenticator code."


class LoginTOTPRequest(BaseModel):
    user_id: str
    code: str

    @field_validator("code")
    @classmethod
    def code_is_digits(cls, v: str) -> str:
        if not v.isdigit() or len(v) != 6:
            raise ValueError("TOTP code must be exactly 6 digits.")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int         # seconds


class RefreshTokenRequest(BaseModel):
    refresh_token: str
