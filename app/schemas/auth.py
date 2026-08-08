"""Pydantic schemas for authentication endpoints."""
import re
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator


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
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return v


class RegisterResponse(BaseModel):
    user_id: str
    tenant_id: str
    email: str
    totp_secret: str
    totp_qr_code: str


class TOTPVerifyRequest(BaseModel):
    user_id: str
    code: str

    @field_validator("code")
    @classmethod
    def code_is_digits(cls, v: str) -> str:
        if not v.isdigit() or len(v) != 6:
            raise ValueError("Passcode must be exactly 6 digits.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginStep1Response(BaseModel):
    """Returned after password check passes. Prompt Email OTP."""
    user_id: str
    email: str
    requires_otp: bool = True
    message: str = "Password verified. A 6-digit OTP passcode has been sent to your email."


class LoginOTPVerifyRequest(BaseModel):
    user_id: str
    code: str

    @field_validator("code")
    @classmethod
    def code_is_digits(cls, v: str) -> str:
        if not v.isdigit() or len(v) != 6:
            raise ValueError("OTP passcode must be exactly 6 digits.")
        return v


class ResendOTPRequest(BaseModel):
    user_id: str


class ChangePasswordRequest(BaseModel):
    old_password: Optional[str] = None
    new_password: str

    @field_validator("new_password")
    @classmethod
    def new_password_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters long.")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool = False


class RefreshTokenRequest(BaseModel):
    refresh_token: str
