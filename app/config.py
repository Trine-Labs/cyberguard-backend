"""
CyberGuard Backend — Configuration
Loads all settings from environment variables / .env file.
"""
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "CyberGuard"
    app_env: str = "development"
    debug: bool = True
    cors_origins: str = "http://localhost:3000"

    # Database
    database_url: str

    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440000  # Increased for testing
    refresh_token_expire_days: int = 30

    # Encryption (Fernet — local KMS stand-in for Phase 1)
    fernet_encryption_key: str
    kms_key_id: str = "cyberguard-local-v1"

    # Microsoft 365 OAuth
    m365_client_id: str = ""
    m365_client_secret: str = ""
    m365_redirect_uri: str = "http://localhost:8000/api/v1/m365/callback"
    m365_scopes: str = (
        "https://graph.microsoft.com/User.Read.All "
        "https://graph.microsoft.com/AuditLog.Read.All "
        "https://graph.microsoft.com/Policy.Read.All "
        "https://graph.microsoft.com/Directory.Read.All "
        "offline_access"
    )

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # TOTP
    totp_issuer: str = "CyberGuard"

    # Blocked email providers
    blocked_email_domains: str = (
        "gmail.com,yahoo.com,hotmail.com,outlook.com,"
        "protonmail.com,icloud.com,live.com,msn.com,aol.com"
    )

    # Frontend
    frontend_url: str = "http://localhost:3000"

    # NVD API
    nvd_api_key: str = ""

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    @property
    def blocked_email_domains_list(self) -> List[str]:
        return [d.strip().lower() for d in self.blocked_email_domains.split(",")]

    @property
    def m365_scopes_list(self) -> List[str]:
        return self.m365_scopes.split()


@lru_cache()
def get_settings() -> Settings:
    return Settings()
