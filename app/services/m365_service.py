"""
CyberGuard — Microsoft 365 OAuth Service
Handles: OAuth URL construction, authorization code exchange, token management.
"""
import urllib.parse
from typing import Optional
import httpx
from app.config import get_settings

settings = get_settings()

MICROSOFT_AUTH_BASE = "https://login.microsoftonline.com"
MICROSOFT_TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MICROSOFT_AUTHORIZE_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"


def build_admin_consent_url(state: str) -> str:
    """
    Construct the Microsoft Entra ID OAuth Authorization URL with admin consent.
    The 'state' parameter ties the OAuth callback back to our session.

    Uses /authorize with prompt=admin_consent and response_type=code so that:
    1. Microsoft prompts the Global Admin to grant tenant-wide consent.
    2. Microsoft redirects back with an authorization code we can exchange
       for access + refresh tokens (unlike /adminconsent which returns no code).
    """
    params = {
        "client_id": settings.m365_client_id,
        "response_type": "code",
        "redirect_uri": settings.m365_redirect_uri,
        "response_mode": "query",
        "scope": settings.m365_scopes,
        "state": state,
        # prompt=consent forces the consent screen each time.
        # When the user is a Global Admin, Microsoft automatically grants
        # tenant-wide admin consent (same effect as /adminconsent endpoint).
        "prompt": "consent",
    }
    return f"{MICROSOFT_AUTHORIZE_ENDPOINT}?{urllib.parse.urlencode(params)}"


async def exchange_code_for_tokens(authorization_code: str) -> dict:
    """
    Exchange the OAuth authorization code for access + refresh tokens.
    This is a server-to-server call — the authorization code never touches the frontend.
    
    Returns:
        {
            "access_token": str,
            "refresh_token": str,
            "expires_in": int,
            "token_type": str,
            "scope": str,
        }
    
    Raises:
        httpx.HTTPStatusError: If Microsoft returns an error response.
        ValueError: If refresh_token is missing from response.
    """
    payload = {
        "client_id": settings.m365_client_id,
        "client_secret": settings.m365_client_secret,
        "code": authorization_code,
        "redirect_uri": settings.m365_redirect_uri,
        "grant_type": "authorization_code",
        "scope": settings.m365_scopes,
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            MICROSOFT_TOKEN_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        token_data = response.json()
    
    if "refresh_token" not in token_data:
        raise ValueError(
            "Microsoft did not return a refresh_token. "
            "Ensure 'offline_access' scope is included in the consent request."
        )
    
    return token_data


async def refresh_access_token(encrypted_refresh_token_plaintext: str) -> dict:
    """
    Use a refresh token to get a new access token.
    Called by the M365 polling worker (Module 2) during background scans.
    
    SECURITY NOTE: The caller (Celery worker) is responsible for:
    1. Decrypting the refresh token from DB immediately before this call
    2. Discarding both the decrypted refresh token and the returned access token
       from memory as soon as the Graph API calls complete.
    
    Args:
        encrypted_refresh_token_plaintext: The DECRYPTED refresh token string.
            This should NOT be the ciphertext from the DB.
    
    Returns:
        dict with new 'access_token', 'refresh_token', 'expires_in'.
    """
    payload = {
        "client_id": settings.m365_client_id,
        "client_secret": settings.m365_client_secret,
        "refresh_token": encrypted_refresh_token_plaintext,
        "grant_type": "refresh_token",
        "scope": settings.m365_scopes,
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            MICROSOFT_TOKEN_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    
    if response.status_code == 400:
        error_data = response.json()
        if error_data.get("error") == "invalid_grant":
            raise ValueError(
                "M365 refresh token has been revoked or expired. "
                "Tenant must re-authorize the M365 connection."
            )
    
    response.raise_for_status()
    
    # Immediately clear sensitive input from memory
    del encrypted_refresh_token_plaintext
    
    return response.json()
