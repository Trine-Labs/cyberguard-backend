"""M365 Payloads (Pydantic Models)"""
from typing import List, Optional, Any
from pydantic import BaseModel, Field

class ServicePrincipal(BaseModel):
    id: str
    appId: str
    displayName: Optional[str] = None
    appRoles: List[Any] = Field(default_factory=list)
    oauth2PermissionScopes: List[Any] = Field(default_factory=list)

class OAuth2PermissionGrant(BaseModel):
    id: str
    clientId: str
    consentType: str
    principalId: Optional[str] = None
    resourceId: str
    scope: str
