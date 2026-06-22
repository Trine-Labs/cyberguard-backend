"""M365 Graph API Client with Audit Logging"""
import logging
from typing import Dict, Any, List
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.m365_audit_log import M365AuditLog

logger = logging.getLogger(__name__)

class M365GraphClient:
    """
    Client for interacting with Microsoft Graph API.
    Enforces strict read-only access and logs all queries to the audit trail.
    """
    BASE_URL = "https://graph.microsoft.com/v1.0"

    def __init__(self, tenant_id: str, access_token: str, db_session: AsyncSession):
        self.tenant_id = tenant_id
        self.access_token = access_token
        self.db_session = db_session
        self.client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {self.access_token}"},
            timeout=30.0
        )

    async def _audit_log(self, endpoint: str, records_retrieved: int, status_code: int):
        """Write an audit log entry for the API call."""
        audit_entry = M365AuditLog(
            tenant_id=self.tenant_id,
            endpoint_queried=endpoint,
            records_retrieved=records_retrieved,
            status_code=status_code
        )
        self.db_session.add(audit_entry)
        await self.db_session.commit()

    async def _get(self, endpoint: str, silent_errors: bool = False) -> Dict[str, Any]:
        """Perform a GET request to Graph API with audit logging."""
        url = f"{self.BASE_URL}{endpoint}"
        try:
            response = await self.client.get(url)
            status_code = response.status_code
            
            data = {}
            records_retrieved = 0
            if status_code == 200:
                data = response.json()
                if "value" in data and isinstance(data["value"], list):
                    records_retrieved = len(data["value"])
                else:
                    records_retrieved = 1
                    
            await self._audit_log(endpoint, records_retrieved, status_code)
            response.raise_for_status()
            
            return data
        except Exception as e:
            if not silent_errors:
                logger.error(f"Graph API request failed: {e}")
            raise

    async def get_service_principals(self) -> List[Dict[str, Any]]:
        """Fetch Service Principals (Enterprise Applications) to check for illicit consent grants."""
        try:
            data = await self._get("/servicePrincipals?$select=id,appId,displayName,appRoles,oauth2PermissionScopes")
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch service principals: {e}")
            return []

    async def get_oauth2_permission_grants(self) -> List[Dict[str, Any]]:
        """Fetch all delegated permission grants."""
        try:
            data = await self._get("/oauth2PermissionGrants")
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch oauth2 permission grants: {e}")
            return []
        
    async def get_app_role_assignments(self) -> List[Dict[str, Any]]:
        """Fetch all app role assignments (application permissions)."""
        pass

    async def get_users(self) -> List[Dict[str, Any]]:
        """Fetch basic user directory information with signInActivity."""
        try:
            data = await self._get("/users?$select=id,displayName,userPrincipalName,accountEnabled,signInActivity")
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch users: {e}")
            return []

    async def get_mailbox_rules(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fetch inbox rules for users (typically privileged ones to save API calls)."""
        rules_data = []
        # Limit to first 20 users for MVP to avoid rate limiting
        for user in users[:20]:
            try:
                user_id = user.get("id")
                data = await self._get(f"/users/{user_id}/mailFolders/inbox/messageRules", silent_errors=True)
                rules = data.get("value", [])
                if rules:
                    rules_data.append({
                        "user_id": user_id,
                        "upn": user.get("userPrincipalName"),
                        "rules": rules
                    })
            except Exception as e:
                pass # Usually permission denied if missing MailboxSettings.Read
        return rules_data

    async def get_directory_roles(self) -> List[Dict[str, Any]]:
        """Fetch directory roles and their active members."""
        try:
            data = await self._get("/directoryRoles")
            roles = data.get("value", [])
            
            # Hydrate roles with their members
            for role in roles:
                try:
                    members_data = await self._get(f"/directoryRoles/{role['id']}/members?$select=id,displayName,userPrincipalName")
                    role["members"] = members_data.get("value", [])
                except Exception:
                    role["members"] = []
                    
            return roles
        except Exception as e:
            logger.warning(f"Could not fetch directory roles: {e}")
            return []

    async def get_conditional_access_policies(self) -> List[Dict[str, Any]]:
        """Fetch conditional access policies."""
        try:
            data = await self._get("/identity/conditionalAccess/policies")
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch conditional access policies (requires Policy.Read.All): {e}")
            return []

    async def get_mfa_details(self) -> List[Dict[str, Any]]:
        """Attempt to fetch MFA registration details for all users (requires beta endpoint and premium)."""
        try:
            url = f"https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails"
            response = await self.client.get(url)
            
            status_code = response.status_code
            records = 0
            data = {}
            if status_code == 200:
                data = response.json()
                records = len(data.get("value", []))
                
            with open("debug_mfa.txt", "w", encoding="utf-8") as f:
                f.write(f"status: {status_code}\nbody: {response.text}\nheaders: {response.headers}")
            
            await self._audit_log("/beta/reports/authenticationMethods/userRegistrationDetails", records, status_code)
            
            if status_code == 200:
                return data.get("value", [])
            return []
        except Exception as e:
            logger.warning(f"Could not fetch MFA details: {e}")
            with open("debug_mfa_exception.txt", "w", encoding="utf-8") as f:
                f.write(str(e))
            return []

    async def close(self):
        await self.client.aclose()
