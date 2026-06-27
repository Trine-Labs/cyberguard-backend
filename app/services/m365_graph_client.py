"""M365 Graph API Client with Audit Logging"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.m365_audit_log import M365AuditLog

logger = logging.getLogger(__name__)

# High-risk application permission roles (app-level, not delegated)
RISKY_APP_ROLES = {
    "Mail.Read", "Mail.ReadWrite", "Mail.ReadBasic.All",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "Files.Read.All", "Files.ReadWrite.All",
    "RoleManagement.Read.Directory", "RoleManagement.ReadWrite.Directory",
    "User.Read.All", "User.ReadWrite.All",
    "AuditLog.Read.All", "SecurityEvents.Read.All",
    "MailboxSettings.Read", "Calendars.Read",
}


class M365GraphClient:
    """
    Client for interacting with Microsoft Graph API.
    Enforces strict read-only access and logs all queries to the audit trail.
    """
    BASE_URL = "https://graph.microsoft.com/v1.0"
    BETA_URL = "https://graph.microsoft.com/beta"

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

    async def _get(
        self,
        endpoint: str,
        silent_errors: bool = False,
        base: Optional[str] = None,
        paginate: bool = True,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        GET request to Graph API with:
        - Auto-pagination via @odata.nextLink (disable with paginate=False)
        - 429 rate-limit handling using Retry-After header
        - Audit logging per page
        """
        base_url = base or self.BASE_URL
        url = f"{base_url}{endpoint}"
        all_values = []
        data = {}
        try:
            while url:
                retries = 0
                while retries <= max_retries:
                    response = await self.client.get(url)
                    status_code = response.status_code

                    if status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", "10"))
                        logger.warning(
                            f"Graph API 429 on {endpoint} — backing off {retry_after}s "
                            f"(attempt {retries + 1}/{max_retries})"
                        )
                        await asyncio.sleep(retry_after)
                        retries += 1
                        continue

                    data = {}
                    if status_code == 200:
                        data = response.json()
                        page_values = data.get("value", [])
                        if isinstance(page_values, list):
                            all_values.extend(page_values)

                    await self._audit_log(endpoint, len(all_values), status_code)
                    response.raise_for_status()
                    break  # Successful response — exit retry loop

                # Follow @odata.nextLink only if pagination is enabled
                url = data.get("@odata.nextLink") if paginate else None

            if all_values:
                return {"value": all_values}
            return data  # For single-object responses
        except Exception as e:
            if not silent_errors:
                logger.error(f"Graph API request failed: {e}")
            raise

    # ─── User & Identity ──────────────────────────────────────────────────────

    async def get_users(self) -> List[Dict[str, Any]]:
        """Fetch all users (member accounts only) with sign-in activity."""
        try:
            data = await self._get(
                "/users?$filter=userType eq 'Member'"
                "&$select=id,displayName,userPrincipalName,accountEnabled,signInActivity,createdDateTime,userType"
            )
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch users: {e}")
            return []

    async def get_guest_accounts(self) -> List[Dict[str, Any]]:
        """Fetch all guest (external) accounts with their sign-in activity."""
        try:
            data = await self._get(
                "/users?$filter=userType eq 'Guest'"
                "&$select=id,displayName,userPrincipalName,accountEnabled,signInActivity,createdDateTime,userType"
            )
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch guest accounts: {e}")
            return []

    async def get_verified_domains(self) -> List[str]:
        """Fetch the tenant's verified domain names (used for forwarding rule analysis).
        Note: Graph /domains does not support OData $filter — fetch all and filter client-side.
        """
        try:
            data = await self._get("/domains?$select=id,isVerified,isDefault")
            return [d["id"].lower() for d in data.get("value", []) if d.get("isVerified")]
        except Exception as e:
            logger.warning(f"Could not fetch verified domains: {e}")
            return []

    async def get_directory_roles(self) -> List[Dict[str, Any]]:
        """Fetch active directory roles and their members."""
        try:
            data = await self._get("/directoryRoles")
            roles = data.get("value", [])

            # Hydrate each role with its members
            for role in roles:
                try:
                    members_data = await self._get(
                        f"/directoryRoles/{role['id']}/members?$select=id,displayName,userPrincipalName"
                    )
                    role["members"] = members_data.get("value", [])
                except Exception:
                    role["members"] = []

            return roles
        except Exception as e:
            logger.warning(f"Could not fetch directory roles: {e}")
            return []

    async def get_pim_eligible_assignments(self) -> List[Dict[str, Any]]:
        """
        Fetch PIM eligible role assignments (requires RoleManagement.Read.All).
        Returns users who COULD elevate to admin — not currently active admins.
        """
        try:
            data = await self._get(
                "/roleManagement/directory/roleEligibilityScheduleInstances"
                "?$select=id,roleDefinitionId,principalId,directoryScopeId,status"
                "&$expand=principal($select=displayName,userPrincipalName),roleDefinition($select=displayName)"
            )
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch PIM eligible assignments (requires RoleManagement.Read.All): {e}")
            return []

    # ─── MFA & Authentication ─────────────────────────────────────────────────

    async def get_mfa_details(self, users: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Fetch MFA registration status for all users.

        Strategy 1 (preferred): Beta report endpoint — requires Entra ID P1/P2 license.
          GET /beta/reports/authenticationMethods/userRegistrationDetails
          Returns structured isMfaRegistered + methodsRegistered per user.

        Strategy 2 (fallback): Per-user auth methods — works on any license tier.
          GET /users/{id}/authentication/methods
          Requires UserAuthenticationMethod.Read.All scope.
          We normalise the response to match the P2 report shape.
        """
        # ── Strategy 1: P2 report endpoint ──────────────────────────────────
        try:
            endpoint = "/reports/authenticationMethods/userRegistrationDetails"
            url = f"{self.BETA_URL}{endpoint}"
            all_values = []

            while url:
                response = await self.client.get(url)
                status_code = response.status_code
                data = {}

                if status_code == 200:
                    data = response.json()
                    all_values.extend(data.get("value", []))

                await self._audit_log(endpoint, len(all_values), status_code)

                if status_code != 200:
                    logger.info(
                        f"MFA report endpoint returned {status_code} — "
                        "falling back to per-user auth methods (likely no P1/P2 license)"
                    )
                    raise ValueError(f"report_endpoint_unavailable:{status_code}")

                url = data.get("@odata.nextLink")

            if all_values:
                logger.info(f"MFA report: fetched {len(all_values)} user records via P2 endpoint")
                return all_values

            # Empty result — could mean no licensed users; try fallback anyway
            logger.info("MFA report returned 0 records — trying per-user fallback")
            raise ValueError("report_endpoint_empty")

        except Exception as e:
            logger.info(f"Strategy 1 skipped ({e}) — using per-user auth methods fallback")

        # ── Strategy 2: Per-user /authentication/methods ─────────────────────
        if not users:
            logger.warning("MFA fallback: no users list provided — skipping")
            return []

        return await self._get_mfa_per_user(users)

    async def _get_mfa_per_user(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fallback MFA fetch: calls GET /users/{id}/authentication/methods per user.
        Requires UserAuthenticationMethod.Read.All scope (no P2 license needed).
        Normalises output to match the P2 report shape so rules_engine works unchanged.
        """
        METHOD_MAP = {
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": "microsoftAuthenticatorPush",
            "#microsoft.graph.phoneAuthenticationMethod":                  "mobilePhone",
            "#microsoft.graph.emailAuthenticationMethod":                  "email",
            "#microsoft.graph.fido2AuthenticationMethod":                  "fido2",
            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windowsHelloForBusiness",
            "#microsoft.graph.softwareOathAuthenticationMethod":           "softwareOneTimePasscode",
            "#microsoft.graph.temporaryAccessPassAuthenticationMethod":    "temporaryAccessPass",
            "#microsoft.graph.passwordAuthenticationMethod":               None,  # Not MFA
        }
        # Methods that count as MFA (anything except password)
        MFA_METHODS = {
            "microsoftAuthenticatorPush", "mobilePhone", "email",
            "fido2", "windowsHelloForBusiness", "softwareOneTimePasscode",
        }

        results = []
        for user in users:
            user_id  = user.get("id")
            upn      = user.get("userPrincipalName", "")
            if not user_id:
                continue
            try:
                data = await self._get(
                    f"/users/{user_id}/authentication/methods",
                    silent_errors=True,
                    paginate=False,
                )
                raw_methods = data.get("value", [])
                named = [
                    METHOD_MAP.get(m.get("@odata.type", ""))
                    for m in raw_methods
                    if METHOD_MAP.get(m.get("@odata.type", "")) is not None
                ]
                is_mfa = any(m in MFA_METHODS for m in named)
                results.append({
                    "userPrincipalName": upn,
                    "userId": user_id,
                    "isMfaRegistered": is_mfa,
                    "isMfaCapable": is_mfa,
                    "methodsRegistered": named,
                    "_source": "per_user_fallback",
                })
            except Exception:
                pass  # 403 if MailboxSettings not on user — skip silently

        logger.info(f"MFA per-user fallback: collected {len(results)} records")
        return results


    # ─── OAuth & App Permissions ──────────────────────────────────────────────

    async def get_service_principals(self) -> List[Dict[str, Any]]:
        """Fetch service principals (Enterprise Applications)."""
        try:
            data = await self._get(
                "/servicePrincipals?$select=id,appId,displayName,publisherName,appRoles,oauth2PermissionScopes"
            )
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch service principals: {e}")
            return []

    async def get_oauth2_permission_grants(self) -> List[Dict[str, Any]]:
        """Fetch all delegated OAuth2 permission grants."""
        try:
            data = await self._get("/oauth2PermissionGrants")
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch oauth2 permission grants: {e}")
            return []

    async def get_app_role_assignments(self) -> List[Dict[str, Any]]:
        """
        Fetch all application-level role assignments (non-delegated, background permissions).
        These are higher-risk than delegated grants because they apply tenant-wide without
        a signed-in user. e.g. an app granted Mail.Read can read ALL mailboxes silently.
        Requires Directory.Read.All scope.
        """
        try:
            # servicePrincipals/$ref gives us all app-to-app permission grants
            data = await self._get(
                "/servicePrincipals?$select=id,displayName,publisherName,appRoleAssignments"
                "&$expand=appRoleAssignments"
            )
            service_principals = data.get("value", [])

            assignments = []
            for sp in service_principals:
                for assignment in sp.get("appRoleAssignments", []):
                    assignments.append({
                        "principalDisplayName": sp.get("displayName"),
                        "principalId": sp.get("id"),
                        "publisherName": sp.get("publisherName"),
                        "resourceId": assignment.get("resourceId"),
                        "appRoleId": assignment.get("appRoleId"),
                        "principalType": assignment.get("principalType"),
                        "createdDateTime": assignment.get("createdDateTime"),
                    })
            return assignments
        except Exception as e:
            logger.warning(f"Could not fetch app role assignments: {e}")
            return []

    # ─── Policies & Config ────────────────────────────────────────────────────

    async def get_conditional_access_policies(self) -> List[Dict[str, Any]]:
        """Fetch all Conditional Access policies (requires Policy.Read.All)."""
        try:
            data = await self._get("/identity/conditionalAccess/policies")
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch conditional access policies: {e}")
            return []

    async def get_audit_log_status(self) -> Dict[str, Any]:
        """
        Check whether the unified audit log is reachable.
        Fetches exactly ONE record — no pagination — to avoid 429 rate limits.
        Returns a dict with 'reachable' bool and 'has_recent_activity'.
        """
        endpoint = "/auditLogs/directoryAudits?$top=1&$select=id,activityDateTime,category"
        url = f"{self.BASE_URL}{endpoint}"
        try:
            response = await self.client.get(url)
            status_code = response.status_code
            await self._audit_log(endpoint, 1 if status_code == 200 else 0, status_code)

            if status_code == 200:
                records = response.json().get("value", [])
                return {
                    "reachable": True,
                    "has_recent_activity": len(records) > 0,
                }
            if status_code == 403:
                # Scope present but audit log may be disabled or app lacks permission
                logger.warning("Audit log check returned 403 — AuditLog.Read.All may not be consented")
                return {"reachable": False, "has_recent_activity": False, "reason": "forbidden"}

            return {"reachable": False, "has_recent_activity": False, "reason": f"http_{status_code}"}
        except Exception as e:
            logger.warning(f"Could not reach audit log endpoint: {e}")
            return {"reachable": False, "has_recent_activity": False, "reason": str(e)}

    # ─── Mailbox ─────────────────────────────────────────────────────────────

    async def get_mailbox_rules(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fetch inbox rules for all provided users.
        Rate-limited with error suppression — 403 is expected for users without
        an Exchange mailbox or if MailboxSettings.Read is not granted.
        """
        rules_data = []
        for user in users:
            try:
                user_id = user.get("id")
                data = await self._get(
                    f"/users/{user_id}/mailFolders/inbox/messageRules",
                    silent_errors=True
                )
                rules = data.get("value", [])
                if rules:
                    rules_data.append({
                        "user_id": user_id,
                        "upn": user.get("userPrincipalName"),
                        "rules": rules
                    })
            except Exception:
                pass  # Expected: 403 for non-mailbox users or missing scope
        return rules_data

    # ─── SharePoint ───────────────────────────────────────────────────────────

    async def get_sharepoint_settings(self) -> Dict[str, Any]:
        """
        Fetch tenant-level SharePoint/OneDrive sharing configuration.
        Requires SharePointTenantSettings.Read.All scope.
        Uses beta endpoint — no stable v1.0 equivalent.

        Key risk fields:
          sharingCapability: disabled | existingExternalUserSharingOnly |
                             externalUserSharingOnly | externalUserAndGuestSharing (anyone — dangerous)
          defaultSharingLinkType: none | direct | internal | anonymous (dangerous)
          isExternalUserSelfServiceSignUpEnabled: bool
        """
        endpoint = "/admin/sharepoint/settings"
        url = f"{self.BETA_URL}{endpoint}"
        try:
            response = await self.client.get(url)
            status_code = response.status_code
            await self._audit_log(endpoint, 1 if status_code == 200 else 0, status_code)
            if status_code == 200:
                return response.json()
            logger.warning(f"SharePoint settings returned {status_code} — SharePointTenantSettings.Read.All may not be consented")
            return {}
        except Exception as e:
            logger.warning(f"Could not fetch SharePoint settings: {e}")
            return {}

    # ─── Identity Protection ──────────────────────────────────────────────────

    async def get_risky_users(self) -> List[Dict[str, Any]]:
        """
        Fetch users flagged by Entra ID Identity Protection as actively at risk.
        Requires IdentityRiskyUser.Read.All scope + Entra ID P2 license.

        Risk detections: leaked credentials, anonymous IP, atypical travel,
        malware-linked IP, impossible travel, password spray, suspicious sign-in.
        """
        try:
            data = await self._get(
                "/identityProtection/riskyUsers"
                "?$filter=riskState eq 'atRisk'"
                "&$select=id,userPrincipalName,displayName,riskLevel,riskState,"
                "riskDetail,riskLastUpdatedDateTime"
            )
            return data.get("value", [])
        except Exception as e:
            logger.warning(f"Could not fetch risky users (requires IdentityRiskyUser.Read.All + P2): {e}")
            return []

    async def close(self):
        await self.client.aclose()
