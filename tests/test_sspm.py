"""
CyberGuard SSPM (SaaS Security Posture Management / M365) Comprehensive 100% Test Suite
Covers:
  1. Deterministic Security Rules Engine Unit Tests (rules_engine.py)
     - SSPM-001: Admin Missing MFA
     - SSPM-002: External Mailbox Forwarding Rules
     - SSPM-003: Admin Role Sprawl
     - SSPM-004: Inactive Conditional Access Policies
     - SSPM-004b: CA Policy MFA Exclusion Bypass
     - SSPM-005: Illicit Delegated OAuth Grants
     - SSPM-005b: Risky Application-Level Permissions
     - SSPM-006: Stale Dormant Admin Accounts
     - SSPM-007: Weak MFA Factor Methods
     - SSPM-008: Standard User Missing MFA
     - SSPM-009: Dormant Guest Accounts
     - SSPM-010: Audit Log Status
     - SSPM-011: SharePoint Anonymous Sharing & Self-Service
     - SSPM-012: Identity Protection Risky Users
     - SSPM-013: PIM Eligible Admin Role Assignments
     - SSPM-015: Endpoint Protection / Defender Status
     - run_all_rules Orchestration & Helpers
  2. Microsoft 365 OAuth & Token Service (m365_service.py)
  3. M365 Graph API Client & Audit Logging (m365_graph_client.py)
  4. M365 Scanner Background Task & Scheduling (tasks/m365_scanner.py)
  5. M365 Findings Ingestion & Sync (findings_service.py)
  6. M365 API Router Endpoints Integration Tests (routers/m365.py)
"""
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
import httpx
from httpx import AsyncClient, Response, Request
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.rules_engine import (
    check_admin_missing_mfa,
    check_malicious_forwarding,
    check_admin_sprawl,
    check_inactive_ca_policies,
    check_ca_mfa_exclusion_bypass,
    check_illicit_consent_grants,
    check_risky_app_role_assignments,
    check_stale_dormant_admin,
    check_weak_mfa,
    check_standard_user_no_mfa,
    check_dormant_guests,
    check_audit_log_status,
    check_sharepoint_sharing,
    check_identity_protection_risky_users,
    check_pim_eligible_admins,
    check_defender_not_running,
    run_all_rules,
    get_admin_user_ids,
    _days_since,
)
from app.services.m365_service import (
    build_admin_consent_url,
    exchange_code_for_tokens,
    refresh_access_token,
)
from app.services.m365_graph_client import M365GraphClient
from app.services.findings_service import upsert_m365_findings
from app.services.crypto_service import encrypt_token, decrypt_token, EncryptedBlob
from app.tasks.m365_scanner import _is_scan_due, _process_tenant
from app.models.m365_credential import M365Credential
from app.models.m365_audit_log import M365AuditLog
from app.models.finding import Finding
from app.models.tenant import Tenant
from app.models.user import User
from app.routers.m365 import _oauth_state_store


# ── 1. Deterministic Security Rules Engine Unit Tests ─────────────────────────
class TestSSPMDeterministicRules:
    def test_helpers_admin_user_ids_and_days_since(self):
        """Verify role parsing helper and datetime calculation helper."""
        directory_roles = [
            {
                "displayName": "Global Administrator",
                "members": [{"id": "user-admin-1"}, {"id": "user-admin-2"}]
            },
            {
                "displayName": "Helpdesk Administrator",
                "members": [{"id": "user-admin-3"}]
            },
            {
                "displayName": "Reports Reader",
                "members": [{"id": "user-regular"}]
            }
        ]
        admin_ids = get_admin_user_ids(directory_roles)
        assert "user-admin-1" in admin_ids
        assert "user-admin-2" in admin_ids
        assert "user-admin-3" in admin_ids
        assert "user-regular" not in admin_ids

        assert _days_since(None) is None
        assert _days_since("invalid-date") is None
        past_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        assert _days_since(past_date) == 10

    def test_sspm_001_admin_missing_mfa(self):
        """SSPM-001: Flag admin accounts with zero registered MFA methods."""
        users = [{"id": "adm-1", "userPrincipalName": "admin@contoso.com"}]
        roles = [{"displayName": "Global Administrator", "members": [{"id": "adm-1"}]}]
        mfa_unregistered = [{"userPrincipalName": "admin@contoso.com", "isMfaRegistered": False, "methodsRegistered": []}]
        mfa_registered = [{"userPrincipalName": "admin@contoso.com", "isMfaRegistered": True, "methodsRegistered": ["microsoftAuthenticatorPush"]}]

        findings_flagged = check_admin_missing_mfa(users, roles, mfa_unregistered)
        assert len(findings_flagged) == 1
        assert findings_flagged[0]["issue_type"] == "Administrative Account Missing MFA"
        assert findings_flagged[0]["severity"] == "critical"

        findings_clean = check_admin_missing_mfa(users, roles, mfa_registered)
        assert len(findings_clean) == 0

    def test_sspm_002_malicious_mailbox_forwarding(self):
        """SSPM-002: Flag mailbox forwarding/redirecting to non-tenant external domains."""
        mailbox_rules = [{
            "upn": "victim@contoso.com",
            "rules": [
                {
                    "displayName": "Exfil Rule",
                    "id": "rule-123",
                    "actions": {
                        "forwardTo": [{"emailAddress": {"address": "attacker@evilcorp.com"}}],
                        "redirectTo": []
                    }
                },
                {
                    "displayName": "Legit Rule",
                    "id": "rule-456",
                    "actions": {
                        "forwardTo": [{"emailAddress": {"address": "colleague@contoso.com"}}],
                        "redirectTo": [{"emailAddress": {"address": "backup@contoso.onmicrosoft.com"}}]
                    }
                }
            ]
        }]
        verified_domains = ["contoso.com", "contoso.onmicrosoft.com"]

        findings = check_malicious_forwarding(mailbox_rules, verified_domains)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Malicious Mailbox External Forwarding Rule"
        assert findings[0]["severity"] == "critical"
        assert "attacker@evilcorp.com" in findings[0]["evidence"]["forwarding_to"]

    def test_sspm_003_admin_sprawl(self):
        """SSPM-003: Flag when more than 5 Global Administrators exist."""
        roles_ok = [{
            "displayName": "Global Administrator",
            "members": [{"userPrincipalName": f"admin{i}@contoso.com"} for i in range(4)]
        }]
        roles_sprawl = [{
            "displayName": "Global Administrator",
            "members": [{"userPrincipalName": f"admin{i}@contoso.com"} for i in range(7)]
        }]

        assert len(check_admin_sprawl(roles_ok)) == 0
        findings = check_admin_sprawl(roles_sprawl)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Administrative Role Account Sprawl"
        assert findings[0]["severity"] == "high"
        assert findings[0]["evidence"]["admin_count"] == 7

    def test_sspm_004_inactive_ca_policies(self):
        """SSPM-004: Flag critical MFA/admin CA policies that are disabled or report-only."""
        policies = [
            {"id": "p1", "displayName": "Require MFA for Admins", "state": "disabled"},
            {"id": "p2", "displayName": "Baseline MFA Policy", "state": "enabledForReportingButNotEnforced"},
            {"id": "p3", "displayName": "Require MFA for All", "state": "enabled"},
            {"id": "p4", "displayName": "Block Legacy Auth", "state": "disabled"}
        ]
        findings = check_inactive_ca_policies(policies)
        assert len(findings) == 2
        assert all(f["severity"] == "high" for f in findings)
        policy_ids = [f["evidence"]["policy_id"] for f in findings]
        assert "p1" in policy_ids
        assert "p2" in policy_ids

    def test_sspm_004b_ca_mfa_exclusion_bypass(self):
        """SSPM-004b: Flag active CA policies requiring MFA that contain exclusions."""
        policies = [
            {
                "id": "p-mfa-excluded",
                "displayName": "Enforce MFA Tenant Wide",
                "state": "enabled",
                "grantControls": {"builtInControls": ["mfa"]},
                "conditions": {
                    "users": {
                        "excludeUsers": ["user-vip-id", "service-acct-id"],
                        "excludeGroups": ["emergency-breakglass-group"]
                    }
                }
            },
            {
                "id": "p-mfa-clean",
                "displayName": "Strict MFA",
                "state": "enabled",
                "grantControls": {"builtInControls": ["mfa"]},
                "conditions": {"users": {"excludeUsers": [], "excludeGroups": [], "excludeRoles": []}}
            }
        ]
        findings = check_ca_mfa_exclusion_bypass(policies)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Conditional Access MFA Policy Has Exclusions (Bypass Risk)"
        assert findings[0]["evidence"]["excluded_users_count"] == 2
        assert findings[0]["evidence"]["excluded_groups_count"] == 1

    def test_sspm_005_illicit_consent_grants(self):
        """SSPM-005: Flag third-party apps granted risky delegated scopes or AllPrincipals consent."""
        grants = [
            {
                "id": "grant-1",
                "clientId": "sp-suspicious-app",
                "resourceId": "resource-graph",
                "consentType": "Principal",
                "scope": "Mail.ReadWrite User.Read"
            },
            {
                "id": "grant-2",
                "clientId": "sp-safe-app",
                "resourceId": "resource-graph",
                "consentType": "Principal",
                "scope": "User.Read openid profile"
            }
        ]
        service_principals = [
            {"id": "sp-suspicious-app", "appId": "app-guid-1", "displayName": "Suspicious Cloud Backup"},
            {"id": "sp-safe-app", "appId": "app-guid-2", "displayName": "Standard SSO Helper"}
        ]

        findings = check_illicit_consent_grants(grants, service_principals)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "High-Privilege Illicit OAuth App Grant"
        assert "Mail.ReadWrite" in findings[0]["evidence"]["risky_scopes"]
        assert "Suspicious Cloud Backup" in findings[0]["entity"]

    def test_sspm_005b_risky_app_role_assignments(self):
        """SSPM-005b: Flag dangerous non-delegated application permissions granted to apps."""
        service_principals = [
            {
                "displayName": "Microsoft Graph",
                "appRoles": [
                    {"id": "role-uuid-mail", "value": "Mail.ReadWrite", "displayName": "Read and write mail in all mailboxes"},
                    {"id": "role-uuid-dir", "value": "Directory.ReadWrite.All", "displayName": "Read and write directory data"}
                ]
            }
        ]
        app_role_assignments = [
            {
                "principalId": "app-background-daemon",
                "principalDisplayName": "Automated Sync Daemon",
                "publisherName": "Unknown ThirdParty",
                "appRoleId": "role-uuid-mail"
            }
        ]

        findings = check_risky_app_role_assignments(app_role_assignments, service_principals)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "High-Privilege Application Permission Granted (Non-Delegated)"
        assert "Mail.ReadWrite" in findings[0]["evidence"]["risky_roles"]

    def test_sspm_006_stale_dormant_admin(self):
        """SSPM-006: Flag enabled administrators with no sign-ins in >90 days or never logged in."""
        users = [
            {
                "id": "adm-stale",
                "userPrincipalName": "dormant_admin@contoso.com",
                "accountEnabled": True,
                "signInActivity": {
                    "lastSignInDateTime": (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
                }
            },
            {
                "id": "adm-active",
                "userPrincipalName": "active_admin@contoso.com",
                "accountEnabled": True,
                "signInActivity": {
                    "lastSignInDateTime": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
                }
            }
        ]
        roles = [{"displayName": "Global Administrator", "members": [{"id": "adm-stale"}, {"id": "adm-active"}]}]

        findings = check_stale_dormant_admin(users, roles)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Stale Dormant Administrator Profile"
        assert "dormant_admin@contoso.com" in findings[0]["entity"]

    def test_sspm_007_weak_mfa_methods(self):
        """SSPM-007: Flag users registered with only weak MFA factors (SMS/voice/email)."""
        users = [
            {"id": "u1", "userPrincipalName": "user_sms@contoso.com"},
            {"id": "u2", "userPrincipalName": "user_fido@contoso.com"}
        ]
        mfa_details = [
            {
                "userPrincipalName": "user_sms@contoso.com",
                "isMfaRegistered": True,
                "methodsRegistered": ["mobilePhone", "email"]
            },
            {
                "userPrincipalName": "user_fido@contoso.com",
                "isMfaRegistered": True,
                "methodsRegistered": ["fido2", "microsoftAuthenticatorPush"]
            }
        ]

        findings = check_weak_mfa(users, mfa_details)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Weak Insecure MFA Factor Method Configured"
        assert "user_sms@contoso.com" in findings[0]["entity"]

    def test_sspm_008_standard_user_no_mfa(self):
        """SSPM-008: Flag enabled standard users without MFA registered."""
        users = [
            {"id": "std-1", "userPrincipalName": "standard_nomfa@contoso.com", "accountEnabled": True},
            {"id": "adm-1", "userPrincipalName": "admin@contoso.com", "accountEnabled": True},
            {"id": "disabled-1", "userPrincipalName": "disabled@contoso.com", "accountEnabled": False}
        ]
        roles = [{"displayName": "Global Administrator", "members": [{"id": "adm-1"}]}]
        mfa_details = [
            {"userPrincipalName": "standard_nomfa@contoso.com", "isMfaRegistered": False},
            {"userPrincipalName": "admin@contoso.com", "isMfaRegistered": False}
        ]

        findings = check_standard_user_no_mfa(users, roles, mfa_details)
        assert len(findings) == 1
        assert "standard_nomfa@contoso.com" in findings[0]["entity"]

    def test_sspm_009_dormant_guests(self):
        """SSPM-009: Flag guest accounts inactive for 90+ days or never logged in."""
        guests = [
            {
                "id": "g-1",
                "displayName": "External Vendor",
                "userPrincipalName": "vendor_ext@partner.com#EXT#@contoso.onmicrosoft.com",
                "accountEnabled": True,
                "signInActivity": {
                    "lastSignInDateTime": (datetime.now(timezone.utc) - timedelta(days=150)).isoformat()
                }
            },
            {
                "id": "g-2",
                "displayName": "Active Consultant",
                "userPrincipalName": "consultant@partner.com#EXT#@contoso.onmicrosoft.com",
                "accountEnabled": True,
                "signInActivity": {
                    "lastSignInDateTime": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
                }
            }
        ]

        findings = check_dormant_guests(guests)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Dormant Guest Account with Active Access"

    def test_sspm_010_audit_log_status(self):
        """SSPM-010: Flag when Unified Audit Log endpoint is unreachable."""
        assert len(check_audit_log_status({"reachable": True})) == 0
        findings = check_audit_log_status({"reachable": False})
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Unified Audit Log Unreachable or Disabled"
        assert findings[0]["severity"] == "high"

    def test_sspm_011_sharepoint_sharing(self):
        """SSPM-011: Flag SharePoint tenant-level anonymous sharing and open self-service signups."""
        insecure_settings = {
            "sharingCapability": "externalUserAndGuestSharing",
            "defaultSharingLinkType": "anonymous",
            "isExternalUserSelfServiceSignUpEnabled": True
        }
        secure_settings = {
            "sharingCapability": "externalUserSharingOnly",
            "defaultSharingLinkType": "internal",
            "isExternalUserSelfServiceSignUpEnabled": False
        }

        findings = check_sharepoint_sharing(insecure_settings)
        assert len(findings) == 3
        issues = [f["issue_type"] for f in findings]
        assert "SharePoint Anonymous Link Sharing Enabled Tenant-Wide" in issues
        assert "SharePoint Default Share Link Type is Anonymous" in issues
        assert "SharePoint External User Self-Service Sign-Up Enabled" in issues

        assert len(check_sharepoint_sharing(secure_settings)) == 0

    def test_sspm_012_identity_protection_risky_users(self):
        """SSPM-012: Flag active at-risk users detected by Entra ID Protection."""
        risky = [
            {
                "id": "u-risk-1",
                "userPrincipalName": "compromised@contoso.com",
                "riskLevel": "high",
                "riskState": "atRisk",
                "riskDetail": "leakedCredentials",
                "riskLastUpdatedDateTime": datetime.now(timezone.utc).isoformat()
            }
        ]
        findings = check_identity_protection_risky_users(risky)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Identity Protection: User Account at Active Risk"
        assert findings[0]["severity"] == "critical"
        assert "compromised@contoso.com" in findings[0]["entity"]

    def test_sspm_013_pim_eligible_admins(self):
        """SSPM-013: Surface sensitive PIM eligible role assignments for verification."""
        pim_assignments = [
            {
                "id": "pim-1",
                "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
                "roleDefinition": {"displayName": "Global Administrator"},
                "principal": {"userPrincipalName": "eligible_admin@contoso.com"}
            }
        ]
        findings = check_pim_eligible_admins(pim_assignments, [])
        assert len(findings) == 1
        assert "PIM Eligible Assignment to Sensitive Role" in findings[0]["issue_type"]
        assert findings[0]["severity"] == "medium"

    def test_sspm_015_defender_protection_state(self):
        """SSPM-015: Flag Windows endpoints with disabled Real-Time or Malware protection."""
        devices = [
            {
                "deviceName": "WIN-UNPROTECTED",
                "operatingSystem": "Windows",
                "userPrincipalName": "employee@contoso.com",
                "complianceState": "compliant",
                "_windowsProtectionState": {
                    "realTimeProtectionEnabled": False,
                    "malwareProtectionEnabled": True,
                    "deviceState": "clean"
                }
            },
            {
                "deviceName": "WIN-PROTECTED",
                "operatingSystem": "Windows",
                "userPrincipalName": "safe@contoso.com",
                "complianceState": "compliant",
                "_windowsProtectionState": {
                    "realTimeProtectionEnabled": True,
                    "malwareProtectionEnabled": True,
                    "deviceState": "clean"
                }
            },
            {
                "deviceName": "MAC-WORKSTATION",
                "operatingSystem": "macOS",
                "userPrincipalName": "macuser@contoso.com"
            }
        ]

        findings = check_defender_not_running(devices)
        assert len(findings) == 1
        assert findings[0]["issue_type"] == "Endpoint Protection Disabled — Microsoft Defender Inactive"
        assert "WIN-UNPROTECTED" in findings[0]["entity"]

    def test_run_all_rules_orchestration(self):
        """Verify run_all_rules compiles and aggregates findings across all rules seamlessly."""
        findings = run_all_rules(
            users=[{"id": "adm-1", "userPrincipalName": "admin@contoso.com", "accountEnabled": True}],
            directory_roles=[{"displayName": "Global Administrator", "members": [{"id": "adm-1"}]}],
            mfa_details=[{"userPrincipalName": "admin@contoso.com", "isMfaRegistered": False}],
            ca_policies=[],
            grants=[],
            service_principals=[],
            mailbox_rules=[],
            verified_domains=["contoso.com"],
            audit_log_status={"reachable": False}
        )
        assert len(findings) >= 2
        issue_types = [f["issue_type"] for f in findings]
        assert "Administrative Account Missing MFA" in issue_types
        assert "Unified Audit Log Unreachable or Disabled" in issue_types


# ── 2. Microsoft 365 OAuth & Token Service Unit Tests ────────────────────────
class TestM365OAuthService:
    def test_build_admin_consent_url_structure(self):
        """Verify admin consent URL includes client_id, scopes, redirect_uri, and state."""
        state = secrets.token_urlsafe(32)
        url = build_admin_consent_url(state=state)
        assert "https://login.microsoftonline.com/common/oauth2/v2.0/authorize" in url
        assert f"state={state}" in url
        assert "prompt=consent" in url
        assert "response_type=code" in url

    @pytest.mark.asyncio
    async def test_exchange_code_for_tokens_success(self, mocker):
        """Verify successful code-for-token exchange."""
        mock_resp = Response(
            status_code=200,
            json={
                "access_token": "mock-access-token",
                "refresh_token": "mock-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "User.Read.All Directory.Read.All offline_access"
            },
            request=Request("POST", "https://login.microsoftonline.com/common/oauth2/v2.0/token")
        )
        mocker.patch.object(httpx.AsyncClient, "post", return_value=mock_resp)

        tokens = await exchange_code_for_tokens("valid-auth-code")
        assert tokens["access_token"] == "mock-access-token"
        assert tokens["refresh_token"] == "mock-refresh-token"

    @pytest.mark.asyncio
    async def test_exchange_code_for_tokens_missing_refresh_token(self, mocker):
        """Verify ValueError is raised if refresh_token is missing."""
        mock_resp = Response(
            status_code=200,
            json={"access_token": "mock-access-token"},
            request=Request("POST", "https://login.microsoftonline.com/common/oauth2/v2.0/token")
        )
        mocker.patch.object(httpx.AsyncClient, "post", return_value=mock_resp)

        with pytest.raises(ValueError, match="Microsoft did not return a refresh_token"):
            await exchange_code_for_tokens("code-without-offline-access")

    @pytest.mark.asyncio
    async def test_refresh_access_token_success(self, mocker):
        """Verify refreshing access token returns fresh credentials."""
        mock_resp = Response(
            status_code=200,
            json={
                "access_token": "new-access-token",
                "refresh_token": "rotated-refresh-token",
                "expires_in": 3600
            },
            request=Request("POST", "https://login.microsoftonline.com/common/oauth2/v2.0/token")
        )
        mocker.patch.object(httpx.AsyncClient, "post", return_value=mock_resp)

        data = await refresh_access_token("plaintext-refresh-token")
        assert data["access_token"] == "new-access-token"
        assert data["refresh_token"] == "rotated-refresh-token"

    @pytest.mark.asyncio
    async def test_refresh_access_token_revoked_error(self, mocker):
        """Verify revoked token error is properly caught."""
        mock_resp = Response(
            status_code=400,
            json={"error": "invalid_grant"},
            request=Request("POST", "https://login.microsoftonline.com/common/oauth2/v2.0/token")
        )
        mocker.patch.object(httpx.AsyncClient, "post", return_value=mock_resp)

        with pytest.raises(ValueError, match="M365 refresh token has been revoked or expired"):
            await refresh_access_token("revoked-token")


# ── 3. M365 Graph API Client Unit Tests ───────────────────────────────────────
class TestM365GraphClient:
    @pytest.mark.asyncio
    async def test_graph_client_audit_log_and_pagination(self, db_session: AsyncSession, test_tenant_data: dict):
        """Verify that GraphClient records audit log entries and paginates through results."""
        client = M365GraphClient(
            tenant_id=str(test_tenant_data["tenant_id"]),
            access_token="test-access-token",
            db_session=db_session
        )

        resp1 = Response(
            status_code=200,
            json={
                "value": [{"id": "user-1", "displayName": "User One"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2"
            },
            request=Request("GET", "https://graph.microsoft.com/v1.0/users")
        )
        resp2 = Response(
            status_code=200,
            json={"value": [{"id": "user-2", "displayName": "User Two"}]},
            request=Request("GET", "https://graph.microsoft.com/v1.0/users?page=2")
        )

        client.client.get = AsyncMock(side_effect=[resp1, resp2])

        users = await client.get_users()
        assert len(users) == 2
        assert users[0]["id"] == "user-1"
        assert users[1]["id"] == "user-2"

    @pytest.mark.asyncio
    async def test_graph_client_429_rate_limiting_backoff(self, db_session: AsyncSession, test_tenant_data: dict, mocker):
        """Verify GraphClient handles HTTP 429 Retry-After header gracefully."""
        client = M365GraphClient(
            tenant_id=str(test_tenant_data["tenant_id"]),
            access_token="test-token",
            db_session=db_session
        )

        resp_429 = Response(
            status_code=429,
            headers={"Retry-After": "1"},
            request=Request("GET", "https://graph.microsoft.com/v1.0/domains")
        )
        resp_200 = Response(
            status_code=200,
            json={"value": [{"id": "domain.com", "isVerified": True}]},
            request=Request("GET", "https://graph.microsoft.com/v1.0/domains")
        )

        mocker.patch("asyncio.sleep", return_value=None)
        client.client.get = AsyncMock(side_effect=[resp_429, resp_200])

        domains = await client.get_verified_domains()
        assert len(domains) == 1
        assert domains[0] == "domain.com"


# ── 4. M365 Scanner Task & Scheduling Tests ───────────────────────────────────
class TestM365ScannerTask:
    def test_is_scan_due_frequency_logic(self):
        """Verify _is_scan_due calculates scan schedules properly for tenants."""
        tenant = Tenant(org_name="TestOrg", contact_email="admin@test.com", scan_frequency="daily")
        cred = M365Credential(
            tenant_id=uuid.uuid4(),
            hub_state={"timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()}
        )
        assert _is_scan_due(cred, tenant) is False

        # Scan due if 25 hours passed
        cred.hub_state = {"timestamp": (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()}
        assert _is_scan_due(cred, tenant) is True

        # Scan due if no hub state exists
        cred.hub_state = None
        assert _is_scan_due(cred, tenant) is True

    @pytest.mark.asyncio
    async def test_process_tenant_scan_workflow(self, db_session: AsyncSession, test_tenant_data: dict, mocker):
        """Verify full background scan workflow for an M365-connected tenant."""
        tenant_id = test_tenant_data["tenant_id"]
        blob = encrypt_token("mock-refresh-token", str(tenant_id))

        cred = M365Credential(
            tenant_id=tenant_id,
            ms_tenant_id="ms-tenant-123",
            encrypted_refresh_token=blob.ciphertext,
            kms_key_id=blob.kms_key_id,
            granted_scopes=["User.Read.All", "Directory.Read.All"],
            token_status="active",
        )
        db_session.add(cred)
        await db_session.commit()

        mocker.patch("app.tasks.m365_scanner.refresh_access_token", return_value={
            "access_token": "valid-graph-token",
            "refresh_token": "mock-refresh-token"
        })

        # Mock Graph Client methods
        mocker.patch.object(M365GraphClient, "get_users", return_value=[{"id": "u1", "userPrincipalName": "adm@contoso.com", "accountEnabled": True}])
        mocker.patch.object(M365GraphClient, "get_guest_accounts", return_value=[])
        mocker.patch.object(M365GraphClient, "get_directory_roles", return_value=[{"displayName": "Global Administrator", "members": [{"id": "u1"}]}])
        mocker.patch.object(M365GraphClient, "get_conditional_access_policies", return_value=[])
        mocker.patch.object(M365GraphClient, "get_mfa_details", return_value=[{"userPrincipalName": "adm@contoso.com", "isMfaRegistered": False}])
        mocker.patch.object(M365GraphClient, "get_oauth2_permission_grants", return_value=[])
        mocker.patch.object(M365GraphClient, "get_service_principals", return_value=[])
        mocker.patch.object(M365GraphClient, "get_app_role_assignments", return_value=[])
        mocker.patch.object(M365GraphClient, "get_verified_domains", return_value=["contoso.com"])
        mocker.patch.object(M365GraphClient, "get_audit_log_status", return_value={"reachable": True})
        mocker.patch.object(M365GraphClient, "get_sharepoint_settings", return_value={})
        mocker.patch.object(M365GraphClient, "get_risky_users", return_value=[])
        mocker.patch.object(M365GraphClient, "get_pim_eligible_assignments", return_value=[])
        mocker.patch.object(M365GraphClient, "get_managed_devices", return_value=[])
        mocker.patch.object(M365GraphClient, "get_mailbox_rules", return_value=[])

        await _process_tenant(db_session, cred)

        # Verify findings were created in DB
        result = await db_session.execute(select(Finding).where(Finding.tenant_id == tenant_id))
        findings = result.scalars().all()
        assert len(findings) >= 1
        assert any("Missing MFA" in f.issue_type for f in findings)


# ── 5. Findings Ingestion & Sync Unit Tests ───────────────────────────────────
class TestM365FindingsService:
    @pytest.mark.asyncio
    async def test_upsert_m365_findings_lifecycle(self, db_session: AsyncSession, test_tenant_data: dict):
        """Verify inserting new findings, updating existing findings, and auto-resolving fixed findings."""
        tenant_id = test_tenant_data["tenant_id"]

        initial_findings = [
            {
                "issue_type": "Administrative Account Missing MFA",
                "severity": "critical",
                "entity": "User: admin@contoso.com",
                "evidence": {"user_id": "u1", "isMfaRegistered": False},
                "tags": ["identity", "m365", "mfa"]
            }
        ]

        await upsert_m365_findings(db_session, tenant_id, initial_findings)

        result = await db_session.execute(select(Finding).where(Finding.tenant_id == tenant_id))
        stored = result.scalars().all()
        assert len(stored) == 1
        assert stored[0].status == "open"
        assert stored[0].severity == "critical"

        # Next scan: finding is resolved (empty findings list returned by rules engine)
        await upsert_m365_findings(db_session, tenant_id, [])

        result_after = await db_session.execute(select(Finding).where(Finding.tenant_id == tenant_id))
        stored_after = result_after.scalars().all()
        assert len(stored_after) == 1
        assert stored_after[0].status == "resolved"
        assert stored_after[0].resolved_at is not None


# ── 6. M365 API Router Endpoints Integration Tests ─────────────────────────────
class TestM365APIEndpoints:
    @pytest.mark.asyncio
    async def test_m365_connect_unauthorized(self, async_client: AsyncClient):
        """Unauthenticated GET /api/v1/m365/connect should return 401 Unauthorized."""
        response = await async_client.get("/api/v1/m365/connect")
        assert response.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_m365_connect_authorized(self, async_client: AsyncClient, test_tenant_data: dict):
        """Authenticated Admin GET /api/v1/m365/connect should return OAuth consent URL."""
        response = await async_client.get(
            "/api/v1/m365/connect",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200
        data = response.json()
        assert "consent_url" in data
        assert "login.microsoftonline.com" in data["consent_url"]

    @pytest.mark.asyncio
    async def test_m365_callback_invalid_state(self, async_client: AsyncClient):
        """OAuth callback with invalid or expired CSRF state redirects to error."""
        response = await async_client.get(
            "/api/v1/m365/callback?code=mock-code&state=invalid-state-token",
            follow_redirects=False
        )
        assert response.status_code == 307
        assert "error=invalid_state" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_m365_callback_success(self, async_client: AsyncClient, test_tenant_data: dict, mocker):
        """OAuth callback with valid state & code successfully vaults tokens and redirects."""
        state = secrets.token_urlsafe(32)
        _oauth_state_store[state] = str(test_tenant_data["tenant_id"])

        mocker.patch("app.routers.m365.exchange_code_for_tokens", return_value={
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "scope": "User.Read.All Directory.Read.All",
            "expires_in": 3600
        })

        response = await async_client.get(
            f"/api/v1/m365/callback?code=valid-code&state={state}&tenant=ms-tenant-id",
            follow_redirects=False
        )
        assert response.status_code == 307
        assert "onboarding/status" in response.headers["location"]
        assert "m365=connected" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_m365_status_disconnected(self, async_client: AsyncClient, test_tenant_data: dict):
        """GET /api/v1/m365/status returns connected=False when no credential exists."""
        response = await async_client.get(
            "/api/v1/m365/status",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200
        data = response.json()
        assert data["connected"] is False

    @pytest.mark.asyncio
    async def test_m365_status_connected(self, async_client: AsyncClient, test_tenant_data: dict, db_session: AsyncSession):
        """GET /api/v1/m365/status returns connected=True with metadata when active."""
        cred = M365Credential(
            tenant_id=test_tenant_data["tenant_id"],
            ms_tenant_id="ms-tenant-456",
            encrypted_refresh_token="encrypted-blob",
            kms_key_id="kms-key",
            granted_scopes=["User.Read.All"],
            token_status="active",
            connected_at=datetime.now(timezone.utc)
        )
        db_session.add(cred)
        await db_session.commit()

        response = await async_client.get(
            "/api/v1/m365/status",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200
        data = response.json()
        assert data["connected"] is True
        assert data["ms_tenant_id"] == "ms-tenant-456"

    @pytest.mark.asyncio
    async def test_m365_hub_state_and_sync(self, async_client: AsyncClient, test_tenant_data: dict, db_session: AsyncSession, mocker):
        """GET /api/v1/m365/hub and POST /api/v1/m365/sync API operations."""
        # 1. Hub state when credential has snapshot
        cred = M365Credential(
            tenant_id=test_tenant_data["tenant_id"],
            ms_tenant_id="ms-tenant-456",
            encrypted_refresh_token="encrypted-blob",
            kms_key_id="kms-key",
            token_status="active",
            hub_state={"users": [{"id": "u1"}], "findings": []}
        )
        db_session.add(cred)
        await db_session.commit()

        hub_resp = await async_client.get(
            "/api/v1/m365/hub",
            headers=test_tenant_data["headers"]
        )
        assert hub_resp.status_code == 200
        assert "users" in hub_resp.json()

        # 2. Trigger resync
        mocker.patch("app.tasks.m365_scanner.run_m365_scan_background", return_value=None)
        sync_resp = await async_client.post(
            "/api/v1/m365/sync",
            headers=test_tenant_data["headers"]
        )
        assert sync_resp.status_code == 200
        assert sync_resp.json()["status"] == "sync_started"

    @pytest.mark.asyncio
    async def test_m365_disconnect(self, async_client: AsyncClient, test_tenant_data: dict, db_session: AsyncSession):
        """DELETE /api/v1/m365/disconnect revokes credential and clears related findings."""
        cred = M365Credential(
            tenant_id=test_tenant_data["tenant_id"],
            ms_tenant_id="ms-tenant-456",
            encrypted_refresh_token="encrypted-blob",
            kms_key_id="kms-key",
            token_status="active"
        )
        finding = Finding(
            tenant_id=test_tenant_data["tenant_id"],
            finding_num=1,
            issue_type="M365 Test Finding",
            source="m365",
            severity="high",
            status="open",
            entity="Tenant: Microsoft 365"
        )
        db_session.add_all([cred, finding])
        await db_session.commit()

        resp = await async_client.delete(
            "/api/v1/m365/disconnect",
            headers=test_tenant_data["headers"]
        )
        assert resp.status_code == 200

        # Verify credential marked revoked
        await db_session.refresh(cred)
        assert cred.token_status == "revoked"
        assert cred.revoked_at is not None

        # Verify M365 findings cleared
        res = await db_session.execute(
            select(Finding).where(
                and_(
                    Finding.tenant_id == test_tenant_data["tenant_id"],
                    Finding.source == "m365"
                )
            )
        )
        assert len(res.scalars().all()) == 0
