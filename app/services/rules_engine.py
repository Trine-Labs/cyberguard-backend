"""
CyberGuard — M365 Deterministic Detection Rules Engine

Each rule is a pure function:
  Input  → structured data from Graph API
  Output → list of finding dicts (empty = no finding)

Findings dict shape:
  issue_type: str   — human label, stable across scans
  severity:   str   — critical | high | medium | low | info  (set by spec, not invented)
  entity:     str   — affected object (e.g. "User: admin@contoso.com")
  evidence:   dict  — raw supporting data
  tags:       list  — search/filter labels
"""
from typing import List, Dict, Any, Set
from datetime import datetime, timezone

from app.schemas.m365_payloads import OAuth2PermissionGrant, ServicePrincipal

# ─── Constants ────────────────────────────────────────────────────────────────

# Delegated scopes that are dangerous when granted to third-party apps
RISKY_DELEGATED_SCOPES: Set[str] = {
    "Mail.Read", "Mail.ReadWrite",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "Files.Read.All", "Files.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
}

# Application-level roles that are dangerous when granted to background apps
RISKY_APP_ROLES: Set[str] = {
    "Mail.Read", "Mail.ReadWrite", "Mail.ReadBasic.All",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "Files.Read.All", "Files.ReadWrite.All",
    "RoleManagement.Read.Directory", "RoleManagement.ReadWrite.Directory",
    "User.Read.All", "User.ReadWrite.All",
    "AuditLog.Read.All", "SecurityEvents.Read.All",
    "Calendars.Read",
}

# Tracked privileged roles (subset from spec)
TRACKED_ADMIN_ROLES = {
    "Global Administrator", "Privileged Role Administrator",
    "Exchange Administrator", "SharePoint Administrator",
    "User Administrator", "Security Administrator",
    "Conditional Access Administrator", "Application Administrator",
    "Cloud Application Administrator",
}

DORMANT_THRESHOLD_DAYS = 90


# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_admin_user_ids(directory_roles: List[Dict[str, Any]]) -> Set[str]:
    """Return set of user IDs that hold any tracked privileged role."""
    admin_ids: Set[str] = set()
    for role in directory_roles:
        name = role.get("displayName", "")
        if name in TRACKED_ADMIN_ROLES or "Administrator" in name:
            for member in role.get("members", []):
                admin_ids.add(member.get("id"))
    return admin_ids


def _days_since(dt_str: str | None) -> int | None:
    """Return days elapsed since a UTC ISO timestamp, or None if no timestamp."""
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


# ─── Rule: SSPM-001 Admin Missing MFA ─────────────────────────────────────────

def check_admin_missing_mfa(
    users: List[Dict[str, Any]],
    directory_roles: List[Dict[str, Any]],
    mfa_details: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """SSPM-001 Critical — Admin account has zero MFA methods registered."""
    findings = []
    if not mfa_details:
        return findings

    admin_ids = get_admin_user_ids(directory_roles)
    mfa_map = {m.get("userPrincipalName"): m for m in mfa_details}

    for user in users:
        if user.get("id") not in admin_ids:
            continue
        upn = user.get("userPrincipalName")
        mfa = mfa_map.get(upn, {})
        if not mfa.get("isMfaRegistered", False):
            findings.append({
                "issue_type": "Administrative Account Missing MFA",
                "severity": "critical",
                "entity": f"User: {upn}",
                "evidence": {
                    "user_id": user.get("id"),
                    "isMfaRegistered": False,
                    "methodsRegistered": mfa.get("methodsRegistered", []),
                },
                "tags": ["identity", "m365", "mfa", "admin"],
            })
    return findings


# ─── Rule: SSPM-002 External Mailbox Forwarding ───────────────────────────────

def check_malicious_forwarding(
    mailbox_rules: List[Dict[str, Any]],
    verified_domains: List[str],
) -> List[Dict[str, Any]]:
    """SSPM-002 Critical — Inbox rule forwards mail to an external (non-tenant) domain."""
    findings = []
    verified_lower = {d.lower() for d in verified_domains}

    for mbx in mailbox_rules:
        upn = mbx.get("upn")
        for rule in mbx.get("rules", []):
            actions = rule.get("actions", {})
            forward_to = actions.get("forwardTo", [])
            redirect_to = actions.get("redirectTo", [])

            suspect_emails = []
            for recipient in forward_to + redirect_to:
                email = recipient.get("emailAddress", {}).get("address", "")
                if email:
                    domain = email.split("@")[-1].lower()
                    if domain not in verified_lower and "microsoft.com" not in domain:
                        suspect_emails.append(email)

            if suspect_emails:
                findings.append({
                    "issue_type": "Malicious Mailbox External Forwarding Rule",
                    "severity": "critical",
                    "entity": f"Mailbox: {upn}",
                    "evidence": {
                        "rule_name": rule.get("displayName"),
                        "rule_id": rule.get("id"),
                        "forwarding_to": suspect_emails,
                    },
                    "tags": ["identity", "m365", "bec", "exfiltration"],
                })
    return findings


# ─── Rule: SSPM-003 Admin Sprawl ──────────────────────────────────────────────

def check_admin_sprawl(directory_roles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SSPM-003 High — More than 5 Global Administrators assigned (violation of least privilege)."""
    findings = []
    for role in directory_roles:
        is_ga = (
            role.get("roleTemplateId") == "62e90394-69f5-4237-9190-012177145e10"
            or role.get("displayName") == "Global Administrator"
        )
        if is_ga:
            members = role.get("members", [])
            count = len(members)
            upns = [m.get("userPrincipalName") for m in members if "userPrincipalName" in m]
            if count > 5:
                findings.append({
                    "issue_type": "Administrative Role Account Sprawl",
                    "severity": "high",
                    "entity": "Tenant: Global Administrators",
                    "evidence": {"admin_count": count, "admin_users": upns},
                    "tags": ["identity", "m365", "admin", "privilege"],
                })
            break
    return findings


# ─── Rule: SSPM-004 CA Policy Inactive ────────────────────────────────────────

def check_inactive_ca_policies(ca_policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SSPM-004 High — A CA policy with MFA/admin in its name is disabled or in report-only mode."""
    findings = []
    for policy in ca_policies:
        name = policy.get("displayName", "").lower()
        state = policy.get("state", "disabled")
        if ("mfa" in name or "admin" in name or "baseline" in name) and state != "enabled":
            findings.append({
                "issue_type": "Critical Conditional Access Policy Inactive",
                "severity": "high",
                "entity": f"Policy: {policy.get('displayName')}",
                "evidence": {"policy_id": policy.get("id"), "state": state},
                "tags": ["identity", "m365", "conditional-access"],
            })
    return findings


# ─── Rule: SSPM-004b CA Policy MFA Exclusion Bypass ──────────────────────────

def check_ca_mfa_exclusion_bypass(ca_policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    SSPM-004b High — An ENABLED CA policy that requires MFA has user/group/role exclusions.
    Exclusions are the most common way MFA enforcement gets silently bypassed in real tenants.
    """
    findings = []
    for policy in ca_policies:
        if policy.get("state") != "enabled":
            continue

        # Check if policy grants controls include MFA requirement
        grant_controls = policy.get("grantControls") or {}
        built_in = grant_controls.get("builtInControls", [])
        if "mfa" not in built_in:
            continue

        # Check for exclusions
        conditions = policy.get("conditions") or {}
        users_condition = conditions.get("users") or {}
        exclude_users = users_condition.get("excludeUsers", [])
        exclude_groups = users_condition.get("excludeGroups", [])
        exclude_roles = users_condition.get("excludeRoles", [])

        total_exclusions = len(exclude_users) + len(exclude_groups) + len(exclude_roles)
        if total_exclusions > 0:
            findings.append({
                "issue_type": "Conditional Access MFA Policy Has Exclusions (Bypass Risk)",
                "severity": "high",
                "entity": f"Policy: {policy.get('displayName')}",
                "evidence": {
                    "policy_id": policy.get("id"),
                    "excluded_users_count": len(exclude_users),
                    "excluded_groups_count": len(exclude_groups),
                    "excluded_roles_count": len(exclude_roles),
                    "excluded_user_ids": exclude_users[:10],  # cap for storage
                },
                "tags": ["identity", "m365", "conditional-access", "mfa-bypass"],
            })
    return findings


# ─── Rule: SSPM-005 Illicit Delegated OAuth Consent ──────────────────────────

def check_illicit_consent_grants(
    grants: List[Dict[str, Any]],
    service_principals: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """SSPM-005 High — Third-party app has been granted high-privilege delegated scopes."""
    sp_map = {sp["id"]: sp for sp in service_principals}
    findings = []

    grants_by_sp: Dict[str, list] = {}
    for raw_grant in grants:
        try:
            grant = OAuth2PermissionGrant(**raw_grant)
        except Exception:
            continue
        grants_by_sp.setdefault(grant.clientId, []).append(grant)

    for client_id, sp_grants in grants_by_sp.items():
        all_scopes: Set[str] = set()
        consent_types: Set[str] = set()
        grant_ids = []
        for grant in sp_grants:
            all_scopes.update(grant.scope.split())
            consent_types.add(grant.consentType)
            grant_ids.append(grant.id)

        matched_risky = all_scopes.intersection(RISKY_DELEGATED_SCOPES)
        if matched_risky or "AllPrincipals" in consent_types:
            sp_raw = sp_map.get(client_id, {})
            try:
                sp = ServicePrincipal(**sp_raw) if sp_raw else None
                sp_name = sp.displayName if sp else client_id
            except Exception:
                sp_name = client_id

            findings.append({
                "issue_type": "High-Privilege Illicit OAuth App Grant",
                "severity": "high",
                "entity": f"App: {sp_name}",
                "evidence": {
                    "risky_scopes": list(matched_risky),
                    "all_scopes": list(all_scopes),
                    "consentTypes": list(consent_types),
                    "grant_ids": grant_ids,
                },
                "tags": ["identity", "m365", "consent", "oauth"],
            })
    return findings


# ─── Rule: SSPM-005b Risky Application-Level Permissions ─────────────────────

def check_risky_app_role_assignments(
    app_role_assignments: List[Dict[str, Any]],
    service_principals: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    SSPM-005b High — An app has been granted application-level (non-delegated) permissions
    that allow tenant-wide access with no user sign-in required.
    These are higher-risk than delegated grants — the app can operate silently in the background.
    """
    findings = []

    # Build a map of appRoleId → role name from service principals' app roles
    # We'll resolve role names from well-known Microsoft Graph resource SP
    sp_role_map: Dict[str, str] = {}
    for sp in service_principals:
        sp_display = sp.get("displayName", "")
        if "Microsoft Graph" in sp_display or "Office 365" in sp_display:
            for role in sp.get("appRoles", []):
                sp_role_map[role.get("id", "")] = role.get("value", role.get("displayName", ""))

    # Group assignments by principal app
    by_principal: Dict[str, list] = {}
    for assignment in app_role_assignments:
        pid = assignment.get("principalId", "unknown")
        by_principal.setdefault(pid, []).append(assignment)

    for principal_id, assignments in by_principal.items():
        risky_roles = []
        app_name = assignments[0].get("principalDisplayName", principal_id)
        publisher = assignments[0].get("publisherName", "Unknown")

        for a in assignments:
            role_id = a.get("appRoleId", "")
            role_name = sp_role_map.get(role_id, role_id)
            if role_name in RISKY_APP_ROLES:
                risky_roles.append(role_name)

        if risky_roles:
            findings.append({
                "issue_type": "High-Privilege Application Permission Granted (Non-Delegated)",
                "severity": "high",
                "entity": f"App: {app_name}",
                "evidence": {
                    "principal_id": principal_id,
                    "publisher": publisher,
                    "risky_roles": risky_roles,
                    "total_assignments": len(assignments),
                },
                "tags": ["identity", "m365", "app-permissions", "oauth"],
            })
    return findings


# ─── Rule: SSPM-006 Dormant Admin Account ────────────────────────────────────

def check_stale_dormant_admin(
    users: List[Dict[str, Any]],
    directory_roles: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """SSPM-006 Medium — Enabled admin account has not signed in for 90+ days."""
    findings = []
    admin_ids = get_admin_user_ids(directory_roles)

    for user in users:
        if user.get("id") not in admin_ids:
            continue
        if not user.get("accountEnabled", True):
            continue

        sign_in_activity = user.get("signInActivity") or {}
        last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
        days = _days_since(last_sign_in_str)

        is_stale = days is None or days > DORMANT_THRESHOLD_DAYS

        if is_stale:
            upn = user.get("userPrincipalName")
            findings.append({
                "issue_type": "Stale Dormant Administrator Profile",
                "severity": "medium",
                "entity": f"User: {upn}",
                "evidence": {
                    "user_id": user.get("id"),
                    "days_inactive": "Never logged in" if days is None else days,
                    "accountEnabled": True,
                },
                "tags": ["identity", "m365", "stale", "admin"],
            })
    return findings


# ─── Rule: SSPM-007 Weak MFA Method ──────────────────────────────────────────

def check_weak_mfa(
    users: List[Dict[str, Any]],
    mfa_details: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """SSPM-007 Medium — User has MFA but only weak methods (SMS/email/voice) registered."""
    findings = []
    if not mfa_details:
        return findings

    mfa_map = {m.get("userPrincipalName"): m for m in mfa_details}
    strong_methods = {"microsoftAuthenticatorPush", "fido2", "windowsHelloForBusiness", "softwareOneTimePasscode"}
    weak_methods = {"mobilePhone", "email", "voice"}

    for user in users:
        upn = user.get("userPrincipalName")
        mfa = mfa_map.get(upn, {})
        if not mfa.get("isMfaRegistered", False):
            continue

        registered = set(mfa.get("methodsRegistered", []))
        has_strong = bool(registered & strong_methods)
        has_weak = bool(registered & weak_methods)

        if has_weak and not has_strong:
            findings.append({
                "issue_type": "Weak Insecure MFA Factor Method Configured",
                "severity": "medium",
                "entity": f"User: {upn}",
                "evidence": {
                    "user_id": user.get("id"),
                    "methodsRegistered": list(registered),
                    "weak_methods_active": list(registered & weak_methods),
                },
                "tags": ["identity", "m365", "mfa", "weak-auth"],
            })
    return findings


# ─── Rule: SSPM-008 Standard User No MFA ─────────────────────────────────────

def check_standard_user_no_mfa(
    users: List[Dict[str, Any]],
    directory_roles: List[Dict[str, Any]],
    mfa_details: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """SSPM-008 Medium — Standard (non-admin) enabled user has no MFA registered."""
    findings = []
    if not mfa_details:
        return findings

    admin_ids = get_admin_user_ids(directory_roles)
    mfa_map = {m.get("userPrincipalName"): m for m in mfa_details}

    for user in users:
        if user.get("id") in admin_ids:
            continue  # Admins covered by SSPM-001
        if not user.get("accountEnabled", True):
            continue

        upn = user.get("userPrincipalName")
        mfa = mfa_map.get(upn, {})
        if not mfa.get("isMfaRegistered", False):
            findings.append({
                "issue_type": "Standard User Account Missing MFA",
                "severity": "medium",
                "entity": f"User: {upn}",
                "evidence": {
                    "user_id": user.get("id"),
                    "isMfaRegistered": False,
                    "methodsRegistered": [],
                },
                "tags": ["identity", "m365", "mfa", "user"],
            })
    return findings


# ─── Rule: SSPM-009 Dormant Guest Account ────────────────────────────────────

def check_dormant_guests(guest_accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    SSPM-009 Medium — Guest account has not signed in for 90+ days.
    Inactive guests are a common forgotten attack surface — they retain access
    but are often invisible in regular user reviews.
    """
    findings = []
    for guest in guest_accounts:
        if not guest.get("accountEnabled", True):
            continue

        sign_in_activity = guest.get("signInActivity") or {}
        last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
        days = _days_since(last_sign_in_str)

        is_stale = days is None or days > DORMANT_THRESHOLD_DAYS

        if is_stale:
            upn = guest.get("userPrincipalName")
            findings.append({
                "issue_type": "Dormant Guest Account with Active Access",
                "severity": "medium",
                "entity": f"Guest: {upn}",
                "evidence": {
                    "user_id": guest.get("id"),
                    "displayName": guest.get("displayName"),
                    "days_inactive": "Never logged in" if days is None else days,
                    "accountEnabled": True,
                },
                "tags": ["identity", "m365", "guest", "stale"],
            })
    return findings


# ─── Rule: SSPM-010 Audit Logging Unreachable ────────────────────────────────

def check_audit_log_status(audit_log_status: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    SSPM-010 High — Unified audit log endpoint is unreachable or returned no data.
    If audit logging is disabled, security incidents cannot be investigated retroactively.
    Critical for regulated sectors (banking, insurance, healthcare).
    """
    findings = []
    if not audit_log_status.get("reachable", True):
        findings.append({
            "issue_type": "Unified Audit Log Unreachable or Disabled",
            "severity": "high",
            "entity": "Tenant: Audit Configuration",
            "evidence": {
                "reachable": False,
                "detail": "The /auditLogs/directoryAudits endpoint returned an error. "
                          "This may indicate audit logging is disabled or the app lacks AuditLog.Read.All scope.",
            },
            "tags": ["identity", "m365", "audit-log", "compliance"],
        })
    return findings


# ─── Rule: SSPM-011 SharePoint Anonymous Sharing ─────────────────────────────

def check_sharepoint_sharing(sharepoint_settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    SSPM-011 — SharePoint/OneDrive tenant sharing configuration risks.
    
    Rule A (Critical): Anyone (anonymous) links enabled at tenant level.
      sharingCapability == "externalUserAndGuestSharing" means any file can be
      shared via a link that requires no sign-in — the broadest possible exposure.
    
    Rule B (High): Default sharing link type is anonymous.
      Even if tenant allows anonymous links, making them the DEFAULT massively
      increases accidental data leakage risk.
    
    Rule C (Medium): External user self-service sign-up enabled.
      Allows unknown external users to create guest accounts themselves.
    """
    findings = []
    if not sharepoint_settings:
        return findings

    sharing_cap = sharepoint_settings.get("sharingCapability", "")
    default_link = sharepoint_settings.get("defaultSharingLinkType", "")
    self_signup = sharepoint_settings.get("isExternalUserSelfServiceSignUpEnabled", False)

    # Rule A — anonymous links enabled at tenant level
    if sharing_cap == "externalUserAndGuestSharing":
        findings.append({
            "issue_type": "SharePoint Anonymous Link Sharing Enabled Tenant-Wide",
            "severity": "critical",
            "entity": "Tenant: SharePoint / OneDrive",
            "evidence": {
                "sharingCapability": sharing_cap,
                "risk": "Anyone can access files via anonymous links — no sign-in required.",
                "recommendation": "Set sharingCapability to externalUserSharingOnly or lower.",
            },
            "tags": ["m365", "sharepoint", "data-exposure", "compliance"],
        })

    # Rule B — anonymous default link type
    if default_link == "anonymous":
        findings.append({
            "issue_type": "SharePoint Default Share Link Type is Anonymous",
            "severity": "high",
            "entity": "Tenant: SharePoint / OneDrive",
            "evidence": {
                "defaultSharingLinkType": default_link,
                "risk": "When users share files, anonymous links are generated by default.",
                "recommendation": "Change defaultSharingLinkType to 'direct' or 'internal'.",
            },
            "tags": ["m365", "sharepoint", "data-exposure"],
        })

    # Rule C — external self-service sign-up
    if self_signup:
        findings.append({
            "issue_type": "SharePoint External User Self-Service Sign-Up Enabled",
            "severity": "medium",
            "entity": "Tenant: SharePoint / OneDrive",
            "evidence": {
                "isExternalUserSelfServiceSignUpEnabled": True,
                "risk": "External users can create guest accounts without admin approval.",
                "recommendation": "Disable isExternalUserSelfServiceSignUpEnabled.",
            },
            "tags": ["m365", "sharepoint", "guest-access"],
        })

    return findings


# ─── Rule: SSPM-012 Identity Protection Risky Users ──────────────────────────

def check_identity_protection_risky_users(risky_users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    SSPM-012 — Entra Identity Protection has flagged a user as actively at risk.
    
    Risk levels:
      high   → leaked credentials, confirmed compromise, impossible travel
      medium → anonymous IP, atypical location, password spray
      low    → unfamiliar sign-in properties
    
    All riskState==atRisk findings are actionable — they have NOT been dismissed.
    """
    findings = []
    sev_map = {"high": "critical", "medium": "high", "low": "medium"}

    for user in risky_users:
        risk_level = user.get("riskLevel", "low").lower()
        sev = sev_map.get(risk_level, "medium")
        upn = user.get("userPrincipalName", user.get("id"))
        last_updated = user.get("riskLastUpdatedDateTime", "")

        findings.append({
            "issue_type": "Identity Protection: User Account at Active Risk",
            "severity": sev,
            "entity": f"User: {upn}",
            "evidence": {
                "riskLevel": risk_level,
                "riskState": user.get("riskState"),
                "riskDetail": user.get("riskDetail", "unknown"),
                "riskLastUpdatedDateTime": last_updated,
                "displayName": user.get("displayName"),
            },
            "tags": ["identity", "m365", "identity-protection", "compromised"],
        })
    return findings


# ─── Rule: SSPM-013 PIM Eligible Admin Without Safeguards ────────────────────

# Sensitive role IDs (Global Admin + Privileged Role Admin)
SENSITIVE_ROLE_TEMPLATE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
}


def check_pim_eligible_admins(
    pim_assignments: List[Dict[str, Any]],
    directory_roles: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    SSPM-013 — PIM eligible assignments to sensitive roles.

    PIM eligibility is GOOD security practice — it is Microsoft's recommended
    alternative to permanent admin assignment. A user with an eligible assignment
    does NOT currently hold admin powers; they must explicitly activate the role
    (typically for 1-8 hours).

    WHY we still surface it:
      The risk is NOT the eligibility itself — it is the *activation policy*:
        - If activation requires MFA + approval → very low risk (best practice)
        - If activation requires neither → user can silently self-elevate in seconds
      We cannot read activation policy details from Graph API in a single call
      (requires GET /policies/roleManagementPolicies per role), so we surface the
      eligible assignments as MEDIUM visibility findings — operators should open
      PIM and verify that each assignment has:
        1. MFA required on activation
        2. Approval required (at least one approver)
        3. Maximum activation duration ≤ 8 hours

    Severity logic:
      - medium  → sensitive eligible assignment (operator should verify activation policy)
      - medium  → unusually high count of eligible assignments (sprawl)
      - We do NOT flag non-sensitive role eligibilities (e.g., Reports Reader, Teams Admin)
    """
    findings = []
    if not pim_assignments:
        return findings

    sensitive: List[Dict[str, Any]] = []
    for assignment in pim_assignments:
        role_def_id = assignment.get("roleDefinitionId", "")
        role_def    = assignment.get("roleDefinition") or {}
        role_name   = role_def.get("displayName", role_def_id)
        principal   = assignment.get("principal") or {}
        upn = principal.get("userPrincipalName",
              principal.get("displayName",
              assignment.get("principalId")))

        if role_def_id in SENSITIVE_ROLE_TEMPLATE_IDS:
            sensitive.append({
                "upn":           upn,
                "role":          role_name,
                "assignment_id": assignment.get("id"),
            })

    if not sensitive:
        return findings

    # One informational finding per sensitive eligible assignment
    for item in sensitive:
        findings.append({
            "issue_type": "PIM Eligible Assignment to Sensitive Role — Verify Activation Policy",
            "severity":   "medium",
            "entity":     f"User: {item['upn']}",
            "evidence": {
                "role":            item["role"],
                "assignment_type": "eligible (PIM — user does NOT currently hold this role)",
                "what_to_check":   (
                    "In Entra ID → PIM → Azure AD roles → [this role] → Settings, "
                    "verify: (1) MFA required on activation, "
                    "(2) Approval required with a named approver, "
                    "(3) Max activation duration ≤ 8 hours."
                ),
                "note": (
                    "PIM eligibility is best practice. This finding is informational — "
                    "CyberGuard cannot read activation policy details directly from Graph API. "
                    "Manually verify the activation safeguards are in place."
                ),
            },
            "tags": ["identity", "m365", "pim", "privileged-access"],
        })

    # Separate finding if the eligible count is large (sprawl is a risk even with good policies)
    if len(sensitive) > 5:
        findings.append({
            "issue_type": "Excessive PIM Eligible Assignments to Sensitive Roles",
            "severity":   "medium",
            "entity":     "Tenant: PIM Configuration",
            "evidence": {
                "sensitive_eligible_count": len(sensitive),
                "eligible_users": [s["upn"] for s in sensitive[:10]],
                "risk": (
                    "A large pool of eligible admins increases the blast radius if any "
                    "account is compromised. Reduce eligible assignments to the minimum "
                    "required operational set."
                ),
            },
            "tags": ["identity", "m365", "pim", "admin-sprawl"],
        })

    return findings



# ─── Runner ───────────────────────────────────────────────────────────────────

def run_all_rules(
    users: List[Dict[str, Any]],
    directory_roles: List[Dict[str, Any]],
    mfa_details: List[Dict[str, Any]],
    ca_policies: List[Dict[str, Any]],
    grants: List[Dict[str, Any]],
    service_principals: List[Dict[str, Any]],
    mailbox_rules: List[Dict[str, Any]],
    verified_domains: List[str],
    guest_accounts: List[Dict[str, Any]] = None,
    app_role_assignments: List[Dict[str, Any]] = None,
    audit_log_status: Dict[str, Any] = None,
    sharepoint_settings: Dict[str, Any] = None,
    risky_users: List[Dict[str, Any]] = None,
    pim_assignments: List[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Run all M365 detection rules and return a flat list of findings."""
    all_findings = []
    all_findings.extend(check_admin_missing_mfa(users, directory_roles, mfa_details))
    all_findings.extend(check_malicious_forwarding(mailbox_rules, verified_domains))
    all_findings.extend(check_admin_sprawl(directory_roles))
    all_findings.extend(check_inactive_ca_policies(ca_policies))
    all_findings.extend(check_ca_mfa_exclusion_bypass(ca_policies))
    all_findings.extend(check_illicit_consent_grants(grants, service_principals))
    all_findings.extend(check_risky_app_role_assignments(app_role_assignments or [], service_principals))
    all_findings.extend(check_stale_dormant_admin(users, directory_roles))
    all_findings.extend(check_weak_mfa(users, mfa_details))
    all_findings.extend(check_standard_user_no_mfa(users, directory_roles, mfa_details))
    all_findings.extend(check_dormant_guests(guest_accounts or []))
    all_findings.extend(check_audit_log_status(audit_log_status or {}))
    all_findings.extend(check_sharepoint_sharing(sharepoint_settings or {}))
    all_findings.extend(check_identity_protection_risky_users(risky_users or []))
    all_findings.extend(check_pim_eligible_admins(pim_assignments or [], directory_roles))
    return all_findings
