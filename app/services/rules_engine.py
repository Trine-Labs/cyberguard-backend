"""M365 Deterministic Findings Engine"""
from typing import List, Dict, Any
from datetime import datetime, timezone
from app.schemas.m365_payloads import OAuth2PermissionGrant, ServicePrincipal

RISKY_SCOPES = {"Mail.Read", "Mail.ReadWrite", "Directory.Read.All", "Directory.ReadWrite.All", "Files.Read.All", "RoleManagement.ReadWrite.Directory"}

def get_admin_user_ids(directory_roles: List[Dict[str, Any]]) -> set:
    admin_ids = set()
    for role in directory_roles:
        name = role.get("displayName", "")
        # Match tracking roles
        if "Administrator" in name or "Admin" in name:
            for member in role.get("members", []):
                admin_ids.add(member.get("id"))
    return admin_ids

def check_admin_missing_mfa(users: List[Dict[str, Any]], directory_roles: List[Dict[str, Any]], mfa_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # SSPM-001: Critical Severity
    findings = []
    if not mfa_details:
        return findings
        
    admin_ids = get_admin_user_ids(directory_roles)
    
    mfa_map = {m.get("userPrincipalName"): m for m in mfa_details}
    
    for user in users:
        if user.get("id") in admin_ids:
            upn = user.get("userPrincipalName")
            mfa = mfa_map.get(upn, {})
            is_mfa_registered = mfa.get("isMfaRegistered", False)
            if not is_mfa_registered:
                findings.append({
                    "issue_type": "Administrative Account Missing MFA",
                    "severity": "critical",
                    "entity": f"User: {upn}",
                    "evidence": {
                        "user_id": user.get("id"),
                        "roles": "Admin",
                        "isMfaRegistered": False
                    },
                    "tags": ["identity", "m365", "mfa", "admin"]
                })
    return findings

def check_malicious_forwarding(mailbox_rules: List[Dict[str, Any]], verified_domains: List[str]) -> List[Dict[str, Any]]:
    # SSPM-002: Critical Severity
    findings = []
    # mailbox_rules could be a list of { user_id, upn, rules: [] }
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
                    if domain not in verified_domains and "microsoft.com" not in domain:
                        suspect_emails.append(email)
                        
            if suspect_emails:
                findings.append({
                    "issue_type": "Malicious Mailbox External Forwarding Rule",
                    "severity": "critical",
                    "entity": f"Mailbox: {upn}",
                    "evidence": {
                        "rule_name": rule.get("displayName"),
                        "forwarding_to": suspect_emails
                    },
                    "tags": ["identity", "m365", "bec", "exfiltration"]
                })
    return findings

def check_admin_sprawl(directory_roles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # SSPM-003: High Severity
    findings = []
    ga_count = 0
    ga_members = []
    for role in directory_roles:
        if role.get("roleTemplateId") == "62e90394-69f5-4237-9190-012177145e10" or role.get("displayName") == "Global Administrator":
            members = role.get("members", [])
            ga_count = len(members)
            ga_members = [m.get("userPrincipalName") for m in members if "userPrincipalName" in m]
            break
            
    if ga_count > 5:
        findings.append({
            "issue_type": "Administrative Role Account Sprawl",
            "severity": "high",
            "entity": "Tenant: Global Administrators",
            "evidence": {
                "admin_count": ga_count,
                "admin_users": ga_members
            },
            "tags": ["identity", "m365", "admin", "privilege"]
        })
    return findings

def check_inactive_ca_policies(ca_policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # SSPM-004: High Severity
    findings = []
    for policy in ca_policies:
        name = policy.get("displayName", "").lower()
        state = policy.get("state", "disabled")
        
        if ("mfa" in name or "admin" in name or "baseline" in name) and state != "enabled":
            findings.append({
                "issue_type": "Critical Conditional Access Policy Inactive",
                "severity": "high",
                "entity": f"Policy: {policy.get('displayName')}",
                "evidence": {
                    "policy_id": policy.get("id"),
                    "state": state
                },
                "tags": ["identity", "m365", "conditional-access"]
            })
    return findings

def check_illicit_consent_grants(grants: List[Dict[str, Any]], service_principals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # SSPM-005: High Severity
    sp_map = {sp["id"]: sp for sp in service_principals}
    findings = []
    
    # Group grants by service principal to avoid duplicate findings
    grants_by_sp = {}
    for raw_grant in grants:
        grant = OAuth2PermissionGrant(**raw_grant)
        if grant.clientId not in grants_by_sp:
            grants_by_sp[grant.clientId] = []
        grants_by_sp[grant.clientId].append(grant)
        
    for client_id, sp_grants in grants_by_sp.items():
        all_scopes = set()
        consent_types = set()
        grant_ids = []
        for grant in sp_grants:
            all_scopes.update(grant.scope.split())
            consent_types.add(grant.consentType)
            grant_ids.append(grant.id)
            
        matched_risky = all_scopes.intersection(RISKY_SCOPES)
        
        if 'AllPrincipals' in consent_types or matched_risky:
            sp_raw = sp_map.get(client_id, {})
            sp = ServicePrincipal(**sp_raw) if sp_raw else None
            sp_name = sp.displayName if sp else client_id
            
            findings.append({
                "issue_type": "High-Privilege Illicit OAuth App Grant",
                "severity": "high",
                "entity": f"Service Principal: {sp_name}",
                "evidence": {
                    "risky_scopes": list(matched_risky),
                    "consentTypes": list(consent_types),
                    "grant_ids": grant_ids
                },
                "tags": ["identity", "m365", "consent", "oauth"]
            })
            
    return findings

def check_stale_dormant_admin(users: List[Dict[str, Any]], directory_roles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # SSPM-006: Medium Severity
    findings = []
    admin_ids = get_admin_user_ids(directory_roles)
    now = datetime.now(timezone.utc)
    
    for user in users:
        if user.get("id") in admin_ids and user.get("accountEnabled", True):
            sign_in_activity = user.get("signInActivity", {})
            last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
            
            is_stale = False
            days_inactive = -1
            if not last_sign_in_str:
                # Never logged in
                is_stale = True
            else:
                try:
                    last_sign_in = datetime.fromisoformat(last_sign_in_str.replace("Z", "+00:00"))
                    days_inactive = (now - last_sign_in).days
                    if days_inactive > 90:
                        is_stale = True
                except ValueError:
                    pass
            
            if is_stale:
                upn = user.get("userPrincipalName")
                findings.append({
                    "issue_type": "Stale Dormant Administrator Profile",
                    "severity": "medium",
                    "entity": f"User: {upn}",
                    "evidence": {
                        "user_id": user.get("id"),
                        "days_inactive": "Never logged in" if days_inactive == -1 else days_inactive,
                        "accountEnabled": True
                    },
                    "tags": ["identity", "m365", "stale", "admin"]
                })
    return findings

def check_weak_mfa(users: List[Dict[str, Any]], mfa_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # SSPM-007: Medium Severity
    findings = []
    if not mfa_details:
        return findings
    mfa_map = {m.get("userPrincipalName"): m for m in mfa_details}
    
    for user in users:
        upn = user.get("userPrincipalName")
        mfa = mfa_map.get(upn, {})
        is_mfa_registered = mfa.get("isMfaRegistered", False)
        auth_methods = mfa.get("methodsRegistered", [])
        
        # If registered, but only using weak methods
        if is_mfa_registered:
            # Check if they have strong methods
            has_strong_mfa = any(m in auth_methods for m in ["microsoftAuthenticatorPush", "fido2", "windowsHelloForBusiness", "softwareOneTimePasscode"])
            has_weak_mfa = any(m in auth_methods for m in ["mobilePhone", "email", "voice"])
            
            if has_weak_mfa and not has_strong_mfa:
                findings.append({
                    "issue_type": "Weak Insecure MFA Factor Method Configured",
                    "severity": "medium",
                    "entity": f"User: {user.get('userPrincipalName')}",
                    "evidence": {
                        "user_id": user.get("id"),
                        "methodsRegistered": auth_methods
                    },
                    "tags": ["identity", "m365", "mfa", "weak-auth"]
                })
    return findings

def run_all_rules(
    users: List[Dict[str, Any]],
    directory_roles: List[Dict[str, Any]],
    mfa_details: List[Dict[str, Any]],
    ca_policies: List[Dict[str, Any]],
    grants: List[Dict[str, Any]],
    service_principals: List[Dict[str, Any]],
    mailbox_rules: List[Dict[str, Any]],
    verified_domains: List[str]
) -> List[Dict[str, Any]]:
    all_findings = []
    all_findings.extend(check_admin_missing_mfa(users, directory_roles, mfa_details))
    all_findings.extend(check_malicious_forwarding(mailbox_rules, verified_domains))
    all_findings.extend(check_admin_sprawl(directory_roles))
    all_findings.extend(check_inactive_ca_policies(ca_policies))
    all_findings.extend(check_illicit_consent_grants(grants, service_principals))
    all_findings.extend(check_stale_dormant_admin(users, directory_roles))
    all_findings.extend(check_weak_mfa(users, mfa_details))
    return all_findings
