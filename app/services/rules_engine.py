"""M365 Rules Engine"""
from typing import List, Dict, Any
from app.schemas.m365_payloads import OAuth2PermissionGrant, ServicePrincipal

RISKY_SCOPES = {"Mail.Read", "Mail.ReadWrite", "Directory.Read.All", "Directory.ReadWrite.All", "Files.Read.All"}

def check_illicit_consent_grants(
    grants: List[Dict[str, Any]], 
    service_principals: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Evaluates OAuth2 permission grants against known risky scopes.
    Returns a list of dicts representing raw finding evidence.
    """
    sp_map = {sp["id"]: sp for sp in service_principals}
    findings = []
    
    for raw_grant in grants:
        grant = OAuth2PermissionGrant(**raw_grant)
        scopes = set(grant.scope.split())
        matched_risky = scopes.intersection(RISKY_SCOPES)
        
        if matched_risky:
            sp_raw = sp_map.get(grant.clientId, {})
            sp = ServicePrincipal(**sp_raw) if sp_raw else None
            sp_name = sp.displayName if sp else grant.clientId
            
            findings.append({
                "issue_type": "Illicit Consent Grant",
                "severity": "high",
                "entity": f"Service Principal: {sp_name}",
                "evidence": {
                    "risky_scopes": list(matched_risky),
                    "grant_id": grant.id,
                    "consentType": grant.consentType
                },
                "tags": ["identity", "m365", "consent", "oauth"]
            })
            
    return findings
