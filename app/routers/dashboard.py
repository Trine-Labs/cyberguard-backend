"""
CyberGuard — Dashboard Router
Security Overview: posture score, active signals, KPI stats.

Phase 1: Returns realistic hardcoded mock data.
Phase 2: Will query findings + easm_assets to compute live metrics.
"""
from fastapi import APIRouter, Depends
from app.dependencies import get_current_user
from app.models.user import User
from fastapi_cache.decorator import cache
from app.cache_utils import tenant_key_builder

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


# ---------------------------------------------------------------------------
# Hardcoded mock — matches the exact API response shape that live scanners
# will populate. Swapping to DB queries requires only replacing this dict.
# ---------------------------------------------------------------------------
MOCK_OVERVIEW = {
    "posture_score": 87,
    "posture_label": "Strong",
    "threat_level": "Elevated",
    "dnssi_alignment": 78,
    "privileged_risks": 6,
    "attack_surface": {"exposed": 24, "total": 123},
    "active_threats": 6,
    "new_assets_24h": 47,
    "mttr_days": 6.4,
    "assets_online": 124,
    "signal_counts": {"critical": 2, "high": 4, "medium": 2},
    "signals": [
        {
            "id": "sig-001",
            "title": "PIM Admin — No MFA",
            "entity": "breakglass@bank.ma",
            "severity": "critical",
            "time_ago": "2h ago",
            "source": "m365",
        },
        {
            "id": "sig-002",
            "title": "MySQL Port Exposed",
            "entity": "db-prod.bank.ma",
            "severity": "critical",
            "time_ago": "4h ago",
            "source": "ext_scanner",
        },
        {
            "id": "sig-003",
            "title": "External Mail Forward",
            "entity": "admin-sharepoint@bank.ma",
            "severity": "high",
            "time_ago": "8h ago",
            "source": "m365",
        },
        {
            "id": "sig-004",
            "title": "Apache RCE (CVE)",
            "entity": "dev.bank.ma",
            "severity": "high",
            "time_ago": "2d ago",
            "source": "ext_scanner",
        },
        {
            "id": "sig-005",
            "title": "DMARC Policy — None",
            "entity": "mail.bank.ma",
            "severity": "high",
            "time_ago": "14h ago",
            "source": "ext_scanner",
        },
        {
            "id": "sig-006",
            "title": "Risky OAuth Consent",
            "entity": "'E-Invoice Sync'",
            "severity": "medium",
            "time_ago": "1w ago",
            "source": "m365",
        },
        {
            "id": "sig-007",
            "title": "SSL Certificate Expired",
            "entity": "portal.bank.ma",
            "severity": "medium",
            "time_ago": "3d ago",
            "source": "ext_scanner",
        },
        {
            "id": "sig-008",
            "title": "Legacy Auth Enabled",
            "entity": "Exchange Online",
            "severity": "medium",
            "time_ago": "5d ago",
            "source": "m365",
        },
    ],
    # Radar threat signals — (angle_deg, ring 1-4, severity)
    # ring: 1=critical, 2=high, 3=medium, 4=low
    "radar_signals": [
        {"angle": 45,  "ring": 1, "severity": "critical", "label": "PIM Admin — No MFA"},
        {"angle": 155, "ring": 1, "severity": "critical", "label": "MySQL Port Exposed"},
        {"angle": 20,  "ring": 2, "severity": "high",     "label": "External Mail Forward"},
        {"angle": 100, "ring": 2, "severity": "high",     "label": "Apache RCE"},
        {"angle": 130, "ring": 2, "severity": "high",     "label": "DMARC None"},
        {"angle": 170, "ring": 2, "severity": "high",     "label": "Legacy Auth"},
        {"angle": 70,  "ring": 3, "severity": "medium",   "label": "Risky OAuth"},
        {"angle": 115, "ring": 3, "severity": "medium",   "label": "SSL Expired"},
    ],
}


@router.get("/overview")
@cache(expire=60, key_builder=tenant_key_builder)
async def get_dashboard_overview(
    current_user: User = Depends(get_current_user),
):
    """
    Security Overview dashboard data.
    Returns posture score, KPIs, threat signals, radar data.
    """
    return MOCK_OVERVIEW
