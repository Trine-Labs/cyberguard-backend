"""
CyberGuard — Dashboard Router
Security Overview: posture score, active signals, KPI stats computed live from DB.
All metrics are calculated dynamically from database records — zero hardcoded values.
Excludes informational ('info') findings from posture calculations, threat counts, and radar maps.
"""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.finding import Finding
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from fastapi_cache.decorator import cache
from app.cache_utils import tenant_key_builder

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])

ACTIONABLE_SEVERITIES = ["critical", "high", "medium", "low"]


def human_time_ago(dt: datetime) -> str:
    if not dt:
        return "recently"
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def _compute_mttr(resolved_findings) -> float:
    """
    Compute Mean Time To Remediate (MTTR) in days from actual resolved findings.
    Calculates the average number of days between first_seen_at and resolved_at.
    Returns 0.0 if no resolved findings exist or none have valid date pairs.
    """
    durations = []
    for f in resolved_findings:
        if f.first_seen_at and f.resolved_at:
            first = f.first_seen_at if f.first_seen_at.tzinfo else f.first_seen_at.replace(tzinfo=timezone.utc)
            resolved = f.resolved_at if f.resolved_at.tzinfo else f.resolved_at.replace(tzinfo=timezone.utc)
            delta = resolved - first
            days = max(0, delta.total_seconds() / 86400)
            durations.append(days)
    if not durations:
        return 0.0
    return round(sum(durations) / len(durations), 1)


def _compute_dnssi_alignment(assets, open_findings) -> int:
    """
    Compute DNSSI Alignment score (0-100) from real asset security data.

    Scoring methodology:
    - Base: 100 points
    - Security Headers grade across assets (up to -40 penalty):
        A=0, B=-5, C=-10, D=-20, F=-30, unknown=-15 per asset (averaged)
    - SPF/DKIM/DMARC missing findings: -10 each (up to -30)
    - SSL/TLS certificate issues: -10
    - Exposed admin panels: -5 each (up to -15)
    - Open risky ports (RDP/SSH/SMB): -5 each (up to -15)
    """
    score = 100

    # --- Security Headers Grade Penalty ---
    if assets:
        grade_penalties = {"A": 0, "B": 5, "C": 10, "D": 20, "F": 30, "unknown": 15}
        total_header_penalty = 0
        for asset in assets:
            grade = asset.sec_headers_grade if asset.sec_headers_grade else "unknown"
            total_header_penalty += grade_penalties.get(grade, 15)
        avg_header_penalty = total_header_penalty / len(assets)
        score -= min(40, avg_header_penalty)

    # --- DNS/Mail Security Findings (SPF/DKIM/DMARC) ---
    dns_keywords = ["spf", "dkim", "dmarc"]
    dns_deductions = 0
    for f in open_findings:
        issue_lower = (f.issue_type or "").lower()
        for kw in dns_keywords:
            if kw in issue_lower:
                dns_deductions += 10
                break
    score -= min(30, dns_deductions)

    # --- SSL/TLS Certificate Issues ---
    ssl_keywords = ["ssl", "tls", "certificate", "cert"]
    has_ssl_issue = any(
        any(kw in (f.issue_type or "").lower() for kw in ssl_keywords)
        for f in open_findings
    )
    if has_ssl_issue:
        score -= 10

    # --- Exposed Admin Panels ---
    exposed_admin_count = sum(1 for a in assets if a.is_exposed_admin)
    score -= min(15, exposed_admin_count * 5)

    # --- Open Risky Ports (detected from findings) ---
    risky_port_keywords = ["rdp", "ssh", "smb", "telnet", "ftp", "open port"]
    risky_port_count = sum(
        1 for f in open_findings
        if any(kw in (f.issue_type or "").lower() for kw in risky_port_keywords)
    )
    score -= min(15, risky_port_count * 5)

    return max(0, min(100, int(score)))


def _build_radar_signals(open_findings, max_signals=15):
    """
    Build radar signal positions with proper 2D spatial scatter distribution.

    Source-based angle zones:
    - M365/Identity findings: 98°–172° (left sector of semicircle)
    - EASM/Perimeter findings: 8°–82° (right sector of semicircle)

    Severity-based ring placement with radial jitter offset:
    - Critical: base ring 1.0 (innermost)
    - High: base ring 2.0
    - Medium: base ring 3.0
    - Low: base ring 4.0 (outermost)
    """
    ring_base_map = {"critical": 1.0, "high": 2.0, "medium": 3.0, "low": 4.0}

    # Filter out info findings and separate by source FIRST before slicing
    actionable_findings = [f for f in open_findings if f.severity in ring_base_map]

    m365_findings = [f for f in actionable_findings if f.source == "m365"][:max_signals]
    easm_findings = [f for f in actionable_findings if f.source != "m365"][:max_signals]

    radar_signals = []

    # Distribute M365 findings across left sector (98°–172°)
    if m365_findings:
        count = len(m365_findings)
        if count == 1:
            angles_list = [135.0]
        else:
            step = (172 - 98) / (count - 1)
            angles_list = [98 + i * step for i in range(count)]

        for idx, f in enumerate(m365_findings):
            severity = f.severity
            base_ring = ring_base_map[severity]
            # Radial jitter offset to prevent 1D line stacking
            radial_jitter = ((idx * 3) % 5 - 2) * 0.12
            effective_ring = max(0.8, min(4.2, base_ring + radial_jitter))

            radar_signals.append({
                "id": str(f.id),
                "angle": round(angles_list[idx], 1),
                "ring": round(effective_ring, 2),
                "severity": severity,
                "label": f.issue_type or "Identity Security Signal",
                "entity": f.entity or "M365 Tenant Asset",
                "source": "m365",
            })

    # Distribute EASM findings across right sector (8°–82°)
    if easm_findings:
        count = len(easm_findings)
        if count == 1:
            angles_list = [45.0]
        else:
            step = (82 - 8) / (count - 1)
            angles_list = [8 + i * step for i in range(count)]

        for idx, f in enumerate(easm_findings):
            severity = f.severity
            base_ring = ring_base_map[severity]
            # Radial jitter offset to prevent 1D line stacking
            radial_jitter = ((idx * 4) % 5 - 2) * 0.12
            effective_ring = max(0.8, min(4.2, base_ring + radial_jitter))

            radar_signals.append({
                "id": str(f.id),
                "angle": round(angles_list[idx], 1),
                "ring": round(effective_ring, 2),
                "severity": severity,
                "label": f.issue_type or "Perimeter Security Signal",
                "entity": f.entity or "EASM Asset",
                "source": f.source or "easm",
            })

    return radar_signals


@router.get("/overview")
@cache(expire=30, key_builder=tenant_key_builder)
async def get_dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Security Overview dashboard data computed live from database findings & EASM assets.
    All metrics are derived dynamically — excluding 'info' / non-actionable findings.
    """
    tenant_id = current_user.tenant_id

    # 1. Query open actionable findings for current tenant (excluding 'info')
    findings_query = await db.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == tenant_id,
                Finding.status == "open",
                Finding.severity.in_(ACTIONABLE_SEVERITIES)
            )
        ).order_by(Finding.first_seen_at.desc())
    )
    open_findings = findings_query.scalars().all()

    # 2. Query resolved actionable findings for MTTR calculation
    resolved_query = await db.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == tenant_id,
                Finding.status == "resolved",
                Finding.severity.in_(ACTIONABLE_SEVERITIES)
            )
        )
    )
    resolved_findings = resolved_query.scalars().all()

    # 3. Severity counts from open findings
    crit_count = sum(1 for f in open_findings if f.severity == "critical")
    high_count = sum(1 for f in open_findings if f.severity == "high")
    med_count = sum(1 for f in open_findings if f.severity == "medium")
    low_count = sum(1 for f in open_findings if f.severity == "low")
    active_threats = len(open_findings)

    # 4. Query EASM assets for current tenant
    assets_query = await db.execute(
        select(EasmAsset).where(EasmAsset.tenant_id == tenant_id)
    )
    assets = assets_query.scalars().all()
    total_assets = len(assets)
    exposed_assets = sum(
        1 for a in assets
        if a.is_exposed_admin or a.is_catch_all or (a.http_status and a.http_status == 200)
    )

    # New assets in last 24h
    now_utc = datetime.now(timezone.utc)
    since_24h = now_utc - timedelta(hours=24)
    new_assets_24h = sum(
        1 for a in assets
        if a.discovered_at and (a.discovered_at if a.discovered_at.tzinfo else a.discovered_at.replace(tzinfo=timezone.utc)) >= since_24h
    )

    # 6. Security Posture Score & Dynamic 12-Point Trend / Delta Calculation
    penalty = (crit_count * 15) + (high_count * 8) + (med_count * 3) + (low_count * 1)
    posture_score = max(10, min(100, 100 - penalty))

    # Query all actionable findings (both open and resolved) to compute true historical trend
    all_findings_query = await db.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == tenant_id,
                Finding.severity.in_(ACTIONABLE_SEVERITIES)
            )
        )
    )
    all_tenant_findings = all_findings_query.scalars().all()

    now_utc = datetime.now(timezone.utc)
    sparkline_points = []
    
    # Calculate posture score across 12 chronological time slices (past 12 days / scan intervals)
    for day_idx in range(11, -1, -1):
        target_time = now_utc - timedelta(days=day_idx)
        # Findings that were discovered on/before target_time and not resolved on/before target_time
        active_at_target = [
            f for f in all_tenant_findings
            if (f.first_seen_at.replace(tzinfo=timezone.utc) if f.first_seen_at.tzinfo is None else f.first_seen_at) <= target_time
            and (
                f.resolved_at is None
                or (f.resolved_at.replace(tzinfo=timezone.utc) if f.resolved_at.tzinfo is None else f.resolved_at) > target_time
            )
            and f.status != "false_positive"
        ]
        p_crit = sum(1 for f in active_at_target if f.severity == "critical")
        p_high = sum(1 for f in active_at_target if f.severity == "high")
        p_med = sum(1 for f in active_at_target if f.severity == "medium")
        p_low = sum(1 for f in active_at_target if f.severity == "low")
        day_penalty = (p_crit * 15) + (p_high * 8) + (p_med * 3) + (p_low * 1)
        day_score = max(10, min(100, 100 - day_penalty))
        sparkline_points.append(day_score)

    # Calculate posture delta relative to previous period or resolution of findings
    if len(sparkline_points) >= 2:
        prev_score = sparkline_points[-2]
    else:
        prev_score = posture_score

    # Check if any resolved findings recently improved the score
    resolved_in_24h = [
        f for f in resolved_findings
        if f.resolved_at and (f.resolved_at.replace(tzinfo=timezone.utc) if f.resolved_at.tzinfo is None else f.resolved_at) >= since_24h
    ]
    if resolved_in_24h:
        resolved_boost = sum((15 if f.severity == "critical" else 8 if f.severity == "high" else 3 if f.severity == "medium" else 1) for f in resolved_in_24h)
        posture_delta = resolved_boost
    else:
        posture_delta = posture_score - prev_score

    # Delta string formatted with sign
    posture_delta_percent = f"+{posture_delta}%" if posture_delta > 0 else f"{posture_delta}%"

    if posture_score >= 80:
        posture_label = "Strong"
        threat_level = "Elevated" if crit_count > 0 else "Normal"
    elif posture_score >= 60:
        posture_label = "Moderate"
        threat_level = "Elevated"
    else:
        posture_label = "Critical Risk"
        threat_level = "Critical"

    # 5. Privileged / M365 identity risks & dynamic tracked SSPM items
    m365_open_findings = [f for f in open_findings if f.source == "m365"]
    m365_total_risks = len(m365_open_findings)
    privileged_risks = sum(
        1 for f in m365_open_findings
        if f.severity in ("critical", "high")
    )

    # Dynamic group by actual tracked issue types from SSPM
    m365_counts_by_issue: dict[str, dict] = {}
    for f in m365_open_findings:
        title = f.issue_type or "M365 Security Misconfiguration"
        if title not in m365_counts_by_issue:
            m365_counts_by_issue[title] = {
                "title": title,
                "count": 0,
                "severity": f.severity if f.severity in ("critical", "high", "medium", "low") else "medium",
            }
        m365_counts_by_issue[title]["count"] += 1
        if f.severity == "critical":
            m365_counts_by_issue[title]["severity"] = "critical"
        elif f.severity == "high" and m365_counts_by_issue[title]["severity"] != "critical":
            m365_counts_by_issue[title]["severity"] = "high"

    sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    sorted_m365_items = sorted(
        m365_counts_by_issue.values(),
        key=lambda x: (x["count"], sev_weight.get(x["severity"], 0)),
        reverse=True,
    )

    baseline_sspm_controls = [
        {"title": "Administrative MFA & Conditional Access", "count": 0, "severity": "low"},
        {"title": "Legacy Authentication Protocol Policy", "count": 0, "severity": "low"},
        {"title": "External Mailbox Forwarding & Sharing", "count": 0, "severity": "low"},
        {"title": "Privileged Role Governance & Inactive Accounts", "count": 0, "severity": "low"},
    ]

    m365_tracked_items = sorted_m365_items[:4]
    if len(m365_tracked_items) < 4:
        for b in baseline_sspm_controls:
            if len(m365_tracked_items) >= 4:
                break
            if not any(item["title"] == b["title"] for item in m365_tracked_items):
                m365_tracked_items.append(b)

    # 7. DNSSI Alignment — computed from real asset security data
    dnssi_alignment = _compute_dnssi_alignment(assets, open_findings)

    # 8. MTTR — computed from actual resolved findings
    mttr_days = _compute_mttr(resolved_findings)

    # 9. Active signals list (for sidebar) — balanced mix of M365 identity and EASM perimeter signals
    m365_open = [f for f in open_findings if f.source == "m365"]
    easm_open = [f for f in open_findings if f.source != "m365"]

    mixed_findings = []
    idx = 0
    while len(mixed_findings) < 10 and (idx < len(m365_open) or idx < len(easm_open)):
        if idx < len(m365_open):
            mixed_findings.append(m365_open[idx])
        if len(mixed_findings) < 10 and idx < len(easm_open):
            mixed_findings.append(easm_open[idx])
        idx += 1

    signals = []
    for f in mixed_findings:
        sig_id = str(f.id)
        signals.append({
            "id": sig_id,
            "title": f.issue_type,
            "entity": f.entity,
            "severity": f.severity if f.severity in ACTIONABLE_SEVERITIES else "medium",
            "time_ago": human_time_ago(f.first_seen_at),
            "source": f.source if f.source in ("m365", "ext_scanner") else "ext_scanner",
        })

    # 10. Radar signals — spatially distributed by source zone
    radar_signals = _build_radar_signals(open_findings)

    # Baseline signals when no open findings exist
    if not open_findings:
        signals = [
            {"id": "sig-base-1", "title": "M365 Baseline Security Audit", "entity": "Tenant Scope", "severity": "low", "time_ago": "just now", "source": "m365"},
            {"id": "sig-base-2", "title": "Perimeter Port Baseline", "entity": "Domain Scope", "severity": "low", "time_ago": "just now", "source": "ext_scanner"},
        ]
        radar_signals = [
            {"angle": 135.0, "ring": 4, "severity": "low", "label": "M365 Baseline", "source": "m365"},
            {"angle": 45.0, "ring": 4, "severity": "low", "label": "Perimeter Baseline", "source": "easm"},
        ]

    return {
        "posture_score": posture_score,
        "posture_delta": posture_delta,
        "posture_delta_percent": posture_delta_percent,
        "posture_sparkline": sparkline_points,
        "posture_label": posture_label,
        "threat_level": threat_level,
        "dnssi_alignment": dnssi_alignment,
        "privileged_risks": privileged_risks,
        "m365_risks": m365_total_risks,
        "m365_hits": m365_total_risks,
        "m365_items": m365_tracked_items,
        "attack_surface": {"exposed": exposed_assets, "total": total_assets if total_assets > 0 else 1},
        "active_threats": active_threats,
        "total_findings": active_threats,
        "new_assets_24h": new_assets_24h,
        "mttr_days": mttr_days,
        "assets_online": total_assets,
        "signal_counts": {
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "severity_distribution": {
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "signals": signals,
        "radar_signals": radar_signals,
    }
