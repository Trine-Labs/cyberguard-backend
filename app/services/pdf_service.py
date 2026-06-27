"""
CyberGuard — Professional PDF Security Report Generator
Light theme, formal layout suitable for auditors and compliance officers.
"""
import io
from datetime import datetime, timezone
from typing import List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.colors import HexColor

# ── Professional Light Palette ─────────────────────────────────────────────────
WHITE        = HexColor("#FFFFFF")
PAGE_BG      = HexColor("#F8F9FB")
NAVY         = HexColor("#0F1F3D")      # headings, strong text
NAVY_MID     = HexColor("#1E3A5F")      # sub-headings
SLATE        = HexColor("#4A5568")      # body text
MUTED        = HexColor("#718096")      # labels, captions
BORDER_LIGHT = HexColor("#E2E8F0")
BORDER_MED   = HexColor("#CBD5E0")
ACCENT_BLUE  = HexColor("#2563EB")      # CyberGuard brand

# Severity colours (professional, not garish)
C_CRITICAL   = HexColor("#DC2626")
C_HIGH       = HexColor("#EA580C")
C_MEDIUM     = HexColor("#D97706")
C_LOW        = HexColor("#16A34A")
C_INFO       = HexColor("#2563EB")

# Severity left-border tints (very light)
T_CRITICAL   = HexColor("#FEF2F2")
T_HIGH       = HexColor("#FFF7ED")
T_MEDIUM     = HexColor("#FFFBEB")
T_LOW        = HexColor("#F0FDF4")
T_INFO       = HexColor("#EFF6FF")

SEV_COLOR = {
    "critical": (C_CRITICAL, T_CRITICAL),
    "high":     (C_HIGH,     T_HIGH),
    "medium":   (C_MEDIUM,   T_MEDIUM),
    "low":      (C_LOW,      T_LOW),
    "info":     (C_INFO,     T_INFO),
}

SRC_LABEL = {"m365": "SSPM · M365", "ext_scanner": "EASM · External"}
SRC_COLOR = {"m365": HexColor("#1D4ED8"), "ext_scanner": HexColor("#6D28D9")}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles():
    return {
        "cover_brand": ParagraphStyle(
            "cover_brand", fontSize=11, fontName="Helvetica-Bold",
            textColor=ACCENT_BLUE, letterSpacing=2, spaceAfter=2
        ),
        "cover_title": ParagraphStyle(
            "cover_title", fontSize=28, fontName="Helvetica-Bold",
            textColor=NAVY, leading=34, spaceAfter=8
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", fontSize=13, fontName="Helvetica",
            textColor=SLATE, spaceAfter=4
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", fontSize=9, fontName="Helvetica",
            textColor=MUTED, spaceAfter=2
        ),
        "section_label": ParagraphStyle(
            "section_label", fontSize=8, fontName="Helvetica-Bold",
            textColor=ACCENT_BLUE, spaceAfter=4, spaceBefore=18,
            letterSpacing=1.5,
        ),
        "section_title": ParagraphStyle(
            "section_title", fontSize=16, fontName="Helvetica-Bold",
            textColor=NAVY, spaceAfter=10, leading=20
        ),
        "subsection": ParagraphStyle(
            "subsection", fontSize=11, fontName="Helvetica-Bold",
            textColor=NAVY_MID, spaceAfter=6, spaceBefore=12
        ),
        "body": ParagraphStyle(
            "body", fontSize=9, fontName="Helvetica",
            textColor=SLATE, spaceAfter=4, leading=14
        ),
        "caption": ParagraphStyle(
            "caption", fontSize=8, fontName="Helvetica",
            textColor=MUTED, spaceAfter=2, leading=12
        ),
        "label": ParagraphStyle(
            "label", fontSize=7.5, fontName="Helvetica-Bold",
            textColor=MUTED, letterSpacing=0.5
        ),
        "mono": ParagraphStyle(
            "mono", fontSize=8, fontName="Courier",
            textColor=SLATE, spaceAfter=2, leading=12
        ),
        "tbl_header": ParagraphStyle(
            "tbl_header", fontSize=8, fontName="Helvetica-Bold",
            textColor=MUTED, letterSpacing=0.5
        ),
        "tbl_cell": ParagraphStyle(
            "tbl_cell", fontSize=8.5, fontName="Helvetica",
            textColor=SLATE, leading=12
        ),
        "tbl_cell_bold": ParagraphStyle(
            "tbl_cell_bold", fontSize=8.5, fontName="Helvetica-Bold",
            textColor=NAVY
        ),
        "finding_title": ParagraphStyle(
            "finding_title", fontSize=10, fontName="Helvetica-Bold",
            textColor=NAVY, spaceAfter=3, leading=14
        ),
        "finding_entity": ParagraphStyle(
            "finding_entity", fontSize=9, fontName="Helvetica",
            textColor=SLATE, spaceAfter=2
        ),
        "finding_evidence": ParagraphStyle(
            "finding_evidence", fontSize=8, fontName="Courier",
            textColor=SLATE, leading=12
        ),
    }


# ── Page template with header/footer ─────────────────────────────────────────

class _NumberedCanvas:
    """Adds page numbers and a footer line to every page."""

    def __init__(self, canvas, doc, org_name, ts):
        self.__dict__.update(canvas.__dict__)
        self._canvas = canvas
        self._doc = doc
        self._org_name = org_name
        self._ts = ts

    @staticmethod
    def _draw_footer(canvas, doc, org_name, ts, page_num):
        canvas.saveState()
        y = 12 * mm
        canvas.setStrokeColor(BORDER_LIGHT)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, y + 5 * mm, PAGE_W - MARGIN, y + 5 * mm)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, y + 2 * mm, f"CyberGuard Security Report — {org_name}")
        canvas.drawString(MARGIN, y - 1 * mm, f"Generated: {ts}  |  CONFIDENTIAL")
        canvas.drawRightString(PAGE_W - MARGIN, y + 0.5 * mm, f"Page {page_num}")
        canvas.restoreState()


def _make_first_page(canvas, doc, org_name, ts):
    """Cover page — no footer."""
    pass  # cover page is pure flowables


def _make_later_pages(canvas, doc, org_name, ts, page_fn):
    page_fn(canvas, doc, org_name, ts, canvas.getPageNumber())


# ── Stat box table ─────────────────────────────────────────────────────────────

def _stat_box(label: str, value: str, color: colors.Color = NAVY) -> Table:
    """A single KPI stat box."""
    tbl = Table([
        [Paragraph(str(value), ParagraphStyle(
            "stat_val", fontSize=22, fontName="Helvetica-Bold",
            textColor=color, alignment=TA_CENTER
        ))],
        [Paragraph(label, ParagraphStyle(
            "stat_lbl", fontSize=7.5, fontName="Helvetica-Bold",
            textColor=MUTED, alignment=TA_CENTER, letterSpacing=0.5
        ))],
    ], colWidths=[None])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), WHITE),
        ("BOX",          (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("LEFTPADDING",  (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("LINEABOVE",    (0, 0), (-1, 0), 3, color),
    ]))
    return tbl


# ── Main generator ─────────────────────────────────────────────────────────────

def generate_audit_pdf(
    org_name: str,
    findings: List[Dict[str, Any]],
    generated_by: str = "CyberGuard Platform",
) -> bytes:
    """
    Generate a professional light-theme security audit PDF.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    now = datetime.now(timezone.utc)
    ts = now.strftime("%d %B %Y, %H:%M UTC")
    ts_file = now.strftime("%Y-%m-%d")

    S = _styles()

    # Page callbacks
    def _on_first_page(canvas, doc):
        canvas.saveState()
        # Solid navy top bar
        canvas.setFillColor(NAVY)
        canvas.rect(0, PAGE_H - 18 * mm, PAGE_W, 18 * mm, stroke=0, fill=1)
        # Brand text in bar
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(MARGIN, PAGE_H - 11 * mm, "CYBERGUARD")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(HexColor("#93C5FD"))
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 11 * mm, "Security Intelligence Platform")
        canvas.restoreState()

    def _on_later_pages(canvas, doc):
        canvas.saveState()
        # Thin top rule
        canvas.setFillColor(NAVY)
        canvas.rect(0, PAGE_H - 8 * mm, PAGE_W, 8 * mm, stroke=0, fill=1)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.drawString(MARGIN, PAGE_H - 5.5 * mm, "CYBERGUARD")
        canvas.setFillColor(HexColor("#93C5FD"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 5.5 * mm,
                                f"Security Report · {org_name}")
        # Footer
        _NumberedCanvas._draw_footer(canvas, doc, org_name, ts, doc.page)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=24 * mm,
        bottomMargin=22 * mm,
        title=f"CyberGuard Security Report — {org_name}",
        author="CyberGuard Platform",
        onFirstPage=_on_first_page,
        onLaterPages=_on_later_pages,
    )

    story = []

    # ── COVER SECTION ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 16 * mm))
    story.append(Paragraph("SECURITY ASSESSMENT REPORT", S["cover_brand"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(org_name, S["cover_title"]))
    story.append(HRFlowable(width=60 * mm, thickness=3, color=ACCENT_BLUE,
                             lineCap="round", spaceAfter=10))
    story.append(Paragraph(f"Report Date: {ts}", S["cover_meta"]))
    story.append(Paragraph(f"Generated by: {generated_by}", S["cover_meta"]))
    story.append(Paragraph("Classification: CONFIDENTIAL", S["cover_meta"]))
    story.append(Spacer(1, 6 * mm))

    # ── SUMMARY STATISTICS ────────────────────────────────────────────────────
    open_f   = [f for f in findings if f.get("status") == "open"]
    res_f    = [f for f in findings if f.get("status") != "open"]
    by_sev: Dict[str, int] = {}
    by_src: Dict[str, int] = {}
    for f in open_f:
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        src = f.get("source", "unknown")
        by_src[src] = by_src.get(src, 0) + 1

    story.append(Paragraph("EXECUTIVE SUMMARY", S["section_label"]))
    story.append(Paragraph("Security Posture Overview", S["section_title"]))

    # KPI row
    kpi_row = [[
        _stat_box("TOTAL FINDINGS", str(len(findings)), NAVY),
        _stat_box("OPEN", str(len(open_f)), C_CRITICAL if len(open_f) else C_LOW),
        _stat_box("CRITICAL", str(by_sev.get("critical", 0)), C_CRITICAL),
        _stat_box("HIGH", str(by_sev.get("high", 0)), C_HIGH),
        _stat_box("MEDIUM", str(by_sev.get("medium", 0)), C_MEDIUM),
        _stat_box("RESOLVED", str(len(res_f)), C_LOW),
    ]]
    kpi_w = CONTENT_W / 6
    kpi_tbl = Table(kpi_row, colWidths=[kpi_w] * 6, spaceBefore=4, spaceAfter=14)
    kpi_tbl.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(kpi_tbl)

    # Source breakdown table
    story.append(Paragraph("FINDINGS BY SOURCE", S["section_label"]))
    src_rows = [
        [Paragraph("SOURCE", S["tbl_header"]),
         Paragraph("OPEN FINDINGS", S["tbl_header"]),
         Paragraph("DESCRIPTION", S["tbl_header"])],
        [Paragraph("SSPM · Microsoft 365", S["tbl_cell_bold"]),
         Paragraph(str(by_src.get("m365", 0)), S["tbl_cell"]),
         Paragraph("Identity, access, and configuration issues in your M365 tenant", S["tbl_cell"])],
        [Paragraph("EASM · External Scanner", S["tbl_cell_bold"]),
         Paragraph(str(by_src.get("ext_scanner", 0)), S["tbl_cell"]),
         Paragraph("Internet-facing assets: DNS, SSL, headers, exposed services", S["tbl_cell"])],
    ]
    src_tbl = Table(src_rows, colWidths=[CONTENT_W * 0.3, CONTENT_W * 0.15, CONTENT_W * 0.55])
    src_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#F1F5F9")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, HexColor("#F8FAFC")]),
        ("BOX",           (0, 0), (-1, -1), 0.75, BORDER_MED),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(src_tbl)
    story.append(Spacer(1, 4 * mm))

    # Severity breakdown table
    story.append(Paragraph("SEVERITY BREAKDOWN", S["section_label"]))
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_rows = [[
        Paragraph("SEVERITY", S["tbl_header"]),
        Paragraph("OPEN", S["tbl_header"]),
        Paragraph("RISK LEVEL", S["tbl_header"]),
    ]]
    risk_desc = {
        "critical": "Immediate action required. Active exploitation risk.",
        "high":     "Remediate within 48 hours. Significant exposure.",
        "medium":   "Address within 30 days. Moderate risk.",
        "low":      "Best-practice improvement. Low immediate risk.",
        "info":     "Informational. No direct threat.",
    }
    for sev in sev_order:
        cnt = by_sev.get(sev, 0)
        col, _ = SEV_COLOR.get(sev, (MUTED, WHITE))
        sev_rows.append([
            Paragraph(sev.upper(), ParagraphStyle(
                "sv", fontSize=8.5, fontName="Helvetica-Bold", textColor=col
            )),
            Paragraph(str(cnt), ParagraphStyle(
                "svc", fontSize=8.5, fontName="Helvetica-Bold",
                textColor=col if cnt > 0 else MUTED
            )),
            Paragraph(risk_desc[sev], S["tbl_cell"]),
        ])

    sev_tbl = Table(sev_rows,
                    colWidths=[CONTENT_W * 0.18, CONTENT_W * 0.1, CONTENT_W * 0.72])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#F1F5F9")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, HexColor("#F8FAFC")]),
        ("BOX",           (0, 0), (-1, -1), 0.75, BORDER_MED),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(sev_tbl)

    # ── PAGE BREAK → FINDINGS ────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("FINDINGS DETAIL", S["section_label"]))
    story.append(Paragraph("Security Findings & Evidence", S["section_title"]))
    story.append(Paragraph(
        "Each finding below was detected deterministically by CyberGuard's rules engine. "
        "Evidence is captured at scan time and stored immutably. "
        "Findings are sorted by severity (critical → info).",
        S["body"]
    ))
    story.append(Spacer(1, 4 * mm))

    # Sort findings by severity
    sev_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_weight.get(f.get("severity", "info"), 5),
                       f.get("first_seen_at", ""))
    )

    for idx, f in enumerate(sorted_findings, 1):
        sev   = f.get("severity", "info").lower()
        src   = f.get("source", "unknown")
        sev_col, sev_bg = SEV_COLOR.get(sev, (MUTED, WHITE))
        src_col = SRC_COLOR.get(src, MUTED)
        src_lbl = SRC_LABEL.get(src, src.upper())
        status  = f.get("status", "open").upper()
        st_col  = C_LOW if status == "RESOLVED" else (MUTED if status == "FALSE_POSITIVE" else C_CRITICAL)

        # Finding ID + badges row
        badge_row = Table([[
            Paragraph(
                f"<b>{f.get('finding_id', f'FIN-{idx}')}</b>",
                ParagraphStyle("fid", fontSize=9, fontName="Helvetica-Bold", textColor=NAVY)
            ),
            Table([[
                Paragraph(sev.upper(), ParagraphStyle(
                    "sb", fontSize=7.5, fontName="Helvetica-Bold",
                    textColor=sev_col, alignment=TA_CENTER
                )),
            ]], colWidths=[22 * mm], style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), sev_bg),
                ("BOX",           (0, 0), (-1, -1), 0.75, sev_col),
                ("TOPPADDING",    (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ])),
            Table([[
                Paragraph(src_lbl, ParagraphStyle(
                    "srcb", fontSize=7.5, fontName="Helvetica-Bold",
                    textColor=src_col, alignment=TA_CENTER
                )),
            ]], colWidths=[32 * mm], style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#EFF6FF")),
                ("BOX",           (0, 0), (-1, -1), 0.75, src_col),
                ("TOPPADDING",    (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ])),
            Paragraph(status, ParagraphStyle(
                "st", fontSize=7.5, fontName="Helvetica-Bold",
                textColor=st_col, alignment=TA_RIGHT
            )),
        ]], colWidths=[CONTENT_W * 0.3, 22 * mm, 32 * mm, CONTENT_W - 0.3 * CONTENT_W - 54 * mm])
        badge_row.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        # Issue title
        issue_para = Paragraph(f.get("issue_type", "Unknown Issue"), S["finding_title"])

        # Entity + first seen row
        first_seen = f.get("first_seen_at", "")
        try:
            dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            first_seen = dt.strftime("%d %b %Y, %H:%M UTC")
        except Exception:
            pass

        meta_data = [[
            Paragraph("AFFECTED ENTITY", S["label"]),
            Paragraph("FIRST DETECTED", S["label"]),
        ], [
            Paragraph(f.get("entity", "—"), S["tbl_cell"]),
            Paragraph(first_seen or "—", S["tbl_cell"]),
        ]]
        meta_tbl = Table(meta_data, colWidths=[CONTENT_W * 0.6, CONTENT_W * 0.4])
        meta_tbl.setStyle(TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]))

        # Evidence block
        evidence = f.get("evidence") or {}
        ev_rows = []
        for k, v in list(evidence.items())[:6]:
            val_str = str(v)
            if len(val_str) > 130:
                val_str = val_str[:130] + "…"
            ev_rows.append([
                Paragraph(str(k), S["label"]),
                Paragraph(val_str.replace("<", "&lt;").replace(">", "&gt;"), S["finding_evidence"]),
            ])

        ev_content = []
        if ev_rows:
            ev_content.append(Paragraph("EVIDENCE", S["label"]))
            ev_tbl = Table(ev_rows, colWidths=[CONTENT_W * 0.22, CONTENT_W * 0.78 - 6 * mm])
            ev_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#F8FAFC")),
                ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TEXTCOLOR",     (0, 0), (0, -1), MUTED),
            ]))
            ev_content.append(ev_tbl)

        # Full card — white box with left colour bar
        inner_content = [
            badge_row,
            Spacer(1, 2 * mm),
            issue_para,
            meta_tbl,
        ] + ([Spacer(1, 2 * mm)] + ev_content if ev_content else [])

        inner_tbl = Table([[inner_content]], colWidths=[CONTENT_W - 4 * mm])
        inner_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ]))

        # Outer card — provides the left coloured bar + outer border
        card = Table(
            [[None, inner_tbl]],
            colWidths=[4 * mm, CONTENT_W - 4 * mm]
        )
        card.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), sev_col),   # coloured bar
            ("BACKGROUND",    (1, 0), (-1, -1), WHITE),
            ("BOX",           (0, 0), (-1, -1), 0.75, BORDER_MED),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))

        story.append(KeepTogether([card, Spacer(1, 3 * mm)]))

    # ── FOOTER NOTE ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width=CONTENT_W, thickness=0.5, color=BORDER_MED, spaceAfter=6))
    story.append(Paragraph(
        "This report was generated automatically by the CyberGuard Security Intelligence Platform. "
        "All findings are based on deterministic detection rules applied to data collected at scan time. "
        "This document is confidential and intended solely for authorised security and compliance personnel. "
        "Unauthorised disclosure is prohibited.",
        ParagraphStyle("disc", fontSize=7.5, fontName="Helvetica",
                        textColor=MUTED, alignment=TA_CENTER, leading=11)
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()
