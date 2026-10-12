"""Professional PDF report built with ReportLab (pure Python, no external services)."""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from white.reporting import analytics
from white.scanner.models import STATUS_LABELS, CheckStatus, Finding, ScanReport

INK = colors.HexColor("#1f2328")
MUTED = colors.HexColor("#5b616b")
BORDER = colors.HexColor("#d9dce1")
SURFACE = colors.HexColor("#f6f7f8")
ACCENT = colors.HexColor("#1f7a4d")
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#b42318"),
    "HIGH": colors.HexColor("#d9541e"),
    "MEDIUM": colors.HexColor("#c98500"),
    "LOW": colors.HexColor("#2a78d6"),
    "INFO": colors.HexColor("#6b7280"),
}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "body",
        parent=base["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=INK,
        alignment=TA_LEFT,
        splitLongWords=True,
    )
    return {
        "brand": ParagraphStyle(
            "brand", parent=body, fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=ACCENT
        ),
        "title": ParagraphStyle(
            "title", parent=body, fontName="Helvetica-Bold", fontSize=16, leading=20, spaceAfter=4
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "h2", parent=body, fontName="Helvetica-Bold", fontSize=11, leading=14, spaceBefore=8, spaceAfter=3
        ),
        "body": body,
        "small": ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=MUTED),
        "label": ParagraphStyle(
            "label", parent=body, fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=MUTED
        ),
        "cell": ParagraphStyle("cell", parent=body, fontSize=8.5, leading=11),
        "mono": ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=7.8, leading=10),
    }


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")), style)


def _table(rows: list[list], widths: list[float], header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), SURFACE))
    table.setStyle(TableStyle(style))
    return table


def _severity_pie(report: ScanReport) -> Drawing | None:
    data = analytics.severity_chart(report)
    pairs = [
        (label, key, value)
        for label, key, value in zip(data["labels"], data["keys"], data["values"], strict=True)
        if value
    ]
    if not pairs:
        return None
    drawing = Drawing(240, 150)
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 10, 10, 120, 120
    pie.data = [v for _, _, v in pairs]
    pie.labels = None
    pie.innerRadiusFraction = 0.55
    pie.strokeColor = colors.white
    pie.strokeWidth = 1.5
    for i, (_, key, _) in enumerate(pairs):
        pie.slices[i].fillColor = SEVERITY_COLORS[key]
    drawing.add(pie)
    y = 120
    for label, key, value in pairs:
        drawing.add(String(150, y, f"{label}: {value}", fontName="Helvetica", fontSize=9, fillColor=INK))
        drawing.add(Rect(140, y - 1, 7, 7, fillColor=SEVERITY_COLORS[key], strokeColor=None))
        y -= 16
    return drawing


def _category_bars(report: ScanReport) -> Drawing | None:
    data = analytics.category_chart(report)
    if not any(data["values"]):
        return None
    labels = list(reversed(data["labels"]))
    values = list(reversed(data["values"]))
    drawing = Drawing(260, 150)
    chart = HorizontalBarChart()
    chart.x, chart.y, chart.width, chart.height = 115, 10, 130, 130
    chart.data = [values]
    chart.categoryAxis.categoryNames = labels
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 8
    chart.categoryAxis.labels.dx = -4
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.categoryAxis.strokeColor = BORDER
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values) + 1
    chart.valueAxis.valueStep = max(1, (max(values) + 1) // 4)
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.strokeColor = BORDER
    chart.bars[0].fillColor = colors.HexColor("#2a78d6")
    chart.bars[0].strokeColor = None
    chart.barLabelFormat = "%d"
    chart.barLabels.fontSize = 7
    chart.barLabels.fontName = "Helvetica"
    chart.barLabels.nudge = 6
    drawing.add(chart)
    return drawing


def _finding_block(f: Finding, s: dict[str, ParagraphStyle], index: int) -> list:
    sev_color = SEVERITY_COLORS[f.severity.value].hexval()[2:]
    status = (
        "Confirmed observation" if f.status == CheckStatus.FINDING else "Possible issue - needs confirmation"
    )
    head = Paragraph(
        f'<font color="#{sev_color}"><b>{escape(f.severity.label.upper())}</b></font>'
        f"&nbsp;&nbsp;{index}. {escape(f.title)}",
        s["h2"],
    )
    meta = _p(
        f"{status} | Confidence: {f.confidence.value.title()} | Category: "
        f"{f.category.label} | Check: {f.check_id} v{f.check_version}" + (f" | {f.owasp}" if f.owasp else ""),
        s["small"],
    )
    parts: list = [KeepTogether([head, meta]), Spacer(1, 3)]
    for label, text in (
        ("What we found", f.summary),
        ("Why it matters", f.business_impact),
        ("What to do", f.recommendation),
    ):
        parts += [_p(label, s["label"]), _p(text, s["body"]), Spacer(1, 2)]
    if f.affected_url:
        parts += [_p("Affected URL", s["label"]), _p(f.affected_url, s["mono"]), Spacer(1, 2)]
    parts += [
        _p("Technical details", s["label"]),
        _p(f.technical_details, s["body"]),
        _p("Technical remediation", s["label"]),
        _p(f.technical_remediation, s["body"]),
    ]
    if f.evidence:
        rows = [[_p("Evidence", s["label"]), _p("Observed value", s["label"])]]
        rows += [[_p(e.label, s["cell"]), _p(e.value, s["mono"])] for e in f.evidence]
        parts += [Spacer(1, 3), _table(rows, [40 * mm, 130 * mm])]
    if f.references:
        refs = "; ".join(f"{r.title}: {r.url}" for r in f.references)
        parts += [_p(f"References: {refs}", s["small"])]
    parts.append(Spacer(1, 8))
    return parts


def build_pdf(report: ScanReport, comparison: analytics.Comparison | None = None) -> bytes:
    s = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"WHITE security assessment - {report.hostname}",
        author="WHITE",
        subject="Website security assessment",
    )

    def decorate(canvas, document) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"WHITE security assessment - {report.hostname[:80]}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
        canvas.setStrokeColor(BORDER)
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.restoreState()

    label, _tone = analytics.overall_assessment(report)
    summary = report.summary
    story: list = [
        _p("WHITE", s["brand"]),
        _p("Website security assessment", s["title"]),
        Spacer(1, 4),
    ]
    finished = report.finished_at.strftime("%Y-%m-%d %H:%M UTC") if report.finished_at else "not finished"
    meta_rows = [
        ["Target", report.target_url],
        ["Final URL", report.final_url or "-"],
        ["Scan started", report.started_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Scan finished", finished],
        ["Duration", f"{report.duration_seconds or 0:.1f} seconds"],
        ["Scan status", report.state.value.replace("_", " ").title()],
        ["Scan ID", report.scan_id],
        ["WHITE version", f"{report.tool_version} (report schema {report.schema_version})"],
        ["Active input checks", "Enabled" if report.active_checks_enabled else "Not enabled"],
    ]
    story.append(
        _table(
            [[_p(k, s["label"]), _p(v, s["cell"])] for k, v in meta_rows], [40 * mm, 134 * mm], header=False
        )
    )

    story += [
        _p("Executive summary", s["h1"]),
        _p(f"Overall assessment: {label}", s["h2"]),
        _p(analytics.executive_summary(report), s["body"]),
        Spacer(1, 6),
    ]
    sev = summary.severity_counts
    count_rows = [
        [_p(h, s["label"]) for h in ("Critical", "High", "Medium", "Low", "Informational", "Checks run")],
        [
            _p(v, s["cell"])
            for v in (
                sev.CRITICAL,
                sev.HIGH,
                sev.MEDIUM,
                sev.LOW,
                sev.INFO,
                summary.checks_total - summary.status_counts.get("NOT_TESTED", 0),
            )
        ],
    ]
    story.append(_table(count_rows, [29 * mm] * 6))

    pie, bars = _severity_pie(report), _category_bars(report)
    if pie or bars:
        story += [Spacer(1, 6), _p("Findings by severity and category", s["h2"])]
        cells = [[pie or _p("No findings.", s["small"]), bars or _p("No findings.", s["small"])]]
        chart_table = Table(cells, colWidths=[85 * mm, 89 * mm])
        chart_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(chart_table)

    actions = analytics.prioritized_actions(report)
    story.append(_p("Prioritised action plan", s["h1"]))
    if actions:
        rows = [[_p(h, s["label"]) for h in ("#", "Priority", "Action", "Why")]]
        for i, a in enumerate(actions, 1):
            pri = a["severity_label"] + ("" if a["status"] == "FINDING" else " (to confirm)")
            rows.append(
                [_p(i, s["cell"]), _p(pri, s["cell"]), _p(a["action"], s["cell"]), _p(a["why"], s["cell"])]
            )
        story.append(_table(rows, [8 * mm, 24 * mm, 66 * mm, 76 * mm]))
    else:
        story.append(
            _p(
                "No actions are required based on the checks that ran. Continue routine "
                "maintenance and re-scan after changes.",
                s["body"],
            )
        )

    if comparison is not None and comparison.available:
        c = comparison.counts()
        story += [
            _p("Comparison with the previous scan", s["h1"]),
            _p(
                f"Compared with scan {comparison.previous_scan_id}: {c['new']} new, "
                f"{c['unresolved']} still present, {c['fixed']} no longer detected, "
                f"{c['unverified']} could not be re-verified (the check did not complete).",
                s["body"],
            ),
        ]
        if comparison.fixed:
            story.append(
                _p("No longer detected: " + "; ".join(f.title for f in comparison.fixed), s["small"])
            )

    findings = report.findings
    story += [CondPageBreak(60 * mm), _p("Findings in detail", s["h1"])]
    if not findings:
        story.append(_p("No findings were recorded by the checks that ran.", s["body"]))
    for i, finding in enumerate(findings, 1):
        story += _finding_block(finding, s, i)

    story += [
        PageBreak(),
        _p("Scan coverage", s["h1"]),
        _p(
            "Every check and its outcome. 'Passed' means only that the specific issue was not detected.",
            s["small"],
        ),
        Spacer(1, 4),
    ]
    rows = [[_p(h, s["label"]) for h in ("Check", "Outcome", "Details")]]
    for check in report.checks:
        detail = check.message + (" Errors: " + "; ".join(check.errors) if check.errors else "")
        rows.append(
            [_p(check.name, s["cell"]), _p(STATUS_LABELS[check.status], s["cell"]), _p(detail, s["cell"])]
        )
    story.append(_table(rows, [50 * mm, 26 * mm, 98 * mm]))
    if report.errors:
        story += [_p("Scan errors", s["h2"])] + [_p(e, s["body"]) for e in report.errors]

    story += [_p("Limitations and disclaimer", s["h1"])]
    story += [_p(f"- {text}", s["body"]) for text in report.limitations]
    story.append(
        _p(
            "This report must only be produced for websites you own or are authorised "
            "to assess. Severity reflects potential impact; confidence reflects how "
            "certain the observation is. Neither is a guarantee.",
            s["small"],
        )
    )
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return buffer.getvalue()
