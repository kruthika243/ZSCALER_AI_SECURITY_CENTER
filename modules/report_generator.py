
import json
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from database.scan_history import get_scan_history


# ==========================================
# COLOR PALETTE
# ==========================================

NAVY = colors.HexColor("#12304A")
BLUE = colors.HexColor("#176B9A")
LIGHT_BLUE = colors.HexColor("#EAF1F7")
LIGHT_GREY = colors.HexColor("#F4F6F8")
DARK = colors.HexColor("#243447")
GREY = colors.HexColor("#64748B")

GREEN = colors.HexColor("#15803D")
RED = colors.HexColor("#B91C1C")
ORANGE = colors.HexColor("#C2410C")
YELLOW = colors.HexColor("#B7791F")


# ==========================================
# PDF GENERATOR
# ==========================================

def generate_security_report(scan_id):

    # --------------------------------------
    # 1. FETCH SCAN RECORD
    # --------------------------------------

    records = get_scan_history(limit=5000)

    selected = next(
        (
            record for record in records
            if int(record["id"]) == int(scan_id)
        ),
        None,
    )

    if selected is None:
        raise ValueError("Selected scan record was not found.")

    # --------------------------------------
    # 2. PARSE SAVED DATA
    # --------------------------------------

    def parse_json(value, fallback):
        try:
            parsed = json.loads(value or "")
            return parsed
        except (ValueError, TypeError):
            return fallback

    reasons = parse_json(selected.get("reasons"), [])

    if not isinstance(reasons, list):
        reasons = []

    features = parse_json(selected.get("features"), {})

    if not isinstance(features, dict):
        features = {}

    google_matches = parse_json(
        selected.get("google_matches"),
        [],
    )

    if not isinstance(google_matches, list):
        google_matches = []

    google_status = (
        selected.get("google_status") or "NOT_CHECKED"
    )

    structural_level = str(
        selected.get("risk_level", "UNKNOWN")
    ).upper()

    # Google threat match takes priority.
    if google_status == "MATCH":
        overall_verdict = "CRITICAL"
    else:
        overall_verdict = str(
            selected.get("overall_verdict") or structural_level
        ).upper()

    # --------------------------------------
    # 3. CREATE PDF DOCUMENT
    # --------------------------------------

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=13 * mm,
        leftMargin=13 * mm,
        topMargin=10 * mm,
        bottomMargin=15 * mm,
        title="Zscaler URL Security Report",
        author="Zscaler AI Security Center",
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="Brand",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=21,
        alignment=1,
        textColor=NAVY,
        spaceAfter=2,
    ))

    styles.add(ParagraphStyle(
        name="SubtitleCustom",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        alignment=1,
        textColor=GREY,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="SectionCustom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=NAVY,
        spaceBefore=6,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name="BodyCustom",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9.5,
        textColor=DARK,
    ))

    styles.add(ParagraphStyle(
        name="SmallCustom",
        parent=styles["Normal"],
        fontSize=6.8,
        leading=8.5,
        textColor=GREY,
    ))

    styles.add(ParagraphStyle(
        name="TableCustom",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        textColor=DARK,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="RiskLabel",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.white,
    ))

    styles.add(ParagraphStyle(
        name="RiskValue",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=22,
        textColor=colors.white,
    ))

    story = []

    def section(title):
        story.append(
            Paragraph(
                escape(title),
                styles["SectionCustom"],
            )
        )

    def cell(value):
        if isinstance(value, (list, dict)):
            value = json.dumps(value)

        return Paragraph(
            escape(str(value)),
            styles["TableCustom"],
        )

    def add_info_table(rows, background=LIGHT_GREY):
        table = Table(
            rows,
            colWidths=[184 * mm],
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), background),
            ("BOX", (0, 0), (-1, -1), 0.4,
             colors.HexColor("#D5DEE8")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        story.append(table)

    # ======================================
    # 4. REPORT HEADER
    # ======================================

    story.append(Paragraph(
        "ZSCALER AI SECURITY CENTER",
        styles["Brand"],
    ))

    story.append(Paragraph(
        "URL SECURITY ANALYSIS REPORT",
        styles["SubtitleCustom"],
    ))

    header_line = Table(
        [[""]],
        colWidths=[184 * mm],
        rowHeights=[1.2],
    )

    header_line.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BLUE),
    ]))

    story.append(header_line)
    story.append(Spacer(1, 5))

    # ======================================
    # 5. REPORT INFORMATION
    # ======================================

    section("REPORT INFORMATION")

    metadata = [
        [
            cell("REPORT REFERENCE"),
            cell(f"SCAN-{selected['id']}"),
            cell("SCAN DATE"),
            cell(selected["scanned_at"]),
        ],
        [
            cell("HOSTNAME"),
            cell(selected["hostname"]),
            cell("OVERALL VERDICT"),
            cell(overall_verdict),
        ],
        [
            cell("ANALYZED URL"),
            Paragraph(
                escape(str(selected["url"])),
                styles["TableCustom"],
            ),
            "",
            "",
        ],
    ]

    metadata_table = Table(
        metadata,
        colWidths=[
            34 * mm,
            58 * mm,
            28 * mm,
            64 * mm,
        ],
    )

    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE),
        ("BACKGROUND", (2, 0), (2, 1), LIGHT_BLUE),
        ("BACKGROUND", (0, 2), (-1, 2), LIGHT_GREY),
        ("SPAN", (1, 2), (3, 2)),
        ("GRID", (0, 0), (-1, -1), 0.35,
         colors.HexColor("#D5DEE8")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(metadata_table)

    # ======================================
    # 6. RISK ASSESSMENT
    # ======================================

    section("RISK ASSESSMENT")

    score = int(selected["risk_score"])

    level_colors = {
        "LOW": GREEN,
        "MODERATE": YELLOW,
        "HIGH": ORANGE,
        "CRITICAL": RED,
    }

    risk_color = level_colors.get(overall_verdict, NAVY)

    score_content = [
        Paragraph("STRUCTURAL RISK SCORE", styles["RiskLabel"]),
        Spacer(1, 2),
        Paragraph(f"{score}/100", styles["RiskValue"]),
    ]

    classification_content = [
        Paragraph("OVERALL SECURITY VERDICT", styles["RiskLabel"]),
        Spacer(1, 2),
        Paragraph(
            escape(overall_verdict),
            styles["RiskValue"],
        ),
    ]

    risk_table = Table(
        [[score_content, classification_content]],
        colWidths=[92 * mm, 92 * mm],
        rowHeights=[22 * mm],
    )

    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), NAVY),
        ("BACKGROUND", (1, 0), (1, 0), risk_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(risk_table)

    story.append(Spacer(1, 3))

    story.append(Paragraph(
        f"Original structural classification: "
        f"<b>{escape(structural_level)}</b>. "
        "The structural score and overall verdict are separate "
        "measurements.",
        styles["SmallCustom"],
    ))

    # ======================================
    # 7. GOOGLE SAFE BROWSING INTELLIGENCE
    # ======================================

    section("GOOGLE SAFE BROWSING THREAT INTELLIGENCE")

    if google_status == "MATCH":

        status_text = "THREAT MATCH DETECTED"
        status_color = RED
        description = (
            "Google Safe Browsing reported a match in its queried "
            "threat lists. Treat this URL as dangerous."
        )

    elif google_status == "NO_MATCH":

        status_text = "NO THREAT-LIST MATCH FOUND"
        status_color = GREEN
        description = (
            "No match was found in the queried Google Safe Browsing "
            "threat lists. This does not guarantee that the URL is safe."
        )

    elif google_status == "ERROR":

        status_text = "CHECK UNAVAILABLE"
        status_color = YELLOW
        description = (
            "The Google Safe Browsing check could not be completed. "
            "No safety conclusion can be drawn from this result."
        )

    else:

        status_text = "NOT CHECKED"
        status_color = GREY
        description = (
            "Google Safe Browsing was not checked for this historical scan."
        )

    status_table = Table(
        [[
            Paragraph(
                f"<b>{escape(status_text)}</b>",
                styles["BodyCustom"],
            )
        ]],
        colWidths=[184 * mm],
    )

    status_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), status_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.4, status_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(status_table)
    story.append(Spacer(1, 3))

    story.append(Paragraph(
        escape(description),
        styles["BodyCustom"],
    ))

    story.append(Spacer(1, 4))

    if google_status == "MATCH" and google_matches:

        match_rows = [[
            cell("THREAT TYPE"),
            cell("PLATFORM"),
            cell("ENTRY TYPE"),
        ]]

        for match in google_matches:

            if not isinstance(match, dict):
                continue

            match_rows.append([
                cell(match.get("threatType", "Not specified")),
                cell(match.get("platformType", "Not specified")),
                cell(match.get("threatEntryType", "Not specified")),
            ])

        if len(match_rows) > 1:

            match_table = Table(
                match_rows,
                colWidths=[61 * mm, 61 * mm, 62 * mm],
                repeatRows=1,
            )

            match_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BLUE),
                ("GRID", (0, 0), (-1, -1), 0.35,
                 colors.HexColor("#D5DEE8")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))

            story.append(match_table)

    elif google_status == "MATCH":

        story.append(Paragraph(
            "Google reported a threat match, but detailed match "
            "information was not saved.",
            styles["SmallCustom"],
        ))

    story.append(Spacer(1, 3))

    story.append(Paragraph(
        "This product includes results from Google Safe Browsing.",
        styles["SmallCustom"],
    ))

    # ======================================
    # 8. DETECTION EVIDENCE
    # ======================================

    section("STRUCTURAL DETECTION EVIDENCE")

    if reasons:

        evidence_rows = []

        for reason in reasons:

            evidence_rows.append([
                Paragraph(
                    f"&#8226; {escape(str(reason))}",
                    styles["BodyCustom"],
                )
            ])

    else:

        evidence_rows = [[
            Paragraph(
                "No configured suspicious URL indicators detected.",
                styles["BodyCustom"],
            )
        ]]

    add_info_table(evidence_rows)

    # ======================================
    # 9. EXTRACTED URL FEATURES
    # ======================================

    section("EXTRACTED URL FEATURES")

    feature_items = list(features.items())
    feature_rows = []

    for index in range(0, len(feature_items), 2):

        first_key, first_value = feature_items[index]

        row = [
            cell(first_key),
            cell(first_value),
        ]

        if index + 1 < len(feature_items):

            second_key, second_value = feature_items[index + 1]

            row.extend([
                cell(second_key),
                cell(second_value),
            ])

        else:

            row.extend([
                cell(""),
                cell(""),
            ])

        feature_rows.append(row)

    if feature_rows:

        feature_table = Table(
            feature_rows,
            colWidths=[
                35 * mm,
                57 * mm,
                35 * mm,
                57 * mm,
            ],
        )

        feature_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE),
            ("BACKGROUND", (2, 0), (2, -1), LIGHT_BLUE),
            ("GRID", (0, 0), (-1, -1), 0.3,
             colors.HexColor("#D5DEE8")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))

        story.append(feature_table)

    # ======================================
    # 10. SECURITY RECOMMENDATION
    # ======================================

    section("SECURITY RECOMMENDATION")

    if google_status == "MATCH":

        recommendation = (
            "BLOCK THIS URL. Google Safe Browsing identified a threat. "
            "Do not visit the website, enter personal information, "
            "or interact with its content."
        )

    elif overall_verdict in ["HIGH", "CRITICAL"]:

        recommendation = (
            "Avoid interacting with this URL. Verify the destination "
            "through an independent trusted channel."
        )

    elif overall_verdict == "MODERATE":

        recommendation = (
            "Exercise caution. Review the URL and verify the destination "
            "before entering sensitive information."
        )

    elif google_status == "ERROR":

        recommendation = (
            "Google Safe Browsing verification was unavailable. "
            "Do not interpret the missing result as confirmation of safety."
        )

    else:

        recommendation = (
            "No major configured indicators were detected. "
            "This does not guarantee that the website is safe."
        )

    recommendation_table = Table(
        [[
            Paragraph(
                escape(recommendation),
                styles["BodyCustom"],
            )
        ]],
        colWidths=[184 * mm],
    )

    recommendation_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE),
        ("BOX", (0, 0), (-1, -1), 0.5, BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(recommendation_table)

    # ======================================
    # 11. METHODOLOGY AND LIMITATIONS
    # ======================================

    section("METHODOLOGY & LIMITATIONS")

    story.append(Paragraph(
        "This report summarizes local heuristic URL analysis and "
        "the saved Google Safe Browsing response. Structural risk "
        "scores are rule-based indicators, not probabilities of "
        "malicious activity. A Google no-match result does not "
        "guarantee safety. API errors and unchecked results must "
        "not be interpreted as clean results. The scanner does not "
        "visit or execute the submitted website.",
        styles["SmallCustom"],
    ))

    # ======================================
    # 12. FOOTER
    # ======================================

    def draw_footer(canvas, doc):

        canvas.saveState()

        canvas.setStrokeColor(
            colors.HexColor("#D5DEE8")
        )

        canvas.line(
            13 * mm,
            9 * mm,
            A4[0] - 13 * mm,
            9 * mm,
        )

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GREY)

        canvas.drawString(
            13 * mm,
            5 * mm,
            "ZSCALER AI SECURITY CENTER",
        )

        canvas.drawRightString(
            A4[0] - 13 * mm,
            5 * mm,
            f"SECURITY REPORT | PAGE {doc.page}",
        )

        canvas.restoreState()

    # ======================================
    # 13. BUILD PDF
    # ======================================

    document.build(
        story,
        onFirstPage=draw_footer,
        onLaterPages=draw_footer,
    )

    buffer.seek(0)

    return buffer.getvalue()
