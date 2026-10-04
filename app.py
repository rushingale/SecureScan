from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    send_file
)

from scanner.target_validator import validate_target
from scanner.nmap_scanner import scan_target
from scanner.result_analyzer import analyze_scan
from scanner.http_header_scanner import scan_http_headers
from scanner.http_method_scanner import scan_http_methods
from scanner.sensitive_path_scanner import scan_sensitive_paths
from scanner.ssl_scanner import scan_ssl_certificate
from scanner.security_intelligence import enrich_findings
from scanner.risk_calculator import calculate_risk

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.enums import (
    TA_CENTER,
    TA_LEFT
)
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    PageBreak
)

from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

from xml.sax.saxutils import escape

from io import BytesIO
from datetime import datetime


app = Flask(__name__)


# ==========================================================
# HOME
# ==========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================================
# TARGET VALIDATION
# ==========================================================

@app.route(
    "/validate-target",
    methods=["POST"]
)
def validate():

    data = request.get_json()

    if not data or "target" not in data:

        return jsonify({
            "error": "Please provide a target"
        }), 400

    result = validate_target(
        data["target"]
    )

    return jsonify(result)


# ==========================================================
# MAIN SECURITY SCAN
# ==========================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    data = request.get_json()

    if not data or "target" not in data:

        return jsonify({
            "error": "Please provide a target"
        }), 400

    target = data["target"]


    # ------------------------------------------------------
    # Validate target
    # ------------------------------------------------------

    validation = validate_target(
        target
    )

    if not validation["valid"]:

        return jsonify(
            validation
        ), 400


    # ------------------------------------------------------
    # Scan Profile
    # ------------------------------------------------------

    scan_profile = data.get(
        "scanProfile",
        "top50"
    )

    allowed_profiles = {
        "top20",
        "top50",
        "top100",
        "all"
    }

    if scan_profile not in allowed_profiles:

        scan_profile = "top50"


    # ------------------------------------------------------
    # Nmap scan
    # ------------------------------------------------------

    scan_result = scan_target(
        target,
        scan_profile
    )


    # ------------------------------------------------------
    # Analyze Nmap results
    # ------------------------------------------------------

    analysis = analyze_scan(
        scan_result
    )

    if not analysis.get("success"):

        return jsonify(
            analysis
        ), 500


    # ------------------------------------------------------
    # Get open ports
    # ------------------------------------------------------

    open_ports = analysis.get(
        "open_ports",
        []
    )


    # ------------------------------------------------------
    # HTTP security headers
    # ------------------------------------------------------

    http_findings = scan_http_headers(
        target,
        open_ports
    )


    # ------------------------------------------------------
    # HTTP methods
    # ------------------------------------------------------

    method_findings = scan_http_methods(
        target,
        open_ports
    )


    # ------------------------------------------------------
    # Sensitive paths
    # ------------------------------------------------------

    sensitive_path_findings = scan_sensitive_paths(
        target,
        open_ports
    )


    # ------------------------------------------------------
    # SSL/TLS
    # ------------------------------------------------------

    ssl_findings = scan_ssl_certificate(
        target,
        open_ports
    )


    # ------------------------------------------------------
    # Combine findings
    # ------------------------------------------------------

    analysis["findings"].extend(
        http_findings
    )

    analysis["findings"].extend(
        method_findings
    )

    analysis["findings"].extend(
        sensitive_path_findings
    )

    analysis["findings"].extend(
        ssl_findings
    )


    # ------------------------------------------------------
    # Add security intelligence
    # ------------------------------------------------------

    analysis["findings"] = enrich_findings(
        analysis["findings"]
    )


    # ------------------------------------------------------
    # Update finding count
    # ------------------------------------------------------

    analysis["summary"]["findings"] = len(
        analysis["findings"]
    )


    # ------------------------------------------------------
    # Calculate risk
    # ------------------------------------------------------

    risk = calculate_risk(
        analysis
    )


    return jsonify({

        "scan": scan_result,

        "analysis": analysis,

        "risk": risk

    })


# ==========================================================
# PDF HELPER FUNCTIONS
# ==========================================================

def safe_text(value):
    """
    Safely convert scanner output into ReportLab-compatible text.
    """

    if value is None:

        return ""

    return escape(
        str(value)
    )


def severity_color(severity):
    """
    Return professional severity colors.
    """

    severity = str(
        severity
    ).lower()


    if severity == "critical":

        return colors.HexColor(
            "#dc2626"
        )


    if severity == "high":

        return colors.HexColor(
            "#ea580c"
        )


    if severity == "medium":

        return colors.HexColor(
            "#d97706"
        )


    if severity == "low":

        return colors.HexColor(
            "#2563eb"
        )


    return colors.HexColor(
        "#64748b"
    )


def risk_color(level):

    level = str(
        level
    ).lower()


    if level == "critical":

        return colors.HexColor(
            "#dc2626"
        )


    if level == "high":

        return colors.HexColor(
            "#ea580c"
        )


    if level == "medium":

        return colors.HexColor(
            "#d97706"
        )


    if level == "low":

        return colors.HexColor(
            "#16a34a"
        )


    return colors.HexColor(
        "#64748b"
    )


def add_page_number(canvas, document):

    canvas.saveState()


    width, height = A4


    # ------------------------------------------------------
    # Top accent line
    # ------------------------------------------------------

    canvas.setStrokeColor(
        colors.HexColor("#0f172a")
    )

    canvas.setLineWidth(
        2
    )

    canvas.line(
        40,
        height - 28,
        width - 40,
        height - 28
    )


    # ------------------------------------------------------
    # Footer line
    # ------------------------------------------------------

    canvas.setStrokeColor(
        colors.HexColor("#cbd5e1")
    )

    canvas.setLineWidth(
        0.5
    )

    canvas.line(
        40,
        30,
        width - 40,
        30
    )


    # ------------------------------------------------------
    # Footer text
    # ------------------------------------------------------

    canvas.setFont(
        "Helvetica",
        7.5
    )

    canvas.setFillColor(
        colors.HexColor("#64748b")
    )


    canvas.drawString(
        40,
        18,
        "SecureScan • Automated Security Assessment"
    )


    canvas.drawRightString(
        width - 40,
        18,
        f"Page {document.page}"
    )


    canvas.restoreState()


# ==========================================================
# PDF REPORT
# ==========================================================

@app.route(
    "/export-pdf",
    methods=["POST"]
)
def export_pdf():

    data = request.get_json()


    if not data:

        return jsonify({
            "error": "No report data provided"
        }), 400


    target = data.get(
        "target",
        "Unknown Target"
    )


    scan_date = data.get(
        "scanDate",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )


    analysis = data.get(
        "analysis",
        {}
    )


    risk = data.get(
        "risk",
        {}
    )


    scan_data = data.get(
        "scan",
        {}
    )


    scan_profile = scan_data.get(
        "scan_profile",
        "top50"
    )


    profile_names = {

        "top20":
            "Top 20 — Quick",

        "top50":
            "Top 50 — Balanced",

        "top100":
            "Top 100 — Thorough",

        "all":
            "All Ports — Full Scan"

    }


    scan_profile_name = profile_names.get(
        scan_profile,
        str(scan_profile)
    )


    # ======================================================
    # PDF DOCUMENT
    # ======================================================

    buffer = BytesIO()


    document = SimpleDocTemplate(

        buffer,

        pagesize=A4,

        rightMargin=42,

        leftMargin=42,

        topMargin=48,

        bottomMargin=42,

        title="SecureScan Security Assessment Report",

        author="SecureScan"

    )


    elements = []


    styles = getSampleStyleSheet()


    # ======================================================
    # COLORS
    # ======================================================

    NAVY = colors.HexColor(
        "#0f172a"
    )

    DARK = colors.HexColor(
        "#1e293b"
    )

    SLATE = colors.HexColor(
        "#475569"
    )

    MUTED = colors.HexColor(
        "#64748b"
    )

    LIGHT = colors.HexColor(
        "#f8fafc"
    )

    BORDER = colors.HexColor(
        "#cbd5e1"
    )

    CYAN = colors.HexColor(
        "#0891b2"
    )

    GREEN = colors.HexColor(
        "#16a34a"
    )

    WARNING_BG = colors.HexColor(
        "#fff7ed"
    )

    WARNING_BORDER = colors.HexColor(
        "#fdba74"
    )


    # ======================================================
    # PDF STYLES
    # ======================================================

    title_style = ParagraphStyle(

        "ReportTitle",

        parent=styles["Title"],

        fontName="Helvetica-Bold",

        fontSize=25,

        leading=30,

        alignment=TA_LEFT,

        textColor=NAVY,

        spaceAfter=6

    )


    subtitle_style = ParagraphStyle(

        "ReportSubtitle",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=10.5,

        leading=15,

        textColor=SLATE,

        spaceAfter=18

    )


    section_style = ParagraphStyle(

        "SectionHeading",

        parent=styles["Heading2"],

        fontName="Helvetica-Bold",

        fontSize=15,

        leading=19,

        textColor=NAVY,

        spaceBefore=14,

        spaceAfter=9,

        keepWithNext=True

    )


    subsection_style = ParagraphStyle(

        "SubsectionHeading",

        parent=styles["Heading3"],

        fontName="Helvetica-Bold",

        fontSize=10.5,

        leading=14,

        textColor=DARK,

        spaceBefore=7,

        spaceAfter=6,

        keepWithNext=True

    )


    normal_style = ParagraphStyle(

        "ReportNormal",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=8.8,

        leading=13,

        textColor=DARK,

        spaceAfter=5

    )


    small_style = ParagraphStyle(

        "ReportSmall",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=7.5,

        leading=10,

        textColor=MUTED,

        spaceAfter=3

    )


    table_style = ParagraphStyle(

        "TableText",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=7.8,

        leading=10,

        textColor=DARK

    )


    table_bold_style = ParagraphStyle(

        "TableBold",

        parent=styles["Normal"],

        fontName="Helvetica-Bold",

        fontSize=7.8,

        leading=10,

        textColor=DARK

    )


    finding_style = ParagraphStyle(

        "FindingTitle",

        parent=styles["Heading3"],

        fontName="Helvetica-Bold",

        fontSize=10.5,

        leading=14,

        textColor=NAVY,

        spaceAfter=5

    )


    cve_style = ParagraphStyle(

        "CVEText",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=7.2,

        leading=9,

        textColor=DARK

    )


    # ======================================================
    # REPORT HEADER
    # ======================================================

    header_table = Table(

        [[

            Paragraph(
                "<b>SECURESCAN</b>",
                ParagraphStyle(
                    "Brand",
                    parent=styles["Normal"],
                    fontName="Helvetica-Bold",
                    fontSize=12,
                    textColor=colors.white,
                    leading=14
                )
            ),

            Paragraph(
                "SECURITY ASSESSMENT",
                ParagraphStyle(
                    "HeaderRight",
                    parent=styles["Normal"],
                    fontName="Helvetica-Bold",
                    fontSize=7.5,
                    alignment=TA_CENTER,
                    textColor=colors.white,
                    leading=10
                )
            )

        ]],

        colWidths=[
            330,
            150
        ]

    )


    header_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                NAVY
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                9
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                9
            )

        ])

    )


    elements.append(
        header_table
    )


    elements.append(
        Spacer(1, 22)
    )


    elements.append(

        Paragraph(
            "Security Assessment Report",
            title_style
        )

    )


    elements.append(

        Paragraph(
            "Automated vulnerability and attack-surface assessment",
            subtitle_style
        )

    )


    # ======================================================
    # SCAN INFORMATION
    # ======================================================

    elements.append(

        Paragraph(
            "01  •  Scan Information",
            section_style
        )

    )


    scan_info = [

        [

            Paragraph(
                "<b>TARGET</b>",
                table_bold_style
            ),

            Paragraph(
                safe_text(target),
                table_style
            ),

            Paragraph(
                "<b>SCAN DATE</b>",
                table_bold_style
            ),

            Paragraph(
                safe_text(scan_date),
                table_style
            )

        ],

        [

            Paragraph(
                "<b>SCAN PROFILE</b>",
                table_bold_style
            ),

            Paragraph(
                safe_text(scan_profile_name),
                table_style
            ),

            Paragraph(
                "<b>ENGINE</b>",
                table_bold_style
            ),

            Paragraph(
                "Nmap + SecureScan Analysis",
                table_style
            )

        ]

    ]


    info_table = Table(

        scan_info,

        colWidths=[
            80,
            160,
            80,
            160
        ]

    )


    info_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                LIGHT
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                BORDER
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])

    )


    elements.append(
        info_table
    )


    elements.append(
        Spacer(1, 17)
    )


    # ======================================================
    # RISK SUMMARY
    # ======================================================

    elements.append(

        Paragraph(
            "02  •  Security Risk Summary",
            section_style
        )

    )


    score = risk.get(
        "score",
        0
    )


    level = risk.get(
        "level",
        "Unknown"
    )


    summary = analysis.get(
        "summary",
        {}
    )


    open_port_count = summary.get(
        "open_ports",
        0
    )


    finding_count = summary.get(
        "findings",
        0
    )


    current_risk_color = risk_color(
        level
    )


    risk_score_style = ParagraphStyle(

        "RiskScore",

        parent=styles["Normal"],

        fontName="Helvetica-Bold",

        fontSize=25,

        leading=28,

        alignment=TA_CENTER,

        textColor=current_risk_color

    )


    risk_level_style = ParagraphStyle(

        "RiskLevel",

        parent=styles["Normal"],

        fontName="Helvetica-Bold",

        fontSize=10,

        leading=13,

        alignment=TA_CENTER,

        textColor=current_risk_color

    )


    metric_number_style = ParagraphStyle(

        "MetricNumber",

        parent=styles["Normal"],

        fontName="Helvetica-Bold",

        fontSize=18,

        leading=21,

        alignment=TA_CENTER,

        textColor=NAVY

    )


    metric_label_style = ParagraphStyle(

        "MetricLabel",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=7.5,

        leading=10,

        alignment=TA_CENTER,

        textColor=MUTED

    )


    risk_table = Table(

        [[

            [

                Paragraph(
                    f"{safe_text(score)}",
                    risk_score_style
                ),

                Paragraph(
                    "/ 100",
                    ParagraphStyle(
                        "RiskOutOf",
                        parent=styles["Normal"],
                        fontSize=7.5,
                        alignment=TA_CENTER,
                        textColor=MUTED
                    )
                ),

                Paragraph(
                    safe_text(level).upper(),
                    risk_level_style
                )

            ],

            [

                Paragraph(
                    safe_text(open_port_count),
                    metric_number_style
                ),

                Paragraph(
                    "OPEN PORTS",
                    metric_label_style
                )

            ],

            [

                Paragraph(
                    safe_text(finding_count),
                    metric_number_style
                ),

                Paragraph(
                    "FINDINGS",
                    metric_label_style
                )

            ]

        ]],

        colWidths=[
            170,
            155,
            155
        ]

    )


    risk_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, 0),
                colors.HexColor("#f8fafc")
            ),

            (
                "BACKGROUND",
                (1, 0),
                (-1, 0),
                colors.white
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                BORDER
            ),

            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.5,
                BORDER
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                13
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                13
            )

        ])

    )


    elements.append(
        risk_table
    )


    elements.append(
        Spacer(1, 17)
    )


    # ======================================================
    # OPEN PORTS
    # ======================================================

    elements.append(

        Paragraph(
            "03  •  Open Ports and Services",
            section_style
        )

    )


    open_ports = analysis.get(
        "open_ports",
        []
    )


    if not open_ports:

        empty_table = Table(

            [[

                Paragraph(
                    "✓  No open ports were detected during the assessment.",
                    normal_style
                )

            ]],

            colWidths=[
                480
            ]

        )


        empty_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#f0fdf4")
                ),

                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.7,
                    colors.HexColor("#86efac")
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )

            ])

        )


        elements.append(
            empty_table
        )

    else:

        port_data = [

            [

                Paragraph(
                    "<b>PORT</b>",
                    table_bold_style
                ),

                Paragraph(
                    "<b>PROTOCOL</b>",
                    table_bold_style
                ),

                Paragraph(
                    "<b>SERVICE</b>",
                    table_bold_style
                ),

                Paragraph(
                    "<b>PRODUCT / VERSION</b>",
                    table_bold_style
                )

            ]

        ]


        for port in open_ports:

            product = port.get(
                "product",
                ""
            )


            version = port.get(
                "version",
                ""
            )


            product_version = (

                f"{product} {version}"

            ).strip()


            port_data.append([

                Paragraph(
                    f"<b>{safe_text(port.get('port', ''))}</b>",
                    table_style
                ),

                Paragraph(
                    safe_text(port.get("protocol", "")),
                    table_style
                ),

                Paragraph(
                    safe_text(port.get("service", "")),
                    table_style
                ),

                Paragraph(
                    safe_text(product_version) or "Not identified",
                    table_style
                )

            ])


        ports_table = Table(

            port_data,

            colWidths=[
                55,
                70,
                105,
                250
            ],

            repeatRows=1,

            hAlign="LEFT"

        )


        ports_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    NAVY
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.45,
                    BORDER
                ),

                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, -1),
                    colors.white
                ),

                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor("#f8fafc")
                    ]
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )

            ])

        )


        elements.append(
            ports_table
        )


    elements.append(
        Spacer(1, 18)
    )


    # ======================================================
    # SECURITY FINDINGS
    # ======================================================

    elements.append(

        Paragraph(
            "04  •  Security Findings",
            section_style
        )

    )


    findings = analysis.get(
        "findings",
        []
    )


    if not findings:

        clean_table = Table(

            [[

                Paragraph(
                    "<b>✓ No security findings detected</b><br/>"
                    "The automated checks did not identify issues "
                    "requiring attention.",
                    normal_style
                )

            ]],

            colWidths=[
                480
            ]

        )


        clean_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#f0fdf4")
                ),

                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    colors.HexColor("#86efac")
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    12
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    12
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    10
                )

            ])

        )


        elements.append(
            clean_table
        )


    else:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            severity = finding.get(
                "severity",
                "Unknown"
            )


            title = finding.get(
                "title",
                "Unnamed Finding"
            )


            description = finding.get(
                "description",
                ""
            )


            port = finding.get(
                "port",
                "N/A"
            )


            source = finding.get(
                "source",
                "SecureScan"
            )


            why_it_matters = finding.get(
                "why_it_matters",
                "Not available."
            )


            possible_impact = finding.get(
                "possible_impact",
                "Not available."
            )


            recommended_fix = finding.get(
                "recommended_fix",
                "Review the security configuration."
            )


            current_severity_color = severity_color(
                severity
            )


            # --------------------------------------------------
            # Finding title
            # --------------------------------------------------

            finding_header = Table(

                [[

                    Paragraph(
                        f"<b>{safe_text(severity).upper()}</b>",
                        ParagraphStyle(
                            f"Severity{index}",
                            parent=styles["Normal"],
                            fontName="Helvetica-Bold",
                            fontSize=7,
                            alignment=TA_CENTER,
                            textColor=colors.white
                        )
                    ),

                    Paragraph(
                        f"<b>{index}. {safe_text(title)}</b>",
                        finding_style
                    )

                ]],

                colWidths=[
                    68,
                    412
                ],

                hAlign="LEFT"

            )


            finding_header.setStyle(

                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, 0),
                        current_severity_color
                    ),

                    (
                        "BACKGROUND",
                        (1, 0),
                        (1, 0),
                        colors.HexColor("#f8fafc")
                    ),

                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        BORDER
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE"
                    ),

                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        8
                    ),

                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        8
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    )

                ])

            )


            finding_elements = [

                finding_header,

                Spacer(
                    1,
                    5
                )

            ]


            # --------------------------------------------------
            # Finding metadata
            # --------------------------------------------------

            metadata_table = Table(

                [[

                    Paragraph(
                        f"<b>Source:</b> {safe_text(source)}",
                        small_style
                    ),

                    Paragraph(
                        f"<b>Affected Port:</b> {safe_text(port)}",
                        small_style
                    )

                ]],

                colWidths=[
                    330,
                    150
                ]

            )


            metadata_table.setStyle(

                TableStyle([

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),

                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        0
                    ),

                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        0
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        2
                    )

                ])

            )


            finding_elements.append(
                metadata_table
            )


            # --------------------------------------------------
            # CVE section
            # --------------------------------------------------

            cves = finding.get(
                "cves"
            )


            if cves:

                finding_elements.append(

                    Paragraph(
                        "Vulnerability References",
                        subsection_style
                    )

                )


                finding_elements.append(

                    Paragraph(

                        "Potential vulnerability references associated "
                        "with the detected software or version. These "
                        "references require manual verification and do "
                        "not independently establish exploitability.",

                        normal_style

                    )

                )


                displayed_cves = cves[:5]


                cve_data = [

                    [

                        Paragraph(
                            "<b>CVE</b>",
                            cve_style
                        ),

                        Paragraph(
                            "<b>CVSS</b>",
                            cve_style
                        ),

                        Paragraph(
                            "<b>SEVERITY</b>",
                            cve_style
                        ),

                        Paragraph(
                            "<b>REFERENCE</b>",
                            cve_style
                        )

                    ]

                ]


                for cve in displayed_cves:

                    cve_id = cve.get(
                        "cve",
                        "Unknown"
                    )


                    cvss = cve.get(
                        "cvss",
                        "N/A"
                    )


                    cve_severity = cve.get(
                        "severity",
                        "Unknown"
                    )


                    reference = cve.get(
                        "reference",
                        ""
                    )


                    cve_data.append([

                        Paragraph(
                            f"<b>{safe_text(cve_id)}</b>",
                            cve_style
                        ),

                        Paragraph(
                            safe_text(cvss),
                            cve_style
                        ),

                        Paragraph(
                            safe_text(cve_severity),
                            cve_style
                        ),

                        Paragraph(
                            safe_text(reference),
                            cve_style
                        )

                    ])


                cve_table = Table(

                    cve_data,

                    colWidths=[
                        105,
                        55,
                        75,
                        245
                    ],

                    repeatRows=1,

                    hAlign="LEFT"

                )


                cve_table.setStyle(

                    TableStyle([

                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            DARK
                        ),

                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white
                        ),

                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            BORDER
                        ),

                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [
                                colors.white,
                                colors.HexColor("#f8fafc")
                            ]
                        ),

                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP"
                        ),

                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            6
                        ),

                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            6
                        ),

                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            5
                        ),

                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            5
                        )

                    ])

                )


                finding_elements.append(
                    cve_table
                )


                remaining = (

                    len(cves)
                    -
                    len(displayed_cves)

                )


                if remaining > 0:

                    finding_elements.append(

                        Paragraph(

                            f"+ {remaining} additional "
                            f"CVE reference(s) identified.",

                            small_style

                        )

                    )


                verification_status = finding.get(

                    "verification_status",

                    "Potential / Requires Verification"

                )


                verification_table = Table(

                    [[

                        Paragraph(
                            "<b>⚠ VERIFICATION STATUS</b>",
                            cve_style
                        ),

                        Paragraph(
                            safe_text(
                                verification_status
                            ),
                            cve_style
                        )

                    ]],

                    colWidths=[
                        150,
                        330
                    ]

                )


                verification_table.setStyle(

                    TableStyle([

                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            WARNING_BG
                        ),

                        (
                            "BOX",
                            (0, 0),
                            (-1, -1),
                            0.7,
                            WARNING_BORDER
                        ),

                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP"
                        ),

                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        ),

                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        ),

                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            6
                        ),

                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            6
                        )

                    ])

                )


                finding_elements.append(
                    Spacer(1, 5)
                )


                finding_elements.append(
                    verification_table
                )


            else:

                # --------------------------------------------------
                # Normal finding description
                # --------------------------------------------------

                if description:

                    finding_elements.append(

                        Paragraph(
                            f"<b>Description:</b> "
                            f"{safe_text(description)}",
                            normal_style
                        )

                    )


            # --------------------------------------------------
            # Security intelligence
            # --------------------------------------------------

            finding_elements.append(

                Paragraph(
                    f"<b>Why It Matters:</b> "
                    f"{safe_text(why_it_matters)}",
                    normal_style
                )

            )


            finding_elements.append(

                Paragraph(
                    f"<b>Possible Impact:</b> "
                    f"{safe_text(possible_impact)}",
                    normal_style
                )

            )


            finding_elements.append(

                Paragraph(
                    f"<b>Recommended Fix:</b> "
                    f"{safe_text(recommended_fix)}",
                    normal_style
                )

            )


            # --------------------------------------------------
            # Finding container
            # --------------------------------------------------

            finding_table = Table(

                [[
                    finding_elements
                ]],

                colWidths=[
                    480
                ],

                hAlign="LEFT"

            )


            finding_table.setStyle(

                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        colors.white
                    ),

                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        BORDER
                    ),

                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        10
                    ),

                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        10
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        9
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        9
                    )

                ])

            )


            elements.append(
                KeepTogether(
                    finding_table
                )
            )


            elements.append(
                Spacer(1, 10)
            )


    # ======================================================
    # RISK INTERPRETATION
    # ======================================================

    elements.append(

        Paragraph(
            "05  •  Assessment Interpretation",
            section_style
        )

    )


    interpretation_text = {

        "Critical":
            "Immediate attention is recommended. "
            "The assessment identified security conditions "
            "that may represent significant exposure.",

        "High":
            "High-priority security improvements are recommended. "
            "The assessment identified conditions that could "
            "increase the target's attack surface or security risk.",

        "Medium":
            "Security improvements are recommended. "
            "The assessment identified weaknesses that should "
            "be reviewed and addressed as part of normal hardening.",

        "Low":
            "The assessment identified limited security concerns. "
            "Routine hardening and security best practices are recommended."

    }


    interpretation = interpretation_text.get(

        str(level),

        "Review the identified findings and recommendations "
        "for additional context."

    )


    interpretation_table = Table(

        [[

            Paragraph(
                f"<b>Current Risk Level: "
                f"{safe_text(level).upper()}</b><br/><br/>"
                f"{safe_text(interpretation)}",
                normal_style
            )

        ]],

        colWidths=[
            480
        ]

    )


    interpretation_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#f8fafc")
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                current_risk_color
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                10
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                10
            )

        ])

    )


    elements.append(
        interpretation_table
    )


    elements.append(
        Spacer(1, 18)
    )


    # ======================================================
    # DISCLAIMER
    # ======================================================

    elements.append(

        Paragraph(
            "06  •  Assessment Disclaimer",
            section_style
        )

    )


    disclaimer_table = Table(

        [[

            Paragraph(

                "<b>SECURITY ASSESSMENT DISCLAIMER</b><br/><br/>"

                "This report is generated from automated security "
                "checks performed by SecureScan. Results should be "
                "reviewed by a qualified security professional before "
                "making security decisions.<br/><br/>"

                "Nmap NSE results and CVE references may require "
                "manual verification. A vulnerability reference "
                "does not by itself prove that a target is exploitable. "
                "Software-version matching may also produce potential "
                "or contextual references that require validation.<br/><br/>"

                "Only systems for which explicit authorization has "
                "been obtained should be scanned.",

                small_style

            )

        ]],

        colWidths=[
            480
        ]

    )


    disclaimer_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#f8fafc")
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                colors.HexColor("#94a3b8")
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                11
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                11
            )

        ])

    )


    elements.append(
        disclaimer_table
    )


    # ======================================================
    # BUILD PDF
    # ======================================================

    document.build(

        elements,

        onFirstPage=add_page_number,

        onLaterPages=add_page_number

    )


    buffer.seek(0)


    # ======================================================
    # SAFE FILE NAME
    # ======================================================

    safe_target = "".join(

        char
        if char.isalnum()
        else "_"

        for char in str(target)

    )


    filename = (

        f"SecureScan_Report_"
        f"{safe_target}.pdf"

    )


    return send_file(

        buffer,

        as_attachment=True,

        download_name=filename,

        mimetype="application/pdf"

    )


# ==========================================================
# START FLASK
# ==========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )