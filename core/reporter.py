import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class AgentGuardReporter:
    """
    AgentGuard Resmi Denetim ve EU AI Act Uyum Raporlayıcısı (PDF Generator).
    """

    @staticmethod
    def generate_pdf_report(scan_results: dict) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        normal_style = styles["Normal"]
        
        # Özel Stiller
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=6
        )
        
        subtitle_style = ParagraphStyle(
            "SubTitleStyle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=15
        )

        heading2_style = ParagraphStyle(
            "Heading2Style",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0F172A"),
            spaceBefore=12,
            spaceAfter=8
        )

        story = []

        # Başlık ve Üst Bilgi
        story.append(Paragraph("🛡️ AgentGuard AI Security Audit Report", title_style))
        story.append(Paragraph(f"Standard: <b>EU AI Act (Art. 15 Cybersecurity) & OWASP LLM Top 10</b> | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", subtitle_style))
        story.append(Spacer(1, 10))

        # Özet Tablosu (Executive Summary)
        status_color = colors.HexColor("#DC2626") if scan_results.get("compliance_status") == "FAILED" else colors.HexColor("#16A34A")
        
        summary_data = [
            ["Metric", "Value"],
            ["Target System", str(scan_results.get("target", "Target LLM Agent"))],
            ["Total Attack Vectors Tested", str(scan_results.get("total_tests", 0))],
            ["Vulnerabilities Detected", str(scan_results.get("vulnerable_tests", 0))],
            ["Overall Risk Score", f"%{scan_results.get('risk_score', 0)}"],
            ["EU AI Act Compliance Status", scan_results.get("compliance_status", "UNKNOWN")]
        ]

        summary_table = Table(summary_data, colWidths=[240, 300])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#F1F5F9")),
            ("TEXTCOLOR", (0, 0), (1, 0), colors.HexColor("#0F172A")),
            ("FONTNAME", (0, 0), (1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TEXTCOLOR", (1, 5), (1, 5), status_color),
            ("FONTNAME", (1, 5), (1, 5), "Helvetica-Bold"),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 15))

        # Zafiyet Detayları Tablosu
        story.append(Paragraph("Detailed Vulnerability Findings", heading2_style))
        
        findings = scan_results.get("findings", [])
        if not findings:
            story.append(Paragraph("No critical vulnerabilities were identified during this evaluation run.", normal_style))
        else:
            findings_data = [["ID & Severity", "Category & Finding", "Attack Prompt & Leak Summary"]]
            for item in findings:
                id_sev = f"{item.get('id')}\n[{item.get('severity')}]"
                cat_name = f"<b>{item.get('category')}</b><br/>{item.get('name')}"
                details = f"<b>Payload:</b> {item.get('attack_prompt')[:100]}...<br/><b>Leak:</b> {str(item.get('agent_leak'))[:120]}..."
                
                findings_data.append([
                    Paragraph(id_sev, normal_style),
                    Paragraph(cat_name, normal_style),
                    Paragraph(details, normal_style)
                ])

            findings_table = Table(findings_data, colWidths=[90, 180, 270])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8FAFC")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(findings_table)

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()