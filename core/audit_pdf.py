import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from core.models import SecurityAuditReport

class AuditPDFGenerator:
    @staticmethod
    def build(report: SecurityAuditReport) -> bytes:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("TStyle", parent=styles["Heading1"], fontSize=20, textColor=colors.HexColor("#0F172A"), spaceAfter=4)
        sub_style = ParagraphStyle("SStyle", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#64748B"), spaceAfter=14)
        h2_style = ParagraphStyle("H2Style", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#1E293B"), spaceBefore=10, spaceAfter=6)
        cell_style = ParagraphStyle("CStyle", parent=styles["Normal"], fontSize=8, leading=10)

        story = []
        story.append(Paragraph("🛡️ AgentGuard Cybersecurity Audit Report", title_style))
        story.append(Paragraph(f"Standards: <b>EU AI Act (Art. 15) & OWASP Agentic Top 10</b> | Execution Time: {report.execution_time_seconds}s", sub_style))

        status_color = colors.HexColor("#DC2626") if report.compliance_status == "FAILED" else colors.HexColor("#16A34A")
        summary_rows = [
            ["Metric", "Result"],
            ["Target System", report.target_system],
            ["Model", report.model_name],
            ["Total Test Vectors", str(report.total_vectors_tested)],
            ["Vulnerabilities Found", str(report.vulnerabilities_detected)],
            ["Calculated Risk Score", f"%{report.risk_score_percentage}"],
            ["EU AI Act Compliance", report.compliance_status]
        ]
        
        t_summary = Table(summary_rows, colWidths=[200, 340])
        t_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TEXTCOLOR", (1, 6), (1, 6), status_color),
            ("FONTNAME", (1, 6), (1, 6), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 14))

        story.append(Paragraph("Identified Security Findings & Recommendations", h2_style))
        if not report.findings:
            story.append(Paragraph("No critical vulnerabilities were triggered.", cell_style))
        else:
            findings_data = [["ID & Severity", "Category & Finding", "Details & Mitigation"]]
            for f in report.findings:
                id_sev = f"<b>{f.vector_id}</b><br/><font color='red'>[{f.severity.value}]</font>"
                cat = f"<b>{f.vector_name}</b><br/>{f.category.value}"
                detail = f"<b>Leak:</b> {f.response_text[:110]}...<br/><b>Fix:</b> {f.mitigation_advice}"
                
                findings_data.append([
                    Paragraph(id_sev, cell_style),
                    Paragraph(cat, cell_style),
                    Paragraph(detail, cell_style)
                ])

            t_findings = Table(findings_data, colWidths=[85, 175, 280])
            t_findings.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8FAFC")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(t_findings)

        doc.build(story)
        buf.seek(0)
        return buf.getvalue()