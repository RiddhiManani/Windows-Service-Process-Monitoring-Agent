"""
report_generator.py - Professional Report Generator
=====================================================
Generates comprehensive security reports in PDF, CSV, Excel,
JSON, and TXT formats with charts, threat timelines, and
MITRE ATT&CK mappings.

Author: Security Research Team
Version: 1.0.0
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, Image,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from modules.logger import get_logger
from modules.utils import get_system_info, ensure_directory, format_timestamp

logger = get_logger("report_generator")

REPORTS_DIR = "reports"
EXPORTS_DIR = "exports"

SEVERITY_COLORS = {
    "Critical": "#DC143C",
    "High":     "#FF4500",
    "Medium":   "#FFA500",
    "Low":      "#1E90FF",
}


class ReportGenerator:
    """
    Generates professional security reports in multiple formats.
    Includes charts, threat timelines, MITRE mappings, and system info.
    """

    def __init__(self, db_manager, alert_manager) -> None:
        self._db = db_manager
        self._alerts = alert_manager
        ensure_directory(REPORTS_DIR)
        ensure_directory(EXPORTS_DIR)
        logger.info("ReportGenerator initialized.")

    def _timestamp_str(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _report_name(self, fmt: str) -> str:
        return f"SecurityReport_{self._timestamp_str()}.{fmt}"

    # ------------------------------------------------------------------
    # Chart Generators
    # ------------------------------------------------------------------

    def _generate_severity_chart(self, summary: dict, out_path: str) -> str:
        """Generate a pie chart of alerts by severity."""
        labels, sizes, chart_colors = [], [], []
        for sev, color in SEVERITY_COLORS.items():
            count = summary.get(sev, 0)
            if count > 0:
                labels.append(f"{sev} ({count})")
                sizes.append(count)
                chart_colors.append(color)
        if not sizes:
            sizes, labels, chart_colors = [1], ["No Alerts"], ["#555555"]

        fig, ax = plt.subplots(figsize=(6, 4), facecolor="#1a1a2e")
        ax.set_facecolor("#1a1a2e")
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=chart_colors,
            autopct="%1.1f%%", startangle=140,
            textprops={"color": "white", "fontsize": 9},
        )
        for at in autotexts:
            at.set_color("white")
        ax.set_title("Alert Severity Distribution", color="white", fontsize=12, pad=12)
        plt.tight_layout()
        plt.savefig(out_path, dpi=120, bbox_inches="tight", facecolor="#1a1a2e")
        plt.close(fig)
        return out_path

    def _generate_top_processes_chart(self, top_procs: list, out_path: str) -> str:
        """Generate a horizontal bar chart of top suspicious processes."""
        if not top_procs:
            top_procs = [{"process_name": "None", "alert_count": 0}]
        names = [p["process_name"][:20] for p in top_procs[:10]]
        counts = [p["alert_count"] for p in top_procs[:10]]

        fig, ax = plt.subplots(figsize=(7, 4), facecolor="#1a1a2e")
        ax.set_facecolor("#16213e")
        bars = ax.barh(names, counts, color="#DC143C", edgecolor="#FF6B6B")
        ax.set_xlabel("Alert Count", color="white")
        ax.set_title("Top Suspicious Processes", color="white", fontsize=12)
        ax.tick_params(colors="white")
        ax.spines["bottom"].set_color("#444")
        ax.spines["left"].set_color("#444")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    str(count), va="center", color="white", fontsize=8)
        plt.tight_layout()
        plt.savefig(out_path, dpi=120, bbox_inches="tight", facecolor="#1a1a2e")
        plt.close(fig)
        return out_path

    def _generate_timeline_chart(self, timeline: list, out_path: str) -> str:
        """Generate an alert timeline line chart."""
        if not timeline:
            fig, ax = plt.subplots(figsize=(8, 3), facecolor="#1a1a2e")
            ax.text(0.5, 0.5, "No timeline data", ha="center", va="center",
                    color="white", transform=ax.transAxes)
            plt.savefig(out_path, dpi=100, facecolor="#1a1a2e")
            plt.close(fig)
            return out_path

        times = [t["time"] for t in timeline[-20:]]
        for sev, color in SEVERITY_COLORS.items():
            vals = [t.get(sev, 0) for t in timeline[-20:]]
            plt.plot(times, vals, label=sev, color=color, linewidth=2, marker="o", markersize=4)

        fig = plt.gcf()
        fig.set_facecolor("#1a1a2e")
        ax = plt.gca()
        ax.set_facecolor("#16213e")
        ax.tick_params(colors="white", labelsize=7)
        ax.set_title("Alert Timeline", color="white", fontsize=12)
        ax.set_xlabel("Time", color="white")
        ax.set_ylabel("Count", color="white")
        plt.xticks(rotation=45, ha="right")
        ax.legend(facecolor="#1a1a2e", labelcolor="white", fontsize=8)
        plt.tight_layout()
        plt.savefig(out_path, dpi=120, bbox_inches="tight", facecolor="#1a1a2e")
        plt.close()
        return out_path

    # ------------------------------------------------------------------
    # Data Collectors
    # ------------------------------------------------------------------

    def _collect_report_data(self) -> dict:
        """Collect all data needed for report generation."""
        sys_info = get_system_info()
        alert_summary = self._db.get_alert_summary()
        all_alerts = self._db.get_all_alerts(limit=500)
        top_procs = self._alerts.get_top_suspicious_processes(10)
        timeline = self._alerts.get_alert_timeline()
        processes = self._db.get_recent_processes(100)
        services = self._db.get_recent_services(100)

        return {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_info": sys_info,
            "alert_summary": alert_summary,
            "all_alerts": all_alerts,
            "top_processes": top_procs,
            "timeline": timeline,
            "processes": processes,
            "services": services,
        }

    # ------------------------------------------------------------------
    # JSON Report
    # ------------------------------------------------------------------

    def generate_json_report(self) -> str:
        """Generate a comprehensive JSON report."""
        data = self._collect_report_data()
        path = os.path.join(REPORTS_DIR, self._report_name("json"))
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, default=str)
            logger.info(f"JSON report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"JSON report failed: {e}")
            return ""

    # ------------------------------------------------------------------
    # CSV Report
    # ------------------------------------------------------------------

    def generate_csv_report(self) -> str:
        """Generate a CSV report of all alerts."""
        data = self._collect_report_data()
        path = os.path.join(REPORTS_DIR, self._report_name("csv"))
        try:
            alerts = data["all_alerts"]
            if not alerts:
                alerts = [{"message": "No alerts recorded"}]
            df = pd.DataFrame(alerts)
            df.to_csv(path, index=False, encoding="utf-8")
            logger.info(f"CSV report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"CSV report failed: {e}")
            return ""

    # ------------------------------------------------------------------
    # Excel Report
    # ------------------------------------------------------------------

    def generate_excel_report(self) -> str:
        """Generate a multi-sheet Excel report."""
        data = self._collect_report_data()
        path = os.path.join(REPORTS_DIR, self._report_name("xlsx"))
        try:
            with pd.ExcelWriter(path, engine="openpyxl") as writer:
                # Alerts sheet
                alerts_df = pd.DataFrame(data["all_alerts"]) if data["all_alerts"] else pd.DataFrame({"message": ["No alerts"]})
                alerts_df.to_excel(writer, sheet_name="Alerts", index=False)

                # Summary sheet
                summary = data["alert_summary"]
                summary_df = pd.DataFrame([{
                    "Severity": k, "Count": v
                } for k, v in summary.items()])
                summary_df.to_excel(writer, sheet_name="Summary", index=False)

                # Processes sheet
                procs_df = pd.DataFrame(data["processes"]) if data["processes"] else pd.DataFrame({"message": ["No data"]})
                procs_df.to_excel(writer, sheet_name="Processes", index=False)

                # Services sheet
                svcs_df = pd.DataFrame(data["services"]) if data["services"] else pd.DataFrame({"message": ["No data"]})
                svcs_df.to_excel(writer, sheet_name="Services", index=False)

                # Top Processes sheet
                top_df = pd.DataFrame(data["top_processes"]) if data["top_processes"] else pd.DataFrame({"message": ["No data"]})
                top_df.to_excel(writer, sheet_name="Top Threats", index=False)

                # System Info sheet
                sys_flat = {k: str(v) for k, v in data["system_info"].items()}
                sys_df = pd.DataFrame([{"Property": k, "Value": v} for k, v in sys_flat.items()])
                sys_df.to_excel(writer, sheet_name="System Info", index=False)

            logger.info(f"Excel report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"Excel report failed: {e}")
            return ""

    # ------------------------------------------------------------------
    # TXT Report
    # ------------------------------------------------------------------

    def generate_txt_report(self) -> str:
        """Generate a human-readable plain text report."""
        data = self._collect_report_data()
        path = os.path.join(REPORTS_DIR, self._report_name("txt"))
        lines = []
        SEP = "=" * 70

        lines += [
            SEP,
            "  WINDOWS SERVICE & PROCESS MONITORING AGENT",
            "  SECURITY REPORT",
            SEP,
            f"  Generated : {data['generated_at']}",
            f"  Hostname  : {data['system_info'].get('hostname', 'N/A')}",
            f"  OS        : {data['system_info'].get('os', 'N/A')}",
            SEP, "",
            "ALERT SUMMARY",
            "-" * 40,
        ]
        for sev in ("Critical", "High", "Medium", "Low", "Total"):
            lines.append(f"  {sev:<12}: {data['alert_summary'].get(sev, 0)}")

        lines += ["", "TOP SUSPICIOUS PROCESSES", "-" * 40]
        for p in data["top_processes"][:10]:
            lines.append(f"  {p['process_name']:<30} Alerts: {p['alert_count']}")

        lines += ["", "RECENT CRITICAL ALERTS", "-" * 40]
        critical = [a for a in data["all_alerts"] if a.get("severity") == "Critical"][:10]
        for a in critical:
            lines.append(f"  [{a.get('timestamp','')[:19]}] {a.get('process_name','N/A')} | {a.get('reason','')[:60]}")

        lines += ["", SEP, "  END OF REPORT", SEP]

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            logger.info(f"TXT report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"TXT report failed: {e}")
            return ""

    # ------------------------------------------------------------------
    # PDF Report
    # ------------------------------------------------------------------

    def generate_pdf_report(self) -> str:
        """Generate a professional PDF report with charts."""
        data = self._collect_report_data()
        path = os.path.join(REPORTS_DIR, self._report_name("pdf"))
        charts_dir = os.path.join(REPORTS_DIR, "charts")
        ensure_directory(charts_dir)
        ts = self._timestamp_str()

        # Generate charts
        pie_path   = os.path.join(charts_dir, f"severity_{ts}.png")
        bar_path   = os.path.join(charts_dir, f"top_procs_{ts}.png")
        time_path  = os.path.join(charts_dir, f"timeline_{ts}.png")
        self._generate_severity_chart(data["alert_summary"], pie_path)
        self._generate_top_processes_chart(data["top_processes"], bar_path)
        self._generate_timeline_chart(data["timeline"], time_path)

        styles = getSampleStyleSheet()
        dark_bg = colors.HexColor("#0d1117")
        accent  = colors.HexColor("#00d4ff")
        red_c   = colors.HexColor("#DC143C")
        white_c = colors.white

        title_style = ParagraphStyle("Title", parent=styles["Title"],
            textColor=accent, fontSize=20, spaceAfter=6, alignment=TA_CENTER)
        sub_style = ParagraphStyle("Sub", parent=styles["Normal"],
            textColor=white_c, fontSize=10, spaceAfter=4, alignment=TA_CENTER)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
            textColor=accent, fontSize=13, spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle("Body", parent=styles["Normal"],
            textColor=white_c, fontSize=9, spaceAfter=3)
        warn_style = ParagraphStyle("Warn", parent=styles["Normal"],
            textColor=red_c, fontSize=9, spaceAfter=3)

        doc = SimpleDocTemplate(path, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm)

        story = []

        # Title page
        story.append(Paragraph("Windows Service &amp; Process Monitoring Agent", title_style))
        story.append(Paragraph("SECURITY ANALYSIS REPORT", sub_style))
        story.append(HRFlowable(width="100%", thickness=1, color=accent, spaceAfter=8))
        sys_info = data["system_info"]
        story.append(Paragraph(f"Generated: {data['generated_at']}", body_style))
        story.append(Paragraph(f"Hostname: {sys_info.get('hostname','N/A')}", body_style))
        story.append(Paragraph(f"OS: {sys_info.get('os','N/A')}", body_style))
        story.append(Paragraph(f"IP Address: {sys_info.get('ip_address','N/A')}", body_style))
        story.append(Spacer(1, 0.4*cm))

        # Alert Summary table
        story.append(Paragraph("Alert Summary", h2_style))
        summary = data["alert_summary"]
        tbl_data = [["Severity", "Count"]]
        sev_colors_map = {"Critical": "#DC143C", "High": "#FF4500", "Medium": "#FFA500", "Low": "#1E90FF"}
        for sev in ("Critical", "High", "Medium", "Low", "Total"):
            tbl_data.append([sev, str(summary.get(sev, 0))])
        tbl = Table(tbl_data, colWidths=[8*cm, 4*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#00d4ff")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.black),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#161b22")),
            ("TEXTCOLOR",  (0,1), (-1,-1), white_c),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#161b22"), colors.HexColor("#1c2128")]),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("ALIGN",      (1,0), (1,-1), "CENTER"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 0.5*cm))

        # Charts
        story.append(Paragraph("Threat Visualisation", h2_style))
        for img_path in (pie_path, bar_path, time_path):
            if os.path.isfile(img_path):
                story.append(Image(img_path, width=14*cm, height=8*cm))
                story.append(Spacer(1, 0.3*cm))

        story.append(PageBreak())

        # Recent Critical Alerts
        story.append(Paragraph("Critical Alerts", h2_style))
        critical = [a for a in data["all_alerts"] if a.get("severity") == "Critical"][:20]
        if critical:
            alert_tbl_data = [["Time", "Process", "PID", "Reason"]]
            for a in critical:
                alert_tbl_data.append([
                    str(a.get("timestamp",""))[:19],
                    str(a.get("process_name","N/A"))[:20],
                    str(a.get("pid","")),
                    str(a.get("reason",""))[:55],
                ])
            atbl = Table(alert_tbl_data, colWidths=[3.5*cm, 3.5*cm, 1.5*cm, 8.5*cm])
            atbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), red_c),
                ("TEXTCOLOR",  (0,0), (-1,0), white_c),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#161b22")),
                ("TEXTCOLOR",  (0,1), (-1,-1), white_c),
                ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#30363d")),
                ("FONTSIZE",   (0,0), (-1,-1), 7),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#161b22"), colors.HexColor("#1c2128")]),
            ]))
            story.append(atbl)
        else:
            story.append(Paragraph("No critical alerts recorded.", body_style))

        story.append(Spacer(1, 0.5*cm))

        # MITRE ATT&CK mapping
        story.append(Paragraph("MITRE ATT&CK Technique Mapping", h2_style))
        mitre_counts: dict = {}
        for a in data["all_alerts"]:
            t = a.get("mitre_technique", "N/A")
            mitre_counts[t] = mitre_counts.get(t, 0) + 1
        mitre_tbl_data = [["MITRE Technique", "Alert Count"]]
        for tech, cnt in sorted(mitre_counts.items(), key=lambda x: -x[1])[:15]:
            mitre_tbl_data.append([tech, str(cnt)])
        mtbl = Table(mitre_tbl_data, colWidths=[10*cm, 4*cm])
        mtbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#00d4ff")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.black),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#161b22")),
            ("TEXTCOLOR",  (0,1), (-1,-1), white_c),
            ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#30363d")),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
        ]))
        story.append(mtbl)

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", h2_style))
        recs = [
            "Investigate all Critical and High severity alerts immediately.",
            "Ensure Windows Defender and security services are running.",
            "Review processes executing from Temp, Downloads, or Recycle Bin.",
            "Audit startup registry keys for unauthorized persistence entries.",
            "Monitor parent-child process chains for LOLBin abuse patterns.",
            "Keep Windows and all software patched and up to date.",
            "Restrict PowerShell execution policy and enable script block logging.",
            "Deploy application whitelisting to prevent unauthorized execution.",
        ]
        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(f"{i}. {rec}", body_style))

        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=accent))
        story.append(Paragraph("Windows Service &amp; Process Monitoring Agent | Confidential Security Report", sub_style))

        try:
            doc.build(story)
            logger.info(f"PDF report generated: {path}")
            return path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return ""

    # ------------------------------------------------------------------
    # One-Click All Reports
    # ------------------------------------------------------------------

    def generate_all_reports(self) -> dict:
        """
        Generate all report formats at once.

        Returns:
            Dictionary mapping format to file path.
        """
        logger.info("Generating all report formats...")
        return {
            "pdf":   self.generate_pdf_report(),
            "csv":   self.generate_csv_report(),
            "excel": self.generate_excel_report(),
            "json":  self.generate_json_report(),
            "txt":   self.generate_txt_report(),
        }

    def export_logs_csv(self, logs: list) -> str:
        """
        Export a list of log dicts to a CSV file.

        Args:
            logs: List of log record dicts.

        Returns:
            Path to the generated CSV file.
        """
        path = os.path.join(EXPORTS_DIR, f"Logs_{self._timestamp_str()}.csv")
        try:
            if not logs:
                logs = [{"message": "No logs"}]
            df = pd.DataFrame(logs)
            df.to_csv(path, index=False, encoding="utf-8")
            logger.info(f"Logs exported to CSV: {path}")
            return path
        except Exception as e:
            logger.error(f"Log CSV export failed: {e}")
            return ""

    def export_alerts_excel(self, alerts: list) -> str:
        """
        Export alert data to an Excel file.

        Args:
            alerts: List of alert dicts.

        Returns:
            Path to the generated Excel file.
        """
        path = os.path.join(EXPORTS_DIR, f"Alerts_{self._timestamp_str()}.xlsx")
        try:
            df = pd.DataFrame(alerts) if alerts else pd.DataFrame({"message": ["No alerts"]})
            df.to_excel(path, index=False, engine="openpyxl")
            logger.info(f"Alerts exported to Excel: {path}")
            return path
        except Exception as e:
            logger.error(f"Alert Excel export failed: {e}")
            return ""
