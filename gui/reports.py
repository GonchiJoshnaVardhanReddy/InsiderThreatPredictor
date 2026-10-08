"""Reports page — export CSVs and a PDF."""

from __future__ import annotations

import csv as csv_mod
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import List

import customtkinter as ctk

from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CARD, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
    REPORTS_DIR,
)
from database import db_manager as db
from gui.theme import CardFrame, info_banner, section_title
from utils.helpers import log, severity_from_score


class ReportsPage(ctk.CTkFrame):
    """Export CSV / PDF reports and view quick summaries."""

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app

        section_title(
            self, "Reports",
            "Export activity, risk and incident data; produce a PDF briefing"
        )

        # Quick summary card
        self.summary_card = CardFrame(self)
        self.summary_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(self.summary_card, text="Quick summary",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(anchor="w", padx=14, pady=(12, 4))
        self.summary_label = ctk.CTkLabel(
            self.summary_card, text="Loading…",
            font=("Segoe UI", 12), text_color=COLOUR_TEXT,
            anchor="w", justify="left", wraplength=800,
        )
        self.summary_label.pack(anchor="w", padx=14, pady=(2, 12))

        # Export actions
        actions_card = CardFrame(self)
        actions_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(actions_card, text="Export options",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(anchor="w", padx=14, pady=(12, 4))

        button_grid = ctk.CTkFrame(actions_card, fg_color="transparent")
        button_grid.pack(fill="x", padx=14, pady=(4, 12))

        exports = [
            ("📋 Activity history",   self.export_activity,      COLOUR_BLUE),
            ("🚨 Incident history",   self.export_incidents,     COLOUR_RED),
            ("👥 User risk report",   self.export_users,         COLOUR_CYAN),
            ("📊 Alerts summary",     self.export_alerts,        COLOUR_YELLOW),
            ("📄 PDF security brief", self.export_pdf,           COLOUR_GREEN),
        ]
        for text, command, colour in exports:
            ctk.CTkButton(
                button_grid, text=text, fg_color=colour,
                command=command, width=200, height=42,
            ).pack(side="left", padx=6, pady=6)

        # Recent exports
        self.history_card = CardFrame(self)
        self.history_card.pack(fill="both", expand=True, padx=24, pady=8)
        ctk.CTkLabel(self.history_card, text="Generated reports",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(anchor="w", padx=14, pady=(12, 4))
        self.history_box = ctk.CTkTextbox(
            self.history_card, fg_color=COLOUR_BG, text_color=COLOUR_TEXT, height=260,
        )
        self.history_box.pack(fill="both", expand=True, padx=14, pady=(2, 12))
        self.history_box.configure(state="disabled")

        info_banner(
            self,
            f"Reports are saved under {REPORTS_DIR}. "
            "You can also pick a destination when you click Export.",
            COLOUR_TEXT_DIM,
        ).pack(anchor="w", padx=24, pady=(0, 12))

        self.refresh()

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self.refresh()

    # -----------------------------------------------------------
    def refresh(self) -> None:
        try:
            users = db.list_users()
            incidents = db.list_incidents()
            alerts = db.list_alerts()
            events = db.count_activity()
            sev = db.alerts_per_severity()
            high_risk = sum(1 for u in users if u.get("risk_score", 0) >= 50)
            summary = (
                f"Total events logged: {events}\n"
                f"Total alerts: {len(alerts)} (LOW={sev['LOW']}, MEDIUM={sev['MEDIUM']}, "
                f"HIGH={sev['HIGH']}, CRITICAL={sev['CRITICAL']})\n"
                f"Total incidents: {len(incidents)}\n"
                f"High-risk users: {high_risk}\n"
                f"Users by department: {self._by_department(users)}\n"
            )
            self.summary_label.configure(text=summary)
        except Exception as exc:  # pragma: no cover
            log.warning("Refresh summary failed: %s", exc)

    # -----------------------------------------------------------
    def _by_department(self, users) -> str:
        counts: dict = {}
        for u in users:
            counts[u["department"]] = counts.get(u["department"], 0) + 1
        return ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "—"

    # -----------------------------------------------------------
    def _write_csv(self, default_name: str, headers: List[str], rows: List[List]):
        target = filedialog.asksaveasfilename(
            title="Save report",
            initialdir=str(REPORTS_DIR),
            initialfile=default_name,
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not target:
            return None
        path = Path(target)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv_mod.writer(handle)
            writer.writerow(headers)
            writer.writerows(rows)
        db.audit("analyst", "export_csv", str(path))
        self._log(f"CSV saved: {path}")
        return path

    # -----------------------------------------------------------
    def export_activity(self) -> None:
        rows = db.recent_activity(limit=10000)
        headers = ["timestamp", "user_id", "user_name", "event_type",
                   "risk_points", "login_hour", "files_accessed",
                   "download_mb", "usb_activity", "privileged",
                   "data_transfer_mb", "description"]
        data = [
            [r.get(h, "") for h in headers]
            for r in rows
        ]
        path = self._write_csv("activity_history.csv", headers, data)
        if path:
            messagebox.showinfo("Export complete", f"Activity history saved to:\n{path}")

    def export_incidents(self) -> None:
        rows = db.list_incidents()
        headers = ["incident_id", "user_id", "user_name", "trigger_score",
                   "status", "summary", "created_at", "updated_at"]
        data = [[r.get(h, "") for h in headers] for r in rows]
        path = self._write_csv("incident_history.csv", headers, data)
        if path:
            messagebox.showinfo("Export complete", f"Incident history saved to:\n{path}")

    def export_users(self) -> None:
        rows = db.list_users()
        headers = ["user_id", "name", "department", "role", "email",
                   "baseline_login_hour", "baseline_daily_downloads",
                   "baseline_file_access", "risk_score", "account_status"]
        data = [[r.get(h, "") for h in headers] for r in rows]
        path = self._write_csv("user_risk_report.csv", headers, data)
        if path:
            messagebox.showinfo("Export complete", f"User risk report saved to:\n{path}")

    def export_alerts(self) -> None:
        rows = db.list_alerts()
        headers = ["alert_id", "user_id", "user_name", "event_type",
                   "risk_score", "severity", "status", "description",
                   "created_at", "acknowledged_at", "resolved_at"]
        data = [[r.get(h, "") for h in headers] for r in rows]
        path = self._write_csv("alerts_summary.csv", headers, data)
        if path:
            messagebox.showinfo("Export complete", f"Alerts summary saved to:\n{path}")

    # -----------------------------------------------------------
    def export_pdf(self) -> None:
        target = filedialog.asksaveasfilename(
            title="Save PDF briefing",
            initialdir=str(REPORTS_DIR),
            initialfile="security_brief.pdf",
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")],
        )
        if not target:
            return
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import (
                Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            )
        except ImportError:
            messagebox.showerror(
                "ReportLab not installed",
                "Install reportlab via `pip install reportlab` to enable PDF export.",
            )
            return

        path = Path(target)
        doc = SimpleDocTemplate(str(path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph("Insider Threat Predictor — Security Brief", styles["Title"]))
        story.append(Paragraph(
            f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 12))

        users = db.list_users()
        incidents = db.list_incidents()
        alerts = db.list_alerts()
        sev = db.alerts_per_severity()
        events = db.count_activity()
        high_risk = sum(1 for u in users if u.get("risk_score", 0) >= 50)

        story.append(Paragraph("Summary", styles["Heading2"]))
        summary_rows = [
            ["Metric", "Value"],
            ["Total users", len(users)],
            ["High-risk users", high_risk],
            ["Total events logged", events],
            ["Total alerts", len(alerts)],
            ["Alerts (LOW)", sev["LOW"]],
            ["Alerts (MEDIUM)", sev["MEDIUM"]],
            ["Alerts (HIGH)", sev["HIGH"]],
            ["Alerts (CRITICAL)", sev["CRITICAL"]],
            ["Total incidents", len(incidents)],
        ]
        story.append(_pdf_table(summary_rows))

        story.append(Paragraph("Top 10 users", styles["Heading2"]))
        user_rows = [["Name", "Department", "Risk", "Status"]]
        for u in sorted(users, key=lambda x: -x.get("risk_score", 0))[:10]:
            user_rows.append([
                u["name"], u["department"],
                f"{u.get('risk_score', 0):.1f}",
                u.get("account_status", ""),
            ])
        story.append(_pdf_table(user_rows))

        story.append(Paragraph("Recent alerts", styles["Heading2"]))
        alert_rows = [["Time", "User", "Event", "Severity", "Status"]]
        for a in alerts[:15]:
            alert_rows.append([
                str(a.get("created_at", ""))[:19],
                a.get("user_name") or f"User {a['user_id']}",
                a.get("event_type", ""),
                a.get("severity", ""),
                a.get("status", ""),
            ])
        story.append(_pdf_table(alert_rows))

        doc.build(story)
        db.audit("analyst", "export_pdf", str(path))
        self._log(f"PDF saved: {path}")
        messagebox.showinfo("PDF exported", f"Security brief saved to:\n{path}")

    # -----------------------------------------------------------
    def _log(self, message: str) -> None:
        self.history_box.configure(state="normal")
        self.history_box.insert("0.0", f"{datetime.now():%Y-%m-%d %H:%M:%S} — {message}\n")
        self.history_box.configure(state="disabled")


def _pdf_table(rows: List[List]) -> "Table":
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    table = Table(rows)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F4C81")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ]
    table.setStyle(TableStyle(style_cmds))
    return table