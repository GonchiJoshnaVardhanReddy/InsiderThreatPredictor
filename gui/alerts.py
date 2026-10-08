"""Security Alerts page."""

from __future__ import annotations

from datetime import datetime
from tkinter import messagebox, ttk
from typing import Optional

import customtkinter as ctk

from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CARD, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
)
from database import db_manager as db
from gui.theme import CardFrame, info_banner, section_title, style_treeview
from utils.helpers import fmt_dt, log, truncate


class AlertsPage(ctk.CTkFrame):
    """Searchable + filterable list of all security alerts."""

    SEVERITIES = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    STATUSES = ["ALL", "OPEN", "ACKNOWLEDGED", "RESOLVED"]

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app

        section_title(
            self, "Security Alerts",
            "All HIGH and CRITICAL events raised by the risk engine"
        )

        # Filter toolbar
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=24, pady=8)

        ctk.CTkLabel(toolbar, text="Search:", font=("Segoe UI", 11),
                     text_color=COLOUR_TEXT_DIM).pack(side="left", padx=(0, 4))
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_table())
        ctk.CTkEntry(toolbar, textvariable=self.search_var, width=180,
                     placeholder_text="user/event").pack(side="left", padx=4)

        ctk.CTkLabel(toolbar, text="Severity:", font=("Segoe UI", 11),
                     text_color=COLOUR_TEXT_DIM).pack(side="left", padx=(12, 4))
        self.sev_var = ctk.StringVar(value="ALL")
        ctk.CTkOptionMenu(toolbar, variable=self.sev_var, values=self.SEVERITIES,
                          command=lambda _v: self._refresh_table(),
                          fg_color=COLOUR_PANEL, button_color=COLOUR_BLUE,
                          text_color=COLOUR_TEXT).pack(side="left", padx=4)

        ctk.CTkLabel(toolbar, text="Status:", font=("Segoe UI", 11),
                     text_color=COLOUR_TEXT_DIM).pack(side="left", padx=(12, 4))
        self.status_var = ctk.StringVar(value="ALL")
        ctk.CTkOptionMenu(toolbar, variable=self.status_var, values=self.STATUSES,
                          command=lambda _v: self._refresh_table(),
                          fg_color=COLOUR_PANEL, button_color=COLOUR_BLUE,
                          text_color=COLOUR_TEXT).pack(side="left", padx=4)

        ctk.CTkButton(toolbar, text="✓ Acknowledge", fg_color=COLOUR_BLUE,
                      command=lambda: self._update_status("ACKNOWLEDGED")).pack(side="right", padx=4)
        ctk.CTkButton(toolbar, text="Resolve", fg_color=COLOUR_GREEN,
                      command=lambda: self._update_status("RESOLVED")).pack(side="right", padx=4)
        ctk.CTkButton(toolbar, text="Link to incident", fg_color=COLOUR_CYAN,
                      text_color=COLOUR_BG,
                      command=self._link_incident).pack(side="right", padx=4)

        # Alerts table
        card = CardFrame(self)
        card.pack(fill="both", expand=True, padx=24, pady=8)
        style = ttk.Style()
        style_treeview(style)
        cols = ("ID", "Time", "User", "Event", "Severity", "Score", "Status", "Description")
        widths = (60, 150, 130, 150, 90, 70, 110, 280)
        tree_frame = ctk.CTkFrame(card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=14)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("LOW", foreground=COLOUR_GREEN)
        self.tree.tag_configure("MEDIUM", foreground=COLOUR_YELLOW)
        self.tree.tag_configure("HIGH", foreground=COLOUR_RED)
        self.tree.tag_configure("CRITICAL", foreground=COLOUR_RED)
        self.tree.tag_configure("RESOLVED", foreground=COLOUR_TEXT_DIM)
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        # Detail panel
        self.detail_card = CardFrame(self)
        self.detail_card.pack(fill="x", padx=24, pady=(0, 12))
        self.detail_label = ctk.CTkLabel(
            self.detail_card, text="Select an alert to view details.",
            font=("Segoe UI", 12), text_color=COLOUR_TEXT,
            anchor="w", justify="left",
        )
        self.detail_label.pack(anchor="w", padx=14, pady=12)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self._refresh_table()

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self._refresh_table()

    # -----------------------------------------------------------
    def _refresh_table(self) -> None:
        severity = self.sev_var.get()
        status = self.status_var.get()
        search = self.search_var.get().strip() or None
        alerts = db.list_alerts(severity=severity, status=status, search=search)
        self.tree.delete(*self.tree.get_children())
        for alert in alerts:
            tags = [alert.get("severity", "LOW")]
            if alert.get("status") == "RESOLVED":
                tags.append("RESOLVED")
            self.tree.insert(
                "", "end", iid=str(alert["alert_id"]),
                values=(
                    alert["alert_id"],
                    fmt_dt(_parse_dt(alert.get("created_at"))),
                    alert.get("user_name") or f"User {alert['user_id']}",
                    alert.get("event_type", ""),
                    alert.get("severity", ""),
                    f"{float(alert.get('risk_score', 0)):.1f}",
                    alert.get("status", ""),
                    truncate(alert.get("description", ""), 60),
                ),
                tags=tuple(tags),
            )

    # -----------------------------------------------------------
    def _selected_alert_id(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select alert", "Please pick an alert first.")
            return None
        try:
            return int(sel[0])
        except ValueError:
            return None

    def _update_status(self, status: str) -> None:
        alert_id = self._selected_alert_id()
        if alert_id is None:
            return
        if status == "ACKNOWLEDGED":
            db.acknowledge_alert(alert_id)
        elif status == "RESOLVED":
            db.resolve_alert(alert_id)
        db.audit("analyst", "alert_status", f"alert={alert_id} status={status}")
        self._refresh_table()

    def _link_incident(self) -> None:
        alert_id = self._selected_alert_id()
        if alert_id is None:
            return
        from response import incident_response
        rows = db.list_alerts()
        alert = next((r for r in rows if r["alert_id"] == alert_id), None)
        if not alert:
            return
        if alert.get("incident_id"):
            messagebox.showinfo(
                "Already linked",
                f"Alert is already linked to incident #{alert['incident_id']}.",
            )
            return
        incidents = incident_response.list_incidents()
        candidate = next(
            (i for i in incidents if i["user_id"] == alert["user_id"] and i["status"] in ("OPEN", "UNDER INVESTIGATION")),
            None,
        )
        if not candidate:
            incident_id = db.insert_incident(
                user_id=alert["user_id"],
                trigger_score=float(alert.get("risk_score", 0)),
                summary=f"Created from alert #{alert_id}",
            )
        else:
            incident_id = candidate["incident_id"]
        db.link_alert_to_incident(alert_id, incident_id)
        db.audit("analyst", "alert_link", f"alert={alert_id} incident={incident_id}")
        messagebox.showinfo("Linked", f"Alert #{alert_id} linked to incident #{incident_id}.")
        self._refresh_table()

    def _on_select(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        alert_id = int(sel[0])
        rows = db.list_alerts()
        alert = next((a for a in rows if a["alert_id"] == alert_id), None)
        if alert:
            self.detail_label.configure(
                text=(
                    f"Alert #{alert['alert_id']}  •  User: {alert.get('user_name') or alert['user_id']}\n"
                    f"Type: {alert['event_type']}    Severity: {alert['severity']}    "
                    f"Score: {float(alert['risk_score']):.1f}\n"
                    f"Status: {alert['status']}    Linked incident: {alert.get('incident_id') or '-'}\n"
                    f"Description: {alert.get('description', '')}"
                ),
            )


def _parse_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None