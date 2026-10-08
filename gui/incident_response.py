"""Incident Response page."""

from __future__ import annotations

from datetime import datetime
from tkinter import messagebox, ttk

import customtkinter as ctk

from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CARD, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
)
from database import db_manager as db
from gui.theme import CardFrame, info_banner, section_title, style_treeview
from response import incident_response
from utils.helpers import fmt_dt, log


class IncidentResponsePage(ctk.CTkFrame):
    """Manage simulated incident response actions."""

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app
        self.selected_incident_id: int | None = None

        section_title(
            self, "Automated Response",
            "Safely simulated containment, investigation and recovery actions",
        )

        info_banner(
            self,
            "All actions operate only on the fictional user accounts in this system. "
            "Nothing is changed on real systems.",
            COLOUR_TEXT_DIM,
        ).pack(anchor="w", padx=24, pady=(2, 8))

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=24, pady=4)
        ctk.CTkButton(toolbar, text="Refresh", fg_color=COLOUR_BLUE,
                      command=self._refresh).pack(side="left", padx=4)

        # Incidents table
        inc_card = CardFrame(self)
        inc_card.pack(fill="both", expand=True, padx=24, pady=8)
        ctk.CTkLabel(inc_card, text="Open & recent incidents",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(6, 4))
        style = ttk.Style()
        style_treeview(style)
        cols = ("ID", "User", "Score", "Status", "Created", "Updated")
        widths = (50, 160, 70, 160, 150, 150)
        tree_frame = ctk.CTkFrame(inc_card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=6)
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=8)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("OPEN", foreground=COLOUR_RED)
        self.tree.tag_configure("UNDER INVESTIGATION", foreground=COLOUR_YELLOW)
        self.tree.tag_configure("CONTAINED", foreground=COLOUR_CYAN)
        self.tree.tag_configure("RESOLVED", foreground=COLOUR_TEXT_DIM)
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Action buttons
        actions_card = CardFrame(self)
        actions_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(actions_card, text="Simulated response actions",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(anchor="w", padx=14, pady=(10, 4))
        action_row = ctk.CTkFrame(actions_card, fg_color="transparent")
        action_row.pack(fill="x", padx=14, pady=(2, 10))

        self.action_buttons = {}
        for code, (label, detail) in incident_response.RESPONSE_ACTIONS.items():
            colour = {
                "ACK": COLOUR_BLUE,
                "INVEST": COLOUR_BLUE,
                "CONTAIN": COLOUR_RED,
                "RESTORE": COLOUR_GREEN,
                "RESOLVE": COLOUR_GREEN,
            }.get(code, COLOUR_CYAN)
            btn = ctk.CTkButton(
                action_row, text=label, width=140, fg_color=colour,
                command=lambda c=code: self._perform(c),
            )
            btn.pack(side="left", padx=4)
            self.action_buttons[code] = btn
        self.status_label = ctk.CTkLabel(
            actions_card, text="Select an incident to enable actions.",
            font=("Segoe UI", 11), text_color=COLOUR_TEXT_DIM,
        )
        self.status_label.pack(anchor="w", padx=14, pady=(0, 10))

        # Audit log
        audit_card = CardFrame(self)
        audit_card.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        ctk.CTkLabel(audit_card, text="Response audit log",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(anchor="w", padx=14, pady=(10, 4))
        cols2 = ("Time", "Incident", "User", "Action", "By", "Details")
        widths2 = (150, 60, 130, 110, 110, 300)
        tree_frame2 = ctk.CTkFrame(audit_card, fg_color="transparent")
        tree_frame2.pack(fill="both", expand=True, padx=10, pady=(2, 10))
        self.audit_tree = ttk.Treeview(
            tree_frame2, columns=cols2, show="headings", height=8,
        )
        for col, w in zip(cols2, widths2):
            self.audit_tree.heading(col, text=col)
            self.audit_tree.column(col, width=w, anchor="w")
        self.audit_tree.pack(side="left", fill="both", expand=True)
        sb2 = ttk.Scrollbar(tree_frame2, orient="vertical", command=self.audit_tree.yview)
        sb2.pack(side="right", fill="y")
        self.audit_tree.configure(yscrollcommand=sb2.set)

        self._refresh()

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self._refresh()

    # -----------------------------------------------------------
    def _refresh(self) -> None:
        # Incidents
        self.tree.delete(*self.tree.get_children())
        incidents = incident_response.list_incidents()
        for inc in incidents:
            self.tree.insert(
                "", "end", iid=str(inc["incident_id"]),
                values=(
                    inc["incident_id"],
                    inc.get("user_name") or f"User {inc['user_id']}",
                    f"{float(inc['trigger_score']):.1f}",
                    inc["status"],
                    fmt_dt(_parse_dt(inc.get("created_at"))),
                    fmt_dt(_parse_dt(inc.get("updated_at"))),
                ),
                tags=(inc["status"],),
            )

        # Audit log
        self.audit_tree.delete(*self.audit_tree.get_children())
        actions = incident_response.actions_overview()[:50]
        for a in actions:
            self.audit_tree.insert(
                "", "end",
                values=(
                    fmt_dt(_parse_dt(a.get("timestamp"))),
                    a.get("incident_id", "-"),
                    a.get("user_name") or f"User {a['user_id']}",
                    a.get("action_type", ""),
                    a.get("performed_by", ""),
                    a.get("details", ""),
                ),
            )

    # -----------------------------------------------------------
    def _on_select(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            self.selected_incident_id = None
            return
        try:
            self.selected_incident_id = int(sel[0])
        except ValueError:
            self.selected_incident_id = None
            return
        incident = db.get_incident(self.selected_incident_id)
        if incident:
            recommended = incident_response.recommended_actions(incident)
            self.status_label.configure(
                text=(
                    f"Incident #{self.selected_incident_id} selected. "
                    f"Recommended next step(s): {', '.join(recommended) or 'none'}"
                )
            )

    def _perform(self, action: str) -> None:
        if self.selected_incident_id is None:
            messagebox.showwarning("Select an incident", "Pick an incident first.")
            return
        try:
            result = incident_response.perform_action(self.selected_incident_id, action)
        except Exception as exc:
            log.exception("Response action failed: %s", exc)
            messagebox.showerror("Action failed", str(exc))
            return
        messagebox.showinfo(
            "Action performed",
            f"{action} applied to incident #{self.selected_incident_id}.",
        )
        self._refresh()
        # Propagate to other pages
        if self.app.pages.get("Dashboard"):
            self.app.pages["Dashboard"].refresh()


def _parse_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None