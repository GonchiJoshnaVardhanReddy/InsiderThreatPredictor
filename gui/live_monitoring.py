"""Live Monitoring page — shows real OS monitor events and simulated activity."""

from __future__ import annotations

from datetime import datetime
from tkinter import ttk
from typing import Optional

import customtkinter as ctk

from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CARD, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
)
from database import db_manager as db
from engine.risk_engine import RISK_BANDS, band_for_score
from gui.theme import CardFrame, info_banner, section_title, style_treeview
from monitor.base import MonitorEvent
from utils.helpers import fmt_dt


class LiveMonitoringPage(ctk.CTkFrame):
    """Streams both real monitor events and simulated activity."""

    MAX_ROWS = 80

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app

        section_title(
            self, "Live Monitoring",
            "Real OS activity from the monitors + optional activity simulator"
        )

        # Filter / control row
        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.pack(fill="x", padx=24, pady=6)
        self.sim_start_button = ctk.CTkButton(
            controls, text="▶ Simulate Activity", fg_color=COLOUR_BLUE,
            command=self.app.start_demo_generator,
        )
        self.sim_start_button.pack(side="left", padx=4)
        self.sim_stop_button = ctk.CTkButton(
            controls, text="■ Stop Activity", fg_color=COLOUR_RED,
            command=self.app.stop_demo_generator,
        )
        self.sim_stop_button.pack(side="left", padx=4)
        ctk.CTkButton(
            controls, text="Clear feed", fg_color=COLOUR_BLUE,
            command=self._clear_feed,
        ).pack(side="left", padx=4)
        self.status_label = ctk.CTkLabel(
            controls, text="Live OS monitors running",
            font=("Segoe UI", 12, "bold"), text_color=COLOUR_GREEN,
        )
        self.status_label.pack(side="left", padx=12)

        self.feed_card = CardFrame(self)
        self.feed_card.pack(fill="both", expand=True, padx=24, pady=10)
        ctk.CTkLabel(self.feed_card, text="Live activity feed",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(8, 0))

        style = ttk.Style()
        style_treeview(style)
        cols = ("Time", "Source", "Event", "Risk", "Description")
        widths = (150, 110, 160, 60, 360)
        tree_frame = ctk.CTkFrame(self.feed_card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=14)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("LOW", foreground=COLOUR_GREEN)
        self.tree.tag_configure("MEDIUM", foreground=COLOUR_YELLOW)
        self.tree.tag_configure("HIGH", foreground=COLOUR_RED)
        self.tree.tag_configure("CRITICAL", foreground=COLOUR_RED)
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        self.banner = info_banner(
            self,
            "Real OS monitors (file system, processes, network, USB, "
            "Windows Security events) populate the table as you use your computer. "
            "Start the activity simulator only when demonstrating the system on a "
            "machine that does not generate real activity.",
            COLOUR_TEXT_DIM,
        )
        self.banner.pack(anchor="w", padx=24, pady=(0, 14))

        self._seed_initial()
        self.on_simulation_state(self.app.simulation_running())

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self.on_simulation_state(self.app.simulation_running())
        self._seed_initial()

    def on_simulation_state(self, running: bool) -> None:
        """Keep both the buttons and the status label honest."""
        self.sim_start_button.configure(state="disabled" if running else "normal")
        self.sim_stop_button.configure(state="normal" if running else "disabled")
        if running:
            self.status_label.configure(text="Sample activity: running", text_color=COLOUR_GREEN)
        else:
            self.status_label.configure(text="Live OS monitors running", text_color=COLOUR_GREEN)

    # Real OS monitor callback ----------------------------------
    def on_monitor_event(self, event: MonitorEvent) -> None:
        score = float(event.risk_points)
        band = band_for_score(score, RISK_BANDS)
        ts = _parse_dt(event.timestamp) or datetime.now()
        self.tree.insert(
            "", 0,
            values=(
                fmt_dt(ts),
                event.source,
                event.event_type,
                f"+{score:.0f}",
                event.description,
            ),
            tags=(band,),
        )
        self._trim()

    # Demo data generator callback ------------------------------
    def on_demo_event(self, event) -> None:
        score = float(event.risk_points)
        band = band_for_score(score, RISK_BANDS)
        ts = _parse_dt(event.timestamp) or datetime.now()
        self.tree.insert(
            "", 0,
            values=(
                fmt_dt(ts),
                "simulated",
                event.event_type,
                f"+{score:.0f}",
                f"{event.user_name} — {event.description}",
            ),
            tags=(band,),
        )
        self._trim()

    # -----------------------------------------------------------
    def _trim(self) -> None:
        rows = self.tree.get_children()
        if len(rows) > self.MAX_ROWS:
            for r in rows[self.MAX_ROWS:]:
                try:
                    self.tree.delete(r)
                except Exception:
                    # Row may already have been cleared by a refresh — ignore.
                    pass

    def _clear_feed(self) -> None:
        self.tree.delete(*self.tree.get_children())

    def _seed_initial(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for ev in db.recent_activity(limit=self.MAX_ROWS):
            score = float(ev.get("risk_points", 0))
            band = band_for_score(score, RISK_BANDS)
            ts = _parse_dt(ev.get("timestamp"))
            self.tree.insert(
                "", "end",
                values=(
                    fmt_dt(ts),
                    "history",
                    ev.get("event_type", ""),
                    f"+{score:.0f}",
                    f"{ev.get('user_name') or 'User %s' % ev.get('user_id')} — {ev.get('description', '')}",
                ),
                tags=(band,),
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