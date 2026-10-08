"""Main dashboard page — real-time KPIs and charts."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from tkinter import ttk

from ai import anomaly_detector
from config.settings import (
    COLOUR_BG,
    COLOUR_BLUE,
    COLOUR_CARD,
    COLOUR_CYAN,
    COLOUR_GREEN,
    COLOUR_PANEL,
    COLOUR_RED,
    COLOUR_TEXT,
    COLOUR_TEXT_DIM,
    COLOUR_YELLOW,
)
from database import db_manager as db
from engine.risk_engine import RISK_BANDS, band_for_score
from gui.theme import (
    CardFrame,
    KPICard,
    info_banner,
    section_title,
    severity_colour,
    style_dark_axes,
    style_treeview,
)
from monitor.base import MonitorEvent
from utils.helpers import fmt_dt, log


# Pretty labels for each real monitor (kept here so the dashboard does not
# need to know how the MonitorManager is wired).
MONITOR_LABELS: dict = {
    "file_system":     "File System",
    "process_monitor": "Processes",
    "network_monitor": "Network",
    "usb_monitor":     "USB Devices",
    "eventlog_monitor": "Windows Security Log",
}


class DashboardPage(ctk.CTkFrame):
    """KPIs, charts, alerts feed and a live monitor status row."""

    REFRESH_MS = 4000

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app
        self._build()
        self._refresh_id: Optional[str] = None
        self.after(800, self.refresh)

    # ---------------------------------------------------------------
    def _build(self) -> None:
        section_title(
            self,
            "Security Operations Dashboard",
            "Live KPIs, risk distribution and recent alerts — fed by OS-level monitors",
        )

        # Real monitor status row --------------------------------
        monitors_card = CardFrame(self)
        monitors_card.pack(fill="x", padx=24, pady=(0, 8))
        ctk.CTkLabel(
            monitors_card, text="Real OS monitors",
            font=("Segoe UI", 13, "bold"), text_color=COLOUR_CYAN,
        ).pack(anchor="w", padx=14, pady=(10, 4))
        self.monitor_status_frame = ctk.CTkFrame(monitors_card, fg_color="transparent")
        self.monitor_status_frame.pack(fill="x", padx=14, pady=(0, 10))
        self.monitor_status_labels = {}
        for key, label in MONITOR_LABELS.items():
            cell = ctk.CTkFrame(self.monitor_status_frame, fg_color=COLOUR_CARD, corner_radius=8)
            cell.pack(side="left", padx=4, pady=4, expand=True, fill="x")
            ctk.CTkLabel(
                cell, text=label,
                font=("Segoe UI", 10, "bold"), text_color=COLOUR_TEXT_DIM,
            ).pack(padx=8, pady=(6, 0))
            state_lbl = ctk.CTkLabel(
                cell, text="● starting",
                font=("Segoe UI", 11, "bold"), text_color=COLOUR_YELLOW,
            )
            state_lbl.pack(padx=8, pady=(0, 6))
            self.monitor_status_labels[key] = state_lbl

        # KPI row ----------------------------------------------------
        kpi_row = ctk.CTkFrame(self, fg_color="transparent")
        kpi_row.pack(fill="x", padx=24, pady=(0, 8))
        for i in range(3):
            kpi_row.grid_columnconfigure(i, weight=1)
        self.kpi_total_users = KPICard(kpi_row, "Total Users", "0", COLOUR_CYAN, "👥")
        self.kpi_active_users = KPICard(kpi_row, "Active Users", "0", COLOUR_GREEN, "✅")
        self.kpi_high_risk = KPICard(kpi_row, "High-Risk Users", "0", COLOUR_RED, "⚠")
        for col, card in enumerate((self.kpi_total_users, self.kpi_active_users, self.kpi_high_risk)):
            card.grid(row=0, column=col, padx=8, pady=4, sticky="ew")

        kpi_row2 = ctk.CTkFrame(self, fg_color="transparent")
        kpi_row2.pack(fill="x", padx=24, pady=(0, 8))
        for i in range(3):
            kpi_row2.grid_columnconfigure(i, weight=1)
        self.kpi_alerts = KPICard(kpi_row2, "Security Alerts", "0", COLOUR_YELLOW, "🚨")
        self.kpi_events = KPICard(kpi_row2, "Events Captured", "0", COLOUR_BLUE, "📈")
        self.kpi_anomalies = KPICard(
            kpi_row2, "Legacy Anomalies", "—", COLOUR_TEXT_DIM, "🧪",
            subtitle="optional IsolationForest · off by default",
        )
        for col, card in enumerate((self.kpi_alerts, self.kpi_events, self.kpi_anomalies)):
            card.grid(row=0, column=col, padx=8, pady=4, sticky="ew")

        # Kev behavioural model row. These are probabilities (0-100%), a
        # different scale from the rule engine's 0-100 risk score above, so
        # they are labelled as such and never merged into the risk numbers.
        kpi_row3 = ctk.CTkFrame(self, fg_color="transparent")
        kpi_row3.pack(fill="x", padx=24, pady=(0, 8))
        for i in range(3):
            kpi_row3.grid_columnconfigure(i, weight=1)
        self.kpi_ai_threats = KPICard(
            kpi_row3, "AI Threats", "0", COLOUR_RED, "🤖",
            subtitle="Kev v3 · user-days at or above threshold",
        )
        self.kpi_kev_highest = KPICard(
            kpi_row3, "Highest Kev Risk", "—", COLOUR_CYAN, "📛",
            subtitle="Kev probability, not the rule score",
        )
        self.kpi_kev_average = KPICard(
            kpi_row3, "Average Kev Risk", "—", COLOUR_CYAN, "📊",
            subtitle="Kev probability, not the rule score",
        )
        for col, card in enumerate(
            (self.kpi_ai_threats, self.kpi_kev_highest, self.kpi_kev_average)
        ):
            card.grid(row=0, column=col, padx=8, pady=4, sticky="ew")

        # Activity simulator + refresh --------------------------------
        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.pack(fill="x", padx=24, pady=(0, 8))
        self.sim_start_button = ctk.CTkButton(
            controls, text="▶ Simulate Activity",
            fg_color=COLOUR_BLUE, hover_color="#1B4F72",
            text_color="white", width=180,
            command=self.app.start_demo_generator,
        )
        self.sim_start_button.pack(side="left", padx=4)
        self.sim_stop_button = ctk.CTkButton(
            controls, text="■ Stop Activity",
            fg_color=COLOUR_RED, hover_color="#C0392B",
            text_color="white", width=160,
            command=self.app.stop_demo_generator,
        )
        self.sim_stop_button.pack(side="left", padx=4)
        ctk.CTkButton(
            controls, text="↻ Refresh Dashboard",
            fg_color=COLOUR_CYAN, hover_color="#5BC0BE",
            text_color=COLOUR_BG, width=180,
            command=self.refresh,
        ).pack(side="left", padx=4)
        self.demo_status = ctk.CTkLabel(
            controls, text="Sample activity: off — live monitors only",
            font=("Segoe UI", 12, "bold"),
            text_color=COLOUR_TEXT_DIM,
        )
        self.demo_status.pack(side="left", padx=18)
        self.on_simulation_state(self.app.simulation_running())

        # Charts row --------------------------------------------------
        charts = ctk.CTkFrame(self, fg_color="transparent")
        charts.pack(fill="both", expand=True, padx=24, pady=(4, 4))
        charts.grid_columnconfigure(0, weight=1)
        charts.grid_columnconfigure(1, weight=1)
        charts.grid_rowconfigure(0, weight=1)

        self.risk_pie_card = CardFrame(charts)
        self.risk_pie_card.grid(row=0, column=0, padx=6, pady=4, sticky="nsew")
        ctk.CTkLabel(self.risk_pie_card, text="Risk Distribution",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(8, 0))
        self.pie_fig = Figure(figsize=(4, 3), dpi=100, facecolor=COLOUR_PANEL)
        self.pie_ax = self.pie_fig.add_subplot(111)
        self.pie_ax.set_facecolor(COLOUR_PANEL)
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=self.risk_pie_card)
        self.pie_canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

        self.bar_card = CardFrame(charts)
        self.bar_card.grid(row=0, column=1, padx=6, pady=4, sticky="nsew")
        ctk.CTkLabel(self.bar_card, text="Top Risk Users",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(8, 0))
        self.bar_fig = Figure(figsize=(4, 3), dpi=100, facecolor=COLOUR_PANEL)
        self.bar_ax = self.bar_fig.add_subplot(111)
        self.bar_ax.set_facecolor(COLOUR_PANEL)
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=self.bar_card)
        self.bar_canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

        # Bottom row: activity trend + alerts tree --------------------
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="both", expand=True, padx=24, pady=(4, 8))
        bottom.grid_columnconfigure(0, weight=2)
        bottom.grid_columnconfigure(1, weight=3)
        bottom.grid_rowconfigure(0, weight=1)

        self.trend_card = CardFrame(bottom)
        self.trend_card.grid(row=0, column=0, padx=6, pady=4, sticky="nsew")
        ctk.CTkLabel(self.trend_card, text="Activity Trend (last 7 days)",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(8, 0))
        self.trend_fig = Figure(figsize=(4, 3), dpi=100, facecolor=COLOUR_PANEL)
        self.trend_ax = self.trend_fig.add_subplot(111)
        self.trend_ax.set_facecolor(COLOUR_PANEL)
        self.trend_canvas = FigureCanvasTkAgg(self.trend_fig, master=self.trend_card)
        self.trend_canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

        self.alerts_card = CardFrame(bottom)
        self.alerts_card.grid(row=0, column=1, padx=6, pady=4, sticky="nsew")
        ctk.CTkLabel(self.alerts_card, text="Recent Alerts & Activity",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(8, 0))

        style = ttk.Style()
        style_treeview(style)
        tree_frame = ctk.CTkFrame(self.alerts_card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("Time", "User", "Event", "Source"),
            show="headings",
            height=10,
        )
        for col, width in zip(("Time", "User", "Event", "Source"), (140, 140, 200, 110)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("LOW", foreground=COLOUR_GREEN)
        self.tree.tag_configure("MEDIUM", foreground=COLOUR_YELLOW)
        self.tree.tag_configure("HIGH", foreground=COLOUR_RED)
        self.tree.tag_configure("CRITICAL", foreground=COLOUR_RED)
        self.tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sb.pack(fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        # Footer status bar
        status_bar = ctk.CTkFrame(self, fg_color=COLOUR_PANEL, corner_radius=8)
        status_bar.pack(fill="x", padx=24, pady=(0, 14))
        self.status_label = ctk.CTkLabel(
            status_bar, text="Engine: idle",
            font=("Segoe UI", 11, "bold"),
            text_color=COLOUR_TEXT_DIM,
        )
        self.status_label.pack(side="left", padx=14, pady=6)
        ctk.CTkLabel(
            status_bar, text="INSIDER THREAT PREDICTOR — AI-POWERED UEBA",
            font=("Segoe UI", 11, "bold"),
            text_color=COLOUR_CYAN,
        ).pack(side="right", padx=14, pady=6)

    # ---------------------------------------------------------------
    def on_show(self) -> None:
        # Re-read the simulator state on every visit: it can be started or
        # stopped from the Live Monitoring page while this page is hidden.
        self.on_simulation_state(self.app.simulation_running())
        self.refresh()

    # Called by app when a real monitor fires.
    def on_monitor_event(self, event: MonitorEvent) -> None:
        self.status_label.configure(
            text=f"Live: {event.event_type} ({event.source}) — {event.description[:60]}"
        )
        self.refresh()

    # Called by app when the activity simulator fires.
    def on_demo_event(self, event) -> None:
        self.status_label.configure(
            text=f"Simulated: {event.event_type} for {event.user_name} (+{event.risk_points:.0f})"
        )
        self.refresh()

    def on_simulation_state(self, running: bool) -> None:
        """Reflect whether the simulator is running, on both buttons at once."""
        self.sim_start_button.configure(state="disabled" if running else "normal")
        self.sim_stop_button.configure(state="normal" if running else "disabled")
        if running:
            self.demo_status.configure(text="Sample activity: running", text_color=COLOUR_GREEN)
        else:
            self.demo_status.configure(
                text="Sample activity: off — live monitors only", text_color=COLOUR_TEXT_DIM
            )

    # ---------------------------------------------------------------
    def refresh(self) -> None:
        try:
            self._update_monitor_status()
            self._update_kpis()
            self._update_pie()
            self._update_bar()
            self._update_trend()
            self._update_alerts()
        except Exception as exc:  # pragma: no cover
            log.exception("Dashboard refresh failed: %s", exc)
        finally:
            if self._refresh_id is not None:
                try:
                    self.after_cancel(self._refresh_id)
                except Exception:
                    pass
            self._refresh_id = self.after(self.REFRESH_MS, self.refresh)

    # ---------------------------------------------------------------
    def _update_monitor_status(self) -> None:
        status = {s["name"]: s for s in self.app.monitors.status()}
        for key, lbl in self.monitor_status_labels.items():
            entry = status.get(key)
            if not entry:
                lbl.configure(text="● unavailable", text_color=COLOUR_RED)
                continue
            if entry["running"]:
                lbl.configure(text="● live", text_color=COLOUR_GREEN)
            else:
                err = entry.get("last_error") or "starting"
                lbl.configure(text=f"● {err[:18]}", text_color=COLOUR_YELLOW)

    def _update_kpis(self) -> None:
        counts = db.count_users()
        self.kpi_total_users.set_value(str(counts["total"]))
        self.kpi_active_users.set_value(str(counts["active"]))
        self.kpi_high_risk.set_value(str(counts["high_risk"]))
        self.kpi_alerts.set_value(str(db.count_alerts()))
        self.kpi_events.set_value(str(db.count_activity()))
        # Kev results are cached, so reading the summary here costs nothing.
        # Inference itself only ever runs on the background worker.
        self._apply_kev_summary(anomaly_detector.summary())

    def _apply_kev_summary(self, summary: Dict) -> None:
        """Render the Kev tiles. Probabilities are 0-1 internally, shown as %."""
        highest = summary.get("highest_probability")
        average = summary.get("average_probability")
        threshold = summary.get("threshold")

        self.kpi_ai_threats.set_value(str(summary.get("threat_count", 0)))
        self.kpi_kev_highest.set_value(
            f"{highest * 100:.1f}%" if highest is not None else "—"
        )
        self.kpi_kev_average.set_value(
            f"{average * 100:.1f}%" if average is not None else "—"
        )

        breached = highest is not None and threshold is not None and highest >= threshold
        self.kpi_kev_highest.value_label.configure(
            text_color=COLOUR_RED if breached else COLOUR_CYAN
        )
        if not summary.get("loaded"):
            self.kpi_ai_threats.set_subtitle(
                "Kev " + ("loading…" if summary.get("status") == "loading"
                          else str(summary.get("status") or "not loaded"))
            )
        else:
            self.kpi_ai_threats.set_subtitle(
                f"Kev v3 · {summary.get('analyzed_users', 0)} user-days analysed"
            )

    def on_kev_results(self, results) -> None:
        """Fresh Kev results arrived from the background worker."""
        self._apply_kev_summary(anomaly_detector.summary())

    # ---------------------------------------------------------------
    def _update_pie(self) -> None:
        users = db.list_users()
        bands = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for u in users:
            bands[band_for_score(u.get("risk_score", 0), RISK_BANDS)] += 1
        values = list(bands.values())
        # Skip the redraw when nothing changed (avoids needless flicker).
        if values == getattr(self, "_last_pie_values", None):
            return
        self._last_pie_values = values
        ax = self.pie_ax
        ax.clear()
        colours = [severity_colour(k) for k in bands.keys()]
        labels = [f"{k} ({v})" for k, v in bands.items() if v > 0]
        if sum(values) == 0:
            ax.text(0.5, 0.5, "No data", color=COLOUR_TEXT_DIM,
                    ha="center", va="center", fontsize=12)
        else:
            ax.pie(
                [v for v in values if v > 0],
                labels=labels,
                colors=[colours[i] for i, v in enumerate(values) if v > 0],
                startangle=90,
                textprops={"color": COLOUR_TEXT, "fontsize": 10},
            )
        ax.set_title("User Risk Distribution", color=COLOUR_CYAN, fontsize=11)
        self.pie_canvas.draw_idle()

    def _update_bar(self) -> None:
        users = sorted(db.list_users(), key=lambda u: -u.get("risk_score", 0))[:8]
        signature = tuple((u["user_id"], round(u.get("risk_score", 0), 1)) for u in users)
        if signature == getattr(self, "_last_bar_sig", None):
            return
        self._last_bar_sig = signature
        names = [u["name"].split()[0] for u in users]
        scores = [u.get("risk_score", 0) for u in users]
        ax = self.bar_ax
        ax.clear()
        if not users:
            ax.text(0.5, 0.5, "No data", color=COLOUR_TEXT_DIM,
                    ha="center", va="center", fontsize=12, transform=ax.transAxes)
        else:
            colours = [severity_colour(band_for_score(s, RISK_BANDS)) for s in scores]
            ax.bar(names, scores, color=colours)
            ax.set_ylabel("Risk Score", color=COLOUR_TEXT_DIM)
            style_dark_axes(ax, title="Top Risk Users")
        self.bar_canvas.draw_idle()

    def _update_trend(self) -> None:
        data = db.activity_per_day(days=7)
        if data == getattr(self, "_last_trend_data", None):
            return
        self._last_trend_data = data
        ax = self.trend_ax
        ax.clear()
        if not data:
            ax.text(0.5, 0.5, "No data", color=COLOUR_TEXT_DIM,
                    ha="center", va="center", fontsize=12, transform=ax.transAxes)
        else:
            labels = [d[0][5:] for d in data]
            values = [d[1] for d in data]
            ax.plot(labels, values, color=COLOUR_CYAN, marker="o", linewidth=2)
            ax.fill_between(range(len(values)), values, color=COLOUR_CYAN, alpha=0.2)
            ax.set_ylabel("Events", color=COLOUR_TEXT_DIM)
            style_dark_axes(ax, title="Daily Activity")
        self.trend_canvas.draw_idle()

    def _update_alerts(self) -> None:
        self.tree.delete(*self.tree.get_children())
        rows = db.list_alerts()[:15]
        if not rows:
            for r in db.recent_activity(limit=10):
                self.tree.insert(
                    "", "end",
                    values=(
                        fmt_dt(_parse_dt(r.get("timestamp"))),
                        r.get("user_name") or f"User {r['user_id']}",
                        r.get("event_type", ""),
                        "real" if r.get("description", "").startswith(("Process ", "USB ", "Connection")) else "log",
                    ),
                    tags=("LOW",),
                )
            return
        for r in rows:
            self.tree.insert(
                "", "end",
                values=(
                    fmt_dt(_parse_dt(r.get("created_at"))),
                    r.get("user_name") or f"User {r['user_id']}",
                    r.get("event_type", ""),
                    "alerts",
                ),
                tags=(r.get("severity", "LOW"),),
            )

    # ---------------------------------------------------------------
    def destroy(self, *args, **kwargs):
        if self._refresh_id is not None:
            try:
                self.after_cancel(self._refresh_id)
            except Exception:
                pass
        super().destroy(*args, **kwargs)


def _parse_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None