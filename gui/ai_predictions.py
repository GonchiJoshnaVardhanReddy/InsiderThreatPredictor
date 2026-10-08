"""AI Risk Prediction page — the Kev v3 behavioural detector.

The page reads results through the `ai.anomaly_detector` facade only. It never
imports the Kev model, torch, or the feature adapter directly.

Kev answers one question per employee-day: does this activity indicate a
potential insider threat? The number shown is a probability, not a score, and
it is deliberately kept separate from the rule engine's 0-100 risk score.
"""

from __future__ import annotations

from tkinter import ttk
from typing import Dict, List

import customtkinter as ctk

from ai import anomaly_detector
from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
)
from gui.theme import CardFrame, info_banner, section_title, style_treeview

DISCLAIMER = (
    "Kev is a behavioural risk signal, not proof of malicious activity. It was "
    "trained on CERT-style daily activity and this application maps Windows "
    "telemetry onto that feature set, so treat deviations as leads to "
    "investigate. Response actions in this app are simulated and audited."
)

COLUMNS = ("User", "Kev Probability", "Decision", "Baseline Anomaly",
           "History", "Last Updated")
WIDTHS = (170, 130, 210, 130, 80, 150)


class AIPredictionsPage(ctk.CTkFrame):
    """Show Kev v3 behavioural predictions for every user."""

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app

        section_title(
            self, "AI Risk Prediction",
            "Kev v3 behavioural model · baseline-aware insider-threat detection"
        )

        # Controls + model status -------------------------------------
        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.pack(fill="x", padx=24, pady=6)
        ctk.CTkButton(
            controls, text="🔄 Rescan Users", fg_color=COLOUR_CYAN,
            text_color=COLOUR_BG, command=self._rescan,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            controls, text="📄 Coverage Report", fg_color=COLOUR_BLUE,
            command=self._show_coverage,
        ).pack(side="left", padx=4)

        self.status_label = ctk.CTkLabel(
            controls, text="Kev: starting…",
            font=("Segoe UI", 12, "bold"), text_color=COLOUR_TEXT_DIM,
        )
        self.status_label.pack(side="left", padx=12)

        # Headline counters -------------------------------------------
        self.stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_frame.pack(fill="x", padx=24, pady=(2, 6))
        self._stat_labels: Dict[str, ctk.CTkLabel] = {}
        for key, caption in (
            ("analyzed_users", "Analyzed Users"),
            ("highest_probability", "Highest Probability"),
            ("threat_count", "Flagged"),
            ("normal_count", "Normal"),
            ("threshold", "Threshold"),
        ):
            tile = ctk.CTkFrame(self.stats_frame, fg_color=COLOUR_PANEL, corner_radius=8)
            tile.pack(side="left", padx=4, ipadx=10, ipady=4)
            value = ctk.CTkLabel(tile, text="—", font=("Segoe UI", 16, "bold"),
                                 text_color=COLOUR_CYAN)
            value.pack(padx=12, pady=(6, 0))
            ctk.CTkLabel(tile, text=caption, font=("Segoe UI", 9),
                         text_color=COLOUR_TEXT_DIM).pack(padx=12, pady=(0, 6))
            self._stat_labels[key] = value

        self.banner = info_banner(self, DISCLAIMER, COLOUR_TEXT_DIM)
        self.banner.pack(anchor="w", padx=24, pady=(0, 8))

        # Results table ------------------------------------------------
        self.card = CardFrame(self)
        self.card.pack(fill="both", expand=True, padx=24, pady=8)
        style = ttk.Style()
        style_treeview(style)
        tree_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree = ttk.Treeview(tree_frame, columns=COLUMNS, show="headings", height=12)
        for col, width in zip(COLUMNS, WIDTHS):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("THREAT", foreground=COLOUR_RED)
        self.tree.tag_configure("NORMAL", foreground=COLOUR_GREEN)
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        # Detail panel -------------------------------------------------
        self.detail_card = CardFrame(self)
        self.detail_card.pack(fill="x", padx=24, pady=(4, 12))
        self.detail_label = ctk.CTkLabel(
            self.detail_card,
            text="Select a row to see the feature deviations behind its probability.",
            font=("Consolas", 11), text_color=COLOUR_TEXT,
            justify="left", anchor="w",
        )
        self.detail_label.pack(anchor="w", padx=14, pady=12)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self._results: List[Dict] = []
        self._last_status: str | None = None
        self.refresh()

    # ---------------------------------------------------------------
    def on_show(self) -> None:
        self.refresh()

    def on_kev_results(self, results) -> None:
        """Called by the app after a background scoring run."""
        self._results = list(results)
        self._render()

    def on_monitor_event(self, _event) -> None:
        """Refresh when Kev finishes loading; otherwise just retitle."""
        if anomaly_detector.status() != self._last_status:
            self.refresh()
        else:
            self._render_status()

    on_demo_event = on_monitor_event

    # ---------------------------------------------------------------
    def _rescan(self) -> None:
        """Ask for a fresh scan. Scoring runs in the background."""
        anomaly_detector.request_full_scan()
        self.status_label.configure(
            text="Kev: rescanning users in the background…",
            text_color=COLOUR_YELLOW,
        )

    def refresh(self) -> None:
        self._results = anomaly_detector.predict_for_all()
        self._last_status = anomaly_detector.status()
        self._render()

    def _render(self) -> None:
        self._render_status()
        self._render_stats()
        self._render_table()

    # ---------------------------------------------------------------
    def _render_status(self) -> None:
        status = anomaly_detector.status()
        info = anomaly_detector.model_info()
        name = info.get("reference") or info.get("model") or "-"

        if status == "loaded":
            self.status_label.configure(
                text=f"Kev loaded · {name} · {info.get('device', '?')}",
                text_color=COLOUR_GREEN,
            )
        elif status == "loading":
            self.status_label.configure(
                text="Kev loading… (first run builds a CUDA context)", text_color=COLOUR_YELLOW,
            )
        elif status == "error":
            self.status_label.configure(
                text=f"Kev unavailable — {info.get('error') or 'unknown error'}",
                text_color=COLOUR_RED,
            )
        else:
            self.status_label.configure(text="Kev not loaded yet", text_color=COLOUR_TEXT_DIM)

    def _render_stats(self) -> None:
        summary = anomaly_detector.summary()
        highest = summary.get("highest_probability")
        threshold = summary.get("threshold")

        values = {
            "analyzed_users": str(summary.get("analyzed_users", 0)),
            "highest_probability": f"{highest * 100:.1f}%" if highest is not None else "—",
            "threat_count": str(summary.get("threat_count", 0)),
            "normal_count": str(summary.get("normal_count", 0)),
            "threshold": f"{threshold * 100:.2f}%" if threshold else "—",
        }
        colours = {
            "threat_count": COLOUR_RED if summary.get("threat_count") else COLOUR_GREEN,
            "highest_probability": (
                COLOUR_RED if highest is not None and threshold and highest >= threshold
                else COLOUR_CYAN
            ),
        }
        for key, text in values.items():
            label = self._stat_labels.get(key)
            if label is not None:
                label.configure(text=text, text_color=colours.get(key, COLOUR_CYAN))

    def _render_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for row in sorted(self._results, key=lambda r: -r["probability"]):
            self.tree.insert(
                "", "end", iid=str(row["user_id"]),
                values=(
                    row["user_name"],
                    f"{row['probability'] * 100:.1f}%  ({row['probability']:.4f})",
                    row["label"].replace("_", " "),
                    f"{row['baseline_anomaly_score']:.3f}",
                    str(row["baseline_history"]),
                    row["date"],
                ),
                tags=("THREAT" if row["is_threat"] else "NORMAL",),
            )

    # ---------------------------------------------------------------
    def _on_select(self, _evt=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        user_id = int(selection[0])
        row = next((r for r in self._results if r["user_id"] == user_id), None)
        if row is None:
            return

        lines = [
            f"User: {row['user_name']}    Day: {row['date']}",
            f"Kev probability: {row['probability']:.4f}   "
            f"Threshold: {row['threshold']:.4f}   Decision: "
            f"{row['label'].replace('_', ' ')}",
            f"Baseline anomaly score: {row['baseline_anomaly_score']:.4f}   "
            f"Prior observations: {row['baseline_history']}",
            f"Model: {row['model']}",
            "",
            f"{'Feature':<22}{'Value':>8}{'Deviation':>12}   Mapping",
            "-" * 66,
        ]
        for name, value in row["features"].items():
            deviation = row["deviations"].get(name, 0.0)
            coverage = row["feature_coverage"].get(name, "")
            lines.append(f"{name:<22}{value:>8.0f}{deviation:>12.4f}   {coverage}")

        lines += [
            "",
            "Deviation = |today - median(previous 30 days)| / (median + 1).",
            "Mapping is how faithfully this app can build the CERT feature from",
            "Windows telemetry: direct / proxy / degenerate / absent.",
            "",
            "Behavioural risk signal — not proof of malicious activity.",
        ]
        self.detail_label.configure(text="\n".join(lines))

    def _show_coverage(self) -> None:
        """Explain, in the UI, where the Windows->CERT feature mapping is weak."""
        from tkinter import Toplevel

        window = Toplevel(self)
        window.title("Kev feature mapping — Windows telemetry to CERT")
        window.geometry("900x520")
        window.configure(bg=COLOUR_BG)

        ctk.CTkLabel(
            window,
            text="Kev was trained on CERT r4.2 daily user behaviour. This table "
                 "documents how each CERT feature is reconstructed from Windows "
                 "telemetry collected by this application.",
            font=("Segoe UI", 12), text_color=COLOUR_TEXT,
            justify="left", wraplength=860, anchor="w",
        ).pack(anchor="w", padx=16, pady=(14, 10))

        frame = ctk.CTkFrame(window, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        columns = ("Feature", "Mapping", "Source", "Notes")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        style_treeview(ttk.Style())
        for col, width in zip(columns, (170, 100, 240, 380)):
            tree.heading(col, text=col)
            tree.column(col, width=width, anchor="w")
        tree.tag_configure("direct", foreground=COLOUR_GREEN)
        tree.tag_configure("proxy", foreground=COLOUR_YELLOW)
        tree.tag_configure("degenerate", foreground=COLOUR_TEXT_DIM)
        tree.tag_configure("absent", foreground=COLOUR_RED)
        for entry in anomaly_detector.summary().get("coverage", []):
            tree.insert("", "end", values=(
                entry["feature"], entry["verdict"], entry["source"], entry["notes"],
            ), tags=(entry["verdict"],))
        tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        sb.pack(side="right", fill="y")
        tree.configure(yscrollcommand=sb.set)
