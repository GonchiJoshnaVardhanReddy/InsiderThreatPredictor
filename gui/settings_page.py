"""Settings page — controls real monitors, risk weights and the activity simulator."""

from __future__ import annotations

from tkinter import messagebox
from typing import Dict

import customtkinter as ctk

from ai import anomaly_detector
from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CARD, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
    DB_PATH,
    DEFAULT_RISK_WEIGHTS,
    KEV_THRESHOLD as DEFAULT_KEV_THRESHOLD,
)
from gui.theme import CardFrame, info_banner, section_title


EVENT_LABELS = {
    "normal_activity":         "Normal activity",
    "unusual_login_time":      "Unusual login time",
    "failed_login":            "Failed login",
    "large_download":          "Large download",
    "usb_copy":                "USB copy",
    "restricted_file_access":  "Restricted file access",
    "bulk_data_transfer":      "Bulk data transfer",
    "privilege_escalation":    "Privilege escalation",
}

MONITOR_LABELS: dict = {
    "file_system":     "File System",
    "process_monitor": "Processes",
    "network_monitor": "Network",
    "usb_monitor":     "USB Devices",
    "eventlog_monitor": "Windows Security Log",
}


class SettingsPage(ctk.CTkFrame):
    """Configure risk, monitors and the activity simulator; reset stored data."""

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app

        section_title(
            self, "Settings",
            "Tune risk weights, thresholds, monitors and simulated activity"
        )

        # --- Real OS monitors -----------------------------------------------
        mon_card = CardFrame(self)
        mon_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            mon_card, text="Real OS monitors",
            font=("Segoe UI", 14, "bold"), text_color=COLOUR_CYAN,
        ).pack(anchor="w", padx=14, pady=(12, 4))
        info_banner(
            mon_card,
            "These monitors observe your Windows machine in real time. "
            "Toggle them on/off without restarting the application.",
            COLOUR_TEXT_DIM,
        ).pack(anchor="w", padx=14, pady=(0, 8))

        self.monitor_buttons: Dict[str, ctk.CTkButton] = {}
        row_frame = ctk.CTkFrame(mon_card, fg_color="transparent")
        row_frame.pack(fill="x", padx=14, pady=(0, 12))
        for name, label in MONITOR_LABELS.items():
            btn = ctk.CTkButton(
                row_frame, text=f"{label}: …",
                fg_color=COLOUR_CARD, command=lambda n=name: self._toggle_monitor(n),
                width=240,
            )
            btn.pack(side="left", padx=4, pady=4)
            self.monitor_buttons[name] = btn
        self._refresh_monitor_buttons()

        # --- Risk weights -------------------------------------------------
        risk_card = CardFrame(self)
        risk_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            risk_card, text="Risk weights",
            font=("Segoe UI", 14, "bold"), text_color=COLOUR_CYAN,
        ).pack(anchor="w", padx=14, pady=(12, 4))
        self.weight_vars: Dict[str, ctk.StringVar] = {}
        weights_grid = ctk.CTkFrame(risk_card, fg_color="transparent")
        weights_grid.pack(fill="x", padx=14, pady=4)
        weights_grid.grid_columnconfigure(1, weight=1)

        for i, (event_key, label) in enumerate(EVENT_LABELS.items()):
            current = float(self.app.engine.weights.get(event_key, DEFAULT_RISK_WEIGHTS.get(event_key, 0)))
            var = ctk.StringVar(value=str(current))
            self.weight_vars[event_key] = var
            ctk.CTkLabel(
                weights_grid, text=label, font=("Segoe UI", 11),
                text_color=COLOUR_TEXT,
            ).grid(row=i, column=0, sticky="w", padx=4, pady=2)
            ctk.CTkEntry(
                weights_grid, textvariable=var, width=80,
                fg_color=COLOUR_BG, text_color=COLOUR_TEXT,
            ).grid(row=i, column=1, sticky="e", padx=4, pady=2)

        thresh_row = ctk.CTkFrame(risk_card, fg_color="transparent")
        thresh_row.pack(fill="x", padx=14, pady=8)
        ctk.CTkLabel(
            thresh_row, text="Risk threshold (MEDIUM band starts at)",
            font=("Segoe UI", 11), text_color=COLOUR_TEXT,
        ).pack(side="left")
        self.threshold_var = ctk.StringVar(value=str(self.app.engine.threshold))
        ctk.CTkEntry(
            thresh_row, textvariable=self.threshold_var, width=80,
            fg_color=COLOUR_BG, text_color=COLOUR_TEXT,
        ).pack(side="right")
        ctk.CTkButton(
            thresh_row, text="Save risk settings", fg_color=COLOUR_CYAN,
            text_color=COLOUR_BG, command=self._save_risk_settings,
        ).pack(side="right", padx=8)

        # --- Kev behavioural model ---------------------------------------
        kev_card = CardFrame(self)
        kev_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            kev_card, text="Kev behavioural model (primary detector)",
            font=("Segoe UI", 14, "bold"), text_color=COLOUR_CYAN,
        ).pack(anchor="w", padx=14, pady=(12, 4))
        info_banner(
            kev_card,
            "Kev answers one question per employee-day: does this activity "
            "indicate a potential insider threat? It was trained on CERT-style "
            "daily activity and this application maps Windows telemetry onto "
            "that feature set, so its probability is a behavioural risk signal "
            "— not proof of malicious intent. The checkpoint is loaded once and "
            "is never retrained from here.",
            COLOUR_TEXT_DIM,
        ).pack(anchor="w", padx=14, pady=(0, 8))

        self.kev_grid = ctk.CTkFrame(kev_card, fg_color="transparent")
        self.kev_grid.pack(fill="x", padx=14, pady=4)
        self.kev_grid.grid_columnconfigure(1, weight=1)
        self.kev_values: Dict[str, ctk.CTkLabel] = {}
        for row, (key, caption) in enumerate((
            ("model", "Model"),
            ("source", "Loaded from"),
            ("device", "Device"),
            ("status", "Status"),
            ("features", "Feature builder"),
        )):
            ctk.CTkLabel(
                self.kev_grid, text=caption, font=("Segoe UI", 11),
                text_color=COLOUR_TEXT_DIM,
            ).grid(row=row, column=0, sticky="w", padx=4, pady=2)
            value = ctk.CTkLabel(
                self.kev_grid, text="—", font=("Segoe UI", 11),
                text_color=COLOUR_TEXT, anchor="w", justify="left", wraplength=700,
            )
            value.grid(row=row, column=1, sticky="w", padx=8, pady=2)
            self.kev_values[key] = value

        threshold_row = ctk.CTkFrame(kev_card, fg_color="transparent")
        threshold_row.pack(fill="x", padx=14, pady=(6, 12))
        ctk.CTkLabel(
            threshold_row, text="Decision threshold:",
            font=("Segoe UI", 11), text_color=COLOUR_TEXT,
        ).pack(side="left")
        self.kev_threshold_var = ctk.StringVar(value=str(anomaly_detector.threshold()))
        ctk.CTkEntry(
            threshold_row, textvariable=self.kev_threshold_var, width=170,
            fg_color=COLOUR_BG, text_color=COLOUR_TEXT,
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            threshold_row, text="Apply threshold", fg_color=COLOUR_CYAN,
            text_color=COLOUR_BG, command=self._save_kev_threshold,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            threshold_row, text="Reload model", fg_color=COLOUR_BLUE,
            command=self._reload_kev,
        ).pack(side="left", padx=4)
        ctk.CTkLabel(
            threshold_row,
            text=f"published default {DEFAULT_KEV_THRESHOLD}",
            font=("Segoe UI", 10), text_color=COLOUR_TEXT_DIM,
        ).pack(side="left", padx=8)

        # --- Demo data generator -----------------------------------------
        demo_card = CardFrame(self)
        demo_card.pack(fill="x", padx=36, pady=8)
        ctk.CTkLabel(
            demo_card, text="Activity simulator (opt-in)",
            font=("Segoe UI", 14, "bold"), text_color=COLOUR_CYAN,
        ).pack(anchor="w", padx=14, pady=(12, 4))
        info_banner(
            demo_card,
            "Generates synthetic activity for the sample accounts so the dashboard "
            "has data to show on a quiet machine. OFF by default and clearly tagged "
            "‘simulated’ in the feed; the real OS monitors above are the "
            "primary data source.",
            COLOUR_TEXT_DIM,
        ).pack(anchor="w", padx=14, pady=(0, 8))
        demo_row = ctk.CTkFrame(demo_card, fg_color="transparent")
        demo_row.pack(fill="x", padx=14, pady=8)
        ctk.CTkLabel(
            demo_row, text="Simulation interval (ms):",
            font=("Segoe UI", 11), text_color=COLOUR_TEXT,
        ).pack(side="left")
        self.interval_var = ctk.StringVar(value=str(self.app.demo_generator.interval_ms))
        ctk.CTkEntry(
            demo_row, textvariable=self.interval_var, width=100,
            fg_color=COLOUR_BG, text_color=COLOUR_TEXT,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            demo_row, text="Save interval", fg_color=COLOUR_BLUE,
            command=self._save_interval,
        ).pack(side="left", padx=8)

        # --- Theme + misc --------------------------------------------------
        misc_card = CardFrame(self)
        misc_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(
            misc_card, text="Appearance & data",
            font=("Segoe UI", 14, "bold"), text_color=COLOUR_CYAN,
        ).pack(anchor="w", padx=14, pady=(12, 4))
        theme_row = ctk.CTkFrame(misc_card, fg_color="transparent")
        theme_row.pack(fill="x", padx=14, pady=8)
        ctk.CTkLabel(
            theme_row, text="Appearance mode:",
            font=("Segoe UI", 11), text_color=COLOUR_TEXT,
        ).pack(side="left")
        self.theme_var = ctk.StringVar(value="dark")
        ctk.CTkOptionMenu(
            theme_row, variable=self.theme_var, values=["dark", "light"],
            fg_color=COLOUR_BG, button_color=COLOUR_BLUE,
            text_color=COLOUR_TEXT,
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            theme_row, text="Apply theme", fg_color=COLOUR_BLUE,
            command=self._apply_theme,
        ).pack(side="left", padx=4)

        ctk.CTkLabel(
            misc_card, text=f"Database path: {DB_PATH}",
            font=("Segoe UI", 11), text_color=COLOUR_TEXT_DIM,
        ).pack(anchor="w", padx=14, pady=4)

        demo_row = ctk.CTkFrame(misc_card, fg_color="transparent")
        demo_row.pack(fill="x", padx=14, pady=8)
        ctk.CTkButton(
            demo_row, text="Reset all data", fg_color=COLOUR_RED,
            command=self._reset_demo,
        ).pack(side="left", padx=4)
        info_banner(
            demo_row,
            "Clears alerts, incidents and activity. The Kev checkpoint is "
            "unaffected — it is loaded from disk, not stored in the database.",
            COLOUR_TEXT_DIM,
        ).pack(side="left", padx=10)

        info_banner(
            self,
            "Settings persist in the SQLite `settings` table.",
            COLOUR_TEXT_DIM,
        ).pack(anchor="w", padx=24, pady=(0, 12))

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self._refresh_monitor_buttons()
        self._refresh_kev_status()

    # -----------------------------------------------------------
    def _toggle_monitor(self, name: str) -> None:
        if self.app.monitors.is_running(name):
            self.app.monitors.stop(name)
        else:
            ok = self.app.monitors.start(name)
            if not ok:
                messagebox.showwarning(
                    "Monitor failed",
                    f"Could not start the {name} monitor "
                    "(missing dependency or insufficient privileges).",
                )
        self._refresh_monitor_buttons()
        # Notify the dashboard so the monitor status row updates.
        dash = self.app.pages.get("Dashboard")
        if dash and hasattr(dash, "_update_monitor_status"):
            try:
                dash._update_monitor_status()
            except Exception:
                pass

    def _refresh_monitor_buttons(self) -> None:
        for name, btn in self.monitor_buttons.items():
            running = self.app.monitors.is_running(name)
            label = MONITOR_LABELS.get(name, name)
            if running:
                btn.configure(text=f"● {label} (live)", fg_color=COLOUR_GREEN)
            else:
                btn.configure(text=f"○ {label} (off)", fg_color=COLOUR_CARD)

    def _save_risk_settings(self) -> None:
        try:
            new_weights = {key: float(var.get()) for key, var in self.weight_vars.items()}
            threshold = int(self.threshold_var.get())
        except ValueError:
            messagebox.showerror("Invalid input", "Weights must be numbers; threshold must be integer.")
            return
        self.app.engine.update_weights(new_weights)
        self.app.engine.update_threshold(threshold)
        self.app.demo_generator.update_weights(new_weights)
        messagebox.showinfo("Saved", "Risk settings updated.")

    def _save_interval(self) -> None:
        try:
            ms = int(self.interval_var.get())
        except ValueError:
            messagebox.showerror("Invalid input", "Interval must be an integer (milliseconds).")
            return
        self.app.demo_generator.update_interval(ms)
        from database import db_manager as db
        db.set_setting("sim_interval_ms", str(ms))
        messagebox.showinfo("Saved", f"Simulation interval set to {ms} ms.")

    def _apply_theme(self) -> None:
        import customtkinter as ctk2
        mode = self.theme_var.get()
        ctk2.set_appearance_mode(mode)
        messagebox.showinfo("Theme applied", f"Appearance mode set to '{mode}'.")

    def _reset_demo(self) -> None:
        if not messagebox.askyesno(
            "Confirm reset",
            "Delete all activity, alerts, incidents and challenge scores? Users and "
            "settings are preserved.",
        ):
            return
        from database import db_manager as db
        db.reset_demo_data()
        messagebox.showinfo("Reset complete", "Activity, alerts and incidents have been wiped.")

    def _save_kev_threshold(self) -> None:
        """Change the operating point — confirmed, persisted and audited.

        The threshold decides where a probability becomes an incident, so a
        change is recorded rather than applied silently.
        """
        try:
            value = float(self.kev_threshold_var.get())
        except ValueError:
            messagebox.showerror("Invalid input", "The threshold must be a number.")
            return
        if not 0.0 < value < 1.0:
            messagebox.showerror("Invalid input", "The threshold must be between 0 and 1.")
            return
        if value == anomaly_detector.threshold():
            messagebox.showinfo("No change", "The threshold already has that value.")
            return
        if not messagebox.askyesno(
            "Change the Kev threshold?",
            f"Flag a user-day as a potential insider threat when the Kev "
            f"probability is at or above {value}.\n\n"
            f"Currently in force: {anomaly_detector.threshold()}\n"
            f"Published default:   {DEFAULT_KEV_THRESHOLD}\n\n"
            "Lowering this raises false positives; raising it misses activity. "
            "The change is written to the settings table and the audit log.",
        ):
            return

        from database import db_manager as db

        previous = anomaly_detector.threshold()
        db.set_setting("kev_threshold", repr(value))
        db.audit(
            "operator", "kev_threshold_changed",
            f"threshold {previous} -> {value} (published default {DEFAULT_KEV_THRESHOLD})",
        )
        # Cached decisions were made at the old threshold; rescore to match.
        anomaly_detector.request_full_scan()
        self._refresh_kev_status()
        messagebox.showinfo(
            "Threshold updated",
            f"Users will be re-scored at {value}. The change is in the audit log.",
        )

    def _reload_kev(self) -> None:
        """Force a reload of the checkpoint (e.g. after switching to a local path)."""
        if not messagebox.askyesno(
            "Reload the Kev model?",
            "The checkpoint is unloaded and read again from disk. This takes "
            "roughly 10-20 seconds and the AI page will be empty until it "
            "finishes.",
        ):
            return
        from ai import kev_anomaly_detector as kev

        kev.detector().load(force=True)
        anomaly_detector.request_full_scan()
        self._refresh_kev_status()

    def _refresh_kev_status(self) -> None:
        info = anomaly_detector.model_info()
        status = info.get("status") or "not_loaded"

        if status == "loaded":
            status_text, status_colour = "Loaded", COLOUR_GREEN
        elif status == "loading":
            status_text, status_colour = "Loading…", COLOUR_YELLOW
        elif status == "error":
            status_text, status_colour = f"Error — {info.get('error')}", COLOUR_RED
        else:
            status_text, status_colour = "Not loaded", COLOUR_TEXT_DIM

        if info.get("device"):
            device = f"{info['device']}"
            if info.get("gpu"):
                device += f" — {info['gpu']}"
        else:
            device = "unavailable"
        if not anomaly_detector.kev_cuda_available():
            device += "  (CUDA unavailable)"

        source = info.get("reference") or info.get("model") or "—"
        if info.get("local_path"):
            source = f"{source}  (local path)"
        else:
            source = f"{source}  (Hugging Face hub id)"

        self.kev_values["model"].configure(text=info.get("model") or "—")
        self.kev_values["source"].configure(text=source)
        self.kev_values["device"].configure(text=device)
        self.kev_values["status"].configure(text=status_text, text_color=status_colour)
        self.kev_values["features"].configure(
            text=info.get("repo_path") or "Kev checkout not found"
        )
        self.kev_threshold_var.set(str(anomaly_detector.threshold()))

        # Poll while the background loader is still working so the page does
        # not sit on "Loading…" forever.
        if status == "loading":
            self.after(2000, self._refresh_kev_status)