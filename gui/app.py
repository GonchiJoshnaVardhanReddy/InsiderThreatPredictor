"""
Main application window — sidebar navigation + page router.

The application is organised in three layers:

  1. **Real OS monitors** (file_system, processes, network, USB, Event Log)
     — the primary data source. Started automatically on launch; toggleable
     from the Settings page.
  2. **Activity simulator** — opt-in; produces synthetic activity so the
     dashboard has data to show on a quiet system. Clearly labelled.
  3. **Risk engine + AI + response** — consumes whatever rows appear in
     `activity_logs`, regardless of which layer produced them.
"""

from __future__ import annotations

from typing import Callable, List

import customtkinter as ctk

from config.settings import (
    APP_SUBTITLE,
    APP_TITLE,
    COLOUR_BG,
    COLOUR_BLUE,
    COLOUR_CARD,
    COLOUR_CYAN,
    COLOUR_GREEN,
    COLOUR_PANEL,
    COLOUR_TEXT,
    COLOUR_TEXT_DIM,
    COLOUR_YELLOW,
    DEFAULT_RISK_WEIGHTS,
    DEFAULT_SIM_INTERVAL_MS,
    MIN_WINDOW_SIZE,
    WINDOW_SIZE,
)
from database import db_manager as db
from ai import anomaly_detector
from engine import event_simulator
from engine.event_simulator import EventSimulator
from engine.risk_engine import RiskEngine, load_engine
from gui.theme import configure_global_appearance, enable_windows_dpi_awareness
from monitor.monitor_manager import MonitorEvent, MonitorManager
from utils.helpers import iso_now, log


NAV_GROUPS: List[tuple] = [
    ("Overview",     [("Dashboard", "📊")]),
    ("Activity",     [("User Management", "👤"), ("Live Monitoring", "🛰")]),
    ("Intelligence", [("AI Risk Prediction", "🤖"), ("Sentiment Analysis", "💬")]),
    ("Operations",   [("Security Alerts", "🚨"), ("Automated Response", "🛡")]),
    ("Engagement",   [("Cyber Challenges", "🎯"), ("Reports", "📑")]),
    ("System",       [("Settings", "⚙")]),
]


class Application(ctk.CTk):
    """Top-level window. Holds shared services + the page registry."""

    def __init__(self) -> None:
        enable_windows_dpi_awareness()
        super().__init__()
        configure_global_appearance()
        self.title(f"{APP_TITLE} — {APP_SUBTITLE}")
        self.geometry(WINDOW_SIZE)
        self.minsize(*[int(v) for v in MIN_WINDOW_SIZE.split("x")])
        self.configure(fg_color=COLOUR_BG)

        # Layer 1: real OS monitors -------------------------------
        self.engine: RiskEngine = load_engine()
        self.monitors: MonitorManager = MonitorManager(
            risk_engine=self.engine,
            on_event=self._on_monitor_event,
        )

        # Layer 2: activity simulator (opt-in) --------------------
        # The interval key matches the one db_manager seeds and the Settings
        # page writes; they used to disagree, so a saved interval never applied.
        self.demo_generator: EventSimulator = EventSimulator(
            risk_weights=DEFAULT_RISK_WEIGHTS,
            interval_ms=int(db.get_setting("sim_interval_ms", DEFAULT_SIM_INTERVAL_MS)),
            on_event=self._on_demo_event,
        )

        # Layer 3: GUI state --------------------------------------
        self.pages = {}
        self.nav_buttons = {}
        self.current_page = None
        self._build_layout()

        # Startup order matters: the database is already initialised by main.py,
        # the analysis layer is wired up next, then the UI (built above), then
        # the collectors, then the analysis worker, then the dashboard.
        #
        # Kev loads on a background thread — it pulls a ~1.7 GB base model and
        # builds a CUDA context, which must never run on the Tk main thread.
        try:
            anomaly_detector.set_update_callback(self._on_kev_results)
            anomaly_detector.start_background_load()
        except Exception as exc:  # pragma: no cover
            log.warning("Kev initialisation skipped: %s", exc)

        # Start the real OS monitors in the background.
        try:
            self.monitors.start_all()
        except Exception as exc:  # pragma: no cover
            log.warning("Could not start real monitors: %s", exc)

        # Show the dashboard by default.
        self.show_page("Dashboard")

        # Centre the window on the primary screen.
        self._center_on_screen()

        # Auto-close handler.
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -----------------------------------------------------------
    def _center_on_screen(self) -> None:
        """Place the window in the centre of the primary screen."""
        self.update_idletasks()
        width = max(self.winfo_reqwidth(), 1)
        height = max(self.winfo_reqheight(), 1)
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 3)
        self.geometry(f"+{x}+{y}")

    # -----------------------------------------------------------
    def _build_layout(self) -> None:
        self.sidebar = ctk.CTkFrame(self, width=248, corner_radius=0, fg_color=COLOUR_PANEL)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Brand block ----------------------------------------------
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(20, 12))
        ctk.CTkLabel(
            brand, text="🛡", font=("Segoe UI", 26), text_color=COLOUR_CYAN,
        ).pack(side="left")
        brand_text = ctk.CTkFrame(brand, fg_color="transparent")
        brand_text.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(
            brand_text, text="INSIDER THREAT", font=("Segoe UI", 15, "bold"),
            text_color=COLOUR_TEXT, anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand_text, text="PREDICTOR · AI-POWERED UEBA", font=("Segoe UI", 9, "bold"),
            text_color=COLOUR_CYAN, anchor="w",
        ).pack(anchor="w")

        # Grouped navigation -----------------------------------------
        for group_name, entries in NAV_GROUPS:
            ctk.CTkLabel(
                self.sidebar, text=group_name.upper(),
                font=("Segoe UI", 9, "bold"), text_color=COLOUR_TEXT_DIM,
                anchor="w",
            ).pack(fill="x", padx=20, pady=(10, 2))
            for name, icon in entries:
                btn = ctk.CTkButton(
                    self.sidebar,
                    text=f"  {icon}  {name}",
                    anchor="w",
                    fg_color="transparent",
                    hover_color=COLOUR_BLUE,
                    text_color=COLOUR_TEXT,
                    font=("Segoe UI", 12),
                    corner_radius=8,
                    height=36,
                    cursor="hand2",
                    command=lambda n=name: self.show_page(n),
                )
                btn.pack(fill="x", padx=12, pady=1)
                self.nav_buttons[name] = btn

        # Sidebar footer ------------------------------------------------
        footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=18, pady=16)
        self.status_dot = ctk.CTkLabel(
            footer, text="● Engine Online",
            font=("Segoe UI", 11, "bold"),
            text_color=COLOUR_GREEN, anchor="w",
        )
        self.status_dot.pack(anchor="w")
        ctk.CTkLabel(
            footer, text="v1.0 · local-only · no cloud",
            font=("Segoe UI", 9), text_color=COLOUR_TEXT_DIM, anchor="w",
        ).pack(anchor="w")

        self.container = ctk.CTkFrame(self, fg_color=COLOUR_BG, corner_radius=0)
        self.container.pack(side="right", fill="both", expand=True)

        self._register_pages()

    # -----------------------------------------------------------
    def _register_pages(self) -> None:
        from gui.dashboard import DashboardPage
        from gui.user_management import UserManagementPage
        from gui.live_monitoring import LiveMonitoringPage
        from gui.ai_predictions import AIPredictionsPage
        from gui.sentiment import SentimentPage
        from gui.alerts import AlertsPage
        from gui.incident_response import IncidentResponsePage
        from gui.gamification import GamificationPage
        from gui.reports import ReportsPage
        from gui.settings_page import SettingsPage

        factories = {
            "Dashboard":          DashboardPage,
            "User Management":    UserManagementPage,
            "Live Monitoring":    LiveMonitoringPage,
            "AI Risk Prediction": AIPredictionsPage,
            "Sentiment Analysis": SentimentPage,
            "Security Alerts":    AlertsPage,
            "Automated Response": IncidentResponsePage,
            "Cyber Challenges":   GamificationPage,
            "Reports":            ReportsPage,
            "Settings":           SettingsPage,
        }

        for name, factory in factories.items():
            page = factory(self.container, app=self)
            page.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[name] = page

    # -----------------------------------------------------------
    def show_page(self, name: str) -> None:
        if name not in self.pages:
            return
        for page_name, page in self.pages.items():
            page.lift() if page_name == name else None
        self.pages[name].tkraise()
        self.current_page = name

        for page_name, btn in self.nav_buttons.items():
            if page_name == name:
                btn.configure(fg_color=COLOUR_BLUE, text_color=COLOUR_CYAN)
            else:
                btn.configure(fg_color="transparent", text_color=COLOUR_TEXT)

        page = self.pages[name]
        if hasattr(page, "on_show"):
            try:
                page.on_show()
            except Exception as exc:  # pragma: no cover
                log.warning("Page %s refresh failed: %s", name, exc)

    # -----------------------------------------------------------
    # Activity simulation generator (opt-in)
    # -----------------------------------------------------------
    def simulation_running(self) -> bool:
        """True while the activity simulator is producing events."""
        return self.demo_generator.is_running()

    def _sync_simulation_controls(self) -> None:
        """Push the generator's real state to every page that shows controls.

        Without this the buttons go stale: start it on the Dashboard, switch to
        Live Monitoring, and that page still offers to start what is already
        running. A disabled button also explains itself — clicking Stop when
        nothing is running used to look like a dead button.
        """
        running = self.demo_generator.is_running()
        for page in self.pages.values():
            hook = getattr(page, "on_simulation_state", None)
            if callable(hook):
                try:
                    hook(running)
                except Exception as exc:  # pragma: no cover
                    log.warning("Simulation state refresh failed: %s", exc)

    def start_demo_generator(self) -> None:
        # The behavioural model needs prior days to build a baseline against.
        # A fresh database has only today, so backfill labelled synthetic
        # history once — otherwise every user would look perfectly normal.
        try:
            if event_simulator.history_days_available() < 11:
                event_simulator.seed_demo_history()
        except Exception as exc:  # pragma: no cover
            log.warning("Synthetic history seeding skipped: %s", exc)

        self.demo_generator.update_weights(self.engine.weights)
        self.demo_generator.start(self)
        self._sync_simulation_controls()

        # Populate the behavioural view immediately rather than waiting for
        # the first debounce window to expire.
        try:
            anomaly_detector.request_full_scan()
        except Exception as exc:  # pragma: no cover
            log.debug("Initial Kev scan request failed: %s", exc)

    def stop_demo_generator(self) -> None:
        self.demo_generator.stop()
        self._sync_simulation_controls()

    # -----------------------------------------------------------
    # Real monitor callbacks
    # -----------------------------------------------------------
    def _on_monitor_event(self, event: MonitorEvent) -> None:
        # Monitors emit from background threads; Tkinter is NOT thread-safe.
        # Marshal every GUI update onto the main event loop instead.
        try:
            self.after(0, lambda: self._dispatch_monitor_event(event))
        except RuntimeError:  # pragma: no cover - window already destroyed
            pass

    def _dispatch_monitor_event(self, event: MonitorEvent) -> None:
        self._note_activity_for_kev(getattr(event, "user_id", None))
        for name in ("Dashboard", "Live Monitoring", "AI Risk Prediction", "Security Alerts"):
            page = self.pages.get(name)
            if page is None:
                continue
            callback = getattr(page, "on_monitor_event", None)
            if callable(callback):
                try:
                    callback(event)
                except Exception as exc:  # pragma: no cover
                    log.warning("Page %s monitor callback failed: %s", name, exc)

    def _on_demo_event(self, event) -> None:
        try:
            self.after(0, lambda: self._dispatch_demo_event(event))
        except RuntimeError:  # pragma: no cover - window already destroyed
            pass

    def _dispatch_demo_event(self, event) -> None:
        # The demo generator writes its rows straight to the database, so the
        # rule engine has to be told to re-score — previously it never was,
        # which left demo mode changing activity rows but not risk scores.
        try:
            self.engine.assess_user_and_persist(int(event.user_id))
        except Exception as exc:  # pragma: no cover
            log.warning("Demo risk recompute failed: %s", exc)

        self._note_activity_for_kev(getattr(event, "user_id", None))

        for name in ("Dashboard", "Live Monitoring", "AI Risk Prediction", "Security Alerts"):
            page = self.pages.get(name)
            if page is None:
                continue
            callback = getattr(page, "on_demo_event", None)
            if callable(callback):
                try:
                    callback(event)
                except Exception as exc:  # pragma: no cover
                    log.warning("Page %s demo callback failed: %s", name, exc)

    # -----------------------------------------------------------
    # Kev behavioural scoring (debounced, off the GUI thread)
    # -----------------------------------------------------------
    def _note_activity_for_kev(self, user_id) -> None:
        """Queue the affected user for a debounced Kev re-score.

        Only this user is scored — the old behaviour re-scanned every user for
        every event, which does not scale.
        """
        if user_id is None:
            return
        try:
            anomaly_detector.note_activity(int(user_id))
        except Exception as exc:  # pragma: no cover
            log.debug("Could not queue Kev scoring: %s", exc)

    def _on_kev_results(self, results) -> None:
        """Called from the Kev worker thread — marshal onto the Tk loop."""
        try:
            self.after(0, lambda: self._dispatch_kev_results(results))
        except RuntimeError:  # pragma: no cover - window already destroyed
            pass

    def _dispatch_kev_results(self, results) -> None:
        """Raise alerts for Kev threats and refresh every interested page."""
        for result in results:
            if not result.get("is_threat"):
                continue
            try:
                self.engine.raise_kev_alert(result)
            except Exception as exc:  # pragma: no cover
                log.warning("Kev alert creation failed: %s", exc)

        for name in ("Dashboard", "AI Risk Prediction", "Security Alerts"):
            page = self.pages.get(name)
            if page is None:
                continue
            callback = getattr(page, "on_kev_results", None)
            if callable(callback):
                try:
                    callback(results)
                except Exception as exc:  # pragma: no cover
                    log.warning("Page %s Kev callback failed: %s", name, exc)

    # -----------------------------------------------------------
    def _on_close(self) -> None:
        try:
            self.demo_generator.stop()
        finally:
            try:
                self.monitors.stop_all()
            finally:
                self.destroy()