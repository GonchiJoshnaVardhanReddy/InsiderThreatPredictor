"""Shared theme + helper widgets for the GUI."""

from __future__ import annotations

from tkinter import ttk
from typing import Optional

import customtkinter as ctk

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


def enable_windows_dpi_awareness() -> None:
    """Request per-monitor DPI awareness so text renders crisp on Windows."""
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
    except Exception:  # pragma: no cover - non-Windows or old Windows
        pass


# ---------------------------------------------------------------
# Typography + spacing tokens
# ---------------------------------------------------------------
FONT_FAMILY = "Segoe UI"


def font(size: int, weight: str = "normal") -> tuple:
    """Consistent font tuple used across the whole app."""
    return (FONT_FAMILY, size, weight)


SPACE_XS, SPACE_S, SPACE_M, SPACE_L = 4, 8, 16, 24


def configure_global_appearance() -> None:
    """Initialise CustomTkinter with the dark cybersecurity theme."""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    ctk.ThemeManager.theme["CTk"]["fg_color"] = [COLOUR_BG, COLOUR_BG]


SEVERITY_COLOURS = {
    "LOW":      COLOUR_GREEN,
    "MEDIUM":   COLOUR_YELLOW,
    "HIGH":     COLOUR_RED,
    "CRITICAL": COLOUR_RED,
}


def severity_colour(label: str) -> str:
    return SEVERITY_COLOURS.get(label.upper(), COLOUR_CYAN)


# ---------------------------------------------------------------
# Reusable Card / KPI
# ---------------------------------------------------------------
class CardFrame(ctk.CTkFrame):
    """A rounded panel that visually groups related content."""

    def __init__(self, master, **kwargs):
        kwargs.setdefault("corner_radius", 14)
        kwargs.setdefault("fg_color", COLOUR_PANEL)
        kwargs.setdefault("border_color", COLOUR_CARD)
        kwargs.setdefault("border_width", 1)
        super().__init__(master, **kwargs)


class KPICard(ctk.CTkFrame):
    """A KPI tile for the dashboard — icon chip, label, big value."""

    def __init__(self, master, title: str, value: str, accent: str = COLOUR_CYAN,
                 icon: str = "■", subtitle: str | None = None, **kwargs):
        kwargs.setdefault("corner_radius", 16)
        kwargs.setdefault("fg_color", COLOUR_PANEL)
        kwargs.setdefault("border_color", COLOUR_CARD)
        kwargs.setdefault("border_width", 1)
        super().__init__(master, **kwargs)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(12, 0))
        ctk.CTkLabel(
            header, text=icon, font=(FONT_FAMILY, 16), text_color=accent,
        ).pack(side="left")
        ctk.CTkLabel(
            header, text=f"  {title}", font=(FONT_FAMILY, 12, "bold"),
            text_color=COLOUR_TEXT_DIM, anchor="w",
        ).pack(side="left")

        self.value_label = ctk.CTkLabel(
            self, text=value, font=(FONT_FAMILY, 30, "bold"),
            text_color=accent, anchor="w",
        )
        self.value_label.pack(anchor="w", padx=16, pady=(2, 0))

        self.subtitle_label = None
        if subtitle is not None:
            self.subtitle_label = ctk.CTkLabel(
                self, text=subtitle, font=(FONT_FAMILY, 10),
                text_color=COLOUR_TEXT_DIM, anchor="w",
            )
            self.subtitle_label.pack(anchor="w", padx=16, pady=(0, 12))
        else:
            # Keep geometry stable whether or not a subtitle is shown.
            ctk.CTkLabel(self, text=" ", font=(FONT_FAMILY, 10)).pack(pady=(0, 10))

    def set_value(self, value: str) -> None:
        self.value_label.configure(text=value)

    def set_subtitle(self, text: str | None) -> None:
        if self.subtitle_label is not None:
            self.subtitle_label.configure(text=text or "")


# ---------------------------------------------------------------
# Treeview styling (CustomTkinter doesn't theme ttk, so we patch it)
# ---------------------------------------------------------------
def style_treeview(style: ttk.Style) -> None:
    style.theme_use("clam")
    style.configure(
        "Treeview",
        background=COLOUR_PANEL,
        foreground=COLOUR_TEXT,
        fieldbackground=COLOUR_PANEL,
        rowheight=30,
        bordercolor=COLOUR_CARD,
        font=(FONT_FAMILY, 10),
    )
    style.map(
        "Treeview",
        background=[("selected", COLOUR_BLUE)],
        foreground=[("selected", COLOUR_TEXT)],
    )
    style.configure(
        "Treeview.Heading",
        background=COLOUR_CARD,
        foreground=COLOUR_CYAN,
        font=(FONT_FAMILY, 10, "bold"),
        relief="flat",
        padding=(8, 6),
    )
    style.map("Treeview.Heading", background=[("active", COLOUR_BLUE)])
    style.configure(
        "Vertical.TScrollbar", background=COLOUR_CARD,
        troughcolor=COLOUR_BG, arrowcolor=COLOUR_CYAN,
        bordercolor=COLOUR_BG, lightcolor=COLOUR_CARD, darkcolor=COLOUR_CARD,
    )
    style.configure(
        "Horizontal.TScrollbar", background=COLOUR_CARD,
        troughcolor=COLOUR_BG, arrowcolor=COLOUR_CYAN,
        bordercolor=COLOUR_BG, lightcolor=COLOUR_CARD, darkcolor=COLOUR_CARD,
    )


# ---------------------------------------------------------------
# Matplotlib chart styling
# ---------------------------------------------------------------
def style_dark_axes(ax, title: str | None = None) -> None:
    """Give a matplotlib axes the app's dark, low-noise look."""
    ax.set_facecolor(COLOUR_PANEL)
    ax.grid(True, color=COLOUR_CARD, linewidth=0.5, alpha=0.45)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(COLOUR_CARD)
    ax.tick_params(colors=COLOUR_TEXT_DIM, labelsize=9)
    if title:
        ax.set_title(title, color=COLOUR_CYAN, fontsize=11, pad=10)


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
def section_title(parent, text: str, subtitle: str | None = None):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=SPACE_L, pady=(18, 4))
    label = ctk.CTkLabel(
        frame, text=text, font=(FONT_FAMILY, 22, "bold"),
        text_color=COLOUR_CYAN, anchor="w",
    )
    label.pack(anchor="w")
    if subtitle:
        ctk.CTkLabel(
            frame, text=subtitle, font=(FONT_FAMILY, 12),
            text_color=COLOUR_TEXT_DIM, anchor="w",
        ).pack(anchor="w", pady=(2, 0))
    return frame


BUTTON_KINDS = {
    "primary":   {"fg_color": COLOUR_BLUE, "hover_color": "#1565A8", "text_color": COLOUR_TEXT},
    "accent":    {"fg_color": COLOUR_CYAN, "hover_color": "#7FD6D4", "text_color": COLOUR_BG},
    "success":   {"fg_color": COLOUR_GREEN, "hover_color": "#48D986", "text_color": COLOUR_BG},
    "danger":    {"fg_color": COLOUR_RED,  "hover_color": "#F26B5E", "text_color": COLOUR_TEXT},
    "secondary": {"fg_color": COLOUR_CARD, "hover_color": "#4A6280", "text_color": COLOUR_TEXT},
}


def make_button(parent, text: str, command, kind: str = "primary",
                width: int | None = None, height: int = 36, **kwargs) -> ctk.CTkButton:
    """Create a consistently styled, semantic button."""
    palette = BUTTON_KINDS.get(kind, BUTTON_KINDS["primary"])
    if width is not None:
        kwargs["width"] = width
    return ctk.CTkButton(
        parent, text=text, command=command, height=height,
        corner_radius=8, cursor="hand2",
        fg_color=palette["fg_color"], hover_color=palette["hover_color"],
        text_color=palette["text_color"], font=(FONT_FAMILY, 12, "bold"),
        **kwargs,
    )


def labelled_entry(parent, label_text: str, placeholder: str = ""):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=SPACE_L, pady=6)
    ctk.CTkLabel(
        frame, text=label_text, font=(FONT_FAMILY, 12, "bold"),
        text_color=COLOUR_TEXT_DIM,
    ).pack(anchor="w")
    entry = ctk.CTkEntry(
        frame, placeholder_text=placeholder,
        fg_color=COLOUR_PANEL, border_color=COLOUR_CARD,
        text_color=COLOUR_TEXT, height=34,
    )
    entry.pack(fill="x", pady=(2, 0))
    return entry


def info_banner(parent, text: str, colour=COLOUR_TEXT_DIM):
    return ctk.CTkLabel(
        parent, text=text, font=(FONT_FAMILY, 11),
        text_color=colour, anchor="w", justify="left", wraplength=900,
    )