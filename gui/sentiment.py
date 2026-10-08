"""Sentiment Analysis page."""

from __future__ import annotations

from datetime import datetime
from tkinter import ttk
from typing import List

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from ai.sentiment_analyzer import get_analyzer
from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CARD, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
)
from database import db_manager as db
from gui.theme import CardFrame, info_banner, section_title, style_treeview
from utils.helpers import fmt_dt, log


EXAMPLE_MESSAGES: List[str] = [
    "I love working with this team, the project is going great!",
    "I'm feeling frustrated with the latest management changes.",
    "The meeting agenda looks neutral — no surprises this week.",
    "I might leave the company soon, I'm updating my CV.",
    "Customer feedback has been excellent this quarter.",
    "I'm worried about the security audit tomorrow.",
]


class SentimentPage(ctk.CTkFrame):
    """Local VADER sentiment scoring with history."""

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app
        self.analyzer = get_analyzer()

        section_title(
            self, "Sentiment Analysis",
            "Local text sentiment using NLTK VADER — informational only",
        )

        # Input area
        input_card = CardFrame(self)
        input_card.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(input_card, text="Enter a fictional sample to score",
                     font=("Segoe UI", 13, "bold"),
                     text_color=COLOUR_CYAN).pack(anchor="w", padx=14, pady=(12, 4))
        self.text_box = ctk.CTkTextbox(input_card, height=110, fg_color=COLOUR_BG,
                                        text_color=COLOUR_TEXT)
        self.text_box.pack(fill="x", padx=14, pady=4)

        button_row = ctk.CTkFrame(input_card, fg_color="transparent")
        button_row.pack(fill="x", padx=14, pady=(4, 12))
        ctk.CTkButton(
            button_row, text="Analyze", fg_color=COLOUR_CYAN,
            text_color=COLOUR_BG, command=self._analyse,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            button_row, text="Clear", fg_color=COLOUR_CARD,
            command=lambda: self.text_box.delete("0.0", "end"),
        ).pack(side="left", padx=4)
        ctk.CTkLabel(button_row, text="Examples:",
                     font=("Segoe UI", 11),
                     text_color=COLOUR_TEXT_DIM).pack(side="left", padx=12)
        for example in EXAMPLE_MESSAGES[:3]:
            ctk.CTkButton(
                button_row, text=f"“{example[:28]}…”",
                fg_color=COLOUR_BLUE, command=lambda e=example: self._load_example(e),
            ).pack(side="left", padx=2)

        # Result panel
        results = ctk.CTkFrame(self, fg_color="transparent")
        results.pack(fill="both", expand=True, padx=24, pady=8)
        results.grid_columnconfigure(0, weight=1)
        results.grid_columnconfigure(1, weight=1)
        results.grid_rowconfigure(0, weight=1)

        self.result_card = CardFrame(results)
        self.result_card.grid(row=0, column=0, padx=6, pady=4, sticky="nsew")
        ctk.CTkLabel(self.result_card, text="Latest score",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(8, 0))
        self.label_lbl = ctk.CTkLabel(
            self.result_card, text="—",
            font=("Segoe UI", 22, "bold"), text_color=COLOUR_TEXT,
        )
        self.label_lbl.pack(pady=4)
        self.scores_lbl = ctk.CTkLabel(
            self.result_card, text="compound 0.00 | pos 0.00 | neu 0.00 | neg 0.00",
            font=("Segoe UI", 12), text_color=COLOUR_TEXT_DIM,
        )
        self.scores_lbl.pack(pady=4)

        # Matplotlib bar
        self.fig = Figure(figsize=(4, 2.6), dpi=100, facecolor=COLOUR_PANEL)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(COLOUR_PANEL)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.result_card)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

        # History
        history_card = CardFrame(results)
        history_card.grid(row=0, column=1, padx=6, pady=4, sticky="nsew")
        ctk.CTkLabel(history_card, text="Analysis history",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(8, 0))
        style = ttk.Style()
        style_treeview(style)
        cols = ("Time", "Label", "Compound", "Text")
        widths = (140, 100, 80, 200)
        tree_frame = ctk.CTkFrame(history_card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=10)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("POSITIVE", foreground=COLOUR_GREEN)
        self.tree.tag_configure("NEUTRAL", foreground=COLOUR_CYAN)
        self.tree.tag_configure("NEGATIVE", foreground=COLOUR_RED)
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        self.banner = info_banner(
            self,
            "Sentiment is treated as an optional contextual indicator only — "
            "never as evidence of malicious intent.",
            COLOUR_TEXT_DIM,
        )
        self.banner.pack(anchor="w", padx=24, pady=(0, 12))

        if not self.analyzer.available:
            self.banner.configure(
                text=f"VADER lexicon unavailable: {self.analyzer.init_error}. "
                     "Using a tiny fallback lexicon instead.",
                text_color=COLOUR_YELLOW,
            )
        self._refresh_history()

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self._refresh_history()

    # -----------------------------------------------------------
    def _load_example(self, text: str) -> None:
        self.text_box.delete("0.0", "end")
        self.text_box.insert("0.0", text)

    def _analyse(self) -> None:
        text = self.text_box.get("0.0", "end").strip()
        if not text:
            return
        try:
            result = self.analyzer.analyse(text)
        except Exception as exc:
            log.exception("Sentiment analysis failed: %s", exc)
            return
        colour = {
            "POSITIVE": COLOUR_GREEN,
            "NEUTRAL": COLOUR_CYAN,
            "NEGATIVE": COLOUR_RED,
        }.get(result["label"], COLOUR_TEXT)
        self.label_lbl.configure(text=result["label"], text_color=colour)
        self.scores_lbl.configure(
            text=f"compound {result['compound']:.2f} | pos {result['pos']:.2f} "
                 f"| neu {result['neu']:.2f} | neg {result['neg']:.2f}"
        )
        self._draw_bars(result)
        self._refresh_history()

    def _draw_bars(self, result) -> None:
        ax = self.ax
        ax.clear()
        categories = ["Positive", "Neutral", "Negative"]
        values = [result["pos"], result["neu"], result["neg"]]
        colours = [COLOUR_GREEN, COLOUR_CYAN, COLOUR_RED]
        ax.bar(categories, values, color=colours)
        ax.set_ylim(0, 1)
        ax.set_ylabel("Score", color=COLOUR_TEXT)
        ax.tick_params(colors=COLOUR_TEXT)
        for spine in ax.spines.values():
            spine.set_color(COLOUR_CARD)
        self.canvas.draw_idle()

    def _refresh_history(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for row in db.list_sentiment(limit=20):
            ts = row.get("timestamp")
            try:
                ts_dt = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
            except ValueError:
                ts_dt = None
            text = (row.get("text") or "")[:60]
            self.tree.insert(
                "", "end",
                values=(
                    fmt_dt(ts_dt),
                    row["label"],
                    f"{row['compound']:.2f}",
                    text,
                ),
                tags=(row["label"],),
            )