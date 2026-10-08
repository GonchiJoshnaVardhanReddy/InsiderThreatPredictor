"""Cyber Challenges / Gamification page."""

from __future__ import annotations

from tkinter import messagebox, ttk
from typing import Optional

import customtkinter as ctk

from config.settings import (
    COLOUR_BG, COLOUR_BLUE, COLOUR_CARD, COLOUR_CYAN, COLOUR_GREEN,
    COLOUR_PANEL, COLOUR_RED, COLOUR_TEXT, COLOUR_TEXT_DIM, COLOUR_YELLOW,
)
from gamification import challenges
from gui.theme import CardFrame, info_banner, section_title, style_treeview
from utils.helpers import log


class GamificationPage(ctk.CTkFrame):
    """Multiple-choice security challenges + leaderboard."""

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app

        section_title(
            self, "Cyber Challenges",
            "Train your eye to spot suspicious behaviour — earn points and badges"
        )

        # Layout split: left = challenge, right = leaderboard
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=8)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # Challenge card
        self.challenge_card = CardFrame(body)
        self.challenge_card.grid(row=0, column=0, padx=6, pady=4, sticky="nsew")
        self.challenge_card.grid_columnconfigure(0, weight=1)

        header_row = ctk.CTkFrame(self.challenge_card, fg_color="transparent")
        header_row.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
        ctk.CTkLabel(header_row, text="Challenge",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(side="left")
        self.score_label = ctk.CTkLabel(
            header_row, text="Score: 0",
            font=("Segoe UI", 12, "bold"), text_color=COLOUR_GREEN,
        )
        self.score_label.pack(side="right")

        self.title_label = ctk.CTkLabel(
            self.challenge_card, text="",
            font=("Segoe UI", 16, "bold"), text_color=COLOUR_TEXT,
            anchor="w", justify="left",
        )
        self.title_label.grid(row=1, column=0, sticky="ew", padx=14, pady=(8, 2))

        self.scenario_label = ctk.CTkLabel(
            self.challenge_card, text="",
            font=("Segoe UI", 12), text_color=COLOUR_TEXT_DIM,
            anchor="w", justify="left", wraplength=520,
        )
        self.scenario_label.grid(row=2, column=0, sticky="ew", padx=14)

        self.question_label = ctk.CTkLabel(
            self.challenge_card, text="",
            font=("Segoe UI", 12, "bold"), text_color=COLOUR_CYAN,
            anchor="w", justify="left", wraplength=520,
        )
        self.question_label.grid(row=3, column=0, sticky="ew", padx=14, pady=(8, 4))

        self.options_frame = ctk.CTkFrame(self.challenge_card, fg_color="transparent")
        self.options_frame.grid(row=4, column=0, sticky="ew", padx=14, pady=4)
        self.option_vars: list[ctk.StringVar] = []
        self._option_widgets: list[ctk.CTkRadioButton] = []

        ctk.CTkLabel(
            self.challenge_card, text="Explanation",
            font=("Segoe UI", 12, "bold"), text_color=COLOUR_CYAN,
            anchor="w",
        ).grid(row=5, column=0, sticky="ew", padx=14, pady=(10, 2))
        self.explanation_label = ctk.CTkLabel(
            self.challenge_card, text="",
            font=("Segoe UI", 11), text_color=COLOUR_TEXT,
            anchor="w", justify="left", wraplength=520,
        )
        self.explanation_label.grid(row=6, column=0, sticky="ew", padx=14)

        action_row = ctk.CTkFrame(self.challenge_card, fg_color="transparent")
        action_row.grid(row=7, column=0, sticky="ew", padx=14, pady=14)
        ctk.CTkButton(action_row, text="Submit", fg_color=COLOUR_CYAN,
                      text_color=COLOUR_BG, command=self._submit).pack(side="left", padx=4)
        ctk.CTkButton(action_row, text="Next Challenge", fg_color=COLOUR_BLUE,
                      command=self._load_next).pack(side="left", padx=4)
        ctk.CTkButton(action_row, text="Restart", fg_color=COLOUR_RED,
                      command=self._restart).pack(side="left", padx=4)
        self.feedback_label = ctk.CTkLabel(
            action_row, text="", font=("Segoe UI", 12, "bold"),
            text_color=COLOUR_TEXT_DIM,
        )
        self.feedback_label.pack(side="right", padx=8)

        # Leaderboard
        lb_card = CardFrame(body)
        lb_card.grid(row=0, column=1, padx=6, pady=4, sticky="nsew")
        ctk.CTkLabel(lb_card, text="Leaderboard",
                     font=("Segoe UI", 14, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(10, 4))

        self.participant_var = ctk.StringVar(value="analyst")
        name_row = ctk.CTkFrame(lb_card, fg_color="transparent")
        name_row.pack(fill="x", padx=14)
        ctk.CTkLabel(name_row, text="Your name:",
                     font=("Segoe UI", 11),
                     text_color=COLOUR_TEXT_DIM).pack(side="left", padx=(0, 4))
        ctk.CTkEntry(name_row, textvariable=self.participant_var, width=140,
                     fg_color=COLOUR_BG, text_color=COLOUR_TEXT).pack(side="left", padx=4)

        style = ttk.Style()
        style_treeview(style)
        cols = ("Rank", "Participant", "Score", "Correct", "Attempts")
        widths = (50, 130, 80, 80, 80)
        tree_frame = ctk.CTkFrame(lb_card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=8)
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=10)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        # Initial state
        self.challenges_list = challenges.all_challenges()
        self.challenge_index = 0
        self.current_score = 0
        self.last_attempt_correct: Optional[bool] = None
        self._load_challenge()
        self._refresh_leaderboard()

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self._refresh_leaderboard()

    # -----------------------------------------------------------
    def _clear_options(self) -> None:
        for w in self._option_widgets:
            w.destroy()
        self._option_widgets.clear()
        self.option_vars.clear()

    def _load_challenge(self) -> None:
        ch = self.challenges_list[self.challenge_index % len(self.challenges_list)]
        self.title_label.configure(text=ch.title)
        self.scenario_label.configure(text=f"Scenario: {ch.scenario}")
        self.question_label.configure(text=ch.question)
        self._clear_options()
        for opt in ch.options:
            var = ctk.StringVar(value="")
            rb = ctk.CTkRadioButton(
                self.options_frame, text=opt, variable=var, value=opt,
                fg_color=COLOUR_BLUE, hover_color=COLOUR_CYAN,
                text_color=COLOUR_TEXT,
            )
            rb.pack(anchor="w", pady=2, fill="x")
            self.option_vars.append(var)
            self._option_widgets.append(rb)
        self.explanation_label.configure(text="Submit your choice to see the explanation.")
        self.feedback_label.configure(text="")

    def _submit(self) -> None:
        ch = self.challenges_list[self.challenge_index % len(self.challenges_list)]
        selected_idx = None
        for i, var in enumerate(self.option_vars):
            if var.get():
                selected_idx = i
                break
        if selected_idx is None:
            messagebox.showinfo("Pick an answer", "Choose one of the options first.")
            return
        try:
            result = challenges.evaluate_answer(ch.key, selected_idx)
        except Exception as exc:
            log.exception("Challenge evaluation failed: %s", exc)
            return
        self.current_score += result["points_awarded"]
        self.score_label.configure(text=f"Score: {self.current_score}")
        self.last_attempt_correct = result["correct"]
        if result["correct"]:
            self.feedback_label.configure(text="✓ Correct!", text_color=COLOUR_GREEN)
        else:
            correct_opt = ch.options[ch.correct_index]
            self.feedback_label.configure(
                text=f"✗ Correct: {correct_opt}",
                text_color=COLOUR_RED,
            )
        self.explanation_label.configure(text=result["explanation"])
        # Persist under custom participant if set
        from database import db_manager as db
        try:
            db.insert_challenge_score(
                participant=self.participant_var.get() or "analyst",
                challenge=ch.key,
                score=result["points_awarded"],
                correct=1 if result["correct"] else 0,
                total=1,
            )
        except Exception:
            pass
        self._refresh_leaderboard()

    def _load_next(self) -> None:
        self.challenge_index += 1
        self._load_challenge()

    def _restart(self) -> None:
        if not messagebox.askyesno(
            "Restart challenge",
            "Reset the leaderboard and start over?",
        ):
            return
        try:
            challenges.reset_scores()
        except Exception as exc:
            log.warning("Reset failed: %s", exc)
        self.current_score = 0
        self.challenge_index = 0
        self.score_label.configure(text="Score: 0")
        self._refresh_leaderboard()
        self._load_challenge()

    def _refresh_leaderboard(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for idx, row in enumerate(challenges.leaderboard(limit=10), start=1):
            self.tree.insert(
                "", "end",
                values=(
                    idx,
                    row.get("participant", ""),
                    int(row.get("total_score", 0) or 0),
                    f"{int(row.get('total_correct', 0) or 0)}/{int(row.get('total_questions', 0) or 0)}",
                    int(row.get("attempts", 0) or 0),
                ),
            )