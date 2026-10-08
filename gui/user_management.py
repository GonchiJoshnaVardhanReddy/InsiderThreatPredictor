"""User Management page — CRUD for fictional employees."""

from __future__ import annotations

from tkinter import messagebox, ttk
from typing import Optional

import customtkinter as ctk

from config.settings import (
    ACCOUNT_STATUSES,
    COLOUR_BG,
    COLOUR_BLUE,
    COLOUR_CARD,
    COLOUR_CYAN,
    COLOUR_GREEN,
    COLOUR_PANEL,
    COLOUR_RED,
    COLOUR_TEXT,
    COLOUR_TEXT_DIM,
    DEPARTMENTS,
    ROLES,
)
from database import db_manager as db
from gui.theme import CardFrame, info_banner, section_title, style_treeview
from utils.helpers import band_for_score, log, severity_from_score
from engine.risk_engine import RISK_BANDS


class UserManagementPage(ctk.CTkFrame):
    """Full CRUD over the users table with filtering and risk view."""

    def __init__(self, master, *, app) -> None:
        super().__init__(master, fg_color=COLOUR_BG, corner_radius=0)
        self.app = app
        self.selected_user_id: Optional[int] = None

        section_title(
            self, "User Management",
            "Add, edit and monitor fictional employees"
        )

        # Top toolbar --------------------------------------------------
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=24, pady=8)

        ctk.CTkLabel(toolbar, text="Search:", font=("Segoe UI", 11),
                     text_color=COLOUR_TEXT_DIM).pack(side="left", padx=(0, 4))
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_table())
        ctk.CTkEntry(toolbar, textvariable=self.search_var, width=180,
                     placeholder_text="name/email").pack(side="left", padx=4)

        ctk.CTkLabel(toolbar, text="Department:", font=("Segoe UI", 11),
                     text_color=COLOUR_TEXT_DIM).pack(side="left", padx=(12, 4))
        self.dept_var = ctk.StringVar(value="ALL")
        dept_menu = ctk.CTkOptionMenu(
            toolbar, variable=self.dept_var,
            values=["ALL"] + DEPARTMENTS,
            command=lambda _v: self._refresh_table(),
            fg_color=COLOUR_PANEL, button_color=COLOUR_BLUE,
            text_color=COLOUR_TEXT,
        )
        dept_menu.pack(side="left", padx=4)

        ctk.CTkButton(toolbar, text="+ Add User", fg_color=COLOUR_GREEN,
                      command=self._open_add_dialog).pack(side="right", padx=4)
        ctk.CTkButton(toolbar, text="Edit", fg_color=COLOUR_BLUE,
                      command=self._open_edit_dialog).pack(side="right", padx=4)
        ctk.CTkButton(toolbar, text="Delete", fg_color=COLOUR_RED,
                      command=self._delete_user).pack(side="right", padx=4)
        ctk.CTkButton(toolbar, text="View Risk", fg_color=COLOUR_CYAN,
                      text_color=COLOUR_BG,
                      command=self._view_risk).pack(side="right", padx=4)

        # Table ---------------------------------------------------------
        self.table_card = CardFrame(self)
        self.table_card.pack(fill="both", expand=True, padx=24, pady=8)
        style = ttk.Style()
        style_treeview(style)

        cols = ("ID", "Name", "Department", "Role", "Email", "Risk", "Band", "Status")
        widths = (50, 140, 130, 140, 200, 70, 100, 110)
        self.tree = ttk.Treeview(self.table_card, columns=cols, show="headings", height=12)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("LOW", foreground=COLOUR_GREEN)
        self.tree.tag_configure("MEDIUM", foreground="#F1C40F")
        self.tree.tag_configure("HIGH", foreground=COLOUR_RED)
        self.tree.tag_configure("CRITICAL", foreground=COLOUR_RED)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8, side="left")
        sb = ttk.Scrollbar(self.table_card, orient="vertical", command=self.tree.yview)
        sb.pack(fill="y", side="right")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Status bar
        self.banner = info_banner(self, "Click a row to select a user.", COLOUR_TEXT_DIM)
        self.banner.pack(anchor="w", padx=24, pady=(0, 12))

        self._refresh_table()

    # -----------------------------------------------------------
    def on_show(self) -> None:
        self._refresh_table()

    # -----------------------------------------------------------
    def _refresh_table(self) -> None:
        search = self.search_var.get().strip()
        department = self.dept_var.get()
        users = db.list_users()
        if department and department != "ALL":
            users = [u for u in users if u.get("department") == department]
        if search:
            s = search.lower()
            users = [
                u for u in users
                if s in u["name"].lower() or s in u["email"].lower()
            ]
        self.tree.delete(*self.tree.get_children())
        for u in users:
            score = float(u.get("risk_score", 0))
            band = band_for_score(score, RISK_BANDS)
            self.tree.insert(
                "", "end",
                iid=str(u["user_id"]),
                values=(
                    u["user_id"],
                    u["name"],
                    u["department"],
                    u["role"],
                    u["email"],
                    f"{score:.1f}",
                    band,
                    u.get("account_status", "ACTIVE"),
                ),
                tags=(band,),
            )

    # -----------------------------------------------------------
    def _on_select(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        try:
            self.selected_user_id = int(sel[0])
            user = db.get_user(self.selected_user_id)
            if user:
                self.banner.configure(
                    text=f"Selected: {user['name']} — {user['role']} ({user['department']})"
                )
        except (TypeError, ValueError):
            self.selected_user_id = None

    # -----------------------------------------------------------
    def _open_add_dialog(self) -> None:
        dlg = UserDialog(self, title="Add User")
        self.wait_window(dlg)
        if dlg.result:
            try:
                user_id = db.add_user(dlg.result)
                db.audit("analyst", "user_created", f"id={user_id}")
                self._refresh_table()
                messagebox.showinfo("User added", f"User '{dlg.result['name']}' added.")
            except Exception as exc:
                messagebox.showerror("Could not add user", str(exc))

    def _open_edit_dialog(self) -> None:
        if not self.selected_user_id:
            messagebox.showwarning("Select a user", "Pick a user first.")
            return
        user = db.get_user(self.selected_user_id)
        if not user:
            return
        dlg = UserDialog(self, title="Edit User", user=user)
        self.wait_window(dlg)
        if dlg.result:
            try:
                db.update_user(self.selected_user_id, dlg.result)
                db.audit("analyst", "user_updated", f"id={self.selected_user_id}")
                self._refresh_table()
                messagebox.showinfo("User updated", "User saved.")
            except Exception as exc:
                messagebox.showerror("Could not update user", str(exc))

    def _delete_user(self) -> None:
        if not self.selected_user_id:
            messagebox.showwarning("Select a user", "Pick a user first.")
            return
        user = db.get_user(self.selected_user_id)
        if not user:
            return
        if not messagebox.askyesno("Confirm", f"Delete user '{user['name']}'? This cannot be undone."):
            return
        db.delete_user(self.selected_user_id)
        db.audit("analyst", "user_deleted", f"id={self.selected_user_id}")
        self.selected_user_id = None
        self._refresh_table()

    def _view_risk(self) -> None:
        if not self.selected_user_id:
            messagebox.showwarning("Select a user", "Pick a user first.")
            return
        user = db.get_user(self.selected_user_id)
        if not user:
            return
        events = db.activity_for_user(self.selected_user_id, limit=15)
        assessment = self.app.engine.assess_user(self.selected_user_id, events)
        dlg = RiskProfileDialog(self, user=user, assessment=assessment, events=events)
        self.wait_window(dlg)


# ---------------------------------------------------------------
class UserDialog(ctk.CTkToplevel):
    """Dialog for adding/editing a user."""

    def __init__(self, master, *, title: str, user: dict | None = None) -> None:
        super().__init__(master)
        self.title(title)
        self.geometry("440x600")
        self.configure(fg_color=COLOUR_PANEL)
        self.grab_set()
        self.result: dict | None = None

        ctk.CTkLabel(self, text=title, font=("Segoe UI", 16, "bold"),
                     text_color=COLOUR_CYAN).pack(pady=(18, 8))

        self.name_var = ctk.StringVar(value=user["name"] if user else "")
        self.dept_var = ctk.StringVar(value=user["department"] if user else DEPARTMENTS[0])
        self.role_var = ctk.StringVar(value=user["role"] if user else ROLES[0])
        self.email_var = ctk.StringVar(value=user["email"] if user else "")
        self.base_hour_var = ctk.StringVar(value=str(user["baseline_login_hour"]) if user else "9")
        self.base_dl_var = ctk.StringVar(value=str(user["baseline_daily_downloads"]) if user else "30")
        self.base_fa_var = ctk.StringVar(value=str(user["baseline_file_access"]) if user else "80")
        self.status_var = ctk.StringVar(value=user["account_status"] if user else "ACTIVE")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=8)

        def row(label, var, kind="entry"):
            ctk.CTkLabel(body, text=label, font=("Segoe UI", 11),
                         text_color=COLOUR_TEXT_DIM).pack(anchor="w", pady=(8, 2))
            if kind == "option":
                widget = ctk.CTkOptionMenu(body, variable=var, values=DEPARTMENTS,
                                          fg_color=COLOUR_BG, button_color=COLOUR_BLUE)
            elif kind == "role_option":
                widget = ctk.CTkOptionMenu(body, variable=var, values=ROLES,
                                          fg_color=COLOUR_BG, button_color=COLOUR_BLUE)
            elif kind == "status_option":
                widget = ctk.CTkOptionMenu(body, variable=var, values=ACCOUNT_STATUSES,
                                          fg_color=COLOUR_BG, button_color=COLOUR_BLUE)
            else:
                widget = ctk.CTkEntry(body, textvariable=var, fg_color=COLOUR_BG,
                                       text_color=COLOUR_TEXT)
            widget.pack(fill="x")
            return widget

        row("Name", self.name_var)
        row("Department", self.dept_var, "option")
        row("Role", self.role_var, "role_option")
        row("Email", self.email_var)
        row("Baseline login hour (0-23)", self.base_hour_var)
        row("Baseline daily downloads", self.base_dl_var)
        row("Baseline file access count", self.base_fa_var)
        row("Account status", self.status_var, "status_option")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", pady=14, padx=24)
        ctk.CTkButton(actions, text="Cancel", fg_color=COLOUR_CARD,
                      command=self.destroy).pack(side="right", padx=4)
        ctk.CTkButton(actions, text="Save", fg_color=COLOUR_CYAN,
                      text_color=COLOUR_BG, command=self._save).pack(side="right", padx=4)

    def _save(self) -> None:
        try:
            data = {
                "name": self.name_var.get().strip(),
                "department": self.dept_var.get(),
                "role": self.role_var.get(),
                "email": self.email_var.get().strip(),
                "baseline_login_hour": int(self.base_hour_var.get()),
                "baseline_daily_downloads": int(self.base_dl_var.get()),
                "baseline_file_access": int(self.base_fa_var.get()),
                "account_status": self.status_var.get(),
            }
        except ValueError:
            messagebox.showerror("Invalid input", "Numeric fields must be integers.")
            return
        if not data["name"] or not data["email"]:
            messagebox.showerror("Missing data", "Name and email are required.")
            return
        self.result = data
        self.destroy()


class RiskProfileDialog(ctk.CTkToplevel):
    """Read-only risk profile for a single user."""

    def __init__(self, master, *, user: dict, assessment, events: list) -> None:
        super().__init__(master)
        self.title(f"Risk profile — {user['name']}")
        self.geometry("540x500")
        self.configure(fg_color=COLOUR_PANEL)
        self.grab_set()

        ctk.CTkLabel(
            self, text=f"Risk profile for {user['name']}",
            font=("Segoe UI", 16, "bold"), text_color=COLOUR_CYAN,
        ).pack(pady=12)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=4)
        info = (
            f"Department: {user['department']}\n"
            f"Role: {user['role']}\n"
            f"Status: {user.get('account_status', 'ACTIVE')}\n"
            f"Risk score: {assessment.risk_score:.1f} ({assessment.band})\n"
            f"\nExplanation:\n{assessment.explanation}"
        )
        ctk.CTkLabel(
            body, text=info, font=("Segoe UI", 11),
            text_color=COLOUR_TEXT, anchor="w", justify="left",
        ).pack(fill="x", pady=4)

        ctk.CTkLabel(
            body, text="Recent events",
            font=("Segoe UI", 12, "bold"), text_color=COLOUR_CYAN,
        ).pack(anchor="w", pady=(10, 4))
        events_text = "\n".join(
            f"• {e.get('timestamp', '-')[:19]}  {e.get('event_type', '-')}"
            for e in events[:15]
        ) or "No events recorded."
        text_box = ctk.CTkTextbox(body, fg_color=COLOUR_BG, text_color=COLOUR_TEXT, height=200)
        text_box.pack(fill="both", expand=True, pady=4)
        text_box.insert("0.0", events_text)
        text_box.configure(state="disabled")

        ctk.CTkButton(self, text="Close", fg_color=COLOUR_CARD,
                      command=self.destroy).pack(pady=10)