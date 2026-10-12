"""Family Controls: the parent's GNOME app (GTK 4 and libadwaita).

The window shows each child, with their account, screen time, websites and apps, and a list of
website requests waiting for a decision. Every change runs `pkexec family-ctl ...` (see backend.py)
in a background thread, so the polkit password prompt never freezes the window.
"""

from __future__ import annotations

import sys
import threading
from typing import Callable, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from family_linux.gnome_app.backend import (  # noqa: E402
    BackendError,
    Result,
    approved_entries_for,
    make_client,
    normalise_domain,
    valid_clock,
    valid_username,
)
from family_linux.models import ALWAYS_BLOCKED_COMMANDS, MIN_PASSWORD_LENGTH  # noqa: E402

APP_ID = "org.familylinux.Parent"
TIERS = [("young_child", "Under 10"), ("pre_teen", "10 to 13"), ("teen", "14 and over")]
TIER_NAMES = dict(TIERS)


class FamilyControlsWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application, client) -> None:
        super().__init__(application=app, title="Family Controls", default_width=980, default_height=720)
        self.client = client
        self.state: Optional[dict] = None
        self.selected: Optional[str] = "__requests__"
        self.busy = False

        self.toasts = Adw.ToastOverlay()
        self.split = Adw.NavigationSplitView()

        # Sidebar: requests, then each child
        sidebar = Adw.ToolbarView()
        sidebar_header = Adw.HeaderBar()
        add_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Add a child")
        add_button.connect("clicked", lambda *_: self.show_add_child())
        sidebar_header.pack_start(add_button)
        refresh_button = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh")
        refresh_button.connect("clicked", lambda *_: self.refresh())
        sidebar_header.pack_end(refresh_button)
        sidebar.add_top_bar(sidebar_header)
        self.child_list = Gtk.ListBox(css_classes=["navigation-sidebar"])
        self.child_list.connect("row-activated", self._on_row_activated)
        sidebar.set_content(Gtk.ScrolledWindow(child=self.child_list, vexpand=True))
        self.split.set_sidebar(Adw.NavigationPage(title="Family", child=sidebar))

        # Content
        self.content = Adw.ToolbarView()
        self.content.add_top_bar(Adw.HeaderBar())
        self.content_page = Adw.NavigationPage(title="Family Controls", child=self.content)
        self.split.set_content(self.content_page)

        self.toasts.set_child(self.split)
        self.set_content(self.toasts)
        self._show_status("Opening Family Controls", "Enter your password if asked.", "system-users-symbolic")
        self.refresh()

    # Background calls

    def run(self, work: Callable[[], object], done: Callable[[object], None]) -> None:
        """Runs work() off the main thread and delivers its result to done() on the main thread."""
        self.busy = True

        def worker() -> None:
            try:
                outcome = work()
            except Exception as exc:  # shown to the parent; never crash the window
                outcome = exc
            GLib.idle_add(self._finish, done, outcome)

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, done: Callable[[object], None], outcome: object) -> bool:
        self.busy = False
        done(outcome)
        return GLib.SOURCE_REMOVE

    def change(self, work: Callable[[], Result]) -> None:
        """Runs a change, shows its result, and reloads the state."""

        def done(outcome: object) -> None:
            if isinstance(outcome, Result):
                self.toast(outcome.message)
            else:
                self.toast(f"Something went wrong: {outcome}")
            self.refresh()

        self.run(work, done)

    def toast(self, message: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(message), timeout=4))

    # State

    def refresh(self) -> None:
        def done(outcome: object) -> None:
            if isinstance(outcome, dict):
                self.state = outcome
                self._fill_sidebar()
                self._show_selected()
            else:
                message = str(outcome) if isinstance(outcome, BackendError) else f"Could not read the settings: {outcome}"
                self._show_status("Family Controls is locked", message, "dialog-password-symbolic", retry=True)

        self.run(self.client.state, done)

    def children(self) -> list:
        return (self.state or {}).get("policy", {}).get("children", [])

    def child(self, username: str) -> Optional[dict]:
        return next((c for c in self.children() if c["username"] == username), None)

    def _fill_sidebar(self) -> None:
        while (row := self.child_list.get_row_at_index(0)) is not None:
            self.child_list.remove(row)
        pending = sum(len(names) for names in (self.state or {}).get("requests", {}).values())
        requests_row = Adw.ActionRow(title="Website requests", subtitle=f"{pending} waiting" if pending else "None waiting", activatable=True)
        requests_row.add_prefix(Gtk.Image(icon_name="mail-unread-symbolic" if pending else "mail-read-symbolic"))
        requests_row.key = "__requests__"
        self.child_list.append(requests_row)
        for c in self.children():
            row = Adw.ActionRow(title=c["full_name"], subtitle=c["username"] + ("" if c.get("enabled", True) else " · sign-in off"), activatable=True)
            row.add_prefix(Gtk.Image(icon_name="avatar-default-symbolic"))
            row.key = c["username"]
            self.child_list.append(row)
        if self.selected != "__requests__" and not self.child(self.selected or ""):
            self.selected = "__requests__"

    def _on_row_activated(self, _listbox: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        self.selected = getattr(row, "key", "__requests__")
        self._show_selected()
        self.split.set_show_content(True)

    def _show_selected(self) -> None:
        if self.selected == "__requests__" or not self.child(self.selected or ""):
            self._show_requests()
        else:
            self._show_child(self.child(self.selected))

    def _set_page(self, title: str, widget: Gtk.Widget) -> None:
        self.content_page.set_title(title)
        self.content.set_content(widget)

    def _show_status(self, title: str, description: str, icon: str, retry: bool = False) -> None:
        page = Adw.StatusPage(title=title, description=description, icon_name=icon)
        if retry:
            button = Gtk.Button(label="Try again", halign=Gtk.Align.CENTER, css_classes=["pill", "suggested-action"])
            button.connect("clicked", lambda *_: self.refresh())
            page.set_child(button)
        self._set_page("Family Controls", page)

    # Website requests

    def _show_requests(self) -> None:
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(
            title="Website requests",
            description="Sites a child tried to open that are blocked. Approving allows that site for that child only.",
        )
        page.add(group)
        requests = (self.state or {}).get("requests", {})
        if not any(requests.values()):
            group.add(Adw.ActionRow(title="No requests waiting"))
        for username, names in sorted(requests.items()):
            who = (self.child(username) or {}).get("full_name", username)
            for domain, info in sorted(names.items()):
                row = Adw.ActionRow(title=domain, subtitle=f"{who} · tried {info.get('count', 1)} time(s)")
                approve = Gtk.Button(label="Allow", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
                approve.connect("clicked", lambda *_, u=username, d=domain: self.change(lambda: self.client.approve_request(u, d)))
                deny = Gtk.Button(label="Keep blocked", valign=Gtk.Align.CENTER)
                deny.connect("clicked", lambda *_, u=username, d=domain: self.change(lambda: self.client.deny_request(u, d)))
                row.add_suffix(deny)
                row.add_suffix(approve)
                group.add(row)
        self._set_page("Website requests", page)

    # A child's page

    def _show_child(self, c: dict) -> None:
        username = c["username"]
        page = Adw.PreferencesPage()

        # Account
        account = Adw.PreferencesGroup(title="Account")
        enabled = Adw.SwitchRow(title="Can sign in", subtitle="Turn off to stop this child signing in", active=c.get("enabled", True))
        enabled.connect("notify::active", lambda row, _p: self.change(lambda: self.client.set_enabled(username, row.get_active())))
        account.add(enabled)
        account.add(Adw.ActionRow(title="Age preset", subtitle=TIER_NAMES.get(c.get("age_tier"), c.get("age_tier", ""))))
        remove = Gtk.Button(label="Remove child…", halign=Gtk.Align.START, css_classes=["destructive-action"], margin_top=12)
        remove.connect("clicked", lambda *_: self.confirm_remove(c))
        account.add(remove)
        page.add(account)

        # Screen time
        limits = c.get("time_limits", {})
        used = (self.state or {}).get("usage_today", {}).get(username, 0)
        time_group = Adw.PreferencesGroup(title="Screen time", description=f"Used today: {used} minutes")
        daily = Adw.SpinRow.new_with_range(0, 1440, 15)
        daily.set_title("Daily limit (minutes)")
        daily.set_value(limits.get("daily_limit_minutes", 120))
        weekday = Adw.EntryRow(title="Bedtime on school nights (HH:MM)", text=limits.get("bedtime_weekday", "20:30"))
        weekend = Adw.EntryRow(title="Bedtime on weekends (HH:MM)", text=limits.get("bedtime_weekend", "21:30"))
        wake = Adw.EntryRow(title="Wake time (HH:MM)", text=limits.get("wake_time", "07:00"))
        for row in (daily, weekday, weekend, wake):
            time_group.add(row)
        buttons = Gtk.Box(spacing=12, margin_top=12)
        save = Gtk.Button(label="Save screen time", css_classes=["suggested-action"])
        save.connect("clicked", lambda *_: self.save_time(username, daily, weekday, weekend, wake))
        reset = Gtk.Button(label="Reset today's usage")
        reset.connect("clicked", lambda *_: self.change(lambda: self.client.reset_usage(username)))
        buttons.append(save)
        buttons.append(reset)
        time_group.add(buttons)
        page.add(time_group)

        # Websites
        web = c.get("web_filter", {})
        sites = Adw.PreferencesGroup(title="Websites", description="Blocked sites stay blocked for this child; allowed sites skip the family filter.")
        block_entry = Adw.EntryRow(title="Block a website", show_apply_button=True)
        block_entry.connect("apply", lambda row: self.add_rule(username, row, self.client.block))
        allow_entry = Adw.EntryRow(title="Always allow a website", show_apply_button=True)
        allow_entry.connect("apply", lambda row: self.add_rule(username, row, self.client.allow))
        sites.add(block_entry)
        sites.add(allow_entry)
        for label, domains in (("Blocked", web.get("blocked_domains", [])), ("Allowed", web.get("allowed_domains", []))):
            expander = Adw.ExpanderRow(title=f"{label} websites", subtitle=f"{len(domains)} rule(s)")
            for domain in domains:
                row = Adw.ActionRow(title=domain)
                delete = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Remove", css_classes=["flat"])
                delete.connect("clicked", lambda *_, d=domain: self.change(lambda: self.client.remove_rule(username, d)))
                row.add_suffix(delete)
                expander.add_row(row)
            sites.add(expander)
        page.add(sites)

        # Apps
        approved = c.get("app_policy", {}).get("approved_apps", [])
        apps_group = Adw.PreferencesGroup(title="Apps", description="Approved apps appear in this child's menu. Other apps stay hidden.")
        blocked = {b.lower() for b in ALWAYS_BLOCKED_COMMANDS}
        installed = (self.state or {}).get("apps", [])
        shown = sum(1 for a in installed if a["id"].lower() not in blocked and approved_entries_for(a["id"], approved))
        apps_expander = Adw.ExpanderRow(title="Installed apps", subtitle=f"{shown} of {len(installed)} shown to this child")
        for app in installed:
            app_id, name = app["id"], app["name"]
            if app_id.lower() in blocked:
                row = Adw.ActionRow(title=name, subtitle="Always hidden for children")
                apps_expander.add_row(row)
                continue
            switch = Adw.SwitchRow(title=name, subtitle=app_id, active=bool(approved_entries_for(app_id, approved)))
            switch.connect("notify::active", lambda row, _p, a=app_id: self.toggle_app(username, a, row.get_active(), approved))
            apps_expander.add_row(switch)
        apps_group.add(apps_expander)
        page.add(apps_group)

        self._set_page(c["full_name"], page)

    # Actions

    def save_time(self, username: str, daily, weekday, weekend, wake) -> None:
        times = [weekday.get_text().strip(), weekend.get_text().strip(), wake.get_text().strip()]
        if not all(valid_clock(t) for t in times):
            self.toast("Use 24-hour times such as 20:30.")
            return
        limit = int(daily.get_value())
        self.change(lambda: self.client.set_time(username, limit, times[0], times[1], times[2]))

    def add_rule(self, username: str, row: Adw.EntryRow, action: Callable[[str, str], Result]) -> None:
        domain = normalise_domain(row.get_text())
        if not domain:
            self.toast("Enter a website such as example.com.")
            return
        row.set_text("")
        self.change(lambda: action(username, domain))

    def toggle_app(self, username: str, app_id: str, active: bool, approved: list) -> None:
        if active:
            self.change(lambda: self.client.approve_app(username, app_id))
        else:
            self.change(lambda: self.client.revoke_app(username, app_id, approved))

    def confirm_remove(self, c: dict) -> None:
        dialog = Adw.AlertDialog(
            heading=f"Remove {c['full_name']}?",
            body="Their account is deleted from this computer. Their files stay in their home folder.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("remove", "Remove")
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.connect("response", lambda _d, response: response == "remove" and self.change(lambda: self.client.remove_child(c["username"])))
        dialog.present(self)

    def show_add_child(self) -> None:
        AddChildDialog(self).present(self)


class AddChildDialog(Adw.Dialog):
    def __init__(self, window: FamilyControlsWindow) -> None:
        super().__init__(title="Add a child", content_width=440)
        self.window = window
        view = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        self.add_button = Gtk.Button(label="Add", css_classes=["suggested-action"])
        self.add_button.connect("clicked", lambda *_: self.submit())
        header.pack_start(cancel)
        header.pack_end(self.add_button)
        view.add_top_bar(header)

        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(description=f"The password needs at least {MIN_PASSWORD_LENGTH} characters.")
        self.full_name = Adw.EntryRow(title="Name")
        self.username = Adw.EntryRow(title="Username (lower case, for example sam)")
        self.tier = Adw.ComboRow(title="Age", model=Gtk.StringList.new([label for _, label in TIERS]), selected=1)
        self.password = Adw.PasswordEntryRow(title="Password")
        for row in (self.full_name, self.username, self.tier, self.password):
            group.add(row)
        page.add(group)
        view.set_content(page)
        self.set_child(view)

    def submit(self) -> None:
        username = self.username.get_text().strip()
        full_name = self.full_name.get_text().strip() or username.capitalize()
        password = self.password.get_text()
        if not valid_username(username):
            self.window.toast("Usernames are 3 to 32 lower-case letters, numbers, '_' or '-'.")
            return
        if len(password) < MIN_PASSWORD_LENGTH:
            self.window.toast(f"The password needs at least {MIN_PASSWORD_LENGTH} characters.")
            return
        tier = TIERS[self.tier.get_selected()][0]
        self.close()
        self.window.selected = username
        self.window.change(lambda: self.window.client.add_child(username, full_name, tier, password))


class FamilyControlsApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID)
        self.window: Optional[FamilyControlsWindow] = None

    def do_activate(self) -> None:
        if self.window is None:
            self.window = FamilyControlsWindow(self, make_client())
        self.window.present()


def main(argv: Optional[list] = None) -> int:
    return FamilyControlsApp().run(argv if argv is not None else sys.argv)
