"""Family Controls: the parent's KDE app (Qt 6, through PyQt6).

The window lists each child, with their account, screen time, websites and apps, and the website
requests waiting for a decision. Every change runs `pkexec family-ctl ...` (see backend.py) on a
background thread, so the polkit password prompt never freezes the window. Results come back to
the window's thread through a queued signal.
"""

from __future__ import annotations

import html
import sys
import threading
from typing import Callable, Optional

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from family_linux.kde_app.backend import (
    BackendError,
    Result,
    approved_entries_for,
    make_client,
    normalise_domain,
    valid_clock,
    valid_username,
)
from family_linux.models import ALWAYS_BLOCKED_COMMANDS, MIN_PASSWORD_LENGTH

APP_ID = "org.familylinux.Parent"
TIERS = [("young_child", "Under 10"), ("pre_teen", "10 to 13"), ("teen", "14 and over")]
TIER_NAMES = dict(TIERS)
REQUESTS = "__requests__"


class _Bridge(QObject):
    """Carries a background result to the window: the callback to run, and its outcome."""

    finished = pyqtSignal(object, object)


def _page() -> tuple[QWidget, QVBoxLayout]:
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(24, 24, 24, 24)
    layout.setSpacing(16)
    return page, layout


def _heading(text: str) -> QLabel:
    label = QLabel(text)
    font = label.font()
    font.setPointSize(font.pointSize() + 4)
    font.setBold(True)
    label.setFont(font)
    return label


def _group(title: str, description: str = "") -> tuple[QGroupBox, QVBoxLayout]:
    box = QGroupBox(title)
    layout = QVBoxLayout(box)
    if description:
        note = QLabel(description)
        note.setWordWrap(True)
        layout.addWidget(note)
    return box, layout


class FamilyControlsWindow(QMainWindow):
    def __init__(self, client) -> None:
        super().__init__()
        self.setWindowTitle("Family Controls")
        self.resize(980, 720)
        self.client = client
        self.state: Optional[dict] = None
        self.selected: Optional[str] = REQUESTS
        self.busy = False
        self._filling = False

        self.bridge = _Bridge(self)
        self.bridge.finished.connect(self._deliver)

        toolbar = QToolBar("Family")
        toolbar.setMovable(False)
        toolbar.addAction("Add a child", self.show_add_child)
        toolbar.addAction("Refresh", self.refresh)
        self.addToolBar(toolbar)

        self.child_list = QListWidget()
        self.child_list.setMinimumWidth(240)
        self.child_list.currentItemChanged.connect(self._on_row_changed)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.child_list)
        splitter.addWidget(self.scroll)
        splitter.setSizes([260, 720])
        self.setCentralWidget(splitter)

        self._show_status("Opening Family Controls", "Enter your password if asked.")
        self.refresh()

    # Background calls

    def run(self, work: Callable[[], object], done: Callable[[object], None]) -> None:
        """Runs work() off the window's thread and calls done() with its result on that thread."""
        self.busy = True

        def worker() -> None:
            try:
                outcome = work()
            except Exception as exc:  # shown to the parent; never crash the window
                outcome = exc
            self.bridge.finished.emit(done, outcome)

        threading.Thread(target=worker, daemon=True).start()

    def _deliver(self, done: Callable[[object], None], outcome: object) -> None:
        self.busy = False
        done(outcome)

    def change(self, work: Callable[[], Result]) -> None:
        """Runs a change, shows its result in the status bar, and reloads the state."""

        def done(outcome: object) -> None:
            if isinstance(outcome, Result):
                self.statusBar().showMessage(outcome.message, 6000)
            else:
                self.statusBar().showMessage(f"Something went wrong: {outcome}", 8000)
            self.refresh()

        self.run(work, done)

    # State

    def refresh(self) -> None:
        def done(outcome: object) -> None:
            if isinstance(outcome, dict):
                self.state = outcome
                self._fill_sidebar()
                self._show_selected()
            else:
                message = str(outcome) if isinstance(outcome, BackendError) else f"Could not read the settings: {outcome}"
                self._show_status("Family Controls is locked", message, retry=True)

        self.run(self.client.state, done)

    def children(self) -> list:
        return (self.state or {}).get("policy", {}).get("children", [])

    def child(self, username: str) -> Optional[dict]:
        return next((c for c in self.children() if c["username"] == username), None)

    def _fill_sidebar(self) -> None:
        self._filling = True
        self.child_list.clear()
        pending = sum(len(names) for names in (self.state or {}).get("requests", {}).values())
        self._add_row("Website requests\n" + (f"{pending} waiting" if pending else "None waiting"), REQUESTS)
        for c in self.children():
            subtitle = c["username"] + ("" if c.get("enabled", True) else " · sign-in off")
            self._add_row(f"{c['full_name']}\n{subtitle}", c["username"])
        if self.selected != REQUESTS and not self.child(self.selected or ""):
            self.selected = REQUESTS
        for row in range(self.child_list.count()):
            item = self.child_list.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == self.selected:
                self.child_list.setCurrentItem(item)
                break
        self._filling = False

    def _add_row(self, text: str, key: str) -> None:
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, key)
        self.child_list.addItem(item)

    def _on_row_changed(self, current: Optional[QListWidgetItem], _previous: Optional[QListWidgetItem]) -> None:
        if self._filling or current is None:
            return
        self.selected = current.data(Qt.ItemDataRole.UserRole)
        self._show_selected()

    def _show_selected(self) -> None:
        if self.selected == REQUESTS or not self.child(self.selected or ""):
            self._show_requests()
        else:
            self._show_child(self.child(self.selected))

    def _set_page(self, page: QWidget) -> None:
        old = self.scroll.takeWidget()
        if old is not None:
            old.deleteLater()
        self.scroll.setWidget(page)

    def _show_status(self, title: str, description: str, retry: bool = False) -> None:
        page, layout = _page()
        layout.addStretch()
        heading = _heading(title)
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(heading)
        text = QLabel(description)
        text.setWordWrap(True)
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(text)
        if retry:
            button = QPushButton("Try again")
            button.clicked.connect(lambda _=False: self.refresh())
            layout.addWidget(button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        self._set_page(page)

    # Website requests

    def _show_requests(self) -> None:
        page, layout = _page()
        layout.addWidget(_heading("Website requests"))
        group, group_layout = _group(
            "Blocked sites a child tried to open",
            "Approving allows that site for that child only.",
        )
        requests = (self.state or {}).get("requests", {})
        if not any(requests.values()):
            group_layout.addWidget(QLabel("No requests waiting."))
        for username, names in sorted(requests.items()):
            who = (self.child(username) or {}).get("full_name", username)
            for domain, info in sorted(names.items()):
                row = QHBoxLayout()
                label = QLabel(f"<b>{html.escape(domain)}</b><br>{html.escape(who)} · tried {info.get('count', 1)} time(s)")
                row.addWidget(label, stretch=1)
                deny = QPushButton("Keep blocked")
                deny.clicked.connect(lambda _=False, u=username, d=domain: self.change(lambda: self.client.deny_request(u, d)))
                allow = QPushButton("Allow")
                allow.clicked.connect(lambda _=False, u=username, d=domain: self.change(lambda: self.client.approve_request(u, d)))
                row.addWidget(deny)
                row.addWidget(allow)
                group_layout.addLayout(row)
        layout.addWidget(group)
        layout.addStretch()
        self._set_page(page)

    # A child's page

    def _show_child(self, c: dict) -> None:
        username = c["username"]
        page, layout = _page()
        layout.addWidget(_heading(c["full_name"]))

        # Account
        account, account_layout = _group("Account")
        enabled = QCheckBox("Can sign in (turn off to stop this child signing in)")
        enabled.setChecked(c.get("enabled", True))
        enabled.toggled.connect(lambda on: self.change(lambda: self.client.set_enabled(username, on)))
        account_layout.addWidget(enabled)
        account_layout.addWidget(QLabel(f"Age preset: {TIER_NAMES.get(c.get('age_tier'), c.get('age_tier', ''))}"))
        remove = QPushButton("Remove child…")
        remove.clicked.connect(lambda _=False: self.confirm_remove(c))
        account_layout.addWidget(remove, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(account)

        # Screen time
        limits = c.get("time_limits", {})
        used = (self.state or {}).get("usage_today", {}).get(username, 0)
        time_group, time_layout = _group("Screen time", f"Used today: {used} minutes")
        form = QFormLayout()
        daily = QSpinBox()
        daily.setRange(0, 1440)
        daily.setSingleStep(15)
        daily.setSuffix(" minutes")
        daily.setValue(limits.get("daily_limit_minutes", 120))
        form.addRow("Daily limit", daily)
        weekday = QLineEdit(limits.get("bedtime_weekday", "20:30"))
        weekend = QLineEdit(limits.get("bedtime_weekend", "21:30"))
        wake = QLineEdit(limits.get("wake_time", "07:00"))
        form.addRow("Bedtime on school nights (HH:MM)", weekday)
        form.addRow("Bedtime on weekends (HH:MM)", weekend)
        form.addRow("Wake time (HH:MM)", wake)
        time_layout.addLayout(form)
        buttons = QHBoxLayout()
        save = QPushButton("Save screen time")
        save.clicked.connect(lambda _=False: self.save_time(username, daily, weekday, weekend, wake))
        reset = QPushButton("Reset today's usage")
        reset.clicked.connect(lambda _=False: self.change(lambda: self.client.reset_usage(username)))
        buttons.addWidget(save)
        buttons.addWidget(reset)
        buttons.addStretch()
        time_layout.addLayout(buttons)
        layout.addWidget(time_group)

        # Websites
        web = c.get("web_filter", {})
        sites, sites_layout = _group(
            "Websites",
            "Blocked sites stay blocked for this child. Allowed sites skip the family filter.",
        )
        self._rule_entry("Block a website", lambda domain: self.client.block(username, domain), sites_layout)
        self._rule_entry("Always allow a website", lambda domain: self.client.allow(username, domain), sites_layout)
        for label, domains in (("Blocked", web.get("blocked_domains", [])), ("Allowed", web.get("allowed_domains", []))):
            sites_layout.addWidget(QLabel(f"<b>{label} websites</b> ({len(domains)} rule(s))"))
            for domain in domains:
                row = QHBoxLayout()
                row.addWidget(QLabel(html.escape(domain)), stretch=1)
                remove_rule = QPushButton("Remove")
                remove_rule.clicked.connect(lambda _=False, d=domain: self.change(lambda: self.client.remove_rule(username, d)))
                row.addWidget(remove_rule)
                sites_layout.addLayout(row)
        layout.addWidget(sites)

        # Apps
        approved = c.get("app_policy", {}).get("approved_apps", [])
        apps, apps_layout = _group("Apps", "Approved apps appear in this child's menu. Other apps stay hidden.")
        blocked = {b.lower() for b in ALWAYS_BLOCKED_COMMANDS}
        installed = (self.state or {}).get("apps", [])
        shown = sum(1 for a in installed if a["id"].lower() not in blocked and approved_entries_for(a["id"], approved))
        apps_layout.addWidget(QLabel(f"{shown} of {len(installed)} shown to this child"))
        for app in installed:
            app_id, name = app["id"], app["name"]
            if app_id.lower() in blocked:
                note = QLabel(f"{html.escape(name)} · always hidden for children")
                note.setEnabled(False)
                apps_layout.addWidget(note)
                continue
            switch = QCheckBox(name)
            switch.setToolTip(app_id)
            switch.setChecked(bool(approved_entries_for(app_id, approved)))
            switch.toggled.connect(lambda on, a=app_id: self.toggle_app(username, a, on, approved))
            apps_layout.addWidget(switch)
        layout.addWidget(apps)

        layout.addStretch()
        self._set_page(page)

    def _rule_entry(self, label: str, action: Callable[[str], Result], layout: QVBoxLayout) -> QLineEdit:
        """A website box with an Add button; action(domain) runs when the domain is valid."""
        layout.addWidget(QLabel(label))
        row = QHBoxLayout()
        edit = QLineEdit()
        edit.setPlaceholderText("example.com")
        add = QPushButton("Add")
        edit.returnPressed.connect(lambda: self.add_rule(edit, action))
        add.clicked.connect(lambda _=False: self.add_rule(edit, action))
        row.addWidget(edit, stretch=1)
        row.addWidget(add)
        layout.addLayout(row)
        return edit

    # Actions

    def save_time(self, username: str, daily: QSpinBox, weekday: QLineEdit, weekend: QLineEdit, wake: QLineEdit) -> None:
        times = [weekday.text().strip(), weekend.text().strip(), wake.text().strip()]
        if not all(valid_clock(t) for t in times):
            self.statusBar().showMessage("Use 24-hour times such as 20:30.", 6000)
            return
        limit = daily.value()
        self.change(lambda: self.client.set_time(username, limit, times[0], times[1], times[2]))

    def add_rule(self, edit: QLineEdit, action: Callable[[str], Result]) -> None:
        domain = normalise_domain(edit.text())
        if not domain:
            self.statusBar().showMessage("Enter a website such as example.com.", 6000)
            return
        edit.clear()
        self.change(lambda: action(domain))

    def toggle_app(self, username: str, app_id: str, active: bool, approved: list) -> None:
        if active:
            self.change(lambda: self.client.approve_app(username, app_id))
        else:
            self.change(lambda: self.client.revoke_app(username, app_id, approved))

    def confirm_remove(self, c: dict) -> None:
        box = QMessageBox(QMessageBox.Icon.Warning, f"Remove {c['full_name']}?",
                          "Their account is deleted from this computer. Their files stay in their home folder.", parent=self)
        cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        remove = box.addButton("Remove", QMessageBox.ButtonRole.DestructiveRole)
        box.setDefaultButton(cancel)
        box.exec()
        if box.clickedButton() is remove:
            self.change(lambda: self.client.remove_child(c["username"]))

    def show_add_child(self) -> None:
        AddChildDialog(self).exec()


class AddChildDialog(QDialog):
    def __init__(self, window: FamilyControlsWindow) -> None:
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Add a child")
        self.setMinimumWidth(440)

        self.full_name = QLineEdit()
        self.username = QLineEdit()
        self.username.setPlaceholderText("lower case, for example sam")
        self.tier = QComboBox()
        self.tier.addItems([label for _, label in TIERS])
        self.tier.setCurrentIndex(1)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        form = QFormLayout()
        form.addRow("Name", self.full_name)
        form.addRow("Username", self.username)
        form.addRow("Age", self.tier)
        form.addRow("Password", self.password)
        note = QLabel(f"The password needs at least {MIN_PASSWORD_LENGTH} characters.")
        note.setWordWrap(True)

        cancel = QPushButton("Cancel")
        cancel.clicked.connect(lambda _=False: self.reject())
        add = QPushButton("Add")
        add.setDefault(True)
        add.clicked.connect(lambda _=False: self.submit())
        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(add)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addLayout(buttons)

    def submit(self) -> None:
        username = self.username.text().strip()
        full_name = self.full_name.text().strip() or username.capitalize()
        password = self.password.text()
        if not valid_username(username):
            self.window.statusBar().showMessage("Usernames are 3 to 32 lower-case letters, numbers, '_' or '-'.", 6000)
            return
        if len(password) < MIN_PASSWORD_LENGTH:
            self.window.statusBar().showMessage(f"The password needs at least {MIN_PASSWORD_LENGTH} characters.", 6000)
            return
        tier = TIERS[self.tier.currentIndex()][0]
        self.accept()
        self.window.selected = username
        self.window.change(lambda: self.window.client.add_child(username, full_name, tier, password))


def main(argv: Optional[list] = None) -> int:
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("Family Controls")
    app.setDesktopFileName(f"{APP_ID}.desktop")
    window = FamilyControlsWindow(make_client())
    window.show()
    return app.exec()
