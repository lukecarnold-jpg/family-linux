"""Family Controls window (PyQt6): it builds from the state family-ctl reports, and a child's page shows
their rules. Runs offscreen; skipped where PyQt6 is not installed."""

import json
import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PyQt6.QtWidgets")

from family_linux.kde_app.app import FamilyControlsWindow  # noqa: E402
from family_linux.kde_app.backend import DemoClient  # noqa: E402

STATE = {
    "policy": {
        "children": [
            {
                "username": "sam",
                "full_name": "Sam",
                "enabled": True,
                "age_tier": "pre_teen",
                "time_limits": {"daily_limit_minutes": 90},
                "web_filter": {"blocked_domains": ["example.org"], "allowed_domains": []},
                "app_policy": {"approved_apps": ["firefox-esr"]},
            }
        ]
    },
    "requests": {"sam": {"games.example": {"count": 2}}},
    "apps": [{"id": "firefox-esr", "name": "Firefox ESR"}, {"id": "konsole", "name": "Konsole"}],
    "usage_today": {"sam": 12},
}


@pytest.fixture(scope="module")
def qapp():
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    yield app


def _wait_for(app, predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_window_lists_requests_and_each_child(qapp, tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps(STATE))
    window = FamilyControlsWindow(DemoClient(Path(state)))
    try:
        assert _wait_for(qapp, lambda: window.child_list.count() == 2)
        labels = [window.child_list.item(i).text() for i in range(window.child_list.count())]
        assert labels[0].startswith("Website requests") and "1 waiting" in labels[0]
        assert labels[1].startswith("Sam")
    finally:
        window.close()


def test_child_page_shows_the_websites_and_the_app_switches(qapp, tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps(STATE))
    window = FamilyControlsWindow(DemoClient(Path(state)))
    try:
        assert _wait_for(qapp, lambda: window.child_list.count() == 2)
        window.child_list.setCurrentRow(1)
        qapp.processEvents()
        page = window.scroll.widget()
        assert page is not None
        texts = [label.text() for label in page.findChildren(QtWidgets.QLabel)]
        assert any("example.org" in text for text in texts)
        switches = {box.text(): box for box in page.findChildren(QtWidgets.QCheckBox)}
        assert switches["Firefox ESR"].isChecked()
        assert "Konsole" not in switches  # hidden for children, shown as a note instead
        assert any("Konsole" in text and "always hidden" in text for text in texts)
    finally:
        window.close()
