"""Local Parent Management Web Dashboard for Family Linux.

Provides an intuitive graphical interface for parents to manage
child accounts, screen time, app approvals, web filters, and audit logs
without requiring command-line knowledge.
"""

from __future__ import annotations

import json
import os
import sys
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

from family_linux.config import PolicyConfigManager
from family_linux.models import (
    FamilyPolicy,
    ChildAccount,
    AgeTier,
    DNSProvider,
)
from family_linux.provisioner.system import SystemProvisioner
from family_linux.screentime.tracker import ScreenTimeTracker
from family_linux.audit.logger import AuditLogger
from family_linux.security.adapter import SystemAdapter

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Family Linux Parent Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(22, 30, 49, 0.75);
      --card-border: rgba(255, 255, 255, 0.08);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --accent: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --radius: 14px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', sans-serif;
      background: radial-gradient(circle at 15% 15%, #151e36 0%, #090d16 100%);
      color: var(--text);
      min-height: 100vh;
      display: flex;
    }

    /* Sidebar */
    .sidebar {
      width: 260px;
      background: rgba(13, 18, 30, 0.95);
      border-right: 1px solid var(--card-border);
      padding: 28px 20px;
      display: flex;
      flex-direction: column;
      gap: 28px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, #3b82f6, #8b5cf6);
      border-radius: 10px;
      display: grid;
      place-items: center;
      font-weight: 800;
      font-size: 20px;
      color: #fff;
      box-shadow: 0 8px 16px rgba(59, 130, 246, 0.3);
    }
    .brand-name { font-size: 19px; font-weight: 700; letter-spacing: -0.5px; }
    .brand-sub { font-size: 11px; color: var(--accent); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }

    .nav-links { list-style: none; display: flex; flex-direction: column; gap: 8px; }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 14px;
      border-radius: 10px;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 600;
      font-size: 14px;
      transition: all 0.2s ease;
    }
    .nav-item:hover, .nav-item.active {
      background: rgba(59, 130, 246, 0.15);
      color: #fff;
    }
    .nav-item.active { border-left: 3px solid var(--primary); }

    /* Main Content */
    .main {
      flex: 1;
      padding: 32px 40px;
      overflow-y: auto;
    }

    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
    }
    .page-title { font-size: 26px; font-weight: 800; letter-spacing: -0.5px; }
    .page-desc { color: var(--text-muted); font-size: 14px; margin-top: 4px; }

    /* Top Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }
    .stat-card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      padding: 20px;
      position: relative;
    }
    .stat-label { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); }
    .stat-val { font-size: 24px; font-weight: 800; margin-top: 8px; color: #fff; }
    .stat-badge {
      display: inline-block;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 20px;
      margin-top: 8px;
      font-weight: 600;
    }
    .badge-green { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .badge-blue { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }

    /* Section Cards */
    .section-card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      padding: 28px;
      margin-bottom: 28px;
    }
    .section-title { font-size: 18px; font-weight: 700; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; }

    /* Buttons */
    .btn {
      padding: 10px 18px;
      border-radius: 8px;
      border: none;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .btn-primary { background: var(--primary); color: #fff; }
    .btn-primary:hover { background: var(--primary-hover); transform: translateY(-1px); }
    .btn-secondary { background: rgba(255, 255, 255, 0.08); color: var(--text); }
    .btn-secondary:hover { background: rgba(255, 255, 255, 0.15); }
    .btn-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }

    /* Child Cards Grid */
    .children-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 20px;
    }
    .child-card {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.2s ease;
    }
    .child-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 16px;
    }
    .child-name { font-size: 18px; font-weight: 700; }
    .child-meta { font-size: 12px; color: var(--text-muted); }
    .progress-bar-bg {
      height: 8px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 4px;
      overflow: hidden;
      margin: 12px 0 6px 0;
    }
    .progress-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #10b981, #f59e0b);
      border-radius: 4px;
      transition: width 0.3s ease;
    }

    /* Table */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 12px 14px; color: var(--text-muted); border-bottom: 1px solid var(--card-border); font-weight: 600; }
    td { padding: 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.04); }
    code { font-family: 'JetBrains Mono', monospace; font-size: 12px; background: rgba(255, 255, 255, 0.06); padding: 2px 6px; border-radius: 4px; }

    /* Tag badges */
    .app-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #93c5fd;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      margin: 4px;
    }
    .tag-remove { cursor: pointer; color: #f87171; font-weight: bold; }

    /* Modals / Forms */
    .form-group { margin-bottom: 16px; }
    .form-label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: var(--text-muted); }
    .form-control {
      width: 100%;
      padding: 10px 14px;
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      color: #fff;
      font-family: inherit;
      font-size: 14px;
    }
    .form-control:focus { outline: none; border-color: var(--primary); }

    .modal-overlay {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
      display: none; place-items: center; z-index: 100;
    }
    .modal-overlay.open { display: grid; }
    .modal-box {
      background: #111827;
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      width: 100%; max-width: 480px;
      padding: 28px;
    }
  </style>
</head>
<body>
  <div class="sidebar">
    <div class="brand">
      <div class="brand-icon">F</div>
      <div>
        <div class="brand-name">Family Linux</div>
        <div class="brand-sub">Parent Portal</div>
      </div>
    </div>
    <ul class="nav-links">
      <li class="nav-item active" onclick="switchTab('dashboard')">Dashboard Overview</li>
      <li class="nav-item" onclick="switchTab('children')">Child Accounts</li>
      <li class="nav-item" onclick="switchTab('apps')">Approved Apps</li>
      <li class="nav-item" onclick="switchTab('screentime')">Screen Time & Curfew</li>
      <li class="nav-item" onclick="switchTab('webfilter')">Web Safety & DNS</li>
      <li class="nav-item" onclick="switchTab('audit')">Audit Events</li>
      <li class="nav-item" onclick="switchTab('backups')">Recovery & Backups</li>
    </ul>
  </div>

  <div class="main">
    <div class="header-bar">
      <div>
        <h1 class="page-title" id="page-heading">Parent Control Dashboard</h1>
        <p class="page-desc">Ubuntu LTS child-safe workstation policy management</p>
      </div>
      <div>
        <button class="btn btn-primary" onclick="openAddChildModal()">+ Add Child Account</button>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Parent Administrator</div>
        <div class="stat-val" id="stat-parent-user">parent</div>
        <span class="stat-badge badge-blue">Local Admin (Sudo)</span>
      </div>
      <div class="stat-card">
        <div class="stat-label">Child Accounts</div>
        <div class="stat-val" id="stat-child-count">0</div>
        <span class="stat-badge badge-green">Non-Admin / Protected</span>
      </div>
      <div class="stat-card">
        <div class="stat-label">Firewall Baseline</div>
        <div class="stat-val">ACTIVE</div>
        <span class="stat-badge badge-green">Deny Incoming (UFW)</span>
      </div>
      <div class="stat-card">
        <div class="stat-label">Protected DNS</div>
        <div class="stat-val" id="stat-dns-provider">CleanBrowsing</div>
        <span class="stat-badge badge-blue">SafeSearch Enforced</span>
      </div>
    </div>

    <!-- TAB: Dashboard / Children -->
    <div id="tab-dashboard">
      <div class="section-card">
        <div class="section-title">
          <span>Active Child Profiles</span>
          <span style="font-size: 13px; color: var(--text-muted);">Real-time policy enforcement</span>
        </div>
        <div class="children-grid" id="children-cards-container">
          <!-- Populated by JS -->
        </div>
      </div>
    </div>

    <!-- TAB: Web Safety -->
    <div id="tab-webfilter" style="display: none;">
      <div class="section-card">
        <div class="section-title">Web Filtering & Search Lockdown</div>
        <p style="color: var(--text-muted); font-size: 14px; margin-bottom: 20px;">
          Managed browser policies apply to Firefox and Chromium across all child accounts.
        </p>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px;">
          <div style="background: rgba(15, 23, 42, 0.6); padding: 18px; border-radius: 10px;">
            <div style="font-weight: 700; margin-bottom: 6px;">Strict SafeSearch</div>
            <p style="font-size: 13px; color: var(--text-muted);">Enforced on Google, Bing, DuckDuckGo & YouTube</p>
            <span class="stat-badge badge-green">LOCK ENFORCED</span>
          </div>
          <div style="background: rgba(15, 23, 42, 0.6); padding: 18px; border-radius: 10px;">
            <div style="font-weight: 700; margin-bottom: 6px;">Incognito / Private Mode</div>
            <p style="font-size: 13px; color: var(--text-muted);">Private browsing completely disabled for children</p>
            <span class="stat-badge badge-green">BLOCKED</span>
          </div>
          <div style="background: rgba(15, 23, 42, 0.6); padding: 18px; border-radius: 10px;">
            <div style="font-weight: 700; margin-bottom: 6px;">Developer Tools</div>
            <p style="font-size: 13px; color: var(--text-muted);">Console and page inspectors disabled</p>
            <span class="stat-badge badge-green">DISABLED</span>
          </div>
        </div>

        <div class="form-group" style="display: flex; gap: 12px; margin-top: 20px;">
          <input type="text" id="new-block-domain" class="form-control" placeholder="Block domain (e.g. distractinggame.com)">
          <button class="btn btn-danger" onclick="blockDomain()">Block Domain</button>
        </div>

        <div style="margin-top: 20px;">
          <div class="form-label">Currently Blocked Domains:</div>
          <div id="blocked-domains-list"></div>
        </div>
      </div>
    </div>

    <!-- TAB: Audit Log -->
    <div id="tab-audit" style="display: none;">
      <div class="section-card">
        <div class="section-title">
          <span>Security & Policy Audit Trail</span>
          <button class="btn btn-secondary" onclick="loadAudit()">Refresh Logs</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Event</th>
              <th>User</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody id="audit-table-body">
            <!-- Populated by JS -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Modal: Add Child -->
  <div class="modal-overlay" id="add-child-modal">
    <div class="modal-box">
      <h2 style="font-size: 18px; margin-bottom: 16px;">Add New Child Account</h2>
      <div class="form-group">
        <label class="form-label">Username (login name)</label>
        <input type="text" id="modal-username" class="form-control" placeholder="e.g. emily">
      </div>
      <div class="form-group">
        <label class="form-label">Full Name</label>
        <input type="text" id="modal-fullname" class="form-control" placeholder="e.g. Emily Arnold">
      </div>
      <div class="form-group">
        <label class="form-label">Age Preset Tier</label>
        <select id="modal-tier" class="form-control">
          <option value="young_child">Young Child (Under 10: 90m limit, 8:00 PM curfew)</option>
          <option value="pre_teen" selected>Pre-Teen (10-13: 150m limit, 9:00 PM curfew)</option>
          <option value="teen">Teen (14+: 240m limit, 10:00 PM curfew)</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Password</label>
        <input type="password" id="modal-password" class="form-control" placeholder="Secret password">
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 24px;">
        <button class="btn btn-secondary" onclick="closeAddChildModal()">Cancel</button>
        <button class="btn btn-primary" onclick="submitAddChild()">Create Account</button>
      </div>
    </div>
  </div>

  <script>
    let state = { policy: null, audit: [] };

    async function loadData() {
      try {
        const res = await fetch('/api/policy');
        state.policy = await res.json();
        renderDashboard();
      } catch (err) {
        console.error('Failed to load policy', err);
      }
    }

    async function loadAudit() {
      try {
        const res = await fetch('/api/audit');
        const data = await res.json();
        const tbody = document.getElementById('audit-table-body');
        tbody.innerHTML = '';
        data.forEach(item => {
          const tr = document.createElement('tr');
          const detailsStr = Object.entries(item.details || {}).map(([k, v]) => `${k}=${v}`).join(', ');
          tr.innerHTML = `
            <td><code>${item.timestamp}</code></td>
            <td><span class="stat-badge ${item.severity === 'WARNING' ? 'badge-blue' : 'badge-green'}">${item.severity}</span></td>
            <td><strong>${item.event_type}</strong></td>
            <td>${item.user}</td>
            <td style="color: var(--text-muted);">${detailsStr}</td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        console.error('Failed to load audit', err);
      }
    }

    function renderDashboard() {
      if (!state.policy) return;
      document.getElementById('stat-parent-user').textContent = state.policy.parent.username;
      document.getElementById('stat-child-count').textContent = state.policy.children.length;

      const container = document.getElementById('children-cards-container');
      container.innerHTML = '';

      state.policy.children.forEach(c => {
        const used = c.used_today || 0;
        const total = c.time_limits.daily_limit_minutes || 120;
        const pct = Math.min(100, Math.round((used / total) * 100));

        const card = document.createElement('div');
        card.className = 'child-card';
        card.innerHTML = `
          <div class="child-header">
            <div>
              <div class="child-name">${c.full_name}</div>
              <div class="child-meta">@${c.username} • Tier: ${c.age_tier}</div>
            </div>
            <span class="stat-badge ${c.enabled ? 'badge-green' : 'badge-blue'}">
              ${c.enabled ? 'ACTIVE' : 'DISABLED'}
            </span>
          </div>
          <div>
            <div style="display: flex; justify-content: space-between; font-size: 12px; color: var(--text-muted);">
              <span>Screen Time Used</span>
              <span>${used}m / ${total}m (${pct}%)</span>
            </div>
            <div class="progress-bar-bg">
              <div class="progress-bar-fill" style="width: ${pct}%;"></div>
            </div>
          </div>
          <div style="font-size: 13px; margin: 12px 0; color: var(--text-muted);">
            Bedtime Curfew: <strong>${c.time_limits.bedtime_weekday}</strong> (Weekdays) / <strong>${c.time_limits.bedtime_weekend}</strong> (Weekends)
          </div>
          <div style="margin-top: 16px; display: flex; gap: 8px;">
            <button class="btn btn-secondary" style="font-size: 12px; padding: 6px 10px;" onclick="resetUsage('${c.username}')">Reset Usage</button>
            <button class="btn btn-secondary" style="font-size: 12px; padding: 6px 10px;" onclick="toggleChild('${c.username}', ${!c.enabled})">
              ${c.enabled ? 'Disable' : 'Enable'}
            </button>
          </div>
          <div style="margin-top: 14px;">
            <div class="form-label">Approved Applications:</div>
            <div>
              ${c.app_policy.approved_apps.map(a => `<span class="app-tag">${a}</span>`).join('')}
            </div>
          </div>
        `;
        container.appendChild(card);
      });

      // Render blocked domains
      if (state.policy.children.length > 0) {
        const domList = document.getElementById('blocked-domains-list');
        domList.innerHTML = '';
        state.policy.children[0].web_filter.blocked_domains.forEach(d => {
          const span = document.createElement('span');
          span.className = 'app-tag';
          span.style.borderColor = 'rgba(239, 68, 68, 0.4)';
          span.style.color = '#f87171';
          span.innerHTML = `${d} <span class="tag-remove" onclick="allowDomain('${d}')">&times;</span>`;
          domList.appendChild(span);
        });
      }
    }

    async function toggleChild(username, enable) {
      await fetch('/api/child/toggle', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, enable}),
      });
      loadData();
    }

    async function resetUsage(username) {
      await fetch('/api/child/reset-usage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username}),
      });
      loadData();
    }

    async function blockDomain() {
      const input = document.getElementById('new-block-domain');
      const domain = input.value.trim();
      if (!domain) return;
      await fetch('/api/web/block', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain}),
      });
      input.value = '';
      loadData();
    }

    async function allowDomain(domain) {
      await fetch('/api/web/allow', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain}),
      });
      loadData();
    }

    function openAddChildModal() { document.getElementById('add-child-modal').classList.add('open'); }
    function closeAddChildModal() { document.getElementById('add-child-modal').classList.remove('open'); }

    async function submitAddChild() {
      const username = document.getElementById('modal-username').value.trim();
      const fullname = document.getElementById('modal-fullname').value.trim();
      const tier = document.getElementById('modal-tier').value;
      const password = document.getElementById('modal-password').value;
      if (!username) return alert('Username required');

      await fetch('/api/child', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, fullname, tier, password}),
      });
      closeAddChildModal();
      loadData();
    }

    function switchTab(tab) {
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('tab-dashboard').style.display = (tab === 'dashboard' || tab === 'children' || tab === 'screentime' || tab === 'apps') ? 'block' : 'none';
      document.getElementById('tab-webfilter').style.display = (tab === 'webfilter') ? 'block' : 'none';
      document.getElementById('tab-audit').style.display = (tab === 'audit') ? 'block' : 'none';
      if (tab === 'audit') loadAudit();
    }

    loadData();
    setInterval(loadData, 15000);
  </script>
</body>
</html>
"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Handles REST and page requests for the parent portal."""

    def __init__(self, *args, **kwargs):
        self.config_manager = PolicyConfigManager()
        self.adapter = SystemAdapter()
        self.provisioner = SystemProvisioner(adapter=self.adapter, config_manager=self.config_manager)
        self.tracker = ScreenTimeTracker()
        self.audit = AuditLogger()
        super().__init__(*args, **kwargs)

    def _send_json(self, data: Any, status: int = HTTPStatus.OK) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        url = urlparse(self.path)

        if url.path == "/" or url.path == "/index.html":
            payload = HTML_TEMPLATE.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        elif url.path == "/api/policy":
            policy = self.config_manager.load_policy()
            p_dict = policy.to_dict()
            # Enrich children with live tracker data
            for c_data in p_dict.get("children", []):
                u = c_data.get("username", "")
                c_data["used_today"] = self.tracker.get_minutes_used(u)
            self._send_json(p_dict)

        elif url.path == "/api/audit":
            records = self.audit.get_records(limit=50)
            self._send_json([r.__dict__ for r in records])

        elif url.path == "/api/backups":
            backups = self.config_manager.list_backups()
            self._send_json([{"name": b.name, "path": str(b), "size": b.stat().st_size} for b in backups])

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        url = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}

        policy = self.config_manager.load_policy()

        if url.path == "/api/child":
            username = body.get("username", "")
            fullname = body.get("fullname", username.capitalize())
            tier = body.get("tier", AgeTier.PRE_TEEN.value)
            pwd = body.get("password")

            child = ChildAccount.create(username, fullname, tier, pwd)
            policy.children.append(child)
            self.provisioner.apply_policy(policy, reason=f"Created child {username} via Web UI")
            self._send_json({"status": "ok", "username": username})

        elif url.path == "/api/child/toggle":
            username = body.get("username")
            enable = body.get("enable", True)
            for c in policy.children:
                if c.username == username:
                    c.enabled = enable
            self.provisioner.apply_policy(policy, reason=f"Toggled child {username} via Web UI")
            self._send_json({"status": "ok"})

        elif url.path == "/api/child/reset-usage":
            username = body.get("username")
            if username:
                self.tracker.reset_usage(username)
            self._send_json({"status": "ok"})

        elif url.path == "/api/web/block":
            domain = body.get("domain", "")
            for c in policy.children:
                if domain and domain not in c.web_filter.blocked_domains:
                    c.web_filter.blocked_domains.append(domain)
            self.provisioner.apply_policy(policy, reason=f"Blocked domain {domain} via Web UI")
            self._send_json({"status": "ok"})

        elif url.path == "/api/web/allow":
            domain = body.get("domain", "")
            for c in policy.children:
                if domain in c.web_filter.blocked_domains:
                    c.web_filter.blocked_domains.remove(domain)
            self.provisioner.apply_policy(policy, reason=f"Allowed domain {domain} via Web UI")
            self._send_json({"status": "ok"})

        elif url.path == "/api/backup":
            path = self.config_manager.create_backup("web_ui")
            self._send_json({"status": "ok", "backup": str(path)})

        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown action")


def run_server(port: int = 8443) -> None:
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, DashboardRequestHandler)
    print(f"[Family Linux] Parent Dashboard server running at http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Parent Dashboard server.")
        httpd.server_close()


def main() -> None:
    port = 8443
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(port)


if __name__ == "__main__":
    main()
