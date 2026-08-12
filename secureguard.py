"""
Linux SecureGuard — Ubuntu 22.04 Hardening Configurator
With Security Level Selector (Low / Medium / High)
"""

import sys
import os
import subprocess
import logging
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Callable, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QScrollArea, QProgressBar, QMessageBox,
    QFrame, QSizePolicy, QTextEdit, QGridLayout, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

# ──────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)

logging.basicConfig(
    filename="logs/audit.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def log(msg: str, level: str = "info") -> None:
    getattr(logging, level)(msg)


# ──────────────────────────────────────────────────────────────
# EXECUTION HELPERS
# ──────────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], sudo: bool = False) -> str:
    full = (["sudo"] + cmd) if sudo else cmd
    try:
        result = subprocess.run(full, capture_output=True, text=True, timeout=10)
        return result.stdout.lower()
    except Exception as exc:
        log(f"run_cmd error ({' '.join(full)}): {exc}", "warning")
        return ""


def apply_fix(cmd: list[str]) -> bool:
    full = ["sudo"] + cmd
    log(f"Applying fix: {' '.join(full)}")
    try:
        subprocess.run(full, check=True, timeout=30)
        log("Fix applied successfully")
        return True
    except subprocess.CalledProcessError as exc:
        log(f"Fix failed: {exc}", "error")
        return False
    except subprocess.TimeoutExpired:
        log("Fix timed out", "error")
        return False


def sysctl_get(key: str) -> str:
    return run_cmd(["sysctl", key])


def pkg_installed(name: str) -> bool:
    out = run_cmd(["dpkg", "-l", name])
    return bool(re.search(r"^ii\s+" + re.escape(name), out, re.MULTILINE))


# ── Fix helpers ───────────────────────────────────────────────

def _fix_ufw() -> bool:
    if not bool(re.search(r"\bufw\b", run_cmd(["which", "ufw"]))):
        if not apply_fix(["apt", "install", "-y", "ufw"]):
            return False
    return apply_fix(["ufw", "--force", "enable"])


def _check_apt_autoupdates() -> bool:
    out = run_cmd(["bash", "-c", "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null"])
    return bool(re.search(r'apt::periodic::update-package-lists\s+"1"', out))


def _fix_apt_autoupdates() -> bool:
    return apply_fix(["bash", "-c",
        "echo 'APT::Periodic::Update-Package-Lists \"1\";' "
        "> /etc/apt/apt.conf.d/20auto-upgrades && "
        "echo 'APT::Periodic::Unattended-Upgrade \"1\";' "
        ">> /etc/apt/apt.conf.d/20auto-upgrades"
    ])


def _fix_aslr() -> bool:
    runtime = apply_fix(["sysctl", "-w", "kernel.randomize_va_space=2"])
    persist = apply_fix(["bash", "-c",
        "grep -q 'kernel.randomize_va_space' /etc/sysctl.conf "
        "&& sed -i 's/.*kernel.randomize_va_space.*/kernel.randomize_va_space=2/' /etc/sysctl.conf "
        "|| echo 'kernel.randomize_va_space=2' >> /etc/sysctl.conf"
    ])
    return runtime and persist


def _fix_ip_forward() -> bool:
    runtime = apply_fix(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    persist = apply_fix(["bash", "-c",
        "grep -q 'net.ipv4.ip_forward' /etc/sysctl.conf "
        "&& sed -i 's/.*net.ipv4.ip_forward.*/net.ipv4.ip_forward=0/' /etc/sysctl.conf "
        "|| echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf"
    ])
    return runtime and persist


def _check_pwquality_installed() -> bool:
    return pkg_installed("libpam-pwquality")


def _fix_pwquality_install() -> bool:
    if not apply_fix(["apt", "install", "-y", "libpam-pwquality"]):
        return False
    return apply_fix(["pam-auth-update", "--enable", "pwquality"])


def _check_pam_minlen() -> bool:
    if not _check_pwquality_installed():
        return False
    out = run_cmd(["grep", "-E", r"^\s*minlen", "/etc/security/pwquality.conf"])
    return bool(re.search(r"minlen\s*=\s*(?:1[2-9]|[2-9]\d)", out))


def _fix_pam_minlen() -> bool:
    if not _check_pwquality_installed():
        if not _fix_pwquality_install():
            return False
    return apply_fix(["sed", "-i",
        r"s/^#*\s*minlen\s*=.*/minlen = 12/",
        "/etc/security/pwquality.conf"])


# ──────────────────────────────────────────────────────────────
# POLICY DATACLASS
# ──────────────────────────────────────────────────────────────

@dataclass
class Policy:
    id: str
    title: str
    category: str
    weight: int
    description: str
    check: Callable[[], bool]
    fix: Callable[[], bool]
    levels: list[str]               # which security levels include this policy
    compliant: Optional[bool] = field(default=None, repr=False)

    def run_check(self) -> bool:
        try:
            self.compliant = bool(self.check())
        except Exception as exc:
            log(f"Check error [{self.id}]: {exc}", "warning")
            self.compliant = False
        return self.compliant

    def run_fix(self) -> bool:
        try:
            ok = self.fix()
            if ok:
                self.run_check()
            return ok
        except Exception as exc:
            log(f"Fix error [{self.id}]: {exc}", "error")
            return False


# ──────────────────────────────────────────────────────────────
# SECURITY LEVEL DEFINITIONS
#   LOW    → 6  policies  (ids marked with "low")
#   MEDIUM → 13 policies  (low + medium)
#   HIGH   → 20 policies  (all)
# ──────────────────────────────────────────────────────────────

ALL_POLICIES: list[Policy] = [

    # ════════════════════════════════════════════
    # LOW TIER  (6 policies – core essentials)
    # ════════════════════════════════════════════

    Policy("CIS-1", "UFW Enabled", "Network", 5,
           "Uncomplicated Firewall should be active to filter traffic.",
           check=lambda: bool(re.search(r"\bactive\b", run_cmd(["ufw", "status"]))),
           fix=lambda: _fix_ufw(),
           levels=["Low", "Medium", "High"]),

    Policy("CIS-4", "Root SSH Disabled", "SSH", 5,
           "Direct root login over SSH must be disabled.",
           check=lambda: "permitrootlogin no" in run_cmd(["grep", "-i", "PermitRootLogin", "/etc/ssh/sshd_config"]),
           fix=lambda: apply_fix(["sed", "-i",
               r"s/^#*\s*PermitRootLogin.*/PermitRootLogin no/",
               "/etc/ssh/sshd_config"]),
           levels=["Low", "Medium", "High"]),

    Policy("CIS-11", "Cron Enabled", "Services", 4,
           "The cron daemon should be active for scheduled tasks.",
           check=lambda: run_cmd(["systemctl", "is-active", "cron"]).strip() == "active",
           fix=lambda: apply_fix(["systemctl", "enable", "--now", "cron"]),
           levels=["Low", "Medium", "High"]),

    Policy("CIS-14", "Shadow File 640", "Files", 4,
           "/etc/shadow must not be world-readable.",
           check=lambda: run_cmd(["stat", "-c", "%a", "/etc/shadow"]).strip() in ("640", "000"),
           fix=lambda: apply_fix(["chmod", "640", "/etc/shadow"]),
           levels=["Low", "Medium", "High"]),

    Policy("CIS-15", "Passwd File 644", "Files", 4,
           "/etc/passwd must be world-readable but not writable.",
           check=lambda: "644" in run_cmd(["stat", "-c", "%a", "/etc/passwd"]),
           fix=lambda: apply_fix(["chmod", "644", "/etc/passwd"]),
           levels=["Low", "Medium", "High"]),

    Policy("CIS-18", "Rsyslog Installed", "Logging", 4,
           "System logging daemon must be present.",
           check=lambda: pkg_installed("rsyslog"),
           fix=lambda: apply_fix(["apt", "install", "-y", "rsyslog"]),
           levels=["Low", "Medium", "High"]),

    # ════════════════════════════════════════════
    # MEDIUM TIER  (adds 7 more → 13 total)
    # ════════════════════════════════════════════

    Policy("CIS-2", "Default Deny Incoming", "Network", 5,
           "Reject all unsolicited inbound connections by default.",
           check=lambda: "deny (incoming)" in run_cmd(["ufw", "status", "verbose"]),
           fix=lambda: apply_fix(["ufw", "default", "deny", "incoming"]),
           levels=["Medium", "High"]),

    Policy("CIS-3", "Fail2Ban Installed", "Network", 5,
           "Fail2Ban blocks IPs with repeated failed login attempts.",
           check=lambda: pkg_installed("fail2ban"),
           fix=lambda: apply_fix(["apt", "install", "-y", "fail2ban"]),
           levels=["Medium", "High"]),

    Policy("CIS-5", "SSH Protocol 2 Only", "SSH", 5,
           "Only allow SSHv2; SSHv1 has known critical vulnerabilities.",
           check=lambda: "protocol 2" in run_cmd(["grep", "-i", "^Protocol", "/etc/ssh/sshd_config"]),
           fix=lambda: apply_fix(["bash", "-c",
               "grep -q '^Protocol' /etc/ssh/sshd_config "
               "&& sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config "
               "|| echo 'Protocol 2' >> /etc/ssh/sshd_config"]),
           levels=["Medium", "High"]),

    Policy("CIS-6", "MaxAuthTries ≤ 4", "SSH", 5,
           "Limit SSH authentication attempts to reduce brute-force risk.",
           check=lambda: bool(re.search(r"maxauthtries [1-4]$",
               run_cmd(["grep", "-i", "MaxAuthTries", "/etc/ssh/sshd_config"]))),
           fix=lambda: apply_fix(["bash", "-c",
               "grep -q '^MaxAuthTries' /etc/ssh/sshd_config "
               "&& sed -i 's/^MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config "
               "|| echo 'MaxAuthTries 4' >> /etc/ssh/sshd_config"]),
           levels=["Medium", "High"]),

    Policy("CIS-9", "Unattended Upgrades Installed", "Patch", 5,
           "Automatically install security updates.",
           check=lambda: pkg_installed("unattended-upgrades"),
           fix=lambda: apply_fix(["apt", "install", "-y", "unattended-upgrades"]),
           levels=["Medium", "High"]),

    Policy("CIS-10", "APT Auto Updates Enabled", "Patch", 5,
           "APT must be configured to automatically check for updates.",
           check=lambda: _check_apt_autoupdates(),
           fix=lambda: _fix_apt_autoupdates(),
           levels=["Medium", "High"]),

    Policy("CIS-24", "NTP Installed", "Hardening", 4,
           "Network Time Protocol ensures accurate system timestamps for logs.",
           check=lambda: pkg_installed("ntp") or pkg_installed("chrony"),
           fix=lambda: apply_fix(["apt", "install", "-y", "chrony"]),
           levels=["Medium", "High"]),

    # ════════════════════════════════════════════
    # HIGH TIER  (adds 7 more → 20 total)
    # ════════════════════════════════════════════

    Policy("CIS-12", "Avahi Disabled", "Services", 4,
           "Disable the Avahi mDNS/DNS-SD daemon to reduce attack surface.",
           check=lambda: "inactive" in run_cmd(["systemctl", "is-active", "avahi-daemon"]) or
                         "not-found" in run_cmd(["systemctl", "is-active", "avahi-daemon"]),
           fix=lambda: apply_fix(["systemctl", "disable", "--now", "avahi-daemon"]),
           levels=["High"]),

    Policy("CIS-16", "IP Forwarding Disabled", "Kernel", 4,
           "Disable IP packet forwarding unless this is a router.",
           check=lambda: "= 0" in sysctl_get("net.ipv4.ip_forward"),
           fix=lambda: _fix_ip_forward(),
           levels=["High"]),

    Policy("CIS-17", "ASLR Enabled (Level 2)", "Kernel", 4,
           "Address Space Layout Randomization level 2 mitigates memory exploits.",
           check=lambda: "= 2" in sysctl_get("kernel.randomize_va_space"),
           fix=lambda: _fix_aslr(),
           levels=["High"]),

    Policy("CIS-19", "UFW Logging Enabled", "Logging", 4,
           "UFW should log blocked/allowed traffic for audit purposes.",
           check=lambda: bool(re.search(r"logging:\s+on",
               run_cmd(["ufw", "status", "verbose"]))),
           fix=lambda: apply_fix(["ufw", "logging", "on"]),
           levels=["High"]),

    Policy("CIS-20", "No Empty Passwords", "Accounts", 4,
           "PAM must not allow login with empty passwords.",
           check=lambda: "nullok" not in run_cmd(["grep", "nullok", "/etc/pam.d/common-auth"]),
           fix=lambda: apply_fix(["sed", "-i", "s/nullok//g", "/etc/pam.d/common-auth"]),
           levels=["High"]),

    Policy("CIS-21", "Password Expiry 90 Days", "Accounts", 4,
           "User passwords must expire every 90 days.",
           check=lambda: bool(re.search(r"pass_max_days\s+\d{1,2}$",
               run_cmd(["grep", "-i", "PASS_MAX_DAYS", "/etc/login.defs"]))),
           fix=lambda: apply_fix(["sed", "-i",
               r"s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/",
               "/etc/login.defs"]),
           levels=["High"]),

    Policy("CIS-22", "Core Dumps Restricted", "Hardening", 4,
           "Prevent core dumps that may contain sensitive memory data.",
           check=lambda: "hard core 0" in run_cmd(["grep", "hard core", "/etc/security/limits.conf"]),
           fix=lambda: apply_fix(["bash", "-c",
               "grep -q 'hard core 0' /etc/security/limits.conf "
               "|| echo '* hard core 0' >> /etc/security/limits.conf"]),
           levels=["High"]),
]

# ── Level metadata ────────────────────────────────────────────

LEVEL_META = {
    "Low": {
        "color":       "#d29922",
        "bg":          "rgba(210,153,34,0.12)",
        "border":      "#d29922",
        "icon":        "🟡",
        "description": "Core essentials — firewall, file permissions, SSH root lock, logging.",
    },
    "Medium": {
        "color":       "#388bfd",
        "bg":          "rgba(56,139,253,0.12)",
        "border":      "#388bfd",
        "icon":        "🔵",
        "description": "Balanced hardening — adds brute-force protection, patch management & SSH hardening.",
    },
    "High": {
        "color":       "#f85149",
        "bg":          "rgba(248,81,73,0.12)",
        "border":      "#f85149",
        "icon":        "🔴",
        "description": "Maximum security — full kernel hardening, account policies, service minimisation.",
    },
}


def policies_for_level(level: str) -> list[Policy]:
    return [p for p in ALL_POLICIES if level in p.levels]


# ──────────────────────────────────────────────────────────────
# BACKGROUND WORKERS
# ──────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    progress    = pyqtSignal(int)
    policy_done = pyqtSignal(str, bool)   # policy.id, compliant
    finished    = pyqtSignal(int, int)    # earned, total_weight

    def __init__(self, policies: list[Policy]):
        super().__init__()
        self._policies = policies

    def run(self):
        total        = len(self._policies)
        total_weight = sum(p.weight for p in self._policies)
        earned       = 0
        for i, policy in enumerate(self._policies):
            ok = policy.run_check()
            if ok:
                earned += policy.weight
            self.policy_done.emit(policy.id, ok)
            self.progress.emit(int((i + 1) / total * 100))
        self.finished.emit(earned, total_weight)


class FixWorker(QThread):
    finished = pyqtSignal(str, bool)   # policy.id, success

    def __init__(self, policy: Policy):
        super().__init__()
        self._policy = policy

    def run(self):
        ok = self._policy.run_fix()
        self.finished.emit(self._policy.id, ok)


# ──────────────────────────────────────────────────────────────
# STYLESHEET
# ──────────────────────────────────────────────────────────────

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', 'Ubuntu', sans-serif;
    font-size: 13px;
}
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical {
    background: #161b22; width: 8px; border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #30363d; border-radius: 4px; min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QPushButton#primary {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #238636, stop:1 #2ea043);
    color: #fff; border: none; border-radius: 6px;
    padding: 10px 22px; font-weight: 600; font-size: 13px;
}
QPushButton#primary:hover  { background: #2ea043; }
QPushButton#primary:pressed { background: #1a7f37; }
QPushButton#primary:disabled { background: #21262d; color: #484f58; }

QPushButton#danger {
    background: transparent;
    color: #f85149; border: 1px solid #f85149;
    border-radius: 5px; padding: 4px 12px; font-size: 12px;
}
QPushButton#danger:hover { background: rgba(248,81,73,0.15); }

QPushButton#secondary {
    background: #21262d; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 6px;
    padding: 8px 18px; font-size: 13px;
}
QPushButton#secondary:hover { background: #30363d; border-color: #8b949e; }

QProgressBar {
    background: #21262d; border: none; border-radius: 5px;
    height: 8px; text-align: center; color: transparent;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #238636, stop:1 #56d364);
    border-radius: 5px;
}
QTextEdit {
    background: #161b22; color: #8b949e;
    border: 1px solid #21262d; border-radius: 6px;
    font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px;
    padding: 8px;
}
QLabel#header      { color: #e6edf3; font-size: 20px; font-weight: 700; }
QLabel#subheader   { color: #8b949e; font-size: 12px; }
"""


# ──────────────────────────────────────────────────────────────
# LEVEL SELECTOR CARD
# ──────────────────────────────────────────────────────────────

class LevelCard(QFrame):
    """Clickable security-level card."""
    selected = pyqtSignal(str)

    def __init__(self, level: str, parent=None):
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setObjectName("levelCard") 
        self.level   = level
        self._active = False
        meta = LEVEL_META[level]
        self._color  = meta["color"]
        self._bg     = meta["bg"]

        self.setFixedHeight(90)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._apply_style(False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(3)

        top_widget = QWidget()
        top_widget.setStyleSheet("background: transparent; border: none;")
        top = QHBoxLayout(top_widget)
        top.setContentsMargins(0, 0, 0, 0)
        icon_lbl = QLabel(meta["icon"])
        icon_lbl.setStyleSheet("font-size: 16px;")
        level_lbl = QLabel(level.upper())
        level_lbl.setStyleSheet(f"""
            color: {self._color};
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 1px;
            background: transparent;
            border: none;
        """)
        level_lbl.setAutoFillBackground(False)
        n = len(policies_for_level(level))
        count_lbl = QLabel(f"{n} policies")
        count_lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
        top.addWidget(icon_lbl)
        top.addWidget(level_lbl)
        top.addStretch()
        top.addWidget(count_lbl)

        desc_lbl = QLabel(meta["description"])
        desc_lbl.setStyleSheet("""
            color: #8b949e;
            font-size: 11px;
            background: transparent;   /* 🔥 removes that bottom box */
            border: none;
        """)
        desc_lbl.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        desc_lbl.setAutoFillBackground(False)
        desc_lbl.setWordWrap(True)

        layout.addWidget(top_widget)
        layout.addWidget(desc_lbl)

    def _apply_style(self, active: bool):
        color  = LEVEL_META[self.level]["color"]
        bg     = LEVEL_META[self.level]["bg"] if active else "transparent"
        border = color if active else "#21262d"

        self.setStyleSheet(f"""
            QFrame#levelCard {{
                background: {bg};
                border: 2px solid {border};
                border-radius: 10px;
                outline: none;
            }}

            QFrame#levelCard:focus {{
                outline: none;
                border: 2px solid {border};
            }}

            QFrame#levelCard:pressed {{
                outline: none;
            }}
        """)
        self._active = active
        

    def set_active(self, active: bool):
        self._apply_style(active)

    def mousePressEvent(self, _):
        self.selected.emit(self.level)


# ──────────────────────────────────────────────────────────────
# POLICY ROW WIDGET
# ──────────────────────────────────────────────────────────────

class PolicyRow(QFrame):
    fix_requested = pyqtSignal(str)   # emits policy.id

    def __init__(self, policy: Policy, parent=None):
        super().__init__(parent)
        self.policy = policy
        self._build_ui()

    def _build_ui(self):
        self.setObjectName("policyRow")
        self.setStyleSheet("""
            QFrame#policyRow {
                background: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
                margin: 2px 4px;
            }
            QFrame#policyRow:hover { border-color: #30363d; }
        """)
        self.setFixedHeight(56)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 12, 0)
        layout.setSpacing(12)

        cat = QLabel(self.policy.category)
        cat.setFixedWidth(80)
        cat.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cat.setStyleSheet(f"""
            background: {self._cat_color()};
            color: #fff; border-radius: 4px;
            padding: 2px 6px; font-size: 10px; font-weight: 600;
        """)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        title = QLabel(self.policy.title)
        title.setStyleSheet("color: #e6edf3; font-weight: 600; font-size: 13px;")
        desc = QLabel(self.policy.description)
        desc.setStyleSheet("color: #8b949e; font-size: 11px;")
        desc.setWordWrap(False)
        text_col.addWidget(title)
        text_col.addWidget(desc)

        self.badge = QLabel("—")
        self.badge.setFixedWidth(110)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setStyleSheet("color: #8b949e; font-size: 12px;")

        self.fix_btn = QPushButton("Fix")
        self.fix_btn.setObjectName("danger")
        self.fix_btn.setFixedWidth(60)
        self.fix_btn.setVisible(False)
        self.fix_btn.clicked.connect(lambda: self.fix_requested.emit(self.policy.id))

        layout.addWidget(cat)
        layout.addLayout(text_col, stretch=1)
        layout.addWidget(self.badge)
        layout.addWidget(self.fix_btn)

    def _cat_color(self) -> str:
        return {
            "Network":   "#1f6feb", "SSH":       "#388bfd",
            "Auth":      "#8957e5", "Patch":     "#a371f7",
            "Services":  "#3fb950", "Files":     "#d29922",
            "Kernel":    "#f85149", "Logging":   "#39d353",
            "Accounts":  "#58a6ff", "Hardening": "#ff7b72",
        }.get(self.policy.category, "#8b949e")

    def update_status(self, compliant: bool):
        if compliant:
            self.badge.setText("✔ COMPLIANT")
            self.badge.setStyleSheet(
                "color: #3fb950; font-size: 11px; font-weight: 700;"
                "background: rgba(63,185,80,.12); border-radius: 4px; padding: 2px 6px;")
            self.fix_btn.setVisible(False)
        else:
            self.badge.setText("✖ NON-COMPLIANT")
            self.badge.setStyleSheet(
                "color: #f85149; font-size: 11px; font-weight: 700;"
                "background: rgba(248,81,73,.12); border-radius: 4px; padding: 2px 6px;")
            self.fix_btn.setVisible(True)

    def reset_status(self):
        self.badge.setText("—")
        self.badge.setStyleSheet("color: #8b949e; font-size: 12px;")
        self.fix_btn.setVisible(False)


# ──────────────────────────────────────────────────────────────
# SCORE GAUGE WIDGET
# ──────────────────────────────────────────────────────────────

class ScoreWidget(QLabel):
    def __init__(self, parent=None):
        super().__init__("—", parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._set_style(None)

    def set_score(self, pct: int):
        self.setText(f"{pct}%")
        self._set_style(pct)

    def reset(self):
        self.setText("—")
        self._set_style(None)

    def _set_style(self, pct: Optional[int]):
        if pct is None:
            color, bg = "#8b949e", "rgba(139,148,158,.1)"
        elif pct >= 80:
            color, bg = "#3fb950", "rgba(63,185,80,.15)"
        elif pct >= 50:
            color, bg = "#d29922", "rgba(210,153,34,.15)"
        else:
            color, bg = "#f85149", "rgba(248,81,73,.15)"
        self.setStyleSheet(f"""
            color: {color}; font-size: 48px; font-weight: 800;
            background: {bg}; border: 3px solid {color};
            border-radius: 70px; min-width: 140px; max-width: 140px;
            min-height: 140px; max-height: 140px;
        """)


# ──────────────────────────────────────────────────────────────
# PDF REPORT GENERATOR
# ──────────────────────────────────────────────────────────────

def generate_pdf_report(policies: list[Policy], score: int, level: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"reports/secureguard_{level.lower()}_{timestamp}.pdf"

    doc = SimpleDocTemplate(path, pagesize=(8.5 * inch, 11 * inch),
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"],
                                 fontSize=22, spaceAfter=4, textColor=colors.HexColor("#0d1117"))
    sub_style   = ParagraphStyle("Sub", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#555"))
    cat_style   = ParagraphStyle("Cat", parent=styles["Heading2"],
                                 fontSize=13, spaceAfter=4, textColor=colors.HexColor("#1a1a2e"))

    elements = []
    elements.append(Paragraph("Linux SecureGuard Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
        f"Security Level: <b>{level}</b>  |  Score: <b>{score}%</b>  |  Policies: {len(policies)}",
        sub_style))
    elements.append(Spacer(1, 14))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#ddd")))
    elements.append(Spacer(1, 12))

    compliant_count = sum(1 for p in policies if p.compliant)
    table_data = [
        ["Metric", "Value"],
        ["Security Level", level],
        ["Total Policies", str(len(policies))],
        ["Compliant", str(compliant_count)],
        ["Non-Compliant", str(len(policies) - compliant_count)],
        ["Weighted Score", f"{score}%"],
    ]
    tbl = Table(table_data, colWidths=[2.5 * inch, 2.5 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#0d1117")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#ccc")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.25, colors.HexColor("#ddd")),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 20))

    categories: dict[str, list[Policy]] = {}
    for p in policies:
        categories.setdefault(p.category, []).append(p)

    for cat, items in categories.items():
        elements.append(Paragraph(cat, cat_style))
        rows = [["ID", "Policy", "Weight", "Status"]]
        for p in items:
            rows.append([p.id, p.title, str(p.weight),
                         "Compliant" if p.compliant else "Non-Compliant"])
        t = Table(rows, colWidths=[0.7 * inch, 3.8 * inch, 0.8 * inch, 1.2 * inch])
        row_colors = [
            ("TEXTCOLOR", (3, i), (3, i),
             colors.HexColor("#2ea043") if rows[i][3] == "Compliant"
             else colors.HexColor("#cf222e"))
            for i in range(1, len(rows))
        ]
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#21262d")),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
            ("BOX",           (0, 0), (-1, -1), 0.5,  colors.HexColor("#ccc")),
            ("INNERGRID",     (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            *row_colors,
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

    doc.build(elements)
    log(f"PDF report saved: {path}")
    return path


# ──────────────────────────────────────────────────────────────
# SECURITY LEVEL MANAGER DIALOG
# ──────────────────────────────────────────────────────────────

class LevelManagerDialog(QWidget):
    """
    Standalone window for managing which policies belong to each level.
    Changes are reflected live in ALL_POLICIES[*].levels.
    """
    closed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle("Manage Security Level Policies")
        self.setMinimumSize(780, 600)
        self.setStyleSheet(DARK_STYLE + """
            QCheckBox { spacing: 8px; color: #c9d1d9; font-size: 12px; }
            QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px;
                border: 1px solid #30363d; background: #21262d; }
            QCheckBox::indicator:checked { background: #238636; border-color: #238636; }
        """)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        # Header
        hdr = QLabel("Configure Security Level Policies")
        hdr.setObjectName("header")
        sub = QLabel("Check which levels each policy should appear in. "
                     "Every policy is always available in its own tier and above.")
        sub.setObjectName("subheader")
        sub.setWordWrap(True)
        root.addWidget(hdr)
        root.addWidget(sub)

        # Column headers
        col_hdr = QWidget()
        ch_layout = QHBoxLayout(col_hdr)
        ch_layout.setContentsMargins(16, 0, 16, 0)
        ch_layout.addWidget(QLabel("Policy"), stretch=1)
        ch_layout.addWidget(QLabel("Category"), )
        for lv in ["Low", "Medium", "High"]:
            lbl = QLabel(lv)
            lbl.setFixedWidth(70)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(f"color: {LEVEL_META[lv]['color']}; font-weight: 700;")
            ch_layout.addWidget(lbl)
        col_hdr.setStyleSheet("background: #161b22; border-radius: 6px; padding: 4px 0;")
        root.addWidget(col_hdr)

        # Scrollable policy list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setSpacing(3)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._checkboxes: dict[str, dict[str, QCheckBox]] = {}

        for p in ALL_POLICIES:
            row = QWidget()
            row.setFixedHeight(42)
            row.setStyleSheet(
                "background: #161b22; border: 1px solid #21262d; border-radius: 6px;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(16, 0, 16, 0)

            title = QLabel(f"{p.id}  {p.title}")
            title.setStyleSheet("color: #e6edf3; font-size: 12px;")
            rl.addWidget(title, stretch=1)

            cat = QLabel(p.category)
            cat.setFixedWidth(80)
            cat.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cat.setStyleSheet(
                f"background: {PolicyRow(p)._cat_color()}; color: #fff; "
                f"border-radius: 4px; padding: 2px 4px; font-size: 10px; font-weight: 600;")
            rl.addWidget(cat)

            self._checkboxes[p.id] = {}
            for lv in ["Low", "Medium", "High"]:
                cb = QCheckBox()
                cb.setFixedWidth(70)
                cb.setChecked(lv in p.levels)
                cb.setStyleSheet("QCheckBox { padding-left: 27px; }")
                cb.stateChanged.connect(
                    lambda state, pid=p.id, level=lv: self._on_toggle(pid, level, state))
                self._checkboxes[p.id][lv] = cb
                rl.addWidget(cb)

            inner_layout.addWidget(row)

        scroll.setWidget(inner)
        root.addWidget(scroll, stretch=1)

        # Save / close
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("✔  Save & Close")
        close_btn.setObjectName("primary")
        close_btn.clicked.connect(self.close)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    def _on_toggle(self, policy_id: str, level: str, state: int):
        for p in ALL_POLICIES:
            if p.id == policy_id:
                if state == Qt.CheckState.Checked.value and level not in p.levels:
                    p.levels.append(level)
                elif state != Qt.CheckState.Checked.value and level in p.levels:
                    p.levels.remove(level)
                break

    def closeEvent(self, event):
        self.closed.emit()
        super().closeEvent(event)


# ──────────────────────────────────────────────────────────────
# MAIN WINDOW
# ──────────────────────────────────────────────────────────────

class SecureGuard(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux SecureGuard — Ubuntu 22.04 Hardening")
        self.setMinimumSize(1100, 780)
        self.resize(1240, 900)
        self.setStyleSheet(DARK_STYLE)

        self._rows: dict[str, PolicyRow] = {}      # policy.id → row
        self._active_policies: list[Policy] = []
        self._selected_level: Optional[str] = None
        self._score  = 0
        self._worker: Optional[ScanWorker] = None
        self._fix_worker: Optional[FixWorker] = None
        self._busy   = False
        self._manager_win: Optional[LevelManagerDialog] = None

        self._build_ui()

    # ── Layout ────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        # Top bar
        topbar = QWidget()
        topbar.setFixedHeight(70)
        topbar.setStyleSheet("background: #161b22; border-bottom: 1px solid #21262d;")
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(24, 0, 24, 0)

        icon = QLabel("🛡")
        icon.setStyleSheet("font-size: 28px;")
        title = QLabel("SecureGuard")
        title.setObjectName("header")
        self.sub_lbl = QLabel("CIS Ubuntu 22.04 Benchmark  •  Select a security level to begin")
        self.sub_lbl.setObjectName("subheader")
        self.sub_lbl.setStyleSheet("color: #8b949e; font-size: 12px; margin-left: 8px; margin-top: 6px;")

        self.scan_btn = QPushButton("▶  Run Scan")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setFixedWidth(130)
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self.start_scan)

        self.report_btn = QPushButton("📄  Export PDF")
        self.report_btn.setObjectName("secondary")
        self.report_btn.setFixedWidth(130)
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self.export_report)

        self.manage_btn = QPushButton("⚙  Manage Levels")
        self.manage_btn.setObjectName("secondary")
        self.manage_btn.setFixedWidth(140)
        self.manage_btn.clicked.connect(self.open_manager)

        tb.addWidget(icon)
        tb.addWidget(title)
        tb.addWidget(self.sub_lbl, alignment=Qt.AlignmentFlag.AlignBottom)
        tb.addStretch()
        tb.addWidget(self.manage_btn)
        tb.addSpacing(8)
        tb.addWidget(self.scan_btn)
        tb.addSpacing(8)
        tb.addWidget(self.report_btn)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(5)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)

        # Body
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        sidebar = self._build_sidebar()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet("background: #161b22; border-right: 1px solid #21262d;")

        main_panel = self._build_main_panel()

        body_layout.addWidget(sidebar)
        body_layout.addWidget(main_panel, stretch=1)

        root_layout.addWidget(topbar)
        root_layout.addWidget(self.progress)
        root_layout.addWidget(body, stretch=1)

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 24, 16, 16)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        score_lbl = QLabel("Score")
        score_lbl.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: 600; letter-spacing: 1px;")
        score_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.score_widget = ScoreWidget()
        sw = QWidget()
        sw_l = QVBoxLayout(sw)
        sw_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sw_l.addWidget(score_lbl)
        sw_l.addSpacing(8)
        sw_l.addWidget(self.score_widget, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sw)
        layout.addSpacing(20)

        self.stat_level       = self._stat_row("Level",         "—",  "#8b949e")
        self.stat_compliant   = self._stat_row("Compliant",     "0",  "#3fb950")
        self.stat_noncompliant= self._stat_row("Non-Compliant", "0",  "#f85149")
        self.stat_total       = self._stat_row("Total Policies","—",  "#8b949e")

        layout.addWidget(self.stat_level)
        layout.addWidget(self.stat_compliant)
        layout.addWidget(self.stat_noncompliant)
        layout.addWidget(self.stat_total)
        layout.addStretch()

        log_lbl = QLabel("Audit Log")
        log_lbl.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: 600; letter-spacing: 1px;")
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFixedHeight(130)
        layout.addWidget(log_lbl)
        layout.addWidget(self.log_view)

        return sidebar

    def _stat_row(self, label: str, value: str, color: str) -> QWidget:
        w = QWidget()
        l = QHBoxLayout(w)
        l.setContentsMargins(8, 4, 8, 4)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #8b949e; font-size: 12px;")
        val = QLabel(value)
        val.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: 700;")
        val.setObjectName(f"stat_{label.replace(' ', '_')}")
        l.addWidget(lbl)
        l.addStretch()
        l.addWidget(val)
        w.setStyleSheet("background: #0d1117; border-radius: 6px;")
        return w

    def _build_main_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Security Level Selector ───────────────────────────
        level_header = QLabel("SELECT SECURITY LEVEL")
        level_header.setStyleSheet(
            "color: #8b949e; font-size: 11px; font-weight: 700; letter-spacing: 1.5px;")

        self._level_cards: dict[str, LevelCard] = {}
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        for lv in ["Low", "Medium", "High"]:
            card = LevelCard(lv)
            card.selected.connect(self._on_level_selected)
            self._level_cards[lv] = card
            cards_row.addWidget(card)

        layout.addWidget(level_header)
        layout.addLayout(cards_row)

        # ── Divider ───────────────────────────────────────────
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("color: #21262d;")
        layout.addWidget(divider)

        # ── Filter buttons ────────────────────────────────────
        filter_bar = QWidget()
        fb = QHBoxLayout(filter_bar)
        fb.setContentsMargins(0, 0, 0, 0)
        fb.setSpacing(6)
        self._filter_btns: dict[str, QPushButton] = {}
        for label in ["All", "Non-Compliant", "Compliant"]:
            btn = QPushButton(label)
            btn.setObjectName("secondary")
            btn.setCheckable(True)
            btn.setFixedHeight(30)
            btn.clicked.connect(lambda _, lb=label: self._apply_filter(lb))
            fb.addWidget(btn)
            self._filter_btns[label] = btn
        self._filter_btns["All"].setChecked(True)
        fb.addStretch()

        # Policy count chip
        self.policy_count_lbl = QLabel("")
        self.policy_count_lbl.setStyleSheet(
            "color: #8b949e; font-size: 12px; padding: 4px 10px; "
            "background: #161b22; border-radius: 10px; border: 1px solid #30363d;")
        fb.addWidget(self.policy_count_lbl)

        layout.addWidget(filter_bar)

        # ── Placeholder / scroll area ─────────────────────────
        self.placeholder = QLabel("← Select a security level above to load policies")
        self.placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.placeholder.setStyleSheet(
            "color: #484f58; font-size: 14px; font-style: italic;")
        layout.addWidget(self.placeholder, stretch=1)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setVisible(False)
        self.scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(4)
        self.scroll_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.scroll_widget)
        layout.addWidget(self.scroll, stretch=1)

        return panel

    # ── Level selection ───────────────────────────────────────

    def _on_level_selected(self, level: str):
        if self._busy:
            return
        self._selected_level = level

        # Update cards
        for lv, card in self._level_cards.items():
            card.set_active(lv == level)

        # Rebuild policy rows for this level
        self._rebuild_rows(level)

        # Update UI chrome
        meta = LEVEL_META[level]
        n    = len(self._active_policies)
        self.sub_lbl.setText(
            f"CIS Ubuntu 22.04 Benchmark  •  {level} Security  •  {n} Policies")
        self.policy_count_lbl.setText(f"{n} policies")
        self.scan_btn.setEnabled(True)
        self.report_btn.setEnabled(False)
        self.score_widget.reset()
        self._update_stat("Level", level)
        self._update_stat("Total_Policies", str(n))
        self._update_stat("Compliant", "0")
        self._update_stat("Non-Compliant", "0")
        self.placeholder.setVisible(False)
        self.scroll.setVisible(True)
        self._apply_filter("All")
        self._append_log(f"Security level set to: {level} ({n} policies)")

    def _rebuild_rows(self, level: str):
        # Clear existing rows
        for row in self._rows.values():
            row.setParent(None)
        self._rows.clear()

        self._active_policies = policies_for_level(level)

        # Reset compliant state for policies not in this level
        for p in ALL_POLICIES:
            if p not in self._active_policies:
                p.compliant = None

        for policy in self._active_policies:
            policy.compliant = None          # reset previous scan results
            row = PolicyRow(policy)
            row.fix_requested.connect(self._confirm_fix)
            self._rows[policy.id] = row
            self.scroll_layout.addWidget(row)

    # ── Scan logic ────────────────────────────────────────────

    def start_scan(self):
        if self._busy or not self._selected_level:
            return
        self._busy = True
        self.scan_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        self.progress.setValue(0)
        self._append_log(f"Scanning {len(self._active_policies)} policies [{self._selected_level}]…")

        self._worker = ScanWorker(self._active_policies)
        self._worker.progress.connect(self.progress.setValue)
        self._worker.policy_done.connect(self._on_policy_done)
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.start()

    def _on_policy_done(self, policy_id: str, compliant: bool):
        if policy_id in self._rows:
            self._rows[policy_id].update_status(compliant)

    def _on_scan_finished(self, earned: int, total_weight: int):
        self._score     = int((earned / total_weight) * 100) if total_weight else 0
        compliant_n     = sum(1 for p in self._active_policies if p.compliant)
        non_n           = len(self._active_policies) - compliant_n

        self.score_widget.set_score(self._score)
        self._update_stat("Compliant",     str(compliant_n))
        self._update_stat("Non-Compliant", str(non_n))

        self.scan_btn.setEnabled(True)
        self.report_btn.setEnabled(True)
        self._busy = False
        self._append_log(
            f"Scan complete — {self._selected_level} — Score: {self._score}%  "
            f"({compliant_n}/{len(self._active_policies)} compliant)"
        )
        log(f"Scan complete [{self._selected_level}]. Score: {self._score}%")

    # ── Filter ────────────────────────────────────────────────

    def _apply_filter(self, label: str):
        for lbl, btn in self._filter_btns.items():
            btn.setChecked(lbl == label)
        for row in self._rows.values():
            if label == "All":
                row.setVisible(True)
            elif label == "Compliant":
                row.setVisible(row.policy.compliant is True)
            elif label == "Non-Compliant":
                row.setVisible(row.policy.compliant is False)

    # ── Fix ───────────────────────────────────────────────────

    def _confirm_fix(self, policy_id: str):
        if self._busy:
            QMessageBox.warning(self, "Busy", "A scan or fix is already running.")
            return
        policy = next((p for p in ALL_POLICIES if p.id == policy_id), None)
        if not policy:
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Apply Fix")
        msg.setText(f"<b>{policy.title}</b>")
        msg.setInformativeText(
            f"{policy.description}<br><br>"
            "<i>This will run a privileged command. Continue?</i>")
        msg.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        msg.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if msg.exec() != QMessageBox.StandardButton.Yes:
            return

        self._busy = True
        self.scan_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        for row in self._rows.values():
            row.fix_btn.setEnabled(False)

        self._append_log(f"Applying fix: {policy.title} …")
        self._fix_worker = FixWorker(policy)
        self._fix_worker.finished.connect(self._on_fix_finished)
        self._fix_worker.start()

    def _on_fix_finished(self, policy_id: str, ok: bool):
        policy = next((p for p in ALL_POLICIES if p.id == policy_id), None)
        if policy and policy_id in self._rows:
            self._rows[policy_id].update_status(policy.compliant or False)

        for row in self._rows.values():
            row.fix_btn.setEnabled(True)

        self._busy = False
        self.scan_btn.setEnabled(True)
        self.report_btn.setEnabled(True)

        name = policy.title if policy else policy_id
        self._append_log(f"Fix {'succeeded' if ok else 'FAILED'}: {name}")

        if ok:
            compliant_n = sum(1 for p in self._active_policies if p.compliant is True)
            non_n       = sum(1 for p in self._active_policies if p.compliant is False)
            self._update_stat("Compliant",     str(compliant_n))
            self._update_stat("Non-Compliant", str(non_n))
        else:
            QMessageBox.warning(self, "Fix Failed",
                f"Could not apply fix for <b>{name}</b>.<br>"
                "Check the audit log for details.")

    # ── Report ────────────────────────────────────────────────

    def export_report(self):
        try:
            path = generate_pdf_report(
                self._active_policies, self._score, self._selected_level or "Unknown")
            QMessageBox.information(self, "Report Saved", f"PDF saved to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Report Error", str(exc))

    # ── Level manager ─────────────────────────────────────────

    def open_manager(self):
        if self._manager_win and self._manager_win.isVisible():
            self._manager_win.raise_()
            return
        self._manager_win = LevelManagerDialog(self)
        self._manager_win.closed.connect(self._on_manager_closed)
        self._manager_win.show()

    def _on_manager_closed(self):
        # If a level is already selected, refresh its rows to reflect changes
        if self._selected_level:
            self._on_level_selected(self._selected_level)
            self._append_log("Level policy configuration updated.")

    # ── Helpers ───────────────────────────────────────────────

    def _update_stat(self, label: str, value: str):
        key = f"stat_{label.replace(' ', '_')}"
        widget = self.findChild(QLabel, key)
        if widget:
            widget.setText(value)

    def _append_log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_view.append(f'<span style="color:#3fb950">[{ts}]</span> {msg}')


# ──────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SecureGuard()
    window.show()
    sys.exit(app.exec())
