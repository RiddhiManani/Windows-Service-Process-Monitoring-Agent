"""
dashboard.py - Dark Theme Tkinter Dashboard
=============================================
Professional dark-themed GUI dashboard with real-time monitoring,
live counters, threat cards, color-coded tables, charts, search,
filter, export, settings panel, and notification popups.

Author: Security Research Team
Version: 1.0.0
"""

import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from typing import Optional, Callable

import psutil

from modules.logger import get_logger
from modules.utils import load_json_config, save_json_config, get_system_info, truncate

logger = get_logger("dashboard")

# ── Colour Palette ─────────────────────────────────────────────────────────
BG_DARK    = "#0d1117"
BG_CARD    = "#161b22"
BG_TABLE   = "#1c2128"
BG_HEADER  = "#21262d"
ACCENT     = "#00d4ff"
ACCENT2    = "#7c3aed"
TEXT_WHITE = "#e6edf3"
TEXT_GREY  = "#8b949e"
C_CRIT     = "#ff4444"
C_HIGH     = "#ff8c00"
C_MED      = "#ffd700"
C_LOW      = "#4fc3f7"
C_GREEN    = "#3fb950"
C_BORDER   = "#30363d"

SEVERITY_BG = {
    "Critical": C_CRIT,
    "High":     C_HIGH,
    "Medium":   C_MED,
    "Low":      C_LOW,
}

SETTINGS_PATH = "config/settings.json"
WHITELIST_PATH = "config/whitelist.json"
BLACKLIST_PATH = "config/blacklist.json"


# ── Reusable Widget Helpers ─────────────────────────────────────────────────

def styled_frame(parent, bg=BG_CARD, **kw):
    return tk.Frame(parent, bg=bg, **kw)

def styled_label(parent, text="", fg=TEXT_WHITE, bg=BG_CARD, font=("Consolas", 9), **kw):
    return tk.Label(parent, text=text, fg=fg, bg=bg, font=font, **kw)

def styled_button(parent, text, command, bg=ACCENT2, fg=TEXT_WHITE,
                  font=("Consolas", 9, "bold"), **kw):
    btn = tk.Button(parent, text=text, command=command,
                    bg=bg, fg=fg, font=font,
                    relief=tk.FLAT, cursor="hand2",
                    activebackground=ACCENT, activeforeground=BG_DARK,
                    padx=8, pady=4, **kw)
    return btn

def styled_entry(parent, width=20, **kw):
    e = tk.Entry(parent, bg=BG_TABLE, fg=TEXT_WHITE,
                 insertbackground=TEXT_WHITE, relief=tk.FLAT,
                 font=("Consolas", 9), width=width, **kw)
    return e

def card_frame(parent, title: str, width: int = 160, height: int = 80) -> tuple:
    """Create a metric card; returns (outer_frame, value_label)."""
    frame = tk.Frame(parent, bg=BG_CARD,
                     highlightbackground=C_BORDER, highlightthickness=1,
                     width=width, height=height)
    frame.pack_propagate(False)
    tk.Label(frame, text=title, bg=BG_CARD, fg=TEXT_GREY,
             font=("Consolas", 8)).pack(pady=(8, 0))
    val = tk.Label(frame, text="0", bg=BG_CARD, fg=ACCENT,
                   font=("Consolas", 22, "bold"))
    val.pack()
    return frame, val


def make_treeview(parent, columns: list, heights: int = 18) -> ttk.Treeview:
    """Create a styled dark Treeview."""
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Dark.Treeview",
        background=BG_TABLE, foreground=TEXT_WHITE,
        fieldbackground=BG_TABLE, rowheight=22,
        font=("Consolas", 8))
    style.configure("Dark.Treeview.Heading",
        background=BG_HEADER, foreground=ACCENT,
        font=("Consolas", 9, "bold"), relief="flat")
    style.map("Dark.Treeview",
        background=[("selected", ACCENT2)],
        foreground=[("selected", TEXT_WHITE)])

    tv = ttk.Treeview(parent, columns=columns, show="headings",
                      style="Dark.Treeview", height=heights)
    for col in columns:
        tv.heading(col, text=col)
        tv.column(col, width=100, anchor="w", stretch=True)
    return tv


# ── Notification Popup ──────────────────────────────────────────────────────

class NotificationPopup(tk.Toplevel):
    """Floating alert notification window that auto-closes after a delay."""

    def __init__(self, parent, severity: str, message: str, duration_ms: int = 5000):
        super().__init__(parent)
        self.overrideredirect(True)
        bg = SEVERITY_BG.get(severity, C_LOW)
        self.configure(bg=bg)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.92)

        # Position bottom-right
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"340x80+{sw-360}+{sh-120}")

        tk.Label(self, text=f"⚠  {severity.upper()} ALERT",
                 bg=bg, fg="white", font=("Consolas", 10, "bold")).pack(pady=(8, 2))
        tk.Label(self, text=truncate(message, 50),
                 bg=bg, fg="white", font=("Consolas", 8)).pack()
        tk.Button(self, text="✕", bg=bg, fg="white", relief=tk.FLAT,
                  command=self.destroy, cursor="hand2").place(relx=1.0, rely=0.0,
                  anchor="ne", x=-4, y=4)

        self.after(duration_ms, self.destroy)


# ── Main Dashboard Window ───────────────────────────────────────────────────

class Dashboard(tk.Tk):
    """
    Main application window for the Windows Service & Process Monitoring Agent.
    Hosts tabbed views for Processes, Services, Alerts, Startup, Reports, and Settings.
    """

    def __init__(self, agent_controller=None) -> None:
        super().__init__()
        self._ctrl = agent_controller   # MonitoringAgent reference
        self._auto_refresh = True
        self._refresh_ms   = 5000
        self._popup_enabled = True
        self._severity_filter = "All"
        self._search_var_proc  = tk.StringVar()
        self._search_var_svc   = tk.StringVar()
        self._search_var_alert = tk.StringVar()
        self._status_var = tk.StringVar(value="● Idle")
        self._scan_mode_var = tk.StringVar(value="Quick Scan")

        self._setup_window()
        self._apply_theme()
        self._build_topbar()
        self._build_stat_cards()
        self._build_notebook()
        self._build_statusbar()
        self._start_refresh_loop()
        logger.info("Dashboard initialized.")

    # ------------------------------------------------------------------
    # Window Setup
    # ------------------------------------------------------------------

    def _setup_window(self) -> None:
        settings = load_json_config(SETTINGS_PATH)
        gui = settings.get("gui", {})
        w = gui.get("window_width", 1600)
        h = gui.get("window_height", 900)
        self.title("Windows Service & Process Monitoring Agent  |  v1.0.0")
        self.geometry(f"{w}x{h}")
        self.minsize(1200, 700)
        self.configure(bg=BG_DARK)
        try:
            self.state("zoomed")
        except Exception:
            pass
        self._refresh_ms = gui.get("refresh_rate_ms", 5000)

    def _apply_theme(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab",
            background=BG_CARD, foreground=TEXT_GREY,
            font=("Consolas", 9, "bold"), padding=[14, 6])
        style.map("TNotebook.Tab",
            background=[("selected", BG_HEADER)],
            foreground=[("selected", ACCENT)])
        style.configure("TScrollbar", background=BG_HEADER,
            troughcolor=BG_DARK, arrowcolor=TEXT_GREY)
        style.configure("Horizontal.TProgressbar",
            troughcolor=BG_CARD, background=ACCENT, thickness=14)
        style.configure("Red.Horizontal.TProgressbar",
            troughcolor=BG_CARD, background=C_CRIT, thickness=14)

    # ------------------------------------------------------------------
    # Top Bar
    # ------------------------------------------------------------------

    def _build_topbar(self) -> None:
        bar = tk.Frame(self, bg=BG_HEADER, height=52)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        # Logo / title
        tk.Label(bar, text="🛡  WSPM Agent", bg=BG_HEADER,
                 fg=ACCENT, font=("Consolas", 14, "bold")).pack(side=tk.LEFT, padx=16)

        # Right-side controls
        right = tk.Frame(bar, bg=BG_HEADER)
        right.pack(side=tk.RIGHT, padx=10)

        styled_button(right, "⚡ Quick Scan",  self._on_quick_scan,  bg="#1f6feb").pack(side=tk.LEFT, padx=3)
        styled_button(right, "🔍 Deep Scan",   self._on_deep_scan,   bg="#388bfd").pack(side=tk.LEFT, padx=3)
        styled_button(right, "⏸ Pause",        self._on_pause,       bg="#484f58").pack(side=tk.LEFT, padx=3)
        styled_button(right, "▶ Resume",        self._on_resume,      bg=C_GREEN).pack(side=tk.LEFT, padx=3)
        styled_button(right, "📄 Report",       self._on_generate_report, bg=ACCENT2).pack(side=tk.LEFT, padx=3)
        styled_button(right, "⚙ Settings",     self._open_settings,  bg="#484f58").pack(side=tk.LEFT, padx=3)

        # Auto-refresh toggle
        self._auto_var = tk.BooleanVar(value=True)
        tk.Checkbutton(right, text="Auto Refresh", variable=self._auto_var,
                       bg=BG_HEADER, fg=TEXT_WHITE, selectcolor=BG_CARD,
                       font=("Consolas", 8), activebackground=BG_HEADER,
                       command=self._toggle_auto_refresh).pack(side=tk.LEFT, padx=6)

    # ------------------------------------------------------------------
    # Stat Cards
    # ------------------------------------------------------------------

    def _build_stat_cards(self) -> None:
        row = tk.Frame(self, bg=BG_DARK)
        row.pack(fill=tk.X, padx=10, pady=(6, 0))

        cards_cfg = [
            ("Processes",  ACCENT),
            ("Services",   "#7c3aed"),
            ("🚨 Critical", C_CRIT),
            ("⬆ High",     C_HIGH),
            ("⚠ Medium",   C_MED),
            ("ℹ Low",      C_LOW),
            ("CPU %",      C_GREEN),
            ("RAM %",      "#ff79c6"),
        ]
        self._card_labels = {}
        for title, color in cards_cfg:
            frame, val_lbl = card_frame(row, title)
            val_lbl.configure(fg=color)
            frame.pack(side=tk.LEFT, padx=5, pady=4)
            self._card_labels[title] = val_lbl

        # CPU / RAM progress bars
        gauge_frame = tk.Frame(self, bg=BG_DARK)
        gauge_frame.pack(fill=tk.X, padx=16, pady=(0, 4))

        tk.Label(gauge_frame, text="CPU:", bg=BG_DARK, fg=TEXT_GREY,
                 font=("Consolas", 8)).pack(side=tk.LEFT)
        self._cpu_bar = ttk.Progressbar(gauge_frame, style="Horizontal.TProgressbar",
                                         orient=tk.HORIZONTAL, length=200, maximum=100)
        self._cpu_bar.pack(side=tk.LEFT, padx=(4, 20))

        tk.Label(gauge_frame, text="RAM:", bg=BG_DARK, fg=TEXT_GREY,
                 font=("Consolas", 8)).pack(side=tk.LEFT)
        self._ram_bar = ttk.Progressbar(gauge_frame, style="Red.Horizontal.TProgressbar",
                                         orient=tk.HORIZONTAL, length=200, maximum=100)
        self._ram_bar.pack(side=tk.LEFT, padx=4)

        # Scan mode indicator
        tk.Label(gauge_frame, textvariable=self._scan_mode_var, bg=BG_DARK,
                 fg=TEXT_GREY, font=("Consolas", 8)).pack(side=tk.RIGHT, padx=10)

    # ------------------------------------------------------------------
    # Notebook Tabs
    # ------------------------------------------------------------------

    def _build_notebook(self) -> None:
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        self._tab_procs    = self._build_process_tab()
        self._tab_services = self._build_service_tab()
        self._tab_alerts   = self._build_alerts_tab()
        self._tab_startup  = self._build_startup_tab()
        self._tab_tree     = self._build_tree_tab()
        self._tab_history  = self._build_history_tab()
        self._tab_reports  = self._build_reports_tab()

        tabs = [
            (self._tab_procs,    "⚙ Processes"),
            (self._tab_services, "🔧 Services"),
            (self._tab_alerts,   "🚨 Alerts"),
            (self._tab_startup,  "🚀 Startup"),
            (self._tab_tree,     "🌳 Process Tree"),
            (self._tab_history,  "📜 History"),
            (self._tab_reports,  "📊 Reports"),
        ]
        for frame, label in tabs:
            self._nb.add(frame, text=label)

    # ------------------------------------------------------------------
    # Process Tab
    # ------------------------------------------------------------------

    def _build_process_tab(self) -> tk.Frame:
        frame = styled_frame(self._nb if hasattr(self, '_nb') else self, bg=BG_DARK)

        toolbar = styled_frame(frame, bg=BG_DARK)
        toolbar.pack(fill=tk.X, padx=6, pady=4)
        styled_label(toolbar, "Search:", bg=BG_DARK).pack(side=tk.LEFT)
        e = styled_entry(toolbar, width=24, textvariable=self._search_var_proc)
        e.pack(side=tk.LEFT, padx=(4, 12))
        styled_button(toolbar, "🔎 Filter", self._filter_processes, bg="#1f6feb").pack(side=tk.LEFT)
        styled_button(toolbar, "↺ Refresh", self._refresh_processes, bg="#484f58").pack(side=tk.LEFT, padx=4)
        styled_button(toolbar, "📋 Export CSV", self._export_processes_csv, bg=ACCENT2).pack(side=tk.RIGHT)

        cols = ["PID", "Name", "Parent", "Status", "CPU%", "RAM(MB)",
                "User", "Path", "Signed", "Flags"]
        self._proc_tv = make_treeview(frame, cols, heights=22)
        self._proc_tv.column("PID",    width=55,  stretch=False)
        self._proc_tv.column("Name",   width=140)
        self._proc_tv.column("Parent", width=100)
        self._proc_tv.column("Status", width=70,  stretch=False)
        self._proc_tv.column("CPU%",   width=55,  stretch=False)
        self._proc_tv.column("RAM(MB)",width=70,  stretch=False)
        self._proc_tv.column("User",   width=110)
        self._proc_tv.column("Path",   width=260)
        self._proc_tv.column("Signed", width=60,  stretch=False)
        self._proc_tv.column("Flags",  width=180)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._proc_tv.yview)
        self._proc_tv.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._proc_tv.pack(fill=tk.BOTH, expand=True, padx=4)
        self._proc_tv.tag_configure("suspicious", background="#2d1515", foreground=C_HIGH)
        self._proc_tv.tag_configure("critical",   background="#3d0a0a", foreground=C_CRIT)
        return frame

    # ------------------------------------------------------------------
    # Services Tab
    # ------------------------------------------------------------------

    def _build_service_tab(self) -> tk.Frame:
        frame = styled_frame(self, bg=BG_DARK)

        toolbar = styled_frame(frame, bg=BG_DARK)
        toolbar.pack(fill=tk.X, padx=6, pady=4)
        styled_label(toolbar, "Search:", bg=BG_DARK).pack(side=tk.LEFT)
        e = styled_entry(toolbar, width=24, textvariable=self._search_var_svc)
        e.pack(side=tk.LEFT, padx=(4, 12))
        styled_button(toolbar, "🔎 Filter", self._filter_services, bg="#1f6feb").pack(side=tk.LEFT)
        styled_button(toolbar, "↺ Refresh", self._refresh_services, bg="#484f58").pack(side=tk.LEFT, padx=4)
        styled_button(toolbar, "📋 Export CSV", self._export_services_csv, bg=ACCENT2).pack(side=tk.RIGHT)

        cols = ["Name", "Display Name", "Status", "Start Type", "Account", "Path", "Flags"]
        self._svc_tv = make_treeview(frame, cols, heights=22)
        self._svc_tv.column("Name",         width=140)
        self._svc_tv.column("Display Name", width=200)
        self._svc_tv.column("Status",       width=80,  stretch=False)
        self._svc_tv.column("Start Type",   width=90,  stretch=False)
        self._svc_tv.column("Account",      width=140)
        self._svc_tv.column("Path",         width=260)
        self._svc_tv.column("Flags",        width=180)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._svc_tv.yview)
        self._svc_tv.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._svc_tv.pack(fill=tk.BOTH, expand=True, padx=4)
        self._svc_tv.tag_configure("suspicious", background="#2d1515", foreground=C_HIGH)
        return frame

    # ------------------------------------------------------------------
    # Alerts Tab
    # ------------------------------------------------------------------

    def _build_alerts_tab(self) -> tk.Frame:
        frame = styled_frame(self, bg=BG_DARK)

        toolbar = styled_frame(frame, bg=BG_DARK)
        toolbar.pack(fill=tk.X, padx=6, pady=4)

        styled_label(toolbar, "Search:", bg=BG_DARK).pack(side=tk.LEFT)
        e = styled_entry(toolbar, width=22, textvariable=self._search_var_alert)
        e.pack(side=tk.LEFT, padx=(4, 10))

        styled_label(toolbar, "Severity:", bg=BG_DARK).pack(side=tk.LEFT)
        self._sev_combo = ttk.Combobox(toolbar, values=["All", "Critical", "High", "Medium", "Low"],
                                        width=10, state="readonly",
                                        font=("Consolas", 9))
        self._sev_combo.set("All")
        self._sev_combo.pack(side=tk.LEFT, padx=(4, 10))
        self._sev_combo.bind("<<ComboboxSelected>>", lambda e: self._filter_alerts())

        styled_button(toolbar, "🔎 Filter",      self._filter_alerts,      bg="#1f6feb").pack(side=tk.LEFT)
        styled_button(toolbar, "🗑 Clear",        self._clear_alerts,       bg="#484f58").pack(side=tk.LEFT, padx=4)
        styled_button(toolbar, "📋 Export",       self._export_alerts_excel, bg=ACCENT2).pack(side=tk.RIGHT)

        cols = ["Time", "Severity", "Category", "Process", "PID", "MITRE", "Reason", "Recommendation"]
        self._alert_tv = make_treeview(frame, cols, heights=22)
        self._alert_tv.column("Time",           width=130, stretch=False)
        self._alert_tv.column("Severity",       width=70,  stretch=False)
        self._alert_tv.column("Category",       width=160)
        self._alert_tv.column("Process",        width=130)
        self._alert_tv.column("PID",            width=55,  stretch=False)
        self._alert_tv.column("MITRE",          width=80,  stretch=False)
        self._alert_tv.column("Reason",         width=260)
        self._alert_tv.column("Recommendation", width=220)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._alert_tv.yview)
        self._alert_tv.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._alert_tv.pack(fill=tk.BOTH, expand=True, padx=4)

        for sev, color in SEVERITY_BG.items():
            self._alert_tv.tag_configure(sev.lower(), foreground=color)
        return frame

    # ------------------------------------------------------------------
    # Startup Tab
    # ------------------------------------------------------------------

    def _build_startup_tab(self) -> tk.Frame:
        frame = styled_frame(self, bg=BG_DARK)

        toolbar = styled_frame(frame, bg=BG_DARK)
        toolbar.pack(fill=tk.X, padx=6, pady=4)
        styled_button(toolbar, "↺ Refresh Startup", self._refresh_startup, bg="#484f58").pack(side=tk.LEFT)
        styled_button(toolbar, "📋 Export CSV", self._export_startup_csv, bg=ACCENT2).pack(side=tk.RIGHT)

        cols = ["Name", "Source", "Location", "Command", "New?", "Suspicious?", "Flags"]
        self._startup_tv = make_treeview(frame, cols, heights=22)
        self._startup_tv.column("Name",       width=160)
        self._startup_tv.column("Source",     width=110, stretch=False)
        self._startup_tv.column("Location",   width=200)
        self._startup_tv.column("Command",    width=280)
        self._startup_tv.column("New?",       width=45,  stretch=False)
        self._startup_tv.column("Suspicious?",width=70,  stretch=False)
        self._startup_tv.column("Flags",      width=180)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._startup_tv.yview)
        self._startup_tv.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._startup_tv.pack(fill=tk.BOTH, expand=True, padx=4)
        self._startup_tv.tag_configure("new_entry",    background="#1a2a10", foreground=C_GREEN)
        self._startup_tv.tag_configure("suspicious",   background="#2d1515", foreground=C_HIGH)
        return frame

    # ------------------------------------------------------------------
    # Process Tree Tab
    # ------------------------------------------------------------------

    def _build_tree_tab(self) -> tk.Frame:
        frame = styled_frame(self, bg=BG_DARK)

        toolbar = styled_frame(frame, bg=BG_DARK)
        toolbar.pack(fill=tk.X, padx=6, pady=4)
        styled_button(toolbar, "↺ Rebuild Tree", self._refresh_tree, bg="#484f58").pack(side=tk.LEFT)

        self._tree_text = tk.Text(frame, bg=BG_TABLE, fg=TEXT_WHITE,
                                   font=("Consolas", 9), state=tk.DISABLED,
                                   wrap=tk.NONE, relief=tk.FLAT)
        sb_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._tree_text.yview)
        sb_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self._tree_text.xview)
        self._tree_text.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        self._tree_text.pack(fill=tk.BOTH, expand=True, padx=4)
        return frame

    # ------------------------------------------------------------------
    # History Tab
    # ------------------------------------------------------------------

    def _build_history_tab(self) -> tk.Frame:
        frame = styled_frame(self, bg=BG_DARK)

        toolbar = styled_frame(frame, bg=BG_DARK)
        toolbar.pack(fill=tk.X, padx=6, pady=4)
        styled_button(toolbar, "↺ Load History", self._load_history, bg="#484f58").pack(side=tk.LEFT)
        styled_button(toolbar, "📋 Export", self._export_history_csv, bg=ACCENT2).pack(side=tk.RIGHT)

        cols = ["Time", "Severity", "Category", "Process", "PID", "Reason"]
        self._hist_tv = make_treeview(frame, cols, heights=24)
        self._hist_tv.column("Time",     width=140, stretch=False)
        self._hist_tv.column("Severity", width=70,  stretch=False)
        self._hist_tv.column("Category", width=160)
        self._hist_tv.column("Process",  width=130)
        self._hist_tv.column("PID",      width=55,  stretch=False)
        self._hist_tv.column("Reason",   width=350)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._hist_tv.yview)
        self._hist_tv.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._hist_tv.pack(fill=tk.BOTH, expand=True, padx=4)
        for sev, color in SEVERITY_BG.items():
            self._hist_tv.tag_configure(sev.lower(), foreground=color)
        return frame

    # ------------------------------------------------------------------
    # Reports Tab
    # ------------------------------------------------------------------

    def _build_reports_tab(self) -> tk.Frame:
        frame = styled_frame(self, bg=BG_DARK)

        tk.Label(frame, text="Report Generation", bg=BG_DARK, fg=ACCENT,
                 font=("Consolas", 14, "bold")).pack(pady=(20, 4))
        tk.Label(frame, text="Generate professional security reports in multiple formats",
                 bg=BG_DARK, fg=TEXT_GREY, font=("Consolas", 9)).pack(pady=(0, 20))

        btn_row = styled_frame(frame, bg=BG_DARK)
        btn_row.pack(pady=8)

        btns = [
            ("📄 PDF Report",   self._gen_pdf,   "#dc2626"),
            ("📊 Excel Report", self._gen_excel,  "#16a34a"),
            ("📋 CSV Report",   self._gen_csv,    "#2563eb"),
            ("📝 JSON Report",  self._gen_json,   ACCENT2),
            ("📃 TXT Report",   self._gen_txt,    "#484f58"),
            ("🚀 All Formats",  self._gen_all,    ACCENT),
        ]
        for label, cmd, color in btns:
            styled_button(btn_row, label, cmd, bg=color,
                          font=("Consolas", 10, "bold")).pack(side=tk.LEFT, padx=8, ipady=6)

        self._report_log = tk.Text(frame, bg=BG_TABLE, fg=TEXT_WHITE,
                                    font=("Consolas", 9), height=12,
                                    state=tk.DISABLED, relief=tk.FLAT)
        self._report_log.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        return frame

    def _log_report(self, msg: str) -> None:
        """Append a line to the report log widget."""
        self._report_log.configure(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self._report_log.insert(tk.END, f"[{ts}] {msg}\n")
        self._report_log.see(tk.END)
        self._report_log.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Status Bar
    # ------------------------------------------------------------------

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self, bg=BG_HEADER, height=24)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        tk.Label(bar, textvariable=self._status_var, bg=BG_HEADER,
                 fg=C_GREEN, font=("Consolas", 8)).pack(side=tk.LEFT, padx=10)
        self._time_lbl = tk.Label(bar, text="", bg=BG_HEADER,
                                   fg=TEXT_GREY, font=("Consolas", 8))
        self._time_lbl.pack(side=tk.RIGHT, padx=10)
        self._update_clock()

    def _update_clock(self) -> None:
        self._time_lbl.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._update_clock)

    # ------------------------------------------------------------------
    # Data Population Helpers
    # ------------------------------------------------------------------

    def _populate_processes(self, processes: list) -> None:
        """Fill the process treeview from a list of ProcessInfo dicts."""
        query = self._search_var_proc.get().lower()
        for item in self._proc_tv.get_children():
            self._proc_tv.delete(item)
        for p in processes:
            name = str(p.get("name", ""))
            if query and query not in name.lower() and query not in str(p.get("pid", "")):
                continue
            flags = p.get("flags", [])
            if isinstance(flags, str):
                try:
                    flags = json.loads(flags)
                except Exception:
                    flags = [flags]
            flags_str = ", ".join(flags) if flags else ""
            is_crit = any("BLACKLISTED" in f for f in flags)
            tag = "critical" if is_crit else ("suspicious" if p.get("is_suspicious") else "")
            self._proc_tv.insert("", tk.END, tags=(tag,), values=(
                p.get("pid", ""),
                truncate(name, 22),
                truncate(str(p.get("parent_name", "")), 18),
                p.get("status", ""),
                f"{p.get('cpu_percent', 0):.1f}",
                f"{p.get('memory_mb', 0):.1f}",
                truncate(str(p.get("username", "")), 18),
                truncate(str(p.get("exe_path", "")), 40),
                "✓" if p.get("is_signed") else "✗",
                truncate(flags_str, 30),
            ))

    def _populate_services(self, services: list) -> None:
        """Fill the service treeview."""
        query = self._search_var_svc.get().lower()
        for item in self._svc_tv.get_children():
            self._svc_tv.delete(item)
        for s in services:
            name = str(s.get("name", ""))
            if query and query not in name.lower() and query not in str(s.get("display_name","")).lower():
                continue
            flags = s.get("flags", [])
            if isinstance(flags, str):
                try:
                    flags = json.loads(flags)
                except Exception:
                    flags = [flags]
            tag = "suspicious" if s.get("is_suspicious") else ""
            self._svc_tv.insert("", tk.END, tags=(tag,), values=(
                truncate(name, 22),
                truncate(str(s.get("display_name", "")), 30),
                s.get("status", ""),
                s.get("start_type", ""),
                truncate(str(s.get("account", "")), 20),
                truncate(str(s.get("exe_path", "")), 40),
                truncate(", ".join(flags), 30),
            ))

    def _populate_alerts(self, alerts: list) -> None:
        """Fill the alert treeview, colour-coded by severity."""
        query  = self._search_var_alert.get().lower()
        sev_f  = self._sev_combo.get() if hasattr(self, "_sev_combo") else "All"
        for item in self._alert_tv.get_children():
            self._alert_tv.delete(item)
        for a in alerts:
            sev  = str(a.get("severity", ""))
            proc = str(a.get("process_name", ""))
            reason = str(a.get("reason", ""))
            if sev_f != "All" and sev != sev_f:
                continue
            if query and query not in proc.lower() and query not in reason.lower():
                continue
            tag = sev.lower()
            self._alert_tv.insert("", tk.END, tags=(tag,), values=(
                str(a.get("timestamp", ""))[:19],
                sev,
                truncate(str(a.get("category", "")), 22),
                truncate(proc, 20),
                a.get("pid", ""),
                a.get("mitre_technique", ""),
                truncate(reason, 55),
                truncate(str(a.get("recommendation", "")), 35),
            ))

    def _populate_startup(self, entries: list) -> None:
        """Fill the startup treeview."""
        for item in self._startup_tv.get_children():
            self._startup_tv.delete(item)
        for e in entries:
            flags = e.get("flags", [])
            if isinstance(flags, str):
                try:
                    flags = json.loads(flags)
                except Exception:
                    flags = [flags]
            is_new = bool(e.get("is_new"))
            is_sus = bool(e.get("is_suspicious"))
            tag = "suspicious" if is_sus else ("new_entry" if is_new else "")
            self._startup_tv.insert("", tk.END, tags=(tag,), values=(
                truncate(str(e.get("name", "")), 25),
                e.get("source", ""),
                truncate(str(e.get("location", "")), 30),
                truncate(str(e.get("command", "")), 40),
                "YES" if is_new else "no",
                "YES" if is_sus else "no",
                truncate(", ".join(flags), 30),
            ))

    # ------------------------------------------------------------------
    # Refresh / Controller Bridge
    # ------------------------------------------------------------------

    def _start_refresh_loop(self) -> None:
        """Schedule the periodic auto-refresh cycle."""
        self.after(self._refresh_ms, self._auto_refresh_tick)

    def _auto_refresh_tick(self) -> None:
        """Called periodically to refresh all tabs if auto-refresh is on."""
        if self._auto_var.get():
            self._do_refresh()
        self.after(self._refresh_ms, self._auto_refresh_tick)

    def _do_refresh(self) -> None:
        """Pull latest data from the controller and update all widgets."""
        if not self._ctrl:
            self._update_cards(0, 0, {}, 0, 0)
            return
        try:
            procs    = [p.to_dict() for p in self._ctrl.process_monitor.get_current_processes()]
            svcs     = [s.to_dict() for s in self._ctrl.service_monitor.get_current_services()]
            startup  = [e.to_dict() for e in self._ctrl.startup_auditor.get_current_entries()]
            alerts   = [a.to_dict() for a in self._ctrl.alert_manager.get_alerts(limit=300)]
            counts   = self._ctrl.alert_manager.get_alert_counts()
            cpu      = psutil.cpu_percent()
            ram      = psutil.virtual_memory().percent

            self._populate_processes(procs)
            self._populate_services(svcs)
            self._populate_startup(startup)
            self._populate_alerts(alerts)
            self._update_cards(len(procs), len(svcs), counts, cpu, ram)
            self._status_var.set(f"● Monitoring  |  Last refresh: {datetime.now().strftime('%H:%M:%S')}")
        except Exception as ex:
            logger.error(f"Dashboard refresh error: {ex}")

    def _update_cards(self, proc_count, svc_count, counts, cpu, ram) -> None:
        """Update all stat card values and progress bars."""
        mapping = {
            "Processes":  str(proc_count),
            "Services":   str(svc_count),
            "🚨 Critical": str(counts.get("Critical", 0)),
            "⬆ High":     str(counts.get("High", 0)),
            "⚠ Medium":   str(counts.get("Medium", 0)),
            "ℹ Low":      str(counts.get("Low", 0)),
            "CPU %":      f"{cpu:.1f}",
            "RAM %":      f"{ram:.1f}",
        }
        for key, val in mapping.items():
            if key in self._card_labels:
                self._card_labels[key].configure(text=val)

        self._cpu_bar["value"] = cpu
        self._ram_bar["value"] = ram
        style = ttk.Style()
        style.configure("Horizontal.TProgressbar",
            background=C_CRIT if cpu > 80 else (C_MED if cpu > 60 else C_GREEN))

    # ------------------------------------------------------------------
    # Toolbar / Button Actions
    # ------------------------------------------------------------------

    def _on_quick_scan(self) -> None:
        self._scan_mode_var.set("⚡ Quick Scan Running...")
        self._status_var.set("● Quick Scan...")
        if self._ctrl:
            threading.Thread(target=self._ctrl.run_quick_scan, daemon=True).start()
        self.after(2000, lambda: self._scan_mode_var.set("Quick Scan"))

    def _on_deep_scan(self) -> None:
        self._scan_mode_var.set("🔍 Deep Scan Running...")
        self._status_var.set("● Deep Scan...")
        if self._ctrl:
            threading.Thread(target=self._ctrl.run_deep_scan, daemon=True).start()
        self.after(5000, lambda: self._scan_mode_var.set("Deep Scan"))

    def _on_pause(self) -> None:
        if self._ctrl:
            self._ctrl.scheduler.pause()
        self._status_var.set("⏸ Monitoring Paused")

    def _on_resume(self) -> None:
        if self._ctrl:
            self._ctrl.scheduler.resume()
        self._status_var.set("▶ Monitoring Resumed")

    def _on_generate_report(self) -> None:
        self._nb.select(6)   # Switch to Reports tab
        self._gen_all()

    def _toggle_auto_refresh(self) -> None:
        self._auto_refresh = self._auto_var.get()

    # tab-specific refreshes / filters
    def _refresh_processes(self): self._do_refresh()
    def _filter_processes(self):  self._refresh_processes()
    def _refresh_services(self):  self._do_refresh()
    def _filter_services(self):   self._refresh_services()
    def _filter_alerts(self):     self._do_refresh()
    def _clear_alerts(self):
        if self._ctrl:
            self._ctrl.alert_manager.clear_alerts()
        self._do_refresh()
    def _refresh_startup(self):   self._do_refresh()
    def _load_history(self):
        if not self._ctrl: return
        rows = self._ctrl.db_manager.get_all_alerts(limit=500)
        for item in self._hist_tv.get_children():
            self._hist_tv.delete(item)
        for a in rows:
            sev = str(a.get("severity",""))
            self._hist_tv.insert("", tk.END, tags=(sev.lower(),), values=(
                str(a.get("timestamp",""))[:19],
                sev,
                truncate(str(a.get("category","")),22),
                truncate(str(a.get("process_name","")),18),
                a.get("pid",""),
                truncate(str(a.get("reason","")),55),
            ))

    def _refresh_tree(self):
        if not self._ctrl: return
        text = self._ctrl.process_tree.get_tree_as_text()
        self._tree_text.configure(state=tk.NORMAL)
        self._tree_text.delete("1.0", tk.END)
        self._tree_text.insert(tk.END, text)
        self._tree_text.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Export Actions
    # ------------------------------------------------------------------

    def _export_processes_csv(self) -> None:
        if not self._ctrl: return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV","*.csv")])
        if path:
            try:
                import csv as _csv
                procs = [p.to_dict() for p in self._ctrl.process_monitor.get_current_processes()]
                if procs:
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        w = _csv.DictWriter(f, fieldnames=procs[0].keys())
                        w.writeheader(); w.writerows(procs)
                messagebox.showinfo("Export", f"Processes exported:\n{path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _export_services_csv(self) -> None:
        if not self._ctrl: return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV","*.csv")])
        if path:
            try:
                import csv as _csv
                svcs = [s.to_dict() for s in self._ctrl.service_monitor.get_current_services()]
                if svcs:
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        w = _csv.DictWriter(f, fieldnames=svcs[0].keys())
                        w.writeheader(); w.writerows(svcs)
                messagebox.showinfo("Export", f"Services exported:\n{path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _export_alerts_excel(self) -> None:
        if not self._ctrl: return
        path = filedialog.asksaveasfilename(defaultextension=".xlsx",
                                             filetypes=[("Excel","*.xlsx")])
        if path:
            try:
                alerts = [a.to_dict() for a in self._ctrl.alert_manager.get_alerts(limit=1000)]
                import pandas as pd
                pd.DataFrame(alerts).to_excel(path, index=False, engine="openpyxl")
                messagebox.showinfo("Export", f"Alerts exported:\n{path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _export_startup_csv(self) -> None:
        if not self._ctrl: return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV","*.csv")])
        if path:
            try:
                import csv as _csv
                entries = [e.to_dict() for e in self._ctrl.startup_auditor.get_current_entries()]
                if entries:
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        w = _csv.DictWriter(f, fieldnames=entries[0].keys())
                        w.writeheader(); w.writerows(entries)
                messagebox.showinfo("Export", f"Startup entries exported:\n{path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _export_history_csv(self) -> None:
        if not self._ctrl: return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV","*.csv")])
        if path:
            try:
                import csv as _csv
                rows = self._ctrl.db_manager.get_all_alerts(limit=5000)
                if rows:
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        w = _csv.DictWriter(f, fieldnames=rows[0].keys())
                        w.writeheader(); w.writerows(rows)
                messagebox.showinfo("Export", f"History exported:\n{path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    # ------------------------------------------------------------------
    # Report Generation (Reports Tab buttons)
    # ------------------------------------------------------------------

    def _run_report(self, fn: Callable) -> None:
        def task():
            path = fn()
            msg = f"✓ Report saved: {path}" if path else "✗ Report generation failed."
            self.after(0, lambda: self._log_report(msg))
        threading.Thread(target=task, daemon=True).start()

    def _gen_pdf(self):
        if self._ctrl: self._run_report(self._ctrl.report_generator.generate_pdf_report)
    def _gen_excel(self):
        if self._ctrl: self._run_report(self._ctrl.report_generator.generate_excel_report)
    def _gen_csv(self):
        if self._ctrl: self._run_report(self._ctrl.report_generator.generate_csv_report)
    def _gen_json(self):
        if self._ctrl: self._run_report(self._ctrl.report_generator.generate_json_report)
    def _gen_txt(self):
        if self._ctrl: self._run_report(self._ctrl.report_generator.generate_txt_report)
    def _gen_all(self):
        if not self._ctrl: return
        self._log_report("Generating all report formats...")
        def task():
            results = self._ctrl.report_generator.generate_all_reports()
            for fmt, path in results.items():
                msg = f"✓ {fmt.upper()}: {path}" if path else f"✗ {fmt.upper()} failed"
                self.after(0, lambda m=msg: self._log_report(m))
        threading.Thread(target=task, daemon=True).start()

    # ------------------------------------------------------------------
    # Settings Panel
    # ------------------------------------------------------------------

    def _open_settings(self) -> None:
        """Open the Settings / Configuration panel as a Toplevel window."""
        win = tk.Toplevel(self)
        win.title("Settings")
        win.geometry("780x560")
        win.configure(bg=BG_DARK)
        win.grab_set()

        nb = ttk.Notebook(win)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ── General settings ──────────────────────────────────────────
        gen_frame = styled_frame(win, bg=BG_DARK)
        nb.add(gen_frame, text="⚙ General")

        settings = load_json_config(SETTINGS_PATH)
        mon = settings.get("monitoring", {})

        fields = [
            ("Scan Interval (sec)",      str(mon.get("scan_interval_seconds", 5))),
            ("Deep Scan Interval (sec)", str(mon.get("deep_scan_interval_seconds", 30))),
            ("Max Alerts",               str(settings.get("monitoring", {}).get("max_alerts", 10000))),
            ("Log Retention Days",       str(mon.get("log_retention_days", 30))),
        ]
        entries = {}
        for i, (label, default) in enumerate(fields):
            styled_label(gen_frame, label, bg=BG_DARK).grid(row=i, column=0, sticky="w", padx=16, pady=6)
            e = styled_entry(gen_frame, width=18)
            e.insert(0, default)
            e.grid(row=i, column=1, padx=8, pady=6)
            entries[label] = e

        def save_general():
            try:
                cfg = load_json_config(SETTINGS_PATH)
                cfg.setdefault("monitoring", {})
                cfg["monitoring"]["scan_interval_seconds"]      = int(entries["Scan Interval (sec)"].get())
                cfg["monitoring"]["deep_scan_interval_seconds"] = int(entries["Deep Scan Interval (sec)"].get())
                cfg["monitoring"]["max_alerts"]                 = int(entries["Max Alerts"].get())
                cfg["monitoring"]["log_retention_days"]         = int(entries["Log Retention Days"].get())
                save_json_config(SETTINGS_PATH, cfg)
                if self._ctrl:
                    self._ctrl.scheduler.update_intervals(
                        cfg["monitoring"]["scan_interval_seconds"],
                        cfg["monitoring"]["deep_scan_interval_seconds"],
                    )
                    self._refresh_ms = cfg["monitoring"]["scan_interval_seconds"] * 1000
                messagebox.showinfo("Settings", "General settings saved.")
            except Exception as ex:
                messagebox.showerror("Settings Error", str(ex))

        styled_button(gen_frame, "💾 Save", save_general, bg=C_GREEN).grid(row=len(fields), column=0, columnspan=2, pady=14)

        # ── Whitelist Editor ──────────────────────────────────────────
        wl_frame = styled_frame(win, bg=BG_DARK)
        nb.add(wl_frame, text="✅ Whitelist")
        self._build_list_editor(wl_frame, WHITELIST_PATH, "processes", "names", "Whitelist")

        # ── Blacklist Editor ──────────────────────────────────────────
        bl_frame = styled_frame(win, bg=BG_DARK)
        nb.add(bl_frame, text="🚫 Blacklist")
        self._build_list_editor(bl_frame, BLACKLIST_PATH, "processes", "names", "Blacklist")

        # ── Detection Rules Viewer ────────────────────────────────────
        rules_frame = styled_frame(win, bg=BG_DARK)
        nb.add(rules_frame, text="📋 Rules")
        rules_text = tk.Text(rules_frame, bg=BG_TABLE, fg=TEXT_WHITE,
                             font=("Consolas", 8), relief=tk.FLAT)
        rules_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        try:
            rules_data = load_json_config("config/detection_rules.json")
            rules_text.insert(tk.END, json.dumps(rules_data, indent=2))
        except Exception:
            rules_text.insert(tk.END, "Could not load detection rules.")
        rules_text.configure(state=tk.DISABLED)

        # ── About ─────────────────────────────────────────────────────
        about_frame = styled_frame(win, bg=BG_DARK)
        nb.add(about_frame, text="ℹ About")
        about_lines = [
            ("Windows Service & Process Monitoring Agent", ("Consolas", 14, "bold"), ACCENT),
            ("Version 1.0.0", ("Consolas", 10), TEXT_GREY),
            ("", ("Consolas", 9), TEXT_WHITE),
            ("A professional cybersecurity monitoring tool for Blue Team defenders.", ("Consolas", 9), TEXT_WHITE),
            ("Detects malware, persistence, privilege escalation, and rogue services.", ("Consolas", 9), TEXT_WHITE),
            ("", ("Consolas", 9), TEXT_WHITE),
            ("Built with Python 3.12 · psutil · tkinter · SQLite · ReportLab", ("Consolas", 8), TEXT_GREY),
        ]
        for text, font, color in about_lines:
            tk.Label(about_frame, text=text, bg=BG_DARK, fg=color, font=font).pack(pady=3)

    def _build_list_editor(self, parent: tk.Frame, cfg_path: str,
                           section: str, key: str, title: str) -> None:
        """Build a list editor widget (whitelist/blacklist) inside a settings tab."""
        tk.Label(parent, text=f"{title} Editor", bg=BG_DARK, fg=ACCENT,
                 font=("Consolas", 11, "bold")).pack(pady=(10, 4))

        listbox = tk.Listbox(parent, bg=BG_TABLE, fg=TEXT_WHITE,
                             font=("Consolas", 9), selectbackground=ACCENT2,
                             relief=tk.FLAT, height=14)
        sb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=listbox.yview)
        listbox.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 4))
        listbox.pack(fill=tk.BOTH, expand=True, padx=(10, 0), pady=4)

        def reload_list():
            listbox.delete(0, tk.END)
            data = load_json_config(cfg_path)
            for item in data.get(section, {}).get(key, []):
                listbox.insert(tk.END, item)

        reload_list()

        ctrl_row = styled_frame(parent, bg=BG_DARK)
        ctrl_row.pack(pady=6)
        entry = styled_entry(ctrl_row, width=28)
        entry.pack(side=tk.LEFT, padx=6)

        def add_item():
            val = entry.get().strip()
            if not val:
                return
            data = load_json_config(cfg_path)
            names: list = data.setdefault(section, {}).setdefault(key, [])
            if val not in names:
                names.append(val)
                save_json_config(cfg_path, data)
                reload_list()
                if self._ctrl:
                    self._ctrl.reload_all_configs()
            entry.delete(0, tk.END)

        def remove_item():
            sel = listbox.curselection()
            if not sel:
                return
            val = listbox.get(sel[0])
            data = load_json_config(cfg_path)
            names: list = data.get(section, {}).get(key, [])
            if val in names:
                names.remove(val)
                save_json_config(cfg_path, data)
                reload_list()
                if self._ctrl:
                    self._ctrl.reload_all_configs()

        styled_button(ctrl_row, "➕ Add",    add_item,    bg=C_GREEN).pack(side=tk.LEFT, padx=4)
        styled_button(ctrl_row, "🗑 Remove", remove_item, bg=C_CRIT).pack(side=tk.LEFT, padx=4)

    # ------------------------------------------------------------------
    # Alert Notification
    # ------------------------------------------------------------------

    def notify_alert(self, alert) -> None:
        """
        Display a notification popup for a new alert.
        Safe to call from non-GUI threads via self.after().

        Args:
            alert: Alert instance with severity and reason attributes.
        """
        if not self._popup_enabled:
            return
        settings = load_json_config(SETTINGS_PATH)
        if not settings.get("alerts", {}).get("popup_notifications", True):
            return

        severity = getattr(alert, "severity", "Low")
        reason   = getattr(alert, "reason", "Alert triggered.")

        # Only popup for Critical and High to avoid flooding
        if severity not in ("Critical", "High"):
            return

        def _show():
            try:
                NotificationPopup(self, severity, reason, duration_ms=6000)
            except Exception as e:
                logger.debug(f"Popup error: {e}")

        self.after(0, _show)
