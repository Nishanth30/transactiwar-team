#!/usr/bin/env python3
"""
TransactiWar IP Firewall Manager — GUI
Cross-platform tkinter GUI for managing the IP blocklist.

Usage:
    python firewall_gui.py

Shares profiles with the CLI tool (~/.transactiwar/firewall_profiles.json).
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import threading
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

# ─── Config (shared with CLI) ──────────────────────────────────
CONFIG_DIR  = Path.home() / ".transactiwar"
CONFIG_FILE = CONFIG_DIR / "firewall_profiles.json"

IST = timezone(timedelta(hours=5, minutes=30))

DEFAULT_PROFILE = {
    "name": "azure",
    "host": "20.219.19.72",
    "ssh_user": "saurabh",
    "ssh_key": os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "transactiwar-vm_key.pem"),
    "ssh_password": "",
    "db_user": "app_user",
    "db_pass": "notsqlpassword",
    "db_name": "app_database",
    "db_container": "team-17-db-1",
    "discord_webhook_alerts": "",
    "discord_webhook_timeouts": "",
}

def load_config():
    if not CONFIG_FILE.exists():
        cfg = {"profiles": {"azure": DEFAULT_PROFILE}, "active": "azure"}
        save_config(cfg)
        return cfg
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        cfg = {"profiles": {"azure": DEFAULT_PROFILE}, "active": "azure"}
        save_config(cfg)
        return cfg

def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def get_profile(cfg):
    name = cfg.get("active", "azure")
    profiles = cfg.get("profiles", {})
    return profiles.get(name, DEFAULT_PROFILE)


# ─── SSH / DB ──────────────────────────────────────────────────

def ssh_cmd(profile, command, timeout=15):
    key = os.path.expanduser(profile.get("ssh_key", ""))
    password = profile.get("ssh_password", "")
    host = profile["host"]
    user = profile["ssh_user"]

    if password:
        ssh = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", f"{user}@{host}", command]
    elif key and os.path.isfile(key):
        ssh = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
               "-i", key, f"{user}@{host}", command]
    else:
        ssh = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
               f"{user}@{host}", command]

    try:
        r = subprocess.run(ssh, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "Connection timed out", 1
    except FileNotFoundError:
        return "ssh not found", 1

def db_query(profile, sql, timeout=15):
    container = profile.get("db_container", "team-17-db-1")
    db_user = profile.get("db_user", "app_user")
    db_pass = profile.get("db_pass", "")
    db_name = profile.get("db_name", "app_database")
    cmd = f'''docker exec {container} mysql -u{db_user} -p{db_pass} {db_name} -e "$(cat <<'EOSQL'\n{sql}\nEOSQL\n)" 2>/dev/null'''
    return ssh_cmd(profile, cmd, timeout=timeout)

def send_discord(url, payload):
    if not url:
        return
    try:
        import urllib.request
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json",
            "User-Agent": "TransactiWar-Firewall/1.0",
        }, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


# ─── Color Palette ─────────────────────────────────────────────

BG           = "#1a1b26"
BG_CARD      = "#24283b"
BG_INPUT     = "#2f3347"
FG           = "#c0caf5"
FG_DIM       = "#565f89"
ACCENT       = "#7aa2f7"
RED_FG       = "#f7768e"
GREEN_FG     = "#9ece6a"
YELLOW_FG    = "#e0af68"
ORANGE_FG    = "#ff9e64"
PURPLE_FG    = "#bb9af7"
CYAN_FG      = "#7dcfff"


# ─── Main App ─────────────────────────────────────────────────

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TransactiWar Firewall")
        self.root.geometry("1200x800")
        self.root.configure(bg=BG)
        self.root.minsize(900, 650)

        self.cfg = load_config()
        self.profile = get_profile(self.cfg)

        self._build_styles()
        self._build_ui()
        self._refresh_all()

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_INPUT,
                         borderwidth=0, font=("Menlo", 13))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("TLabel", background=BG, foreground=FG, font=("Menlo", 13))
        style.configure("Header.TLabel", background=BG, foreground=ACCENT, font=("Menlo", 16, "bold"))
        style.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=("Menlo", 12))
        style.configure("Status.TLabel", background=BG_CARD, foreground=GREEN_FG, font=("Menlo", 12))

        style.configure("TButton", background=BG_INPUT, foreground=FG, font=("Menlo", 13),
                         padding=(12, 6))
        style.map("TButton", background=[("active", ACCENT)], foreground=[("active", BG)])

        style.configure("Danger.TButton", background="#3b2030", foreground=RED_FG)
        style.map("Danger.TButton", background=[("active", RED_FG)], foreground=[("active", BG)])

        style.configure("Success.TButton", background="#1a3520", foreground=GREEN_FG)
        style.map("Success.TButton", background=[("active", GREEN_FG)], foreground=[("active", BG)])

        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG, insertcolor=FG,
                         font=("Menlo", 13), padding=6)

        style.configure("TCombobox", fieldbackground=BG_INPUT, foreground=FG, font=("Menlo", 13))

        style.configure("Treeview", background=BG_CARD, foreground=FG, fieldbackground=BG_CARD,
                         font=("Menlo", 12), rowheight=32)
        style.configure("Treeview.Heading", background=BG_INPUT, foreground=ACCENT,
                         font=("Menlo", 10, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG)])

        style.configure("TNotebook", background=BG)
        style.configure("TNotebook.Tab", background=BG_INPUT, foreground=FG_DIM,
                         font=("Menlo", 13), padding=(16, 8))
        style.map("TNotebook.Tab",
                   background=[("selected", BG_CARD)],
                   foreground=[("selected", ACCENT)])

    def _build_ui(self):
        # ── Top bar ──
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=16, pady=(12, 4))

        ttk.Label(top, text="TransactiWar Firewall", style="Header.TLabel").pack(side="left")

        # Profile selector
        pf = ttk.Frame(top)
        pf.pack(side="right")
        ttk.Button(pf, text="+ Add Profile", command=self._add_profile).pack(side="right", padx=(8, 0))
        ttk.Label(pf, text="Deployment:", style="Dim.TLabel").pack(side="left", padx=(0, 6))

        profiles = list(self.cfg.get("profiles", {}).keys())
        self.profile_var = tk.StringVar(value=self.cfg.get("active", "azure"))
        self.profile_combo = ttk.Combobox(pf, textvariable=self.profile_var,
                                           values=profiles, state="readonly", width=18)
        self.profile_combo.pack(side="left")
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_change)

        # Show host next to dropdown
        self.host_label = ttk.Label(pf, text=f"({self.profile['host']})", style="Dim.TLabel")
        self.host_label.pack(side="left", padx=(8, 0))

        # Status bar + IP info row
        info_row = ttk.Frame(self.root, style="Card.TFrame")
        info_row.pack(fill="x", padx=16, pady=(0, 4))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(info_row, textvariable=self.status_var, style="Status.TLabel").pack(side="left")

        self.ip_info_var = tk.StringVar(value="  Detecting IPs...")
        ttk.Label(info_row, textvariable=self.ip_info_var, background=BG_CARD,
                   foreground=CYAN_FG, font=("Menlo", 11)).pack(side="right")

        self._run_async(self._detect_ips)

        # ── Tabs ──
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        self.tab_block   = ttk.Frame(nb, style="Card.TFrame")
        self.tab_blocked = ttk.Frame(nb, style="Card.TFrame")
        self.tab_status  = ttk.Frame(nb, style="Card.TFrame")
        self.tab_logs    = ttk.Frame(nb, style="Card.TFrame")

        nb.add(self.tab_block,   text="  Block IP  ")
        nb.add(self.tab_blocked, text="  Blocked List  ")
        nb.add(self.tab_status,  text="  Attack Dashboard  ")
        nb.add(self.tab_logs,    text="  IP Logs  ")

        self._build_block_tab()
        self._build_blocked_tab()
        self._build_status_tab()
        self._build_logs_tab()

    # ── Block IP Tab ──────────────────────────────────────────

    def _build_block_tab(self):
        f = self.tab_block
        pad = {"padx": 20, "pady": 8}

        ttk.Label(f, text="Block an IP Address", style="Header.TLabel",
                   background=BG_CARD).pack(**pad, anchor="w")

        # IP
        row1 = ttk.Frame(f, style="Card.TFrame")
        row1.pack(fill="x", **pad)
        ttk.Label(row1, text="IP Address:", background=BG_CARD).pack(side="left")
        self.block_ip = ttk.Entry(row1, width=25)
        self.block_ip.pack(side="left", padx=(10, 0))
        ttk.Button(row1, text="Paste My Public IP", command=self._paste_my_ip).pack(side="left", padx=(10, 0))

        # Duration
        row2 = ttk.Frame(f, style="Card.TFrame")
        row2.pack(fill="x", **pad)
        ttk.Label(row2, text="Duration:", background=BG_CARD).pack(side="left")
        self.block_dur = ttk.Combobox(row2, values=["1m", "5m", "15m", "30m", "1h", "2h", "6h", "12h", "1d", "7d", "Permanent"],
                                       state="readonly", width=12)
        self.block_dur.set("30m")
        self.block_dur.pack(side="left", padx=(10, 0))

        # Reason
        row3 = ttk.Frame(f, style="Card.TFrame")
        row3.pack(fill="x", **pad)
        ttk.Label(row3, text="Reason:", background=BG_CARD).pack(side="left")
        self.block_reason = ttk.Entry(row3, width=45)
        self.block_reason.insert(0, "suspicious activity")
        self.block_reason.pack(side="left", padx=(10, 0))

        # Buttons
        row4 = ttk.Frame(f, style="Card.TFrame")
        row4.pack(fill="x", **pad)
        ttk.Button(row4, text="Block IP", style="Danger.TButton",
                    command=self._do_block).pack(side="left")
        ttk.Label(row4, text="", background=BG_CARD).pack(side="left", padx=10)
        self.block_status = tk.StringVar(value="")
        ttk.Label(row4, textvariable=self.block_status, background=BG_CARD,
                   foreground=GREEN_FG).pack(side="left")

    def _do_block(self):
        ip = self.block_ip.get().strip()
        dur = self.block_dur.get()
        reason = self.block_reason.get().strip() or "manual block"

        if not self._validate_ip(ip):
            self.block_status.set("Invalid IP address")
            return

        if dur == "Permanent":
            dur_sql = None
            label = "permanent"
        else:
            dur_sql = dur
            label = dur

        self.block_status.set("Blocking...")
        self._run_async(lambda: self._block_ip(ip, dur_sql, reason, label))

    def _block_ip(self, ip, dur, reason, label):
        who = os.getenv("USER", os.getenv("USERNAME", "unknown"))
        safe_reason = re.sub(r"[^a-zA-Z0-9 _\-.,()/@]", "", reason)[:200]
        safe_who = re.sub(r"[^a-zA-Z0-9_\-.]", "", who)[:32]

        if dur:
            interval = self._parse_dur(dur)
            if not interval:
                self.root.after(0, lambda: self.block_status.set("Invalid duration"))
                return
            sql = f"REPLACE INTO blocked_ips (ip, reason, blocked_by, expires_at) VALUES ('{ip}', '{safe_reason}', '{safe_who}', NOW() + {interval})"
        else:
            sql = f"REPLACE INTO blocked_ips (ip, reason, blocked_by, expires_at) VALUES ('{ip}', '{safe_reason}', '{safe_who}', NULL)"

        self._ensure_table()
        db_query(self.profile, sql)

        # Discord notify with fun messages
        webhook = self.profile.get("discord_webhook_timeouts", "")
        if webhook:
            import random
            now_ist = datetime.now(IST).strftime("%Y-%m-%d %H:%M IST")

            cooldown_msgs = [
                f"Don't abuse the site bro, come back in **{label}** \U0001F612",
                f"Chill out for **{label}**, we're watching you \U0001F440",
                f"Nah fam, you're in timeout for **{label}** \U0001F6D1",
                f"Touch grass for **{label}** and try again \U0001F33F",
                f"You've been benched for **{label}**. Take a water break \U0001F4A7",
                f"**{label}** cooldown. Maybe read the ToS while you wait? \U0001F4DA",
                f"Sir this is a banking app, not a CTF... oh wait. Anyway, **{label}** timeout \U0001F3E6",
                f"Rate limited to 0 requests per **{label}**. Skill issue? \U0001F4A0",
                f"You're on the naughty list for **{label}** \U0001F385",
                f"Bro thought he was slick. **{label}** timeout \U0001F921",
            ]
            perma_msgs = [
                "Permanently banned. That's tough \U0001F480",
                "Gone. Reduced to atoms. Permanent ban \U0001FAE0",
                "You've been yeeted into the shadow realm. Permanently \U0001F573\uFE0F",
                "Perma-banned. We don't negotiate with hackers \U0001F9D1\u200D\U0001F4BB",
                "Your IP has been escorted out of the building. Permanently \U0001F6AA",
                "404: Your access was not found. And never will be \U0001F47B",
            ]

            if dur:
                title = f"\U0001F512 IP Cooldown: {ip}"
                fun_msg = random.choice(cooldown_msgs)
                desc = f"{fun_msg}\n\n**Reason:** {safe_reason}\n**By:** {safe_who}\n**Time:** {now_ist}"
                color = 0xFF8C00
            else:
                title = f"\U0001F6AB Permanently Blocked: {ip}"
                fun_msg = random.choice(perma_msgs)
                desc = f"{fun_msg}\n\n**Reason:** {safe_reason}\n**By:** {safe_who}\n**Time:** {now_ist}"
                color = 0xFF0000
            send_discord(webhook, {"embeds": [{"title": title, "description": desc, "color": color,
                                                "footer": {"text": f"TransactiWar Firewall | {self.profile.get('name','?')}"}}]})

        self.root.after(0, lambda: self.block_status.set(f"Blocked {ip} ({label})"))
        self.root.after(0, self._refresh_blocked)

    # ── Blocked List Tab ──────────────────────────────────────

    def _build_blocked_tab(self):
        f = self.tab_blocked

        toolbar = ttk.Frame(f, style="Card.TFrame")
        toolbar.pack(fill="x", padx=20, pady=(12, 4))
        ttk.Label(toolbar, text="Blocked IPs", style="Header.TLabel",
                   background=BG_CARD).pack(side="left")
        ttk.Button(toolbar, text="Refresh", command=self._refresh_blocked).pack(side="right")
        ttk.Button(toolbar, text="Unblock Selected", style="Success.TButton",
                    command=self._do_unblock).pack(side="right", padx=(0, 8))

        cols = ("ip", "reason", "by", "blocked_at", "expires", "remaining")
        self.blocked_tree = ttk.Treeview(f, columns=cols, show="headings", height=12)

        self.blocked_tree.heading("ip", text="IP Address")
        self.blocked_tree.heading("reason", text="Reason")
        self.blocked_tree.heading("by", text="By")
        self.blocked_tree.heading("blocked_at", text="Blocked At (IST)")
        self.blocked_tree.heading("expires", text="Expires")
        self.blocked_tree.heading("remaining", text="Time Left")

        self.blocked_tree.column("ip", width=140)
        self.blocked_tree.column("reason", width=180)
        self.blocked_tree.column("by", width=80)
        self.blocked_tree.column("blocked_at", width=160)
        self.blocked_tree.column("expires", width=160)
        self.blocked_tree.column("remaining", width=110)

        scroll = ttk.Scrollbar(f, orient="vertical", command=self.blocked_tree.yview)
        self.blocked_tree.configure(yscrollcommand=scroll.set)

        self.blocked_tree.pack(fill="both", expand=True, padx=20, pady=(4, 12))
        scroll.pack(side="right", fill="y")

    def _refresh_blocked(self):
        self._run_async(self._load_blocked)

    def _load_blocked(self):
        self._ensure_table()
        db_query(self.profile, "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= NOW()")
        out, _ = db_query(self.profile, """
            SELECT ip, reason, blocked_by,
                   DATE_FORMAT(CONVERT_TZ(blocked_at, '+00:00', '+05:30'), '%Y-%m-%d %H:%i') AS blocked_ist,
                   IFNULL(DATE_FORMAT(CONVERT_TZ(expires_at, '+00:00', '+05:30'), '%Y-%m-%d %H:%i'), 'PERMANENT') AS expires,
                   CASE
                       WHEN expires_at IS NULL THEN 'permanent'
                       ELSE CONCAT(TIMESTAMPDIFF(MINUTE, NOW(), expires_at), 'm left')
                   END AS remaining
            FROM blocked_ips ORDER BY blocked_at DESC
        """)
        rows = []
        if out:
            lines = out.strip().split('\n')
            for line in lines[1:]:
                parts = line.split('\t')
                if len(parts) >= 6:
                    rows.append(tuple(parts[:6]))

        def update():
            for item in self.blocked_tree.get_children():
                self.blocked_tree.delete(item)
            for row in rows:
                tag = "perm" if row[4] == "PERMANENT" else "temp"
                self.blocked_tree.insert("", "end", values=row, tags=(tag,))
            self.blocked_tree.tag_configure("perm", foreground=RED_FG)
            self.blocked_tree.tag_configure("temp", foreground=YELLOW_FG)

        self.root.after(0, update)

    def _do_unblock(self):
        sel = self.blocked_tree.selection()
        if not sel:
            messagebox.showinfo("Unblock", "Select an IP to unblock.")
            return
        ip = self.blocked_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Unblock", f"Unblock {ip}?"):
            self._run_async(lambda: self._unblock_ip(ip))

    def _unblock_ip(self, ip):
        who = os.getenv("USER", os.getenv("USERNAME", "unknown"))
        db_query(self.profile, f"DELETE FROM blocked_ips WHERE ip = '{ip}'")

        webhook = self.profile.get("discord_webhook_timeouts", "")
        if webhook:
            now_ist = datetime.now(IST).strftime("%Y-%m-%d %H:%M IST")
            send_discord(webhook, {"embeds": [{"title": f"\u2705 IP Unblocked: {ip}",
                                                "description": f"**By:** {who}\n**Time:** {now_ist}",
                                                "color": 0x2ECC71,
                                                "footer": {"text": f"TransactiWar Firewall | {self.profile.get('name','?')}"}}]})

        self.root.after(0, lambda: self._set_status(f"Unblocked {ip}"))
        self.root.after(0, self._refresh_blocked)

    # ── Attack Dashboard Tab ──────────────────────────────────

    def _build_status_tab(self):
        f = self.tab_status

        toolbar = ttk.Frame(f, style="Card.TFrame")
        toolbar.pack(fill="x", padx=20, pady=(12, 4))
        ttk.Label(toolbar, text="Attack Dashboard", style="Header.TLabel",
                   background=BG_CARD).pack(side="left")
        ttk.Button(toolbar, text="Refresh", command=self._refresh_status).pack(side="right")
        ttk.Button(toolbar, text="Block Selected", style="Danger.TButton",
                    command=self._quick_block).pack(side="right", padx=(0, 8))

        cols = ("ip", "hits", "csrf", "auth", "xfer", "probes", "upload", "first", "last")
        self.status_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)

        for col, w in [("ip", 140), ("hits", 55), ("csrf", 55), ("auth", 55),
                        ("xfer", 55), ("probes", 60), ("upload", 60), ("first", 145), ("last", 145)]:
            self.status_tree.heading(col, text=col.upper())
            self.status_tree.column(col, width=w, anchor="center" if w < 80 else "w")

        self.status_tree.column("ip", anchor="w")
        self.status_tree.column("first", anchor="w")
        self.status_tree.column("last", anchor="w")

        self.status_tree.pack(fill="both", expand=True, padx=20, pady=(4, 12))

        # Right-click context menu
        self.status_ctx = tk.Menu(self.root, tearoff=0, bg=BG_CARD, fg=FG,
                                   activebackground=ACCENT, activeforeground=BG,
                                   font=("Menlo", 12))
        self.status_ctx.add_command(label="Block this IP (1m)", command=lambda: self._ctx_block("1m"))
        self.status_ctx.add_command(label="Block this IP (5m)", command=lambda: self._ctx_block("5m"))
        self.status_ctx.add_command(label="Block this IP (30m)", command=lambda: self._ctx_block("30m"))
        self.status_ctx.add_command(label="Block this IP (1h)", command=lambda: self._ctx_block("1h"))
        self.status_ctx.add_command(label="Block this IP (2h)", command=lambda: self._ctx_block("2h"))
        self.status_ctx.add_command(label="Block permanently", command=lambda: self._ctx_block(None))
        self.status_ctx.add_separator()
        self.status_ctx.add_command(label="Send to Block tab", command=self._ctx_send_to_block)
        self.status_ctx.add_command(label="View logs", command=self._ctx_view_logs)

        # Bind right-click (macOS uses Button-2, Linux/Windows uses Button-3)
        self.status_tree.bind("<Button-2>", self._show_status_ctx)
        self.status_tree.bind("<Button-3>", self._show_status_ctx)
        # macOS trackpad right-click
        self.status_tree.bind("<Control-Button-1>", self._show_status_ctx)

    def _show_status_ctx(self, event):
        """Show right-click context menu on the attack dashboard."""
        row = self.status_tree.identify_row(event.y)
        if row:
            self.status_tree.selection_set(row)
            self.status_ctx.post(event.x_root, event.y_root)

    def _get_selected_status_ip(self):
        sel = self.status_tree.selection()
        if not sel:
            return None
        return str(self.status_tree.item(sel[0])["values"][0])

    def _ctx_block(self, duration):
        ip = self._get_selected_status_ip()
        if not ip:
            return
        label = duration or "permanent"
        self._run_async(lambda: self._block_ip(ip, duration, "blocked from dashboard", label))

    def _ctx_send_to_block(self):
        """Send IP to the Block IP tab for custom settings."""
        ip = self._get_selected_status_ip()
        if not ip:
            return
        self.block_ip.delete(0, tk.END)
        self.block_ip.insert(0, ip)
        # Switch to Block tab
        nb = self.tab_block.master
        nb.select(self.tab_block)

    def _ctx_view_logs(self):
        """Open the IP in the Logs tab."""
        ip = self._get_selected_status_ip()
        if not ip:
            return
        self.logs_ip.delete(0, tk.END)
        self.logs_ip.insert(0, ip)
        nb = self.tab_logs.master
        nb.select(self.tab_logs)
        self._refresh_logs()

    def _refresh_status(self):
        self._run_async(self._load_status)

    def _load_status(self):
        out, _ = db_query(self.profile, """
            SELECT client_ip, COUNT(*) AS hits,
                SUM(CASE WHEN webpage LIKE 'CSRF_FAIL%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN webpage LIKE 'LOGIN_FAIL%' OR webpage LIKE 'LOGIN_LOCKED%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN webpage LIKE 'TRANSFER_%' AND webpage != 'TRANSFER_SUCCESS' THEN 1 ELSE 0 END),
                SUM(CASE WHEN webpage LIKE '%PROBE%' OR webpage LIKE '%HIJACK%' OR webpage LIKE '%BRUTE%' THEN 1 ELSE 0 END),
                SUM(CASE WHEN webpage LIKE 'FILE_UPLOAD_FAIL%' THEN 1 ELSE 0 END),
                DATE_FORMAT(CONVERT_TZ(MIN(created_at), '+00:00', '+05:30'), '%Y-%m-%d %H:%i'),
                DATE_FORMAT(CONVERT_TZ(MAX(created_at), '+00:00', '+05:30'), '%Y-%m-%d %H:%i')
            FROM activity_logs
            WHERE webpage NOT IN ('PAGE_VIEW','LOGIN_SUCCESS','LOGOUT','USER_SEARCH',
                'PROFILE_VIEW','PROFILE_UPDATE','PROFILE_IMAGE_UPLOAD',
                'PROFILE_VIEW_OTHER','TRANSFER_SUCCESS','USER_REGISTER')
            AND webpage NOT LIKE 'PAGE_VIEW:%'
            GROUP BY client_ip HAVING hits > 2
            ORDER BY hits DESC LIMIT 30
        """)

        rows = []
        if out:
            for line in out.strip().split('\n')[1:]:
                parts = line.split('\t')
                if len(parts) >= 9:
                    rows.append(tuple(parts[:9]))

        def update():
            for item in self.status_tree.get_children():
                self.status_tree.delete(item)
            for row in rows:
                hits = int(row[1])
                tag = "high" if hits >= 50 else ("med" if hits >= 20 else "low")
                self.status_tree.insert("", "end", values=row, tags=(tag,))
            self.status_tree.tag_configure("high", foreground=RED_FG)
            self.status_tree.tag_configure("med", foreground=YELLOW_FG)
            self.status_tree.tag_configure("low", foreground=CYAN_FG)

        self.root.after(0, update)

    def _quick_block(self):
        sel = self.status_tree.selection()
        if not sel:
            messagebox.showinfo("Block", "Select an IP from the dashboard.")
            return
        ip = self.status_tree.item(sel[0])["values"][0]
        dur = simpledialog.askstring("Block Duration", f"Block {ip} for how long?\n(e.g., 30m, 2h, 1d, or 'permanent')",
                                      initialvalue="30m", parent=self.root)
        if dur:
            if dur.lower() == "permanent":
                self._run_async(lambda: self._block_ip(ip, None, "blocked from dashboard", "permanent"))
            else:
                self._run_async(lambda: self._block_ip(ip, dur, "blocked from dashboard", dur))

    # ── IP Logs Tab ───────────────────────────────────────────

    def _build_logs_tab(self):
        f = self.tab_logs

        toolbar = ttk.Frame(f, style="Card.TFrame")
        toolbar.pack(fill="x", padx=20, pady=(12, 4))
        ttk.Label(toolbar, text="IP:", background=BG_CARD).pack(side="left")
        self.logs_ip = ttk.Entry(toolbar, width=20)
        self.logs_ip.pack(side="left", padx=(8, 8))
        ttk.Button(toolbar, text="Lookup", command=self._refresh_logs).pack(side="left")

        cols = ("time", "user", "event")
        self.logs_tree = ttk.Treeview(f, columns=cols, show="headings", height=16)
        self.logs_tree.heading("time", text="Time (IST)")
        self.logs_tree.heading("user", text="User")
        self.logs_tree.heading("event", text="Event")
        self.logs_tree.column("time", width=160)
        self.logs_tree.column("user", width=120)
        self.logs_tree.column("event", width=500)

        self.logs_tree.pack(fill="both", expand=True, padx=20, pady=(4, 12))

    def _refresh_logs(self):
        ip = self.logs_ip.get().strip()
        if not self._validate_ip(ip):
            messagebox.showwarning("Invalid IP", "Enter a valid IP address.")
            return
        self._run_async(lambda: self._load_logs(ip))

    def _load_logs(self, ip):
        out, _ = db_query(self.profile, f"""
            SELECT DATE_FORMAT(CONVERT_TZ(created_at, '+00:00', '+05:30'), '%Y-%m-%d %H:%i:%s'),
                   IFNULL(username_snapshot, 'guest'), webpage
            FROM activity_logs WHERE client_ip = '{ip}'
            ORDER BY created_at DESC LIMIT 100
        """)

        rows = []
        if out:
            for line in out.strip().split('\n')[1:]:
                parts = line.split('\t')
                if len(parts) >= 3:
                    rows.append(tuple(parts[:3]))

        def update():
            for item in self.logs_tree.get_children():
                self.logs_tree.delete(item)
            for row in rows:
                event = row[2]
                if any(k in event for k in ('FAIL', 'DENIED', 'PROBE', 'BRUTE', 'HIJACK', 'BLOCKED')):
                    tag = "danger"
                elif any(k in event for k in ('INVALID', 'LOCKED')):
                    tag = "warn"
                elif event in ('LOGIN_SUCCESS', 'TRANSFER_SUCCESS'):
                    tag = "ok"
                else:
                    tag = "dim"
                self.logs_tree.insert("", "end", values=row, tags=(tag,))
            self.logs_tree.tag_configure("danger", foreground=RED_FG)
            self.logs_tree.tag_configure("warn", foreground=YELLOW_FG)
            self.logs_tree.tag_configure("ok", foreground=GREEN_FG)
            self.logs_tree.tag_configure("dim", foreground=FG_DIM)

        self.root.after(0, update)

    # ── Helpers ───────────────────────────────────────────────

    def _paste_my_ip(self):
        """Fill the block IP field with the user's public IP."""
        ip = getattr(self, 'public_ip', None)
        if ip and ip != '?':
            self.block_ip.delete(0, tk.END)
            self.block_ip.insert(0, ip)
        else:
            self._set_status("Public IP not detected yet — try again in a moment")

    def _validate_ip(self, ip):
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return all(0 <= int(p) <= 255 for p in ip.split('.'))
        if ':' in ip and re.match(r'^[0-9a-fA-F:]+$', ip):
            return True
        return False

    def _parse_dur(self, s):
        m = re.match(r'^(\d+)\s*(m|min|h|hr|hour|d|day)s?$', s.lower())
        if not m:
            return None
        num, unit = int(m.group(1)), m.group(2)
        if unit in ('m', 'min'): return f"INTERVAL {num} MINUTE"
        if unit in ('h', 'hr', 'hour'): return f"INTERVAL {num} HOUR"
        if unit in ('d', 'day'): return f"INTERVAL {num} DAY"
        return None

    def _ensure_table(self):
        db_query(self.profile, """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip VARCHAR(45) NOT NULL, reason VARCHAR(255) NOT NULL DEFAULT 'manual block',
                blocked_by VARCHAR(32) NOT NULL DEFAULT 'system',
                blocked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL DEFAULT NULL, PRIMARY KEY (ip)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
        """)

    def _set_status(self, msg):
        self.status_var.set(f"{msg}  |  {datetime.now(IST).strftime('%H:%M:%S IST')}")

    def _detect_ips(self):
        """Detect local LAN IP and public IP as seen by the server."""
        import socket
        # Local IP
        local_ip = "?"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        # Public IP via external service
        public_ip = "?"
        try:
            import urllib.request
            public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip()
        except Exception:
            pass

        self.public_ip = public_ip
        self.local_ip = local_ip
        self.root.after(0, lambda: self.ip_info_var.set(
            f"Your IPs  \u2014  LAN: {local_ip}  |  Public: {public_ip}"
        ))

    def _run_async(self, fn):
        """Run a function in a background thread to keep the GUI responsive."""
        def wrapper():
            try:
                fn()
            except Exception as e:
                self.root.after(0, lambda: self._set_status(f"Error: {e}"))
        threading.Thread(target=wrapper, daemon=True).start()

    def _on_profile_change(self, event=None):
        name = self.profile_var.get()
        self.cfg["active"] = name
        save_config(self.cfg)
        self.profile = get_profile(self.cfg)
        self.host_label.configure(text=f"({self.profile['host']})")
        self._set_status(f"Switched to {name} ({self.profile['host']})")
        self._refresh_all()

    def _add_profile(self):
        """Add a new deployment profile via dialog."""
        name = simpledialog.askstring("New Profile", "Profile name (e.g., staging, local-vm):",
                                       parent=self.root)
        if not name:
            return
        name = re.sub(r'[^a-zA-Z0-9_\-]', '', name)

        host = simpledialog.askstring("New Profile", "VM host/IP:", parent=self.root)
        if not host:
            return

        user = simpledialog.askstring("New Profile", "SSH username:", initialvalue="ubuntu",
                                       parent=self.root)
        if not user:
            return

        auth = messagebox.askyesno("SSH Auth", "Use SSH key?\n\nYes = key file\nNo = password")
        if auth:
            key = simpledialog.askstring("New Profile", "Path to SSH key:", parent=self.root)
            password = ""
        else:
            key = ""
            password = simpledialog.askstring("New Profile", "SSH password:", parent=self.root, show="*") or ""

        db_pass = simpledialog.askstring("New Profile", "DB password:", initialvalue="notsqlpassword",
                                          parent=self.root)

        timeout_webhook = simpledialog.askstring("New Profile",
            "Discord webhook for #timed-out-mfs\n(blank to skip):", parent=self.root) or ""

        new_profile = {
            "name": name, "host": host, "ssh_user": user,
            "ssh_key": key or "", "ssh_password": password,
            "db_user": "app_user", "db_pass": db_pass or "notsqlpassword",
            "db_name": "app_database", "db_container": "team-17-db-1",
            "discord_webhook_alerts": "", "discord_webhook_timeouts": timeout_webhook,
        }

        self.cfg.setdefault("profiles", {})[name] = new_profile
        self.cfg["active"] = name
        save_config(self.cfg)
        self.profile = new_profile

        # Update dropdown
        self.profile_combo["values"] = list(self.cfg["profiles"].keys())
        self.profile_var.set(name)
        self.host_label.configure(text=f"({host})")
        self._set_status(f"Created profile: {name} ({host})")
        self._refresh_all()

    def _refresh_all(self):
        self._set_status(f"Connected: {self.profile.get('ssh_user','?')}@{self.profile['host']}")
        self._refresh_blocked()
        self._refresh_status()


def main():
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
