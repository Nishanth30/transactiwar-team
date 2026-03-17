#!/usr/bin/env python3
"""
TransactiWar IP Firewall Manager
Cross-platform CLI tool for managing the IP blocklist.

Usage:
    python firewall.py                     # Interactive menu
    python firewall.py block 10.0.0.5      # Block IP permanently
    python firewall.py block 10.0.0.5 30m  # Block for 30 minutes
    python firewall.py block 10.0.0.5 2h   # Block for 2 hours
    python firewall.py unblock 10.0.0.5    # Remove block
    python firewall.py list                # Show all blocked IPs
    python firewall.py status              # Live attack summary
    python firewall.py logs 10.0.0.5       # Activity from an IP
    python firewall.py watch               # Live tail security events
    python firewall.py profile             # Show / switch deployment profile

Works with any TransactiWar deployment. Configure via profiles:
    python firewall.py profile add azure   # Add a new deployment profile
    python firewall.py profile use azure   # Switch to it
"""

import subprocess
import sys
import os
import re
import json
import shutil
from pathlib import Path

# ─── Profile / Config System ───────────────────────────────────
CONFIG_DIR  = Path.home() / ".transactiwar"
CONFIG_FILE = CONFIG_DIR / "firewall_profiles.json"

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
    """Load config with profiles. Returns (profiles dict, active profile name)."""
    if not CONFIG_FILE.exists():
        return {"profiles": {"azure": DEFAULT_PROFILE}, "active": "azure"}, True
    try:
        data = json.loads(CONFIG_FILE.read_text())
        return data, False
    except (json.JSONDecodeError, KeyError):
        return {"profiles": {"azure": DEFAULT_PROFILE}, "active": "azure"}, True

def save_config(config):
    """Save config to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

def get_active_profile():
    """Get the active deployment profile."""
    config, is_default = load_config()
    if is_default:
        save_config(config)
    name = config.get("active", "azure")
    profiles = config.get("profiles", {})
    if name not in profiles:
        name = next(iter(profiles), "azure")
    return profiles.get(name, DEFAULT_PROFILE)

PROFILE = get_active_profile()

# ─── Colors ─────────────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

def supports_color():
    if os.getenv("NO_COLOR"):
        return False
    if sys.platform == "win32":
        return os.getenv("ANSICON") or "WT_SESSION" in os.environ
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

if not supports_color():
    RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = DIM = RESET = ""


# ─── SSH + MySQL helpers ────────────────────────────────────────

def ssh_cmd(command, timeout=15):
    """Run a command on the VM via SSH."""
    p = PROFILE
    key_path = os.path.expanduser(p.get("ssh_key", ""))
    password = p.get("ssh_password", "")
    host = p["host"]
    user = p["ssh_user"]

    if password:
        # Use sshpass for password-based auth
        ssh = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            f"{user}@{host}",
            command
        ]
    elif key_path and os.path.isfile(key_path):
        ssh = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-i", key_path,
            f"{user}@{host}",
            command
        ]
    else:
        # Try default SSH config / agent
        ssh = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            f"{user}@{host}",
            command
        ]

    try:
        result = subprocess.run(ssh, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "Connection timed out", 1
    except FileNotFoundError:
        print(f"{RED}ssh command not found. Install OpenSSH.{RESET}")
        sys.exit(1)

def db_query(sql, timeout=15):
    """Run a MySQL query via docker exec on the VM."""
    p = PROFILE
    db_user = p.get("db_user", "app_user")
    db_pass = p.get("db_pass", "")
    db_name = p.get("db_name", "app_database")
    container = p.get("db_container", "team-17-db-1")

    # Write SQL to a temp heredoc to avoid shell quoting hell
    cmd = f'''docker exec {container} mysql -u{db_user} -p{db_pass} {db_name} -e "$(cat <<'EOSQL'
{sql}
EOSQL
)" 2>/dev/null'''

    out, rc = ssh_cmd(cmd, timeout=timeout)
    if rc != 0 and "doesn't exist" in out:
        ensure_table()
        out, rc = ssh_cmd(cmd, timeout=timeout)
    return out

def ensure_table():
    """Create blocked_ips table if it doesn't exist."""
    db_query("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip VARCHAR(45) NOT NULL,
            reason VARCHAR(255) NOT NULL DEFAULT 'manual block',
            blocked_by VARCHAR(32) NOT NULL DEFAULT 'system',
            blocked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)


# ─── Discord Webhook ────────────────────────────────────────────

def send_discord_webhook(webhook_url, payload):
    """Send a Discord webhook message. Fire-and-forget."""
    if not webhook_url:
        return
    try:
        import urllib.request
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "TransactiWar-Firewall/1.0"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # Never crash for webhook failure

def notify_block(ip, duration, reason, who):
    """Send block notification to the #timed-out-mfs webhook."""
    webhook = PROFILE.get("discord_webhook_timeouts", "")
    if not webhook:
        return

    if duration:
        title = f"\U0001F512 IP Cooldown: {ip}"
        desc = f"**Duration:** {duration}\n**Reason:** {reason}\n**By:** {who}"
        color = 0xFF8C00  # Orange
    else:
        title = f"\U0001F6AB IP Permanently Blocked: {ip}"
        desc = f"**Reason:** {reason}\n**By:** {who}"
        color = 0xFF0000  # Red

    payload = {
        "embeds": [{
            "title": title,
            "description": desc,
            "color": color,
            "timestamp": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
            "footer": {"text": f"TransactiWar Firewall | {PROFILE.get('name', 'unknown')}"}
        }]
    }
    send_discord_webhook(webhook, payload)

def notify_unblock(ip, who):
    """Send unblock notification to the #timed-out-mfs webhook."""
    webhook = PROFILE.get("discord_webhook_timeouts", "")
    if not webhook:
        return

    payload = {
        "embeds": [{
            "title": f"\u2705 IP Unblocked: {ip}",
            "description": f"**By:** {who}",
            "color": 0x2ECC71,  # Green
            "timestamp": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
            "footer": {"text": f"TransactiWar Firewall | {PROFILE.get('name', 'unknown')}"}
        }]
    }
    send_discord_webhook(webhook, payload)


# ─── Validation ─────────────────────────────────────────────────

def validate_ip(ip):
    """Basic IPv4/IPv6 validation."""
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True
    if ':' in ip and re.match(r'^[0-9a-fA-F:]+$', ip):
        return True
    return False

def parse_duration(s):
    """Parse '30m', '2h', '1d' into MySQL INTERVAL clause."""
    if not s:
        return None, None
    m = re.match(r'^(\d+)\s*(m|min|h|hr|hour|d|day)s?$', s.lower())
    if not m:
        return None, None
    num, unit = int(m.group(1)), m.group(2)
    if unit in ('m', 'min'):
        return f"INTERVAL {num} MINUTE", s
    elif unit in ('h', 'hr', 'hour'):
        return f"INTERVAL {num} HOUR", s
    elif unit in ('d', 'day'):
        return f"INTERVAL {num} DAY", s
    return None, None


# ─── Commands ───────────────────────────────────────────────────

def cmd_block(ip, duration=None, reason="manual block"):
    if not validate_ip(ip):
        print(f"{RED}Invalid IP address: {ip}{RESET}")
        return

    ensure_table()
    who = os.getenv("USER", os.getenv("USERNAME", "unknown"))
    # Sanitize inputs for SQL
    safe_reason = re.sub(r"[^a-zA-Z0-9 _\-.,()/@]", "", reason)[:200]
    safe_who = re.sub(r"[^a-zA-Z0-9_\-.]", "", who)[:32]

    if duration:
        interval, label = parse_duration(duration)
        if not interval:
            print(f"{RED}Invalid duration: {duration}. Use: 30m, 2h, 1d{RESET}")
            return
        sql = f"""REPLACE INTO blocked_ips (ip, reason, blocked_by, expires_at)
                  VALUES ('{ip}', '{safe_reason}', '{safe_who}', NOW() + {interval})"""
    else:
        label = "permanent"
        sql = f"""REPLACE INTO blocked_ips (ip, reason, blocked_by, expires_at)
                  VALUES ('{ip}', '{safe_reason}', '{safe_who}', NULL)"""

    db_query(sql)
    print(f"{RED}{BOLD}BLOCKED{RESET} {ip} ({label}) by {safe_who} — reason: {safe_reason}")
    notify_block(ip, duration, safe_reason, safe_who)

def cmd_unblock(ip):
    if not validate_ip(ip):
        print(f"{RED}Invalid IP address: {ip}{RESET}")
        return

    ensure_table()
    who = os.getenv("USER", os.getenv("USERNAME", "unknown"))
    db_query(f"DELETE FROM blocked_ips WHERE ip = '{ip}'")
    print(f"{GREEN}{BOLD}UNBLOCKED{RESET} {ip}")
    notify_unblock(ip, who)

def cmd_list():
    ensure_table()
    db_query("DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= NOW()")

    out = db_query("""
        SELECT ip, reason, blocked_by, blocked_at,
               IFNULL(CAST(expires_at AS CHAR), 'PERMANENT') AS expires,
               CASE
                   WHEN expires_at IS NULL THEN 'permanent'
                   ELSE CONCAT(
                       TIMESTAMPDIFF(MINUTE, NOW(), expires_at), 'm remaining'
                   )
               END AS time_left
        FROM blocked_ips
        ORDER BY blocked_at DESC
    """)

    if not out or not out.strip():
        print(f"{GREEN}No IPs currently blocked.{RESET}")
        return

    lines = out.strip().split('\n')
    if len(lines) <= 1:
        print(f"{GREEN}No IPs currently blocked.{RESET}")
        return

    print(f"\n{BOLD}{'IP':<20} {'Reason':<22} {'By':<10} {'Blocked At':<22} {'Expires':<22} {'Time Left'}{RESET}")
    print("-" * 110)

    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) >= 6:
            ip, reason, by, at, expires, left = parts[:6]
            exp_color = RED if expires == "PERMANENT" else YELLOW
            print(f"{RED}{ip:<20}{RESET} {reason:<22} {DIM}{by:<10}{RESET} {DIM}{at:<22}{RESET} {exp_color}{expires:<22}{RESET} {CYAN}{left}{RESET}")
    print()

def cmd_status():
    out = db_query("""
        SELECT
            client_ip,
            COUNT(*) AS hits,
            SUM(CASE WHEN webpage LIKE 'CSRF_FAIL%' THEN 1 ELSE 0 END) AS csrf,
            SUM(CASE WHEN webpage LIKE 'LOGIN_FAIL%' OR webpage LIKE 'LOGIN_LOCKED%' THEN 1 ELSE 0 END) AS auth,
            SUM(CASE WHEN webpage LIKE 'TRANSFER_%' AND webpage != 'TRANSFER_SUCCESS' THEN 1 ELSE 0 END) AS transfer,
            SUM(CASE WHEN webpage LIKE '%PROBE%' OR webpage LIKE '%HIJACK%' OR webpage LIKE '%BRUTE%' THEN 1 ELSE 0 END) AS probes,
            SUM(CASE WHEN webpage LIKE 'FILE_UPLOAD_FAIL%' THEN 1 ELSE 0 END) AS upload,
            MIN(created_at) AS first_seen,
            MAX(created_at) AS last_seen
        FROM activity_logs
        WHERE webpage NOT IN ('PAGE_VIEW', 'LOGIN_SUCCESS', 'LOGOUT', 'USER_SEARCH',
                              'PROFILE_VIEW', 'PROFILE_UPDATE', 'PROFILE_IMAGE_UPLOAD',
                              'PROFILE_VIEW_OTHER', 'TRANSFER_SUCCESS', 'USER_REGISTER')
        AND webpage NOT LIKE 'PAGE_VIEW:%'
        GROUP BY client_ip
        HAVING hits > 2
        ORDER BY hits DESC
        LIMIT 20
    """)

    if not out or not out.strip():
        print(f"{GREEN}No suspicious activity detected.{RESET}")
        return

    lines = out.strip().split('\n')
    if len(lines) <= 1:
        print(f"{GREEN}No suspicious activity detected.{RESET}")
        return

    blocked_out = db_query("SELECT ip FROM blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()")
    blocked_ips = set()
    if blocked_out:
        for bline in blocked_out.strip().split('\n')[1:]:
            blocked_ips.add(bline.strip())

    print(f"\n{BOLD}{'IP':<20} {'Hits':>5} {'CSRF':>5} {'Auth':>5} {'Xfer':>5} {'Probe':>5} {'Upload':>6}  {'First Seen':<20} {'Last Seen':<20} {'Status'}{RESET}")
    print("-" * 120)

    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) >= 9:
            ip = parts[0]
            hits, csrf, auth, xfer, probes, upload = parts[1:7]
            first, last = parts[7], parts[8]
            total = int(hits)
            ip_color = RED if total >= 50 else (YELLOW if total >= 20 else CYAN)
            status = f"{RED}BLOCKED{RESET}" if ip in blocked_ips else f"{GREEN}active{RESET}"
            print(f"{ip_color}{ip:<20}{RESET} {hits:>5} {csrf:>5} {auth:>5} {xfer:>5} {probes:>5} {upload:>6}  {DIM}{first:<20} {last:<20}{RESET} {status}")

    print(f"\n{DIM}Tip: block <ip> [duration]  |  logs <ip>  |  unblock <ip>{RESET}\n")

def cmd_logs(ip):
    if not validate_ip(ip):
        print(f"{RED}Invalid IP address: {ip}{RESET}")
        return

    out = db_query(f"""
        SELECT created_at, IFNULL(username_snapshot, 'guest'), webpage
        FROM activity_logs
        WHERE client_ip = '{ip}'
        ORDER BY created_at DESC
        LIMIT 50
    """)

    if not out or not out.strip():
        print(f"{DIM}No activity found for {ip}{RESET}")
        return

    lines = out.strip().split('\n')
    print(f"\n{BOLD}Activity log for {ip} (last 50):{RESET}\n")
    print(f"{'Time':<22} {'User':<16} {'Event'}")
    print("-" * 80)

    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) >= 3:
            ts, user, event = parts[0], parts[1], parts[2]
            if any(k in event for k in ('FAIL', 'DENIED', 'PROBE', 'BRUTE', 'HIJACK', 'BLOCKED')):
                ec = RED
            elif any(k in event for k in ('INVALID', 'LOCKED')):
                ec = YELLOW
            elif event in ('LOGIN_SUCCESS', 'TRANSFER_SUCCESS'):
                ec = GREEN
            else:
                ec = DIM
            print(f"{DIM}{ts:<22}{RESET} {CYAN}{user:<16}{RESET} {ec}{event}{RESET}")
    print()

def cmd_watch():
    import time
    last_id = 0
    print(f"{BOLD}Watching security events on {PROFILE['host']}... (Ctrl+C to stop){RESET}\n")
    try:
        while True:
            out = db_query(f"""
                SELECT id, created_at, client_ip, IFNULL(username_snapshot, 'guest'), webpage
                FROM activity_logs
                WHERE id > {last_id}
                AND (webpage LIKE '%FAIL%' OR webpage LIKE '%DENIED%' OR webpage LIKE '%PROBE%'
                     OR webpage LIKE '%BRUTE%' OR webpage LIKE '%HIJACK%' OR webpage LIKE '%BLOCKED%'
                     OR webpage LIKE '%INVALID%' OR webpage LIKE 'TRANSFER_%')
                AND webpage != 'TRANSFER_SUCCESS'
                ORDER BY id ASC LIMIT 50
            """)
            if out and out.strip():
                for line in out.strip().split('\n')[1:]:
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        eid, ts, ip, user, event = parts[:5]
                        last_id = max(last_id, int(eid))
                        if any(k in event for k in ('PROBE', 'BRUTE', 'HIJACK')):
                            ec = RED + BOLD
                        elif any(k in event for k in ('FAIL', 'DENIED', 'BLOCKED')):
                            ec = RED
                        elif 'INVALID' in event or 'LOCKED' in event:
                            ec = YELLOW
                        else:
                            ec = DIM
                        print(f" {DIM}{ts}{RESET}  {CYAN}{ip:<18}{RESET} {DIM}{user:<14}{RESET} {ec}{event}{RESET}")
            time.sleep(5)
    except KeyboardInterrupt:
        print(f"\n{DIM}Stopped.{RESET}")


# ─── Profile Management ────────────────────────────────────────

def cmd_profile(args):
    config, _ = load_config()
    profiles = config.get("profiles", {})
    active = config.get("active", "")

    if not args:
        # Show current profiles
        print(f"\n{BOLD}Deployment Profiles:{RESET}\n")
        for name, p in profiles.items():
            marker = f" {GREEN}<- active{RESET}" if name == active else ""
            print(f"  {CYAN}{name:<15}{RESET} {p['ssh_user']}@{p['host']}{marker}")
        print(f"\n{DIM}  profile add <name>   — add a new deployment")
        print(f"  profile use <name>   — switch active profile")
        print(f"  profile edit <name>  — edit a profile")
        print(f"  profile remove <name> — remove a profile{RESET}\n")
        return

    subcmd = args[0].lower()

    if subcmd == "use" and len(args) > 1:
        name = args[1]
        if name not in profiles:
            print(f"{RED}Profile '{name}' not found.{RESET}")
            return
        config["active"] = name
        save_config(config)
        print(f"{GREEN}Switched to profile: {name} ({profiles[name]['ssh_user']}@{profiles[name]['host']}){RESET}")

    elif subcmd == "add" and len(args) > 1:
        name = re.sub(r'[^a-zA-Z0-9_\-]', '', args[1])
        print(f"\n{BOLD}Adding deployment profile: {name}{RESET}\n")
        p = {}
        p["name"] = name
        p["host"]         = input(f"  VM host/IP [{CYAN}10.0.0.1{RESET}]: ").strip() or "10.0.0.1"
        p["ssh_user"]     = input(f"  SSH user [{CYAN}ubuntu{RESET}]: ").strip() or "ubuntu"
        auth = input(f"  SSH auth - (k)ey or (p)assword? [{CYAN}k{RESET}]: ").strip().lower() or "k"
        if auth == "p":
            p["ssh_key"] = ""
            p["ssh_password"] = input(f"  SSH password: ").strip()
        else:
            default_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "transactiwar-vm_key.pem")
            p["ssh_key"]      = input(f"  SSH key path [{CYAN}{default_key}{RESET}]: ").strip() or default_key
            p["ssh_password"] = ""
        p["db_user"]      = input(f"  DB user [{CYAN}app_user{RESET}]: ").strip() or "app_user"
        p["db_pass"]       = input(f"  DB password [{CYAN}notsqlpassword{RESET}]: ").strip() or "notsqlpassword"
        p["db_name"]      = input(f"  DB name [{CYAN}app_database{RESET}]: ").strip() or "app_database"
        p["db_container"] = input(f"  DB container [{CYAN}team-17-db-1{RESET}]: ").strip() or "team-17-db-1"
        p["discord_webhook_alerts"]   = input(f"  Discord webhook (security alerts, blank to skip): ").strip()
        p["discord_webhook_timeouts"] = input(f"  Discord webhook (#timed-out-mfs, blank to skip): ").strip()

        profiles[name] = p
        config["profiles"] = profiles
        config["active"] = name
        save_config(config)
        print(f"\n{GREEN}Profile '{name}' created and set as active.{RESET}")

    elif subcmd == "edit" and len(args) > 1:
        name = args[1]
        if name not in profiles:
            print(f"{RED}Profile '{name}' not found.{RESET}")
            return
        p = profiles[name]
        print(f"\n{BOLD}Editing profile: {name}{RESET} (press Enter to keep current value)\n")
        p["host"]         = input(f"  VM host [{CYAN}{p.get('host','')}{RESET}]: ").strip() or p.get("host","")
        p["ssh_user"]     = input(f"  SSH user [{CYAN}{p.get('ssh_user','')}{RESET}]: ").strip() or p.get("ssh_user","")
        p["ssh_key"]      = input(f"  SSH key [{CYAN}{p.get('ssh_key','')}{RESET}]: ").strip() or p.get("ssh_key","")
        p["ssh_password"] = input(f"  SSH password [{CYAN}{'***' if p.get('ssh_password') else ''}{RESET}]: ").strip() or p.get("ssh_password","")
        p["db_user"]      = input(f"  DB user [{CYAN}{p.get('db_user','')}{RESET}]: ").strip() or p.get("db_user","")
        p["db_pass"]      = input(f"  DB password [{CYAN}***{RESET}]: ").strip() or p.get("db_pass","")
        p["db_name"]      = input(f"  DB name [{CYAN}{p.get('db_name','')}{RESET}]: ").strip() or p.get("db_name","")
        p["db_container"] = input(f"  DB container [{CYAN}{p.get('db_container','')}{RESET}]: ").strip() or p.get("db_container","")
        p["discord_webhook_alerts"]   = input(f"  Discord alerts webhook [{CYAN}{p.get('discord_webhook_alerts','')[:30]}...{RESET}]: ").strip() or p.get("discord_webhook_alerts","")
        p["discord_webhook_timeouts"] = input(f"  Discord timeouts webhook [{CYAN}{p.get('discord_webhook_timeouts','')[:30]}...{RESET}]: ").strip() or p.get("discord_webhook_timeouts","")
        profiles[name] = p
        save_config(config)
        print(f"\n{GREEN}Profile '{name}' updated.{RESET}")

    elif subcmd == "remove" and len(args) > 1:
        name = args[1]
        if name not in profiles:
            print(f"{RED}Profile '{name}' not found.{RESET}")
            return
        if len(profiles) <= 1:
            print(f"{RED}Cannot remove the last profile.{RESET}")
            return
        del profiles[name]
        if config["active"] == name:
            config["active"] = next(iter(profiles))
        save_config(config)
        print(f"{GREEN}Profile '{name}' removed.{RESET}")

    else:
        print(f"{YELLOW}Usage: profile [add|use|edit|remove] <name>{RESET}")


# ─── Interactive Menu ───────────────────────────────────────────

def interactive():
    global PROFILE
    PROFILE = get_active_profile()
    width = min(shutil.get_terminal_size().columns, 70)

    print(f"""
{BOLD}{'=' * width}
  TransactiWar IP Firewall Manager
  Target: {PROFILE.get('ssh_user','?')}@{PROFILE.get('host','?')} [{PROFILE.get('name','?')}]
{'=' * width}{RESET}

  {CYAN}block <ip> [duration] [reason]{RESET}  Block an IP
  {GREEN}unblock <ip>{RESET}                    Remove block
  {BLUE}list{RESET}                             Show blocked IPs + time remaining
  {YELLOW}status{RESET}                           Attack summary dashboard
  {MAGENTA}logs <ip>{RESET}                        Activity log for an IP
  {RED}watch{RESET}                            Live security event tail
  {DIM}profile{RESET}                          Manage deployment profiles
  {DIM}quit{RESET}                             Exit
""")

    while True:
        try:
            raw = input(f"{BOLD}firewall [{PROFILE.get('name','?')}]>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()

        if cmd in ('q', 'quit', 'exit'):
            break
        elif cmd == 'help':
            interactive()
            return
        elif cmd == 'block':
            if len(parts) < 2:
                print(f"{YELLOW}Usage: block <ip> [30m|2h|1d] [reason]{RESET}")
                continue
            ip = parts[1]
            dur = parts[2] if len(parts) > 2 and re.match(r'^\d+[mhd]', parts[2]) else None
            rs = 3 if dur else 2
            reason = ' '.join(parts[rs:]) if len(parts) > rs else "manual block"
            cmd_block(ip, dur, reason)
        elif cmd == 'unblock':
            if len(parts) < 2:
                print(f"{YELLOW}Usage: unblock <ip>{RESET}")
                continue
            cmd_unblock(parts[1])
        elif cmd == 'list':
            cmd_list()
        elif cmd == 'status':
            cmd_status()
        elif cmd == 'logs':
            if len(parts) < 2:
                print(f"{YELLOW}Usage: logs <ip>{RESET}")
                continue
            cmd_logs(parts[1])
        elif cmd == 'watch':
            cmd_watch()
        elif cmd == 'profile':
            cmd_profile(parts[1:])
            PROFILE = get_active_profile()
        else:
            print(f"{DIM}Unknown: {cmd}. Type 'help'.{RESET}")


# ─── Entry point ────────────────────────────────────────────────

def main():
    global PROFILE
    PROFILE = get_active_profile()

    if len(sys.argv) < 2:
        interactive()
        return

    cmd = sys.argv[1].lower()

    if cmd == 'block':
        if len(sys.argv) < 3:
            print(f"Usage: firewall.py block <ip> [duration] [reason]")
            sys.exit(1)
        ip = sys.argv[2]
        dur = sys.argv[3] if len(sys.argv) > 3 and re.match(r'^\d+[mhd]', sys.argv[3]) else None
        rs = 4 if dur else 3
        reason = ' '.join(sys.argv[rs:]) if len(sys.argv) > rs else "manual block"
        ensure_table()
        cmd_block(ip, dur, reason)
    elif cmd == 'unblock':
        if len(sys.argv) < 3:
            print(f"Usage: firewall.py unblock <ip>")
            sys.exit(1)
        ensure_table()
        cmd_unblock(sys.argv[2])
    elif cmd == 'list':
        cmd_list()
    elif cmd == 'status':
        cmd_status()
    elif cmd == 'logs':
        if len(sys.argv) < 3:
            print(f"Usage: firewall.py logs <ip>")
            sys.exit(1)
        cmd_logs(sys.argv[2])
    elif cmd == 'watch':
        cmd_watch()
    elif cmd == 'profile':
        cmd_profile(sys.argv[2:])
    else:
        print(f"Unknown: {cmd}")
        print(f"Commands: block, unblock, list, status, logs, watch, profile")
        sys.exit(1)

if __name__ == '__main__':
    main()
