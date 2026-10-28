#!/usr/bin/env python3
"""
Pi-hole Network Intelligence Report

Reads the Pi-hole v6 FTL database, builds an HTML + plain-text weekly report
(daily trend, hourly activity, per-device breakdown, top blocked/allowed
domains, DNS-bypass hints, silent devices) and emails it via Gmail SMTP.

Usage:
    python3 network_intel_report.py              # build, save text copy, email
    python3 network_intel_report.py --no-email   # build and save only
    python3 network_intel_report.py --demo       # fake data, safe for screenshots

Configuration lives in config/config.py (copy config/config.example.py).
"""

import argparse
import importlib.util
import os
import random
import smtplib
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(HERE)

# ── PI-HOLE QUERY STATUS CODES ────────────────────────────────────────────────
# Source: https://docs.pi-hole.net/database/query-database/
#   0 unknown | 1 gravity | 2 forwarded | 3 cache | 4 regex | 5 exact denylist
#   6/7/8 blocked by upstream | 9/10/11 blocked during CNAME inspection
#   12 retried | 13 retried but ignored | 14 already forwarded | 15 database busy
#   16 special domain | 17 stale cache | 18 blocked by upstream (EDE 15)
BLOCKED_STATUSES = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18}
ALLOWED_STATUSES = {2, 3, 12, 13, 14, 17}

DEFAULTS = {
    "DB_PATH": "/etc/pihole/pihole-FTL.db",
    "REPORT_DIR": os.path.join(BASE_DIR, "reports"),
    "GMAIL_FROM": "",
    "GMAIL_APP_PASSWORD": "",
    "GMAIL_TO": "",
    "DAYS_BACK": 7,
    "TIMEZONE": "UTC",
    "PIHOLE_IP": "",
    "LAB_NAME": "my network",
    "DEVICE_NAMES": {},
    "IGNORE_CLIENTS": ["127.0.0.1", "::1"],
    "EXPECTED_DEVICES": [],
    "BYPASS_MIN_QUERIES": 500,
    "BYPASS_MAX_BLOCK_PCT": 5.0,
}


# ── CONFIG ────────────────────────────────────────────────────────────────────

def load_config():
    """Load config/config.py (or $NETINTEL_CONFIG) over the defaults."""
    path = os.environ.get("NETINTEL_CONFIG") or os.path.join(BASE_DIR, "config", "config.py")
    path = os.path.abspath(path)
    if not os.path.exists(path):
        sys.exit(
            f"Config file not found: {path}\n"
            "Copy config/config.example.py to config/config.py and edit it."
        )
    spec = importlib.util.spec_from_file_location("netintel_config", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    cfg = dict(DEFAULTS)
    cfg.update({k: getattr(module, k) for k in dir(module) if k.isupper()})

    # An environment variable wins over the file, so the password can stay out of it.
    env_pw = os.environ.get("NETINTEL_GMAIL_PASSWORD")
    if env_pw:
        cfg["GMAIL_APP_PASSWORD"] = env_pw
    cfg["GMAIL_APP_PASSWORD"] = str(cfg["GMAIL_APP_PASSWORD"]).replace(" ", "")
    return cfg


def demo_config():
    """Config for --demo: fake network, no real values."""
    cfg = dict(DEFAULTS)
    cfg.update({
        "TIMEZONE": "UTC",
        "PIHOLE_IP": "192.168.1.2",
        "LAB_NAME": "demo lab",
        "DEVICE_NAMES": {
            "192.168.1.20": "Living Room TV",
            "192.168.1.21": "Bedroom TV",
            "192.168.1.30": "Alice's Phone",
            "192.168.1.31": "Bob's Laptop",
            "192.168.1.40": "Streaming Stick",
            "192.168.1.50": "Smart Speaker",
        },
        "EXPECTED_DEVICES": ["Bob's Laptop", "Garage Camera"],
    })
    return cfg


def get_tz(name):
    if ZoneInfo and name:
        try:
            return ZoneInfo(name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo


# ── DATA LAYER ────────────────────────────────────────────────────────────────

def get_window(days_back):
    now = datetime.now(timezone.utc)
    return int((now - timedelta(days=days_back)).timestamp()), int(now.timestamp())


def query_db(cfg, start, end):
    """Return (rows, hostnames) from the FTL database (opened read-only)."""
    db_path = cfg["DB_PATH"]
    if not os.path.exists(db_path):
        sys.exit(f"ERROR: FTL database not found at {db_path}")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT timestamp, status, domain, client FROM queries "
            "WHERE timestamp >= ? AND timestamp <= ?",
            (start, end),
        ).fetchall()

        # Hostnames Pi-hole has learned for each client IP (best effort).
        hostnames = {}
        try:
            for r in conn.execute(
                "SELECT ip, name FROM network_addresses "
                "WHERE name IS NOT NULL AND name != ''"
            ):
                hostnames[r["ip"]] = r["name"]
        except sqlite3.Error:
            pass
    finally:
        conn.close()
    return rows, hostnames


def analyse(rows, hostnames, cfg, tz):
    total = len(rows)
    blocked = sum(1 for r in rows if r["status"] in BLOCKED_STATUSES)
    allowed = sum(1 for r in rows if r["status"] in ALLOWED_STATUSES)
    block_pct = round(blocked / total * 100, 1) if total else 0.0

    blocked_domains, allowed_domains = defaultdict(int), defaultdict(int)
    device_stats = defaultdict(lambda: {"total": 0, "blocked": 0})
    hour_counts = defaultdict(int)
    day_counts = defaultdict(lambda: {"total": 0, "blocked": 0})

    for r in rows:
        is_blocked = r["status"] in BLOCKED_STATUSES
        if is_blocked:
            blocked_domains[r["domain"]] += 1
        elif r["status"] in ALLOWED_STATUSES:
            allowed_domains[r["domain"]] += 1

        d = device_stats[r["client"]]
        d["total"] += 1
        d["blocked"] += is_blocked

        local = datetime.fromtimestamp(r["timestamp"], tz=tz)
        hour_counts[local.hour] += 1
        day = day_counts[local.date()]
        day["total"] += 1
        day["blocked"] += is_blocked

    ignore = set(cfg["IGNORE_CLIENTS"]) | ({cfg["PIHOLE_IP"]} if cfg["PIHOLE_IP"] else set())

    device_rows = []
    seen_ids = set()
    for ip, s in sorted(device_stats.items(), key=lambda kv: kv[1]["total"], reverse=True):
        friendly = cfg["DEVICE_NAMES"].get(ip)
        host = hostnames.get(ip)
        name = friendly or host or ip
        seen_ids.update(x.lower() for x in (ip, friendly, host) if x)
        pct = round(s["blocked"] / s["total"] * 100, 1) if s["total"] else 0.0
        bypass = (
            ip not in ignore
            and s["total"] >= cfg["BYPASS_MIN_QUERIES"]
            and pct < cfg["BYPASS_MAX_BLOCK_PCT"]
        )
        device_rows.append((name, ip, s["total"], s["blocked"], pct, bypass))

    silent = [e for e in cfg["EXPECTED_DEVICES"] if e.lower() not in seen_ids]

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "block_pct": block_pct,
        "top_blocked": sorted(blocked_domains.items(), key=lambda x: x[1], reverse=True)[:15],
        "top_allowed": sorted(allowed_domains.items(), key=lambda x: x[1], reverse=True)[:15],
        "device_rows": device_rows,
        "hour_counts": hour_counts,
        "day_counts": dict(sorted(day_counts.items())),  # chronological
        "silent": silent,
    }


# ── DEMO DATA ─────────────────────────────────────────────────────────────────

def demo_rows(days_back):
    """Synthetic traffic so screenshots never contain real data."""
    rng = random.Random(42)
    now = int(datetime.now(timezone.utc).timestamp())
    clients = [
        ("192.168.1.20", 0.30, 0.18), ("192.168.1.21", 0.22, 0.25),
        ("192.168.1.30", 0.20, 0.12), ("192.168.1.40", 0.12, 0.02),
        ("192.168.1.50", 0.08, 0.15), ("192.168.1.2", 0.08, 0.0),
    ]
    blocked_dom = ["ads.example-tracker.net", "telemetry.smart-tv.example", "beacon.analytics.example",
                   "pixel.adnetwork.example", "metrics.video-app.example", "doubleclick.example"]
    allowed_dom = ["www.example.com", "video.streaming.example", "push.vendor.example",
                   "api.weather.example", "cdn.static.example", "mail.example.org", "time.example.net"]
    # Relative traffic by hour of day: quiet at night, busy in the evening.
    hour_weight = [0.15, 0.10, 0.08, 0.08, 0.10, 0.15, 0.30, 0.50, 0.60, 0.55, 0.50, 0.55,
                   0.60, 0.55, 0.50, 0.55, 0.65, 0.80, 0.95, 1.00, 0.95, 0.80, 0.50, 0.30]
    blocked_w = [30, 24, 18, 14, 9, 5]       # uneven, so the top lists look natural
    allowed_w = [30, 22, 18, 12, 9, 6, 3]

    rows = []
    while len(rows) < 20000:
        ts = now - rng.randint(0, days_back * 86400)
        if rng.random() > hour_weight[datetime.fromtimestamp(ts, tz=timezone.utc).hour]:
            continue  # rejection sampling gives the daily rhythm
        ip, _w, block_rate = rng.choices(clients, weights=[c[1] for c in clients])[0]
        is_blocked = rng.random() < block_rate
        domain = (rng.choices(blocked_dom, weights=blocked_w)[0] if is_blocked
                  else rng.choices(allowed_dom, weights=allowed_w)[0])
        rows.append({
            "timestamp": ts,
            "status": 1 if is_blocked else rng.choice([2, 3]),
            "domain": domain,
            "client": ip,
        })
    return rows


# ── HTML REPORT ───────────────────────────────────────────────────────────────

def bar(value, max_value, color, width=200):
    w = int((value / max_value) * width) if max_value else 0
    return (
        f'<span style="display:inline-block;width:{w}px;height:10px;background:{color};'
        f'border-radius:2px;vertical-align:middle;"></span>'
        f'&nbsp;<span style="font-size:12px;color:#555">{value:,}</span>'
    )


def trend_bar(blocked, total, width=120):
    b_w = int((blocked / total) * width) if total else 0
    return (
        f'<span style="display:inline-block;width:{b_w}px;height:8px;background:#e63946;'
        f'border-radius:2px 0 0 2px;vertical-align:middle;"></span>'
        f'<span style="display:inline-block;width:{width - b_w}px;height:8px;background:#2a9d8f;'
        f'border-radius:0 2px 2px 0;vertical-align:middle;"></span>'
    )


SECTION = ('font-family:\'Courier New\',monospace;color:{c};font-size:10px;letter-spacing:2px;'
           'text-transform:uppercase;margin-bottom:10px')
TH = 'padding:6px 10px;font-size:11px;color:#888;font-weight:normal'


def domain_table(items, color):
    top = items[0][1] if items else 1
    out = ""
    for i, (domain, count) in enumerate(items, 1):
        bg = "#fafafa" if i % 2 == 0 else "#ffffff"
        out += (
            f'<tr style="background:{bg}">'
            f'<td style="padding:6px 10px;font-size:12px;color:#888">{i}</td>'
            f'<td style="padding:6px 10px;font-size:13px;color:#333;font-family:monospace">{escape(domain)}</td>'
            f'<td style="padding:6px 10px">{bar(count, top, color)}</td></tr>'
        )
    return out


def make_html(stats, cfg, tz, start_ts, end_ts):
    fmt = "%b %d"
    start_str = datetime.fromtimestamp(start_ts, tz=tz).strftime(fmt)
    end_str = datetime.fromtimestamp(end_ts, tz=tz).strftime("%b %d, %Y")
    generated = datetime.now(tz).strftime("%Y-%m-%d %H:%M")
    ip_label = escape(cfg["PIHOLE_IP"] or "Pi-hole")

    day_rows = ""
    for day, d in stats["day_counts"].items():
        pct = round(d["blocked"] / d["total"] * 100, 1) if d["total"] else 0.0
        day_rows += (
            f'<tr><td style="padding:6px 10px;font-size:13px;color:#333;white-space:nowrap">{day.strftime("%a %b %d")}</td>'
            f'<td style="padding:6px 10px;text-align:right;font-size:13px;color:#333">{d["total"]:,}</td>'
            f'<td style="padding:6px 10px">{trend_bar(d["blocked"], d["total"])}</td>'
            f'<td style="padding:6px 10px;text-align:right;font-size:13px;color:#e63946">{pct}%</td></tr>'
        )

    device_rows = ""
    for name, ip, total, blocked, pct, bypass in stats["device_rows"]:
        flag = " 🚨" if bypass else ""
        device_rows += (
            f'<tr><td style="padding:7px 10px;font-size:13px;color:#333">{escape(name)}{flag}</td>'
            f'<td style="padding:7px 10px;font-size:11px;color:#888;font-family:monospace">{escape(ip)}</td>'
            f'<td style="padding:7px 10px;text-align:right;font-size:13px">{total:,}</td>'
            f'<td style="padding:7px 10px">{trend_bar(blocked, total)}</td>'
            f'<td style="padding:7px 10px;text-align:right;font-size:13px;color:#e63946">{pct}%</td></tr>'
        )

    max_h = max(stats["hour_counts"].values()) if stats["hour_counts"] else 1
    hour_cells = ""
    for h in range(24):
        intensity = int((stats["hour_counts"].get(h, 0) / max_h) * 200) if max_h else 0
        r, g, b = 230 - intensity, 57 - min(57, intensity // 4), 70 - min(70, intensity // 4)
        hour_cells += (
            f'<td style="text-align:center;padding:3px 2px">'
            f'<div style="width:22px;height:22px;background:rgb({max(50, r)},{max(0, g)},{max(0, b)});'
            f'border-radius:3px;margin:0 auto 2px auto;"></div>'
            f'<div style="font-size:9px;color:#999">{h:02d}</div></td>'
        )

    silent_html = ""
    if stats["silent"]:
        names = ", ".join(escape(n) for n in stats["silent"])
        silent_html = (
            f'<tr><td style="padding:24px 32px 0"><div style="{SECTION.format(c="#e63946")}">── Silent Devices</div>'
            f'<div style="font-size:13px;color:#333;border:1px solid #f3c1c5;background:#fff5f5;'
            f'border-radius:6px;padding:10px 12px">No queries this period from: <b>{names}</b>. '
            f'Check that their DNS still points at Pi-hole.</div></td></tr>'
        )

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Courier New',Courier,monospace">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:20px 0"><tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e0e0e0">

<tr><td style="background:#1a1a2e;padding:28px 32px">
  <div style="font-family:'Courier New',monospace;color:#e63946;font-size:11px;letter-spacing:3px;text-transform:uppercase">Pi-hole Network Intelligence</div>
  <div style="font-family:Georgia,serif;color:#ffffff;font-size:24px;margin:8px 0 4px">Weekly Report</div>
  <div style="font-family:'Courier New',monospace;color:#aaaacc;font-size:12px">{start_str} – {end_str} &nbsp;·&nbsp; {cfg["DAYS_BACK"]}-day window &nbsp;·&nbsp; {ip_label}</div>
</td></tr>

<tr><td style="padding:24px 32px 0"><table width="100%" cellpadding="0" cellspacing="0"><tr>
  <td width="33%" style="padding-right:8px"><div style="background:#1a1a2e;border-radius:6px;padding:16px;text-align:center">
    <div style="font-family:'Courier New',monospace;color:#aaaacc;font-size:10px;letter-spacing:2px;text-transform:uppercase">Total Queries</div>
    <div style="color:#ffffff;font-size:28px;font-weight:bold;margin-top:6px">{stats["total"]:,}</div></div></td>
  <td width="33%" style="padding:0 4px"><div style="background:#e63946;border-radius:6px;padding:16px;text-align:center">
    <div style="font-family:'Courier New',monospace;color:#ffcccc;font-size:10px;letter-spacing:2px;text-transform:uppercase">Blocked</div>
    <div style="color:#ffffff;font-size:28px;font-weight:bold;margin-top:6px">{stats["blocked"]:,}</div></div></td>
  <td width="33%" style="padding-left:8px"><div style="background:#2a9d8f;border-radius:6px;padding:16px;text-align:center">
    <div style="font-family:'Courier New',monospace;color:#ccfffa;font-size:10px;letter-spacing:2px;text-transform:uppercase">Block Rate</div>
    <div style="color:#ffffff;font-size:28px;font-weight:bold;margin-top:6px">{stats["block_pct"]}%</div></div></td>
</tr></table></td></tr>

<tr><td style="padding:24px 32px 0">
  <div style="{SECTION.format(c="#e63946")}">── Daily Traffic ({escape(str(cfg["TIMEZONE"]))})</div>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eeeeee;border-radius:6px;overflow:hidden">
    <tr style="background:#f7f7f7"><th style="{TH};text-align:left">Day</th><th style="{TH};text-align:right">Queries</th><th style="{TH}">Split</th><th style="{TH};text-align:right">Blocked %</th></tr>
    {day_rows}
  </table>
</td></tr>

<tr><td style="padding:24px 32px 0">
  <div style="{SECTION.format(c="#e63946")}">── Hourly Activity ({escape(str(cfg["TIMEZONE"]))}) — darker = more queries</div>
  <table cellpadding="0" cellspacing="2" style="width:100%"><tr>{hour_cells}</tr></table>
</td></tr>

<tr><td style="padding:24px 32px 0">
  <div style="{SECTION.format(c="#e63946")}">── Device Breakdown</div>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eeeeee;border-radius:6px;overflow:hidden">
    <tr style="background:#f7f7f7"><th style="{TH};text-align:left">Device</th><th style="{TH};text-align:left">IP</th><th style="{TH};text-align:right">Queries</th><th style="{TH}">Block/Allow</th><th style="{TH};text-align:right">Blocked</th></tr>
    {device_rows}
  </table>
  <div style="font-size:11px;color:#999;margin-top:6px">🚨 = high query volume with a suspiciously low block rate (possible DNS bypass)</div>
</td></tr>

{silent_html}

<tr><td style="padding:24px 32px 0">
  <div style="{SECTION.format(c="#e63946")}">── Top Blocked Domains (attempted)</div>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eeeeee;border-radius:6px;overflow:hidden">
    <tr style="background:#f7f7f7"><th style="{TH};text-align:left">#</th><th style="{TH};text-align:left">Domain</th><th style="{TH}">Hits</th></tr>
    {domain_table(stats["top_blocked"], "#e63946")}
  </table>
</td></tr>

<tr><td style="padding:24px 32px">
  <div style="{SECTION.format(c="#2a9d8f")}">── Top Allowed Domains (most queried)</div>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eeeeee;border-radius:6px;overflow:hidden">
    <tr style="background:#f7f7f7"><th style="{TH};text-align:left">#</th><th style="{TH};text-align:left">Domain</th><th style="{TH}">Hits</th></tr>
    {domain_table(stats["top_allowed"], "#2a9d8f")}
  </table>
</td></tr>

<tr><td style="background:#1a1a2e;padding:16px 32px;text-align:center">
  <div style="font-family:'Courier New',monospace;color:#555577;font-size:11px">
    Generated {generated} &nbsp;·&nbsp; Pi-hole v6 &nbsp;·&nbsp; {escape(cfg["LAB_NAME"])}
  </div>
</td></tr>

</table></td></tr></table>
</body></html>"""


# ── PLAIN TEXT ────────────────────────────────────────────────────────────────

def make_text(stats, cfg, tz, start_ts, end_ts):
    f = "%Y-%m-%d"
    lines = [
        "Pi-hole Network Intelligence Report",
        f"Period: {datetime.fromtimestamp(start_ts, tz=tz).strftime(f)} to {datetime.fromtimestamp(end_ts, tz=tz).strftime(f)}",
        f"Generated: {datetime.now(tz):%Y-%m-%d %H:%M}",
        "=" * 60,
        "",
        "SUMMARY",
        f"  Total queries : {stats['total']:,}",
        f"  Blocked       : {stats['blocked']:,}",
        f"  Allowed       : {stats['allowed']:,}",
        f"  Block rate    : {stats['block_pct']}%",
        "",
        "DAILY",
    ]
    for day, d in stats["day_counts"].items():
        pct = round(d["blocked"] / d["total"] * 100, 1) if d["total"] else 0.0
        lines.append(f"  {day:%a %b %d}  {d['total']:7,} queries  {pct:5.1f}% blocked")

    lines += ["", "DEVICES"]
    for name, ip, total, _b, pct, bypass in stats["device_rows"]:
        lines.append(f"  {name:<24} {ip:<16} {total:7,} queries  {pct:5.1f}% blocked{'  <-- possible bypass' if bypass else ''}")
    if stats["silent"]:
        lines += ["", "SILENT DEVICES (no queries this period)"] + [f"  {n}" for n in stats["silent"]]

    lines += ["", "TOP BLOCKED DOMAINS"]
    lines += [f"  {i:2}. {c:6,}  {d}" for i, (d, c) in enumerate(stats["top_blocked"], 1)]
    lines += ["", "TOP ALLOWED DOMAINS"]
    lines += [f"  {i:2}. {c:6,}  {d}" for i, (d, c) in enumerate(stats["top_allowed"], 1)]
    return "\n".join(lines) + "\n"


# ── OUTPUT ────────────────────────────────────────────────────────────────────

def save_text(report_dir, text, tz):
    os.makedirs(report_dir, exist_ok=True)
    path = os.path.join(report_dir, f"report-{datetime.now(tz):%Y-%m-%d}.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def send_email(cfg, html_body, text_body, subject):
    for key in ("GMAIL_FROM", "GMAIL_TO", "GMAIL_APP_PASSWORD"):
        if not cfg[key]:
            sys.exit(f"ERROR: {key} is not set (config/config.py or NETINTEL_GMAIL_PASSWORD).")

    msg = MIMEMultipart("alternative")
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["GMAIL_FROM"], cfg["GMAIL_TO"]
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))  # last part is preferred by clients

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(cfg["GMAIL_FROM"], cfg["GMAIL_APP_PASSWORD"])
        server.sendmail(cfg["GMAIL_FROM"], cfg["GMAIL_TO"], msg.as_string())


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Pi-hole weekly network intelligence report")
    ap.add_argument("--no-email", action="store_true", help="build and save, but do not send")
    ap.add_argument("--demo", action="store_true", help="use fake data (safe for screenshots); never emails")
    ap.add_argument("--html-out", metavar="PATH", help="also write the HTML report to PATH")
    args = ap.parse_args()

    cfg = demo_config() if args.demo else load_config()
    tz = get_tz(cfg["TIMEZONE"])
    print(f"[{datetime.now(tz)}] Starting Pi-hole intelligence report...")

    start_ts, end_ts = get_window(int(cfg["DAYS_BACK"]))
    if args.demo:
        rows, hostnames = demo_rows(int(cfg["DAYS_BACK"])), {}
    else:
        rows, hostnames = query_db(cfg, start_ts, end_ts)
    print(f"  Rows fetched: {len(rows):,}")
    if not rows:
        print("  No data in window. Exiting.")
        return 0

    stats = analyse(rows, hostnames, cfg, tz)
    html = make_html(stats, cfg, tz, start_ts, end_ts)
    text = make_text(stats, cfg, tz, start_ts, end_ts)

    html_out = args.html_out or ("demo-report.html" if args.demo else None)
    if html_out:
        with open(html_out, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"  HTML saved: {html_out}")

    if args.demo:
        print("Demo mode: nothing saved to report dir, nothing emailed.")
        return 0

    print(f"  Text report saved: {save_text(cfg['REPORT_DIR'], text, tz)}")

    if args.no_email:
        print("  --no-email set: skipping email.")
    else:
        subject = (f"Pi-hole Report — {stats['block_pct']}% blocked "
                   f"({stats['total']:,} queries, {cfg['DAYS_BACK']}-day window)")
        print(f"  Sending email to {cfg['GMAIL_TO']}...")
        send_email(cfg, html, text, subject)
        print("  Email sent.")
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
