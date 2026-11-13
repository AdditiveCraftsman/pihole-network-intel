#!/usr/bin/env python3
"""
Uncovered domains: what your devices contact that no blocklist covers.

A domain is "uncovered" for a device when Pi-hole ALLOWED its queries in the report
window. The query log status is the source of truth, so no blocklist matching is
reimplemented here (adblock lists match subdomains, plain lists are exact-only).

For each (device, domain) the module computes a transparent score from:
  volume, share of the device's traffic, beaconing (regular intervals),
  novelty (not seen before this window), name hints (telemetry, metrics, ...),
  and vendor context (first-party vs third-party to the device's brand).
It then suggests an action: candidate-block / investigate / keep.

Nothing is ever blocked automatically. The module only writes:
  candidates.txt      domain-per-line, review then append to your custom blocklist
  uncovered-DATE.csv  every finding, with its score and tags
  reviewed.json       your decisions (keep / block / investigate) so they stop repeating

Record a decision from the command line:
    python3 scripts/uncovered_domains.py review DOMAIN keep|block|investigate [note...]

Standard library only. Called from network_intel_report.py.
"""

import csv
import json
import math
import os
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from html import escape
from statistics import median

# ── DEFAULTS (all overridable in config/config.py) ───────────────────────────

# Domains your devices legitimately need. Matched as suffixes: "lge.com" would
# match every *.lge.com, so keep entries specific. Extend with NEEDED_DOMAINS.
DEFAULT_NEEDED = [
    # connectivity checks (Android / Google TV / Chromecast)
    "connectivitycheck.gstatic.com", "clients3.google.com", "clients4.google.com",
    # LG webOS firmware / OS update servers (left open on purpose for security patches)
    "snu.lge.com", "su.lge.com", "nsu.lge.com",
    # Netflix core (telemetry hosts such as ichnaea / customerevents are NOT listed)
    "www.netflix.com", "api-global.netflix.com", "secure.netflix.com",
    "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net",
    # time sync
    "ntp.org", "ntp.ubuntu.com", "time.nist.gov", "time.google.com", "time.apple.com",
    "time.android.com", "time.windows.com", "time.cloudflare.com",
]

# Local / reverse-lookup noise: kept in the CSV, never reported.
NOISE_SUFFIXES = ["arpa", "local", "lan", "localdomain", "internal", "home", "pi.hole"]

# Shared hosting: the registrable domain is meaningless (every tenant looks the
# same), so the whole hostname is the unit.
SHARED_HOSTING = [
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "windows.net",
    "googleusercontent.com", "appspot.com", "akamaiedge.net", "akamaized.net",
    "herokuapp.com", "fastly.net", "workers.dev", "github.io",
]

# Small built-in list of multi-part public suffixes (no public-suffix list in the
# standard library). Anything missing only affects the "family" column.
MULTI_TLDS = {
    "co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.kr", "com.mx", "co.nz",
    "com.cn", "co.in", "com.sg", "com.tr", "co.za", "com.pr", "net.pr", "org.pr",
}

# Tokens in a hostname label that hint at telemetry / tracking.
HINT_TOKENS = {
    "telemetry", "metric", "metrics", "analytics", "analytic", "track", "tracker",
    "tracking", "event", "events", "log", "logs", "logging", "crash", "crashlytics",
    "beacon", "beacons", "ad", "ads", "adserver", "sdk", "iot", "stat", "stats",
    "insight", "insights", "collect", "collector", "diag", "diagnostic",
    "diagnostics", "heartbeat", "ping", "tag", "tags", "pixel", "usage", "survey",
}

# Brand words used for first-party / third-party context (plus the MAC vendor).
KNOWN_BRANDS = {
    "lg", "samsung", "apple", "google", "nest", "amazon", "echo", "alexa", "roku",
    "onn", "walmart", "wyze", "ubox", "tplink", "asus", "microsoft", "windows",
    "sony", "vizio", "philips", "xiaomi", "huawei", "oppo", "realme", "creality",
}
_VENDOR_STOP = {
    "inc", "co", "ltd", "llc", "corp", "corporation", "company", "technology",
    "technologies", "electronics", "electronic", "international", "the", "limited",
    "gmbh", "group", "industries", "digital", "network", "networks", "systems",
    "communications", "communication", "wireless", "unknown", "innotek",
}

ACTIONS_SHOWN = ("candidate-block", "investigate")


# ── HELPERS ──────────────────────────────────────────────────────────────────

def _suffix_match(domain, suffixes):
    return any(domain == s or domain.endswith("." + s) for s in suffixes)


def family_of(domain):
    """Registrable-ish domain (e.g. us.nextlgsdp.com -> nextlgsdp.com)."""
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    if _suffix_match(domain, SHARED_HOSTING):
        return domain
    if ".".join(labels[-2:]) in MULTI_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def hint_tags(domain):
    """Telemetry-ish tokens in the hostname (TLD excluded)."""
    found = []
    for label in domain.split(".")[:-1]:
        for tok in re.split(r"[^a-z]+", label):
            if tok in HINT_TOKENS and tok not in found:
                found.append(tok)
    return found


def beacon_info(timestamps):
    """Return (median_gap_seconds, regularity) if queries look periodic, else None.

    Bursts (A + AAAA, retries within 5 s) collapse into one event. Regularity is the
    share of gaps within +-30% of the median gap, so idle nights do not hide a beacon.
    """
    if len(timestamps) < 20:
        return None
    ts = sorted(timestamps)
    events = [ts[0]]
    for t in ts[1:]:
        if t - events[-1] > 5:
            events.append(t)
    gaps = [b - a for a, b in zip(events, events[1:])]
    if len(gaps) < 15:
        return None
    m = median(gaps)
    if m <= 0:
        return None
    regular = sum(1 for g in gaps if 0.7 * m <= g <= 1.3 * m) / len(gaps)
    return (m, regular) if regular >= 0.5 else None


def fmt_interval(seconds):
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def vendor_words(vendor, name):
    words = set()
    for tok in re.split(r"[^a-z0-9]+", (vendor or "").lower()):
        if len(tok) >= 2 and tok not in _VENDOR_STOP:
            words.add(tok)
    for tok in re.split(r"[^a-z0-9]+", (name or "").lower()):
        if tok in KNOWN_BRANDS:
            words.add(tok)
    return words


def vendor_relation(domain, words):
    """first-party / third-party / None (unknown vendor)."""
    if not words:
        return None
    return "first-party" if any(w in domain for w in words) else "third-party"


# ── REVIEW LOG (reviewed.json) ───────────────────────────────────────────────

def load_reviewed(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_reviewed(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def record_review(path, domain, decision, note=""):
    if decision not in ("keep", "block", "investigate"):
        raise ValueError("decision must be keep, block or investigate")
    data = load_reviewed(path)
    data[domain.lower().rstrip(".")] = {
        "decision": decision,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "note": note,
    }
    save_reviewed(path, data)


def _review_for(domain, reviewed):
    """Most specific reviewed entry for domain or a parent domain."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        hit = reviewed.get(".".join(labels[i:]))
        if hit:
            return hit
    return None


# ── DEVICE MAP (IP -> MAC) ───────────────────────────────────────────────────

def load_devices(conn, cfg):
    """Map each client IP to a stable device (keyed by MAC when Pi-hole knows it).

    IPs change (a TV can hop between addresses); the MAC does not.
    Returns ip -> {"key", "name", "vendor", "ips"}.
    """
    by_key = {}
    try:
        rows = conn.execute(
            "SELECT n.hwaddr, n.macVendor, a.ip, a.name, a.lastSeen "
            "FROM network n JOIN network_addresses a ON a.network_id = n.id"
        ).fetchall()
    except sqlite3.Error:
        return {}
    for hw, vendor, ip, name, last_seen in rows:
        dev = by_key.setdefault(hw.lower(), {"key": hw.lower(), "vendor": vendor or "", "addrs": []})
        dev["addrs"].append((last_seen or 0, ip, name or ""))

    friendly = cfg.get("DEVICE_NAMES", {})
    ip_map = {}
    for dev in by_key.values():
        dev["addrs"].sort(reverse=True)  # most recently seen first
        dev["ips"] = [a[1] for a in dev["addrs"]]
        name = next((friendly[ip] for ip in dev["ips"] if ip in friendly), "")
        name = name or next((a[2] for a in dev["addrs"] if a[2]), "")
        dev["name"] = name or dev["vendor"] or dev["ips"][0]
        for ip in dev["ips"]:
            ip_map[ip] = dev
    return ip_map


# ── MAIN ANALYSIS ────────────────────────────────────────────────────────────

def build(rows, cfg, start_ts, blocked_statuses, allowed_statuses, reviewed=None):
    """Analyse already-fetched query rows. Opens the DB read-only for the MAC map
    and the novelty check; with no database (demo mode) those are skipped."""
    top_n = int(cfg.get("UNCOVERED_TOP_N", 8))
    min_q = int(cfg.get("UNCOVERED_MIN_QUERIES", 10))
    thr_block = int(cfg.get("UNCOVERED_BLOCK_SCORE", 55))
    thr_invest = int(cfg.get("UNCOVERED_INVESTIGATE_SCORE", 30))
    needed = DEFAULT_NEEDED + [d.lower().rstrip(".") for d in cfg.get("NEEDED_DOMAINS", [])]
    reviewed = reviewed or {}
    # Devices to leave out entirely (general-purpose machines whose app traffic looks like
    # beaconing): match by friendly name, hostname, IP or MAC, case-insensitive.
    skip = {str(x).strip().lower() for x in cfg.get("UNCOVERED_SKIP", []) if str(x).strip()}
    ignore = set(cfg.get("IGNORE_CLIENTS", [])) | ({cfg["PIHOLE_IP"]} if cfg.get("PIHOLE_IP") else set())
    db_path = cfg.get("DB_PATH") if not cfg.get("_DEMO") else None

    ip_map, seen_before, history_known = {}, set(), False
    if db_path and os.path.exists(db_path):
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            ip_map = load_devices(conn, cfg)
            # One pass over pre-window history (the queries view is slow to probe per domain).
            first = conn.execute("SELECT MIN(timestamp) FROM queries").fetchone()[0]
            if first is not None and first < start_ts - 86400:
                history_known = True
                seen_before = {r[0].lower().rstrip(".") for r in
                               conn.execute("SELECT DISTINCT domain FROM queries WHERE timestamp < ?", (start_ts,))}
        except sqlite3.Error:
            pass
        finally:
            conn.close()

    friendly = cfg.get("DEVICE_NAMES", {})
    devices = {}                     # key -> {"name","vendor","ips","total"}
    agg = {}                         # (key, domain) -> stats

    for r in rows:
        ip = r["client"]
        if ip in ignore:
            continue
        status = r["status"]
        is_blocked = status in blocked_statuses
        if not is_blocked and status not in allowed_statuses:
            continue
        dev = ip_map.get(ip)
        key = dev["key"] if dev else ip
        if skip:
            label = (dev["name"] if dev else friendly.get(ip, ip)).lower()
            if skip & {ip.lower(), key.lower(), label}:
                continue
        d = devices.get(key)
        if d is None:
            d = devices[key] = {
                "name": dev["name"] if dev else friendly.get(ip, ip),
                "vendor": dev["vendor"] if dev else "",
                "ips": set(), "total": 0,
            }
        d["ips"].add(ip)
        d["total"] += 1

        domain = (r["domain"] or "").lower().rstrip(".")
        a = agg.get((key, domain))
        if a is None:
            a = agg[(key, domain)] = {"allowed": 0, "blocked": 0, "ts": [],
                                      "first": r["timestamp"], "last": r["timestamp"],
                                      "last_blocked": is_blocked}
        ts = r["timestamp"]
        if is_blocked:
            a["blocked"] += 1
        else:
            a["allowed"] += 1
            a["ts"].append(ts)
        a["first"] = min(a["first"], ts)
        if ts >= a["last"]:
            a["last"], a["last_blocked"] = ts, is_blocked

    findings = []
    for (key, domain), a in agg.items():
        if a["allowed"] < 1:
            continue
        dev = devices[key]
        total_q = a["allowed"] + a["blocked"]
        f = {
            "device": dev["name"], "device_key": key, "ips": sorted(dev["ips"]),
            "domain": domain, "family": family_of(domain),
            "allowed": a["allowed"], "blocked": a["blocked"],
            "blocked_pct": round(a["blocked"] / total_q * 100, 1),
            "share_pct": round(a["allowed"] / dev["total"] * 100, 2) if dev["total"] else 0.0,
            "first_seen": a["first"], "last_seen": a["last"],
            "new": None, "beacon_s": "", "hints": [], "vendor_relation": "",
            "score": 0, "action": "keep", "note": "",
        }
        findings.append(f)

        # Exclusions first: these never get a suggested action.
        if "." not in domain or _suffix_match(domain, NOISE_SUFFIXES):
            f["action"], f["note"] = "noise", "local / reverse lookup"
            continue
        if _suffix_match(domain, needed):
            f["action"], f["note"] = "needed", "on the needed list"
            continue
        if agg[(key, domain)]["last_blocked"]:
            f["action"], f["note"] = "covered-now", "latest query was blocked"
            continue
        rv = _review_for(domain, reviewed)
        if rv and rv.get("decision") in ("keep", "block"):
            f["action"] = "reviewed-keep" if rv["decision"] == "keep" else "approved-block-pending"
            f["note"] = f"{rv['decision']} {rv.get('date', '')} {rv.get('note', '')}".strip()
            continue
        if a["allowed"] < min_q:
            f["note"] = "below minimum volume"
            continue

        # Scoring (each term is shown in the CSV via its tag, so a score can be explained).
        score = min(30, int(10 * math.log10(a["allowed"])))
        score += min(10, int(round(f["share_pct"])))
        beacon = beacon_info(a["ts"])
        if beacon:
            f["beacon_s"] = round(beacon[0])
            score += 15
        if history_known:
            f["new"] = domain not in seen_before
            if f["new"]:
                score += 10
        f["hints"] = hint_tags(domain)
        score += 8 * min(2, len(f["hints"]))
        rel = vendor_relation(domain, vendor_words(dev["vendor"], dev["name"]))
        f["vendor_relation"] = rel or ""
        if rel == "third-party":
            score += 8
        f["score"] = score

        # Evidence vs context. A telemetry-like name or a regular beat is evidence; being
        # third-party or new is only context. Volume, third-party or new alone never flag a
        # domain (a busy site is not a tracker). A candidate-block needs a name hint, or a
        # beacon that is also third-party or new; a first-party beacon stays at "investigate"
        # so OS-critical hosts are not proposed for blocking.
        evidence = bool(f["hints"]) or bool(beacon)
        escalate = bool(f["hints"]) or (bool(beacon) and (rel == "third-party" or bool(f["new"])))
        if score >= thr_block and escalate:
            f["action"] = "candidate-block"
        elif score >= thr_invest and evidence:
            f["action"] = "investigate"
        if rv and rv.get("decision") == "investigate":
            f["note"] = f"investigating since {rv.get('date', '')} {rv.get('note', '')}".strip()

    findings.sort(key=lambda f: (f["device"].lower(), -f["score"], -f["allowed"]))

    by_dev = defaultdict(list)
    for f in findings:
        if f["action"] in ACTIONS_SHOWN:
            by_dev[f["device_key"]].append(f)
    shown = []
    for key, items in by_dev.items():
        items.sort(key=lambda f: (-f["score"], -f["allowed"]))
        shown.append({
            "name": devices[key]["name"], "key": key, "ips": sorted(devices[key]["ips"]),
            "total": devices[key]["total"],
            "findings": items[:top_n], "more": max(0, len(items) - top_n),
        })
    shown.sort(key=lambda d: -d["total"])

    candidates = sorted({f["domain"] for f in findings if f["action"] == "candidate-block"})
    pending = sorted({f["domain"] for f in findings if f["action"] == "approved-block-pending"})
    return {
        "devices": shown, "all": findings, "candidates": candidates,
        "approved_pending": pending, "history_known": history_known,
        "thresholds": (thr_block, thr_invest),
    }


# ── OUTPUT FILES ─────────────────────────────────────────────────────────────

def write_outputs(result, out_dir, tz):
    """Write candidates.txt (never applied automatically) and the dated CSV."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(tz).strftime("%Y-%m-%d")

    cand_path = os.path.join(out_dir, "candidates.txt")
    with open(cand_path, "w", encoding="utf-8") as fh:
        fh.write(f"# Block candidates from {stamp}. NOT applied automatically.\n"
                 "# Review each line, test for breakage, then append the ones you approve to your\n"
                 "# custom blocklist and run: sudo pihole -g\n")
        for d in result["candidates"]:
            fh.write(d + "\n")

    csv_path = os.path.join(out_dir, f"uncovered-{stamp}.csv")
    cols = ["device", "device_key", "domain", "family", "allowed", "blocked", "blocked_pct",
            "share_pct", "first_seen", "last_seen", "new", "beacon_s", "hints",
            "vendor_relation", "score", "action", "note"]
    with open(csv_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in result["all"]:
            row = []
            for c in cols:
                v = f[c]
                if c in ("first_seen", "last_seen"):
                    v = datetime.fromtimestamp(v, tz=tz).strftime("%Y-%m-%d %H:%M")
                elif c == "hints":
                    v = " ".join(v)
                elif c == "new":
                    v = "" if v is None else int(v)
                row.append(v)
            w.writerow(row)
    return cand_path, csv_path


# ── RENDERING ────────────────────────────────────────────────────────────────

_ACTION_COLOR = {"candidate-block": "#e63946", "investigate": "#e9a23b"}


def _tags(f):
    tags = list(f["hints"])
    if f["beacon_s"] != "":
        tags.append(f"beacon~{fmt_interval(f['beacon_s'])}")
    if f["new"]:
        tags.append("new")
    if f["vendor_relation"]:
        tags.append(f["vendor_relation"])
    return tags


def render_html(result, tz, section_style, th_style):
    if result is None:
        return ""
    head = (f'<tr><td style="padding:24px 32px 0"><div style="{section_style.format(c="#e9a23b")}">'
            f'── Uncovered Domains (allowed, not on any blocklist)</div>')
    if not result["devices"]:
        return head + ('<div style="font-size:13px;color:#555">Nothing to review this week.</div>'
                       '</td></tr>')
    out = [head,
           '<div style="font-size:11px;color:#999;margin-bottom:8px">Review only: nothing is blocked '
           'automatically. Test any candidate for breakage before adding it to your custom blocklist.</div>']
    if not result["history_known"]:
        out.append('<div style="font-size:11px;color:#999;margin-bottom:8px">Not enough history yet '
                   'to flag new domains.</div>')
    if result["approved_pending"]:
        n = len(result["approved_pending"])
        out.append(f'<div style="font-size:12px;color:#b36b00;margin-bottom:8px">{n} domain(s) you approved '
                   f'for blocking are still being allowed: apply them to your custom blocklist.</div>')
    for dev in result["devices"]:
        out.append(
            f'<div style="font-size:12px;color:#333;margin:10px 0 4px"><b>{escape(dev["name"])}</b> '
            f'<span style="color:#999">{escape(", ".join(dev["ips"]))}</span></div>'
            f'<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eeeeee;'
            f'border-radius:6px;overflow:hidden"><tr style="background:#f7f7f7">'
            f'<th style="{th_style};text-align:left">Domain</th><th style="{th_style};text-align:right">Queries</th>'
            f'<th style="{th_style};text-align:left">Tags</th><th style="{th_style};text-align:right">Score</th>'
            f'<th style="{th_style};text-align:left">Suggest</th></tr>')
        for i, f in enumerate(dev["findings"]):
            bg = "#fafafa" if i % 2 else "#ffffff"
            color = _ACTION_COLOR.get(f["action"], "#555")
            out.append(
                f'<tr style="background:{bg}">'
                f'<td style="padding:5px 10px;font-size:12px;color:#333;font-family:monospace;word-break:break-all">{escape(f["domain"])}</td>'
                f'<td style="padding:5px 10px;text-align:right;font-size:12px">{f["allowed"]:,}</td>'
                f'<td style="padding:5px 10px;font-size:11px;color:#777">{escape(" ".join(_tags(f)))}</td>'
                f'<td style="padding:5px 10px;text-align:right;font-size:12px">{f["score"]}</td>'
                f'<td style="padding:5px 10px;font-size:11px;color:{color};white-space:nowrap">{f["action"]}</td></tr>')
        out.append("</table>")
        if dev["more"]:
            out.append(f'<div style="font-size:11px;color:#999;margin-top:4px">+{dev["more"]} more in the CSV</div>')
    out.append("</td></tr>")
    return "".join(out)


def render_text(result):
    if result is None:
        return []
    lines = ["", "UNCOVERED DOMAINS (allowed, not on any blocklist; review only)"]
    if not result["devices"]:
        return lines + ["  Nothing to review this week."]
    if result["approved_pending"]:
        lines.append(f"  {len(result['approved_pending'])} approved-for-block domain(s) still allowed: apply them.")
    for dev in result["devices"]:
        lines.append(f"  {dev['name']} ({', '.join(dev['ips'])})")
        for f in dev["findings"]:
            tags = " ".join(_tags(f))
            lines.append(f"    {f['allowed']:7,}  {f['domain']:<44} score {f['score']:3}  {f['action']:<15} {tags}")
        if dev["more"]:
            lines.append(f"    +{dev['more']} more in the CSV")
    return lines


# ── COMMAND LINE: record a review decision ───────────────────────────────────

def _cli(argv):
    if len(argv) < 4 or argv[1] != "review":
        print(__doc__.split("Record a decision")[1].split("Standard library")[0].strip())
        return 2
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from network_intel_report import load_config  # lazy: avoids a circular import
    cfg = load_config()
    out_dir = cfg.get("UNCOVERED_DIR") or os.path.join(cfg["REPORT_DIR"], "uncovered")
    path = os.path.join(out_dir, "reviewed.json")
    try:
        record_review(path, argv[2], argv[3], " ".join(argv[4:]))
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 2
    print(f"Recorded: {argv[2]} -> {argv[3]} ({path})")
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
