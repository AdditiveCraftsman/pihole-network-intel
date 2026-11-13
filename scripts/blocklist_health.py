#!/usr/bin/env python3
"""
Blocklist health: warn when a blocklist silently stops working.

Pi-hole keeps going when a list fails to download (it just uses an old copy, or none),
so blocking can quietly get worse. This reads gravity.db (read-only) and reports:

  * enabled lists whose last download failed (status 3: old copy used, 4: no copy at all)
  * enabled lists holding 0 domains (never downloaded, empty, or in a format Pi-hole skips)
  * a sharp drop in the total number of blocked domains (gravity) since the last good run

adlist.status values, from the Pi-hole docs (docs.pi-hole.net/database/domain-database):
  1 downloaded OK | 2 unchanged upstream, local copy used
  3 unavailable, local copy used | 4 unavailable, no local copy

The last good domain count is kept in blocklist-health.json (the "baseline"). It only moves
up when a run is healthy, so a drop keeps warning every week until it recovers. If you
removed lists on purpose and the warning is now wrong:
    python3 scripts/blocklist_health.py reset

Standard library only. Called from network_intel_report.py.
"""

import json
import os
import sqlite3
import sys
from datetime import datetime
from html import escape

STATUS_PROBLEM = {
    3: "download failed, using an old copy",
    4: "download failed, no copy available",
}


def _short(address, limit=90):
    return address if len(address) <= limit else address[:limit - 1] + "…"


def _load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path, baseline):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"baseline": baseline, "date": datetime.now().strftime("%Y-%m-%d")}, fh, indent=2)
        fh.write("\n")


def _read_gravity(gravity_path):
    conn = sqlite3.connect(f"file:{gravity_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        lists = conn.execute("SELECT address, enabled, number, status FROM adlist").fetchall()
        total = conn.execute("SELECT COUNT(*) FROM gravity").fetchone()[0]
    finally:
        conn.close()
    return lists, total


def check(gravity_path, state_path=None, drop_pct=20):
    """Return {"total", "lists", "issues", "baseline"}. Never raises: a problem reading
    gravity.db is itself reported as an issue."""
    try:
        lists, total = _read_gravity(gravity_path)
    except (sqlite3.Error, OSError) as exc:
        return {"total": None, "lists": 0, "baseline": None,
                "issues": [f"could not read the blocklist database ({exc})"]}

    issues = []
    enabled = [l for l in lists if l["enabled"]]
    for l in enabled:
        name = _short(l["address"])
        if l["status"] in STATUS_PROBLEM:
            issues.append(f"{name}: {STATUS_PROBLEM[l['status']]}")
        elif l["number"] == 0:
            issues.append(f"{name}: 0 domains (never downloaded, empty, or unreadable)")

    state = _load_state(state_path) if state_path else {}
    baseline = state.get("baseline")
    dropped = bool(baseline) and total < baseline * (1 - drop_pct / 100.0)
    if dropped:
        pct = round((1 - total / baseline) * 100)
        issues.append(f"blocked domains fell to {total:,} from {baseline:,} (-{pct}%)")
    elif state_path:
        # Healthy enough to become the new reference point.
        if not issues or baseline is None or total >= baseline:
            _save_state(state_path, total)
            baseline = total
    return {"total": total, "lists": len(enabled), "issues": issues, "baseline": baseline}


def reset_baseline(gravity_path, state_path):
    _lists, total = _read_gravity(gravity_path)
    _save_state(state_path, total)
    return total


# ── RENDERING ────────────────────────────────────────────────────────────────

def render_html(result, section_style):
    if result is None:
        return ""
    if not result["issues"]:
        return (f'<tr><td style="padding:12px 32px 0"><div style="font-size:11px;color:#999">'
                f'Blocklists OK: {result["lists"]} enabled lists, {result["total"]:,} blocked domains.'
                f'</div></td></tr>')
    items = "".join(f'<li style="margin:3px 0">{escape(i)}</li>' for i in result["issues"])
    return (f'<tr><td style="padding:24px 32px 0"><div style="{section_style.format(c="#e63946")}">'
            f'── Blocklist Problem</div>'
            f'<div style="font-size:13px;color:#333;border:1px solid #f3c1c5;background:#fff5f5;'
            f'border-radius:6px;padding:10px 12px">Blocking may be weaker than usual:'
            f'<ul style="margin:6px 0 4px 18px;padding:0">{items}</ul>'
            f'<span style="font-size:11px;color:#999">Check with: sudo pihole -g, then look at '
            f'Group Management → Adlists in the Pi-hole dashboard.</span></div></td></tr>')


def render_text(result):
    if result is None:
        return []
    if not result["issues"]:
        return [f"  Blocklists    : OK ({result['lists']} lists, {result['total']:,} domains)"]
    return ["", "BLOCKLIST PROBLEM (blocking may be weaker than usual)"] + [f"  {i}" for i in result["issues"]]


# ── COMMAND LINE ─────────────────────────────────────────────────────────────

def _cli(argv):
    if len(argv) != 2 or argv[1] != "reset":
        print("Usage: python3 scripts/blocklist_health.py reset   "
              "(accept today's domain count as the new normal)")
        return 2
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from network_intel_report import gravity_path_for, health_state_path, load_config  # lazy import
    cfg = load_config()
    try:
        total = reset_baseline(gravity_path_for(cfg), health_state_path(cfg))
    except (sqlite3.Error, OSError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"Baseline reset to {total:,} domains.")
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
