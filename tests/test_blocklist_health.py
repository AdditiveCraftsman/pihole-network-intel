"""
Tests for the blocklist-health warning. Standard library only:
    python3 -m unittest discover -s tests -v

They build a throwaway gravity.db with the same adlist/gravity layout as Pi-hole v6.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, HERE)

import blocklist_health as bh  # noqa: E402
import test_uncovered_domains as tud  # noqa: E402  (reuses its FTL database builder)


def make_gravity(path, lists, domains=1000):
    """lists: (address, enabled, number, status). Adds `domains` rows to the gravity table."""
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE adlist (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1, date_added INTEGER NOT NULL DEFAULT 0,
            date_modified INTEGER NOT NULL DEFAULT 0, comment TEXT, date_updated INTEGER,
            number INTEGER NOT NULL DEFAULT 0, invalid_domains INTEGER NOT NULL DEFAULT 0,
            status INTEGER NOT NULL DEFAULT 0, abp_entries INTEGER NOT NULL DEFAULT 0,
            type INTEGER NOT NULL DEFAULT 0, UNIQUE(address, type));
        CREATE TABLE gravity (domain TEXT NOT NULL, adlist_id INTEGER NOT NULL);
    """)
    c.executemany("INSERT INTO adlist(address, enabled, number, status) VALUES (?,?,?,?)", lists)
    c.executemany("INSERT INTO gravity VALUES (?, 1)", [(f"d{i}.example",) for i in range(domains)])
    c.commit()
    c.close()


GOOD = [("https://lists.example/pro.txt", 1, 900, 1), ("file:///etc/pihole/lists/custom.txt", 1, 26, 2)]


class BlocklistHealthTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.grav = os.path.join(self.tmp.name, "gravity.db")
        self.state = os.path.join(self.tmp.name, "state", "blocklist-health.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_healthy(self):
        make_gravity(self.grav, GOOD)
        r = bh.check(self.grav, self.state)
        self.assertEqual(r["issues"], [])
        self.assertEqual((r["lists"], r["total"], r["baseline"]), (2, 1000, 1000))

    def test_failed_downloads_are_flagged(self):
        make_gravity(self.grav, GOOD + [("https://gone.example/a.txt", 1, 500, 3),
                                        ("https://gone.example/b.txt", 1, 0, 4)])
        issues = bh.check(self.grav)["issues"]
        self.assertEqual(len(issues), 2)
        self.assertIn("old copy", issues[0])
        self.assertIn("no copy", issues[1])

    def test_empty_enabled_list_flagged_but_disabled_ignored(self):
        make_gravity(self.grav, GOOD + [("https://empty.example/x.txt", 1, 0, 0),
                                        ("https://off.example/y.txt", 0, 0, 4)])
        issues = bh.check(self.grav)["issues"]
        self.assertEqual(len(issues), 1)
        self.assertIn("empty.example", issues[0])

    def test_drop_warns_until_recovery_then_baseline_moves(self):
        make_gravity(self.grav, GOOD, domains=1000)
        bh.check(self.grav, self.state)                                 # baseline 1000
        os.remove(self.grav)
        make_gravity(self.grav, GOOD, domains=300)                      # the Hagezi-style collapse
        for _ in range(2):                                              # keeps warning, baseline not lowered
            r = bh.check(self.grav, self.state)
            self.assertTrue(any("fell to 300 from 1,000" in i for i in r["issues"]), r)
        os.remove(self.grav)
        make_gravity(self.grav, GOOD, domains=950)                      # recovered
        r = bh.check(self.grav, self.state)
        self.assertEqual(r["issues"], [])
        self.assertEqual(r["baseline"], 950)

    def test_small_decline_is_not_a_warning(self):
        make_gravity(self.grav, GOOD, domains=1000)
        bh.check(self.grav, self.state)
        os.remove(self.grav)
        make_gravity(self.grav, GOOD, domains=900)                      # -10%, under the 20% default
        self.assertEqual(bh.check(self.grav, self.state)["issues"], [])

    def test_reset_accepts_new_normal(self):
        make_gravity(self.grav, GOOD, domains=1000)
        bh.check(self.grav, self.state)
        os.remove(self.grav)
        make_gravity(self.grav, GOOD, domains=300)
        self.assertTrue(bh.check(self.grav, self.state)["issues"])
        self.assertEqual(bh.reset_baseline(self.grav, self.state), 300)
        self.assertEqual(bh.check(self.grav, self.state)["issues"], [])

    def test_unreadable_database_is_reported_not_raised(self):
        r = bh.check(os.path.join(self.tmp.name, "missing.db"), self.state)
        self.assertEqual(len(r["issues"]), 1)
        self.assertIn("could not read", r["issues"][0])

    def test_rendering(self):
        ok = {"total": 1000, "lists": 2, "issues": [], "baseline": 1000}
        bad = {"total": 300, "lists": 2, "issues": ["<b>x</b>: download failed"], "baseline": 1000}
        style = "color:{c}"
        self.assertIn("Blocklists OK", bh.render_html(ok, style))
        html = bh.render_html(bad, style)
        self.assertIn("Blocklist Problem", html)
        self.assertNotIn("<b>x</b>", html)                              # escaped
        self.assertEqual(bh.render_html(None, style), "")
        self.assertIn("BLOCKLIST PROBLEM", "\n".join(bh.render_text(bad)))

    def test_end_to_end_report_shows_problem(self):
        now = int(time.time())
        ftl = os.path.join(self.tmp.name, "pihole-FTL.db")
        tud.make_db(ftl, now)
        make_gravity(os.path.join(self.tmp.name, "gravity.db"),
                     GOOD + [("https://gone.example/a.txt", 1, 0, 4)])
        out = os.path.join(self.tmp.name, "reports")
        cfg_path = os.path.join(self.tmp.name, "config.py")
        with open(cfg_path, "w") as fh:
            fh.write(f"DB_PATH = {ftl!r}\nREPORT_DIR = {out!r}\nPIHOLE_IP = '10.0.0.2'\n")
        proc = subprocess.run([sys.executable, os.path.join(SCRIPTS, "network_intel_report.py"), "--no-email"],
                              env=dict(os.environ, NETINTEL_CONFIG=cfg_path), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        txt = [f for f in os.listdir(out) if f.endswith(".txt")][0]
        with open(os.path.join(out, txt)) as fh:
            body = fh.read()
        self.assertIn("BLOCKLIST PROBLEM", body)
        self.assertIn("gone.example", body)
        self.assertTrue(os.path.exists(os.path.join(out, "blocklist-health.json")))

    def test_end_to_end_without_gravity_db_still_reports(self):
        now = int(time.time())
        ftl = os.path.join(self.tmp.name, "pihole-FTL.db")
        tud.make_db(ftl, now)                                           # no gravity.db next to it
        out = os.path.join(self.tmp.name, "reports")
        cfg_path = os.path.join(self.tmp.name, "config.py")
        with open(cfg_path, "w") as fh:
            fh.write(f"DB_PATH = {ftl!r}\nREPORT_DIR = {out!r}\nPIHOLE_IP = '10.0.0.2'\n")
        proc = subprocess.run([sys.executable, os.path.join(SCRIPTS, "network_intel_report.py"), "--no-email"],
                              env=dict(os.environ, NETINTEL_CONFIG=cfg_path), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        txt = [f for f in os.listdir(out) if f.endswith(".txt")][0]
        with open(os.path.join(out, txt)) as fh:
            self.assertIn("could not read the blocklist database", fh.read())


if __name__ == "__main__":
    unittest.main()
