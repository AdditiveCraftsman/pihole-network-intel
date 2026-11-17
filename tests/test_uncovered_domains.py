"""
Tests for the uncovered-domains report. Standard library only:
    python3 -m unittest discover -s tests -v

They build a throwaway SQLite database with the same tables/view Pi-hole v6 uses
(queries view, network, network_addresses) and fill it with synthetic traffic modelled
on a smart TV: periodic phone-home hosts, a needed-list, blocked telemetry, and one
device that changes IP. No real network data is involved.
"""

import csv
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

import uncovered_domains as ud  # noqa: E402

BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18}
ALLOWED = {2, 3, 12, 13, 14, 17}
TV_MAC = "aa:bb:cc:00:11:22"
DAY = 86400


def make_db(path, now):
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT);
        CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT);
        CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT);
        CREATE TABLE addinfo_by_id (id INTEGER PRIMARY KEY, content BLOB);
        CREATE TABLE query_storage (id INTEGER PRIMARY KEY, timestamp INTEGER, type INTEGER,
            status INTEGER, domain INTEGER, client INTEGER, forward INTEGER, additional_info INTEGER,
            reply_type INTEGER, reply_time REAL, dnssec INTEGER, list_id INTEGER, ede INTEGER);
        CREATE VIEW queries AS SELECT q.id, q.timestamp, q.type, q.status,
            COALESCE(d.domain, q.domain) AS domain, COALESCE(c.ip, q.client) AS client,
            COALESCE(f.forward, q.forward) AS forward, COALESCE(a.content, q.additional_info) AS additional_info,
            q.reply_type, q.reply_time, q.dnssec, q.list_id, q.ede
            FROM query_storage q LEFT JOIN domain_by_id d ON q.domain = d.id
            LEFT JOIN client_by_id c ON q.client = c.id LEFT JOIN forward_by_id f ON q.forward = f.id
            LEFT JOIN addinfo_by_id a ON q.additional_info = a.id;
        CREATE TABLE network (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL,
            interface TEXT NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL,
            numQueries INTEGER NOT NULL, macVendor TEXT, aliasclient_id INTEGER);
        CREATE TABLE network_addresses (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL,
            lastSeen INTEGER NOT NULL, name TEXT, nameUpdated INTEGER);
    """)
    c.execute("INSERT INTO network VALUES (1, ?, 'eth0', ?, ?, 0, 'LG Electronics', NULL)",
              (TV_MAC, now - 30 * DAY, now))
    # Same TV on two IPs (it moved), plus a laptop with no MAC row.
    c.execute("INSERT INTO network_addresses VALUES (1, '10.0.0.200', ?, 'lg-tv', ?)", (now, now))
    c.execute("INSERT INTO network_addresses VALUES (1, '10.0.0.6', ?, 'old-name', ?)", (now - 3 * DAY, now))

    ids = {"d": {}, "c": {}}
    batch = []

    def ident(kind, table, col, value):
        if value not in ids[kind]:
            cur = c.execute(f"INSERT INTO {table}({col}) VALUES (?)", (value,))
            ids[kind][value] = cur.lastrowid
        return ids[kind][value]

    def add(ts, status, domain, ip):
        batch.append((ts, status, ident("d", "domain_by_id", "domain", domain),
                      ident("c", "client_by_id", "ip", ip)))

    start = now - 7 * DAY
    def periodic(domain, every, status=2, since=start, ip_switch=True):
        for i, t in enumerate(range(since, now, every)):
            # first half of the week from the old IP, second half from the new one
            ip = "10.0.0.6" if (ip_switch and t < now - 3 * DAY) else "10.0.0.200"
            add(t + (i * 7) % 11, status, domain, ip)

    # Phone-home hosts that should surface.
    periodic("aic-ngfts.lge.com", 300, since=now - 20 * DAY)      # first-party, seen before: investigate
    periodic("us.nextlgsdp.com", 600, since=now - 20 * DAY)
    periodic("aic.tv.wiselg.com", 900, since=now - 20 * DAY)
    periodic("www.ueiwsp.com", 600)                               # third-party and new
    periodic("a3phael99lf879-ats.iot.us-west-2.amazonaws.com", 480)
    # Must NOT surface.
    periodic("connectivitycheck.gstatic.com", 300)
    periodic("snu.lge.com", 600)
    periodic("api-global.netflix.com", 450)
    periodic("ipv4-c001.1.oca.nflxvideo.net", 200)
    periodic("1.0.0.127.in-addr.arpa", 300)
    periodic("discovery.meethue.com", 300, status=1)              # already blocked
    periodic("ichnaea.netflix.com", 300, status=1)
    # Irregular human browsing: busy but not a beacon, so it must not be flagged.
    import random
    rng = random.Random(1)
    for _ in range(3000):
        add(rng.randint(start, now - 1), 2, "www.google.com", "10.0.0.200")
    # A domain that was allowed early in the week, then blocked: already covered now.
    for t in range(start, now - 2 * DAY, 300):
        add(t, 2, "tracking.later-blocked.example", "10.0.0.200")
    for t in range(now - 2 * DAY, now, 300):
        add(t, 1, "tracking.later-blocked.example", "10.0.0.200")
    # A second, unrelated client (no MAC row).
    for t in range(start, now, 120):
        add(t, 2, "beacon.laptop-vendor.example", "10.0.0.50")
    c.executemany("INSERT INTO query_storage(timestamp, type, status, domain, client) VALUES (?, 1, ?, ?, ?)", batch)
    c.commit()
    c.close()


class UncoveredDomainsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.now = int(time.time())
        cls.db = os.path.join(cls.tmp.name, "ftl.db")
        make_db(cls.db, cls.now)
        conn = sqlite3.connect(f"file:{cls.db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        start = cls.now - 7 * DAY
        cls.rows = conn.execute(
            "SELECT timestamp, status, domain, client FROM queries WHERE timestamp >= ?", (start,)).fetchall()
        conn.close()
        cfg = {"DB_PATH": cls.db, "PIHOLE_IP": "10.0.0.2", "IGNORE_CLIENTS": ["127.0.0.1"],
               "DEVICE_NAMES": {"10.0.0.200": "LG TV Living Room", "10.0.0.50": "Laptop"}}
        cls.cfg = cfg
        cls.start = start
        cls.result = ud.build(cls.rows, cfg, start, BLOCKED, ALLOWED)
        cls.by_domain = {}
        for f in cls.result["all"]:
            cls.by_domain.setdefault(f["domain"], []).append(f)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def action(self, domain, device=None):
        fs = [f for f in self.by_domain[domain] if device is None or f["device"] == device]
        self.assertEqual(len(fs), 1, f"{domain}: expected one finding, got {len(fs)}")
        return fs[0]["action"]

    # Acceptance: the LG family surfaces ...
    def test_lg_family_surfaces(self):
        for d in ("aic-ngfts.lge.com", "us.nextlgsdp.com", "aic.tv.wiselg.com",
                  "www.ueiwsp.com", "a3phael99lf879-ats.iot.us-west-2.amazonaws.com"):
            self.assertIn(self.action(d, "LG TV Living Room"), ud.ACTIONS_SHOWN, d)

    def test_third_party_and_iot_are_block_candidates(self):
        self.assertEqual(self.action("www.ueiwsp.com"), "candidate-block")
        self.assertEqual(self.action("a3phael99lf879-ats.iot.us-west-2.amazonaws.com"), "candidate-block")

    def test_first_party_beacons_stay_investigate(self):
        self.assertEqual(self.action("aic-ngfts.lge.com"), "investigate")

    # ... and the needed / noise / covered ones do not.
    def test_needed_noise_and_covered_are_not_proposed(self):
        self.assertEqual(self.action("connectivitycheck.gstatic.com"), "needed")
        self.assertEqual(self.action("snu.lge.com"), "needed")
        self.assertEqual(self.action("api-global.netflix.com"), "needed")
        self.assertEqual(self.action("ipv4-c001.1.oca.nflxvideo.net"), "needed")
        self.assertEqual(self.action("1.0.0.127.in-addr.arpa"), "noise")
        self.assertEqual(self.action("tracking.later-blocked.example"), "covered-now")
        self.assertNotIn("discovery.meethue.com", self.by_domain)   # only blocked queries
        self.assertNotIn("ichnaea.netflix.com", self.by_domain)

    def test_busy_but_irregular_domain_is_review_only(self):
        # Busy, but no beat and no telemetry name: listed for a look, never a block candidate.
        self.assertEqual(self.action("www.google.com"), "review")
        self.assertNotIn("www.google.com", self.result["candidates"])

    def test_review_tier_lists_busiest_unflagged_domains_with_cap(self):
        tv = next(d for d in self.result["devices"] if d["name"] == "LG TV Living Room")
        review = [f for f in tv["findings"] if f["action"] == "review"]
        self.assertLessEqual(len(review), 5)                                   # default cap
        self.assertEqual([f["allowed"] for f in review], sorted((f["allowed"] for f in review), reverse=True))
        self.assertIn("volume", ud._tags(review[0]))
        # review rows come after flagged rows
        acts = [f["action"] for f in tv["findings"]]
        self.assertEqual(acts, sorted(acts, key=lambda a: a == "review"))

    def test_review_tier_can_be_turned_off_and_tuned(self):
        off = ud.build(self.rows, dict(self.cfg, UNCOVERED_REVIEW_TOP_N=0), self.start, BLOCKED, ALLOWED)
        self.assertNotIn("review", {f["action"] for f in off["all"]})
        one = ud.build(self.rows, dict(self.cfg, UNCOVERED_REVIEW_TOP_N=1), self.start, BLOCKED, ALLOWED)
        tv = next(d for d in one["devices"] if d["name"] == "LG TV Living Room")
        self.assertEqual(sum(f["action"] == "review" for f in tv["findings"]), 1)
        high = ud.build(self.rows, dict(self.cfg, UNCOVERED_REVIEW_MIN_QUERIES=10**6), self.start, BLOCKED, ALLOWED)
        self.assertNotIn("review", {f["action"] for f in high["all"]})

    def test_review_rows_stop_after_keep_decision(self):
        reviewed = {"google.com": {"decision": "keep", "date": "2026-11-17", "note": ""}}
        res = ud.build(self.rows, self.cfg, self.start, BLOCKED, ALLOWED, reviewed)
        acts = {f["domain"]: f["action"] for f in res["all"]}
        self.assertEqual(acts["www.google.com"], "reviewed-keep")

    def test_review_rows_render_in_html_and_text(self):
        text = "\n".join(ud.render_text(self.result))
        self.assertIn("www.google.com", text)
        self.assertIn("review", text)
        html = ud.render_html(self.result, None, "color:{c}", "x")
        self.assertIn("#6b7a99", html)

    def test_candidates_file_content(self):
        self.assertIn("www.ueiwsp.com", self.result["candidates"])
        for bad in ("connectivitycheck.gstatic.com", "snu.lge.com", "api-global.netflix.com",
                    "aic-ngfts.lge.com", "www.google.com"):
            self.assertNotIn(bad, self.result["candidates"])

    # Device grouping and novelty
    def test_one_device_per_mac_across_ip_changes(self):
        names = [d["name"] for d in self.result["devices"]]
        self.assertEqual(names.count("LG TV Living Room"), 1)
        tv = next(d for d in self.result["devices"] if d["name"] == "LG TV Living Room")
        self.assertEqual(tv["ips"], ["10.0.0.200", "10.0.0.6"])

    def test_novelty_uses_history_before_window(self):
        self.assertTrue(self.result["history_known"])
        new = {f["domain"]: f["new"] for f in self.result["all"]}
        self.assertTrue(new["www.ueiwsp.com"])           # only this week
        self.assertFalse(new["aic-ngfts.lge.com"])       # seen 20 days ago

    def test_clients_without_mac_still_reported(self):
        f = next(f for f in self.result["all"] if f["domain"] == "beacon.laptop-vendor.example")
        self.assertEqual(f["device"], "Laptop")
        self.assertEqual(f["action"], "candidate-block")

    # Review log and config
    def test_reviewed_keep_and_block(self):
        reviewed = {"nextlgsdp.com": {"decision": "keep", "date": "2026-11-12", "note": "TV needs it"},
                    "www.ueiwsp.com": {"decision": "block", "date": "2026-11-12", "note": ""}}
        res = ud.build(self.rows, self.cfg, self.start, BLOCKED, ALLOWED, reviewed)
        acts = {f["domain"]: f["action"] for f in res["all"]}
        self.assertEqual(acts["us.nextlgsdp.com"], "reviewed-keep")       # parent domain match
        self.assertEqual(acts["www.ueiwsp.com"], "approved-block-pending")
        self.assertIn("www.ueiwsp.com", res["approved_pending"])
        self.assertNotIn("www.ueiwsp.com", res["candidates"])

    def test_skip_list_excludes_devices(self):
        for token in ("laptop", "10.0.0.50", "LG TV Living Room", TV_MAC):   # name, IP, name, MAC
            res = ud.build(self.rows, dict(self.cfg, UNCOVERED_SKIP=[token]), self.start, BLOCKED, ALLOWED)
            skipped = {"laptop": "Laptop", "10.0.0.50": "Laptop",
                       "LG TV Living Room": "LG TV Living Room", TV_MAC: "LG TV Living Room"}[token]
            self.assertNotIn(skipped, {f["device"] for f in res["all"]}, token)
        res = ud.build(self.rows, dict(self.cfg, UNCOVERED_SKIP=["laptop"]), self.start, BLOCKED, ALLOWED)
        self.assertIn("LG TV Living Room", {f["device"] for f in res["all"]})   # others untouched

    def test_time_servers_are_needed(self):
        for d in ("time.nist.gov", "0.pool.ntp.org", "time.google.com"):
            self.assertTrue(ud._suffix_match(d, ud.DEFAULT_NEEDED), d)

    def test_needed_domains_config_extends_list(self):
        cfg = dict(self.cfg, NEEDED_DOMAINS=["ueiwsp.com"])
        res = ud.build(self.rows, cfg, self.start, BLOCKED, ALLOWED)
        self.assertEqual({f["domain"]: f["action"] for f in res["all"]}["www.ueiwsp.com"], "needed")

    def test_helpers(self):
        self.assertEqual(ud.family_of("us.nextlgsdp.com"), "nextlgsdp.com")
        self.assertEqual(ud.family_of("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(ud.family_of("x.iot.us-west-2.amazonaws.com"), "x.iot.us-west-2.amazonaws.com")
        self.assertIn("telemetry", ud.hint_tags("telemetry.example.com"))
        self.assertEqual(ud.hint_tags("login.example.com"), [])         # "login" is not "log"
        self.assertIsNone(ud.beacon_info(list(range(0, 10 * 10, 10))))  # too few queries
        self.assertIsNotNone(ud.beacon_info(list(range(0, 60 * 300, 300))))

    # End to end through the real script
    def test_end_to_end_no_email(self):
        cfg_path = os.path.join(self.tmp.name, "config.py")
        out = os.path.join(self.tmp.name, "reports")
        with open(cfg_path, "w") as fh:
            fh.write(f'DB_PATH = {self.db!r}\nREPORT_DIR = {out!r}\nPIHOLE_IP = "10.0.0.2"\n'
                     'DEVICE_NAMES = {"10.0.0.200": "LG TV Living Room"}\n')
        env = dict(os.environ, NETINTEL_CONFIG=cfg_path)
        proc = subprocess.run([sys.executable, os.path.join(SCRIPTS, "network_intel_report.py"), "--no-email"],
                              env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        udir = os.path.join(out, "uncovered")
        with open(os.path.join(udir, "candidates.txt")) as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        self.assertIn("www.ueiwsp.com", lines)
        csvs = [f for f in os.listdir(udir) if f.endswith(".csv")]
        self.assertEqual(len(csvs), 1)
        with open(os.path.join(udir, csvs[0])) as fh:
            self.assertTrue(any(r["domain"] == "us.nextlgsdp.com" for r in csv.DictReader(fh)))
        txt = [f for f in os.listdir(out) if f.endswith(".txt")]
        with open(os.path.join(out, txt[0])) as fh:
            self.assertIn("UNCOVERED DOMAINS", fh.read())

    def test_review_cli_records_decision(self):
        path = os.path.join(self.tmp.name, "rv", "reviewed.json")
        ud.record_review(path, "Foo.Example.com.", "keep", "needed for app")
        data = ud.load_reviewed(path)
        self.assertEqual(data["foo.example.com"]["decision"], "keep")
        with self.assertRaises(ValueError):
            ud.record_review(path, "x.com", "maybe")


if __name__ == "__main__":
    unittest.main()
