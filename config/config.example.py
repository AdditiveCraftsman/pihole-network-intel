# Copy this file to config/config.py and edit it.
# config/config.py is git-ignored: never commit real credentials.

# ── Pi-hole ──────────────────────────────────────────────────────────────────
DB_PATH = "/etc/pihole/pihole-FTL.db"   # Pi-hole v6 FTL database (read-only access)
PIHOLE_IP = "192.168.1.2"               # your Pi-hole's IP (shown in the report header)
LAB_NAME = "my home network"            # shown in the report footer

# ── Report ───────────────────────────────────────────────────────────────────
DAYS_BACK = 7                           # report window in days
TIMEZONE = "America/New_York"           # IANA name; controls day/hour buckets
# REPORT_DIR = "/home/pi/network-intel/reports"   # default: <repo>/reports

# ── Email (Gmail SMTP) ───────────────────────────────────────────────────────
# Needs a Gmail *app password* (requires 2-step verification):
#   https://myaccount.google.com/apppasswords
GMAIL_FROM = "you@gmail.com"
GMAIL_TO = "you@gmail.com"             # several recipients: "a@gmail.com, b@gmail.com"
GMAIL_APP_PASSWORD = ""                 # or leave empty and set NETINTEL_GMAIL_PASSWORD

# ── Device names ─────────────────────────────────────────────────────────────
# Optional friendly names by IP. Anything not listed falls back to the hostname
# Pi-hole learned for that IP, then to the bare IP.
DEVICE_NAMES = {
    # "192.168.1.20": "Living Room TV",
    # "192.168.1.30": "Alice's Phone",
}

# Clients never flagged as possible DNS bypass (localhost and PIHOLE_IP are
# always ignored by default).
IGNORE_CLIENTS = ["127.0.0.1", "::1"]

# Devices you expect to see every week. If one sends zero queries, the report
# lists it under "Silent Devices" (its DNS may have reverted).
# Match by friendly name, Pi-hole hostname, or IP, case-insensitive.
EXPECTED_DEVICES = [
    # "alices-phone",
]

# A device is flagged 🚨 when it sends at least this many queries...
BYPASS_MIN_QUERIES = 500
# ...and fewer than this percentage get blocked.
BYPASS_MAX_BLOCK_PCT = 5.0
