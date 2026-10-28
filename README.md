# pihole-network-intel

A weekly, emailed report on what your network is doing, built from Pi-hole's own query database. One small Python script, no extra services, no cloud.

Pi-hole's dashboard shows you the last few hours. This shows you the week: which devices are chatty, which ones are quietly bypassing your DNS, and which ones stopped talking to Pi-hole entirely.

## What's in the report

- **Summary:** total queries, blocked, block rate
- **Daily traffic:** per-day volume and block rate, in your own timezone
- **Hourly activity:** 24-hour heat strip showing when the network is busy
- **Device breakdown:** queries and block rate per device, using friendly names from your config or the hostnames Pi-hole already learned
- **Possible DNS bypass 🚨:** devices with lots of queries but almost nothing blocked (smart TVs and phones hardcoding their own DNS or using DNS-over-HTTPS)
- **Silent devices:** devices you expect to see that sent no queries (their DNS setting probably reverted, e.g. after a reinstall or router change)
- **Top blocked / top allowed domains**
- A plain-text copy saved to disk and attached as the text part of the email

Try it without touching your network: `python3 scripts/network_intel_report.py --demo` writes `demo-report.html` filled with fake data.

## Requirements

- Pi-hole **v6** (reads `/etc/pihole/pihole-FTL.db`)
- Python 3.8+ (standard library only)
- A Gmail account with an [app password](https://myaccount.google.com/apppasswords) if you want email delivery

## Quick start

```bash
git clone https://github.com/AdditiveCraftsman/pihole-network-intel.git
cd pihole-network-intel
cp config/config.example.py config/config.py
nano config/config.py                        # your IP, timezone, email, device names
python3 scripts/network_intel_report.py --no-email   # test without sending
```

Full setup, permissions and the cron job are in [INSTALL.md](INSTALL.md).

## How it counts

Blocked vs. allowed uses the status codes from the [Pi-hole query database docs](https://docs.pi-hole.net/database/query-database/): statuses 1, 4–11, 15, 16 and 18 count as blocked; 2, 3, 12–14 and 17 count as allowed. Block rates depend heavily on your blocklists and devices. A network full of smart TVs typically lands far lower than the percentages blocklist marketing quotes.

## Security notes

- The database is opened **read-only**.
- Your real settings live in `config/config.py`, which is git-ignored. You can leave the Gmail app password out of the file and set the `NETINTEL_GMAIL_PASSWORD` environment variable instead.
- If you ever commit a password by mistake, revoke it in your Google account right away; deleting it from git history later is not enough.

## Roadmap / contributions welcome

- Other delivery options (ntfy, Telegram, Discord webhook, local HTML only)
- Week-over-week deltas and "new device appeared" alerts
- Optional per-device top domains
- Pi-hole v5 support

Issues and pull requests are welcome. Please keep the script dependency-free where you can.

## License

MIT, see [LICENSE](LICENSE).
