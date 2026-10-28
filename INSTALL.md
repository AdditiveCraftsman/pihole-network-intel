# Installation

Tested on a Raspberry Pi 3B running Pi-hole v6 with Unbound. Run everything on the Pi that runs Pi-hole.

## 1. Let your user read the Pi-hole database

The FTL database is owned by the `pihole` group and is read-only to everyone else. Add your user to that group:

```bash
sudo usermod -a -G pihole $USER
```

Log out and back in (or reconnect SSH) so the group change takes effect. Check it:

```bash
groups
ls -l /etc/pihole/pihole-FTL.db
```

You should see `pihole` in your groups, and the database should be group-readable (`-rw-r-----`).

## 2. Get the code

```bash
mkdir -p ~/network-intel && cd ~/network-intel
git clone https://github.com/AdditiveCraftsman/pihole-network-intel.git .
chmod +x scripts/weekly-report.sh
```

## 3. Configure

```bash
cp config/config.example.py config/config.py
chmod 600 config/config.py
nano config/config.py
```

Set at least:

| Setting | What it is |
|---|---|
| `PIHOLE_IP` | Your Pi-hole's IP address |
| `TIMEZONE` | IANA timezone, e.g. `America/Puerto_Rico`. Controls how days and hours are bucketed |
| `GMAIL_FROM`, `GMAIL_TO` | Sender and recipient (can be the same address) |
| `GMAIL_APP_PASSWORD` | Gmail app password (see below), or leave empty and use the environment variable |
| `DEVICE_NAMES` | Optional friendly names by IP |
| `EXPECTED_DEVICES` | Optional list of devices that should show up every week |

### Gmail app password

1. Turn on 2-step verification for the Google account.
2. Go to <https://myaccount.google.com/apppasswords> and create an app password.
3. Paste the 16 characters into `GMAIL_APP_PASSWORD` (spaces are ignored), **or** keep it out of the file and export it:

```bash
export NETINTEL_GMAIL_PASSWORD="xxxx xxxx xxxx xxxx"
```

For cron, put the export line in a file only your user can read and source it from the wrapper, or keep the password in `config/config.py` with `chmod 600`.

## 4. Test

Build the report without sending anything:

```bash
python3 scripts/network_intel_report.py --no-email
```

You should see how many queries were read and a path to the saved text report. Open it and check the numbers look right. Then send a real one:

```bash
python3 scripts/network_intel_report.py
```

## 5. Schedule it

```bash
crontab -e
```

Add this line (Sundays at 11 PM, using the Pi's local time):

```
0 23 * * 0 /home/YOUR_USER/network-intel/scripts/weekly-report.sh
```

Logs go to `logs/report-YYYY-MM-DD.log`.

## Troubleshooting

| Problem | Fix |
|---|---|
| `unable to open database file` or permission denied | You're not in the `pihole` group yet. Redo step 1 and reconnect |
| `FTL database not found` | Check `DB_PATH` in your config. Pi-hole v6 uses `/etc/pihole/pihole-FTL.db` |
| Gmail `Username and Password not accepted` | Use an app password, not your normal password, and check 2-step verification is on |
| Days and hours look shifted | Set `TIMEZONE` correctly |
| Every device is named by IP | Pi-hole hasn't learned hostnames; add `DEVICE_NAMES` entries |
| After an outage the report is empty or the stats look reset | `pihole-FTL.db` can corrupt on power loss. Stop `pihole-FTL`, delete the file, start it again; it rebuilds |
