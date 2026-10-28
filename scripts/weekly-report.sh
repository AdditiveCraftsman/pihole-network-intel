#!/bin/bash
# Pi-hole weekly network intelligence report: cron wrapper.
# Example crontab entry (Sundays 11 PM):
#   0 23 * * 0 /home/YOUR_USER/network-intel/scripts/weekly-report.sh
# Runs the Python generator and keeps a dated log. No sudo needed: the user
# just has to be in the "pihole" group (see INSTALL.md).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${NETINTEL_LOG_DIR:-$BASE_DIR/logs}"
LOG_FILE="$LOG_DIR/report-$(date +%Y-%m-%d).log"

mkdir -p "$LOG_DIR"

echo "=== Weekly report started: $(date) ===" | tee -a "$LOG_FILE"

python3 "$SCRIPT_DIR/network_intel_report.py" 2>&1 | tee -a "$LOG_FILE"
EXIT_CODE=${PIPESTATUS[0]}

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "=== Completed successfully: $(date) ===" | tee -a "$LOG_FILE"
else
    echo "=== FAILED (exit $EXIT_CODE): $(date) ===" | tee -a "$LOG_FILE"
fi

exit "$EXIT_CODE"
