#!/bin/sh
# What it does
# Inventory systemd timers, cron metadata, and pending at jobs without exporting scheduled command text.
# Available flags
# --help; --output-dir DIRECTORY; --user USER selects the crontab owner (default current user); run with appropriate access to inspect another user.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-scheduled-jobs
DESCRIPTION='Inventory systemd timers, cron metadata, and pending at jobs without exporting scheduled command text.'
FLAGS='--user USER selects the crontab owner (default current user); run with appropriate access to inspect another user.'
OPTIONS=user
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


user=$(arg user "$(id -un 2>/dev/null)")
case "$user" in ''|-*|*[!A-Za-z0-9_.-]*) die "Invalid crontab user."; esac
if [ "$INIT_SYSTEM" = systemd ]; then
    capture timers systemctl --no-pager list-timers --all
    capture timer-startup systemctl --no-pager list-unit-files --type=timer
else finding Info timers "No systemd timer provider on the detected init system."; fi
cron_files() {
    for path in /etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic; do
        if [ -e "$path" ]; then
            if [ -d "$path" ]; then
                find "$path" -maxdepth 2 \( -type f -o -type l \) -exec ls -ld {} \; 2>/dev/null
            else ls -ld "$path"; fi
        fi
    done
}
capture cron-file-metadata cron_files
cron_counts() {
    for path in /etc/crontab /etc/anacrontab /etc/cron.d/*; do
        [ -f "$path" ] || continue
        if [ -r "$path" ]; then
            awk 'NF && $1 !~ /^#/ && $0 !~ /^[A-Za-z_][A-Za-z0-9_]*[ \t]*=/ {n++} END {print FILENAME ": scheduled-entry-count=" n+0}' "$path"
        else finding Unknown system-cron-access "A system cron file is unreadable: $path"; fi
    done
}
capture system-cron-counts cron_counts
if have crontab; then
    if [ "$(id -u)" = 0 ]; then cron_text=$(crontab -u "$user" -l 2>/dev/null); cron_rc=$?; else
        [ "$user" = "$(id -un)" ] || die "Inspecting another user's crontab requires root."
        cron_text=$(crontab -l 2>/dev/null); cron_rc=$?
    fi
    if [ "$cron_rc" = 0 ]; then
        cron_count=$(printf '%s\n' "$cron_text" | awk 'NF && $1 !~ /^#/ && $0 !~ /^[A-Za-z_][A-Za-z0-9_]*[ \t]*=/ {n++} END {print n+0}')
        fact selected-crontab-user "$user"
        fact selected-crontab-entry-count "$cron_count"
        unset cron_text
    else finding Unknown user-crontab "No crontab was returned; absence and access errors cannot be distinguished safely."; fi
else finding Unknown cron "crontab is unavailable."; fi
if have atq; then capture at-job-metadata atq; else finding Info at-jobs "atq is not installed."; fi
finding Info privacy "Scheduled command bodies, environment assignments, and job spool contents are excluded."

finish
