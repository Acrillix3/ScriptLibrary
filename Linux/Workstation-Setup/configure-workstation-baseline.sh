#!/bin/sh
# What it does
# Plan or configure an explicit hostname, timezone, or existing generated locale.
# Available flags
# --help; --output-dir DIRECTORY; --hostname NAME; --timezone AREA/CITY; --locale LOCALE (at least one required). Locale must already be generated.
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=configure-workstation-baseline
DESCRIPTION='Plan or configure an explicit hostname, timezone, or existing generated locale.'
FLAGS='--hostname NAME; --timezone AREA/CITY; --locale LOCALE (at least one required). Locale must already be generated.'
OPTIONS='hostname timezone locale'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


host=$(arg hostname "")
zone=$(arg timezone "")
locale_name=$(arg locale "")
[ -n "$host$zone$locale_name" ] || die "Supply hostname, timezone, or locale."
if [ -n "$host" ]; then
 printf '%s\n' "$host" | awk -F. 'length($0)>253 {bad=1} {for(i=1;i<=NF;i++) if(length($i)<1 || length($i)>63 || $i !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) bad=1} END {exit bad}' || die "Invalid hostname labels."
fi
[ "$(printf '%s' "$host" | wc -c)" -le 253 ] || die "Hostname is too long."
case "$zone" in *[!A-Za-z0-9_+/-]*|/*|*..*) die "Invalid timezone." ;; esac
case "$locale_name" in *[!A-Za-z0-9_.@-]*) die "Invalid locale." ;; esac
if [ -n "$zone" ]; then [ -f "/usr/share/zoneinfo/$zone" ] || die "Timezone is not present in the local zoneinfo database."; fi
if [ -n "$locale_name" ]; then
 have locale || die "locale utility is required."
 locale -a 2>/dev/null | awk -v l="$locale_name" 'tolower($0)==tolower(l) {found=1} END {exit !found}' || die "Requested locale has not been generated. Generate it through reviewed OS-specific steps first."
fi
[ "$APPLY" -eq 0 ] || require_root
if [ "$INIT_SYSTEM" = systemd ] && have hostnamectl && have timedatectl && have localectl; then
 [ -z "$host" ] || change hostname hostnamectl set-hostname "$host"
 [ -z "$zone" ] || change timezone timedatectl set-timezone "$zone"
 [ -z "$locale_name" ] || change locale localectl set-locale "LANG=$locale_name"
elif [ "$OS_FAMILY" = alpine ] && [ "$INIT_SYSTEM" = openrc ]; then
 [ -z "$locale_name" ] || die "Locale mutation on minimal Alpine requires a reviewed libc-specific configuration; no glibc assumption is made."
 if [ -n "$host" ]; then
  finding Info hostname-plan "Write /etc/hostname and set current hostname to $host."
  if [ "$APPLY" -eq 1 ]; then
   [ ! -L /etc/hostname ] || die "Symlinked /etc/hostname refused."
   printf '%s\n' "$host" > "$REPORT_DIR/approved-hostname"
   write_config_file /etc/hostname "$REPORT_DIR/approved-hostname" || die "Hostname file write failed."
   change current-hostname hostname "$host"
  fi
 fi
 if [ -n "$zone" ]; then
  finding Info timezone-plan "Set /etc/localtime from the approved zoneinfo entry."
  if [ "$APPLY" -eq 1 ]; then
   [ ! -L /etc/localtime ] || die "Symlinked localtime refused; configure it through native setup-timezone instead."
   backup_file /etc/localtime
   cp "/usr/share/zoneinfo/$zone" "$REPORT_DIR/approved-localtime" || die "Cannot stage timezone."
   change timezone cp "$REPORT_DIR/approved-localtime" /etc/localtime
  fi
 fi
else die "No approved baseline adapter for the active init system."; fi
finding Info restart "No reboot or service restart is initiated. Existing sessions and applications may retain the previous locale or timezone."

finish
