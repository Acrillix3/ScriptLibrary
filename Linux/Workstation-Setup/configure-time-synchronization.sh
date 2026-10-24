#!/bin/sh
# What it does
# Configure approved NTP sources for the single active chrony or timesyncd daemon, with separate restart confirmation.
# Available flags
# --help; --output-dir DIRECTORY; --servers HOST1,HOST2 (required); --daemon auto|chrony|timesyncd|ntpd (default auto). Chrony keeps other sources; ntpd requires manual review.
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=configure-time-synchronization
DESCRIPTION='Configure approved NTP sources for the single active chrony or timesyncd daemon, with separate restart confirmation.'
FLAGS='--servers HOST1,HOST2 (required); --daemon auto|chrony|timesyncd|ntpd (default auto). Chrony keeps other sources; ntpd requires manual review.'
OPTIONS='servers daemon'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


configure_time_main() {
 servers=$(arg servers "")
 daemon=$(arg daemon auto)
 [ -n "$servers" ] || die "Supply --servers as a comma-separated list."
 case "$servers" in *[!A-Za-z0-9.,:_%-]*|,*|*,|*,,*) die "Invalid NTP source list." ;; esac
 oldifs=$IFS; IFS=,; set -- $servers; IFS=$oldifs
 for source do case "$source" in -*|.*|*.) die "Invalid NTP source." ;; esac; done
 case "$daemon" in auto|chrony|timesyncd|ntpd) ;; *) die "Invalid daemon." ;; esac
 active_time() {
  if [ "$INIT_SYSTEM" = systemd ] && have systemctl; then systemctl is-active --quiet "$1" 2>/dev/null
  elif [ "$INIT_SYSTEM" = openrc ] && have rc-service; then rc-service "$1" status >/dev/null 2>&1
  else return 1; fi
 }
 count=0; detected=""; service=""
 # Check aliases within each family once, so chrony/chronyd aliases are not a conflict.
 for svc in chronyd chrony; do if active_time "$svc"; then count=$((count+1)); detected=chrony; service=$svc; break; fi; done
 if active_time systemd-timesyncd; then count=$((count+1)); detected=timesyncd; service=systemd-timesyncd; fi
 for svc in ntpd ntp ntpsec; do if active_time "$svc"; then count=$((count+1)); detected=ntpd; service=$svc; break; fi; done
 if [ "$count" -ne 1 ]; then finding Unknown time-daemon "Exactly one active supported time daemon is required; none or conflicting daemons were detected."; return; fi
 [ "$daemon" = auto ] || [ "$daemon" = "$detected" ] || die "Selected daemon does not match the active daemon."
 target=""; main=""
 case "$detected" in
  timesyncd)
   target=/etc/systemd/timesyncd.conf.d/70-scriptlibrary.conf
   printf '[Time]\nNTP=\nNTP=%s\n' "$(printf '%s' "$servers" | tr ',' ' ')" > "$REPORT_DIR/time-settings" ;;
  chrony)
   for f in /etc/chrony/chrony.conf /etc/chrony.conf; do [ ! -r "$f" ] || main=$f; done
   if [ -z "$main" ]; then finding Unknown chrony-config "No readable chrony configuration."; return; fi
   target=$(awk '$1=="sourcedir" && $2 ~ /^\/etc\/[A-Za-z0-9_\/.-]+$/ {print $2 "/70-scriptlibrary.sources"; exit}' "$main")
   case "$target" in ""|*/../*|*/./*|*//*) finding Unknown chrony-config "Chrony requires an existing safe sourcedir under /etc; no include is added implicitly."; return ;; esac
   [ -d "$(dirname "$target")" ] || { finding Unknown chrony-config "Configured chrony sourcedir does not exist."; return; }
   oldifs=$IFS; IFS=,; set -- $servers; IFS=$oldifs
   : > "$REPORT_DIR/time-settings"
   for server do printf 'server %s iburst\n' "$server" >> "$REPORT_DIR/time-settings"; done ;;
  ntpd)
   finding Unknown ntpd "The existing ntpd daemon is detected, but no source file is changed. Native ntpd variants require a separately reviewed configuration."; return ;;
 esac
 finding Info source-plan "Write dedicated source file $target for active daemon $service. Existing chrony sources and interface-provided timesyncd sources may still participate."
 if [ "$APPLY" -eq 1 ] && [ "$detected" = timesyncd ]; then
  require_root
  [ ! -L /etc/systemd ] && [ ! -L /etc/systemd/timesyncd.conf.d ] || die "Symlinked configuration directory refused."
  change create-dropin-directory mkdir -p /etc/systemd/timesyncd.conf.d || return
 fi
 write_config_file "$target" "$REPORT_DIR/time-settings" || return
 if [ "$APPLY" -eq 1 ]; then restart_service "$service"; fi
 if have chronyc && [ "$detected" = chrony ]; then capture time-verification chronyc tracking; fi
 if have timedatectl && [ "$detected" = timesyncd ]; then capture time-verification timedatectl show-timesync; fi
 finding Info verification "A configured source does not prove synchronization. If restart is deferred, configuration awaits activation; verify after restart and normal convergence."
}
configure_time_main

finish
