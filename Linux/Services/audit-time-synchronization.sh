#!/bin/sh
# What it does
# Detect active time services, inspect configured sources and synchronization status, and flag competing daemons.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-time-synchronization
DESCRIPTION='Detect active time services, inspect configured sources and synchronization status, and flag competing daemons.'
FLAGS='No script-specific flags.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


active_count=0
time_services=''
case "$INIT_SYSTEM" in
    systemd)
        for candidate in chronyd.service chrony.service systemd-timesyncd.service ntpd.service ntp.service ntpsec.service; do
            if systemctl is-active --quiet "$candidate" 2>/dev/null; then
                canonical=$(systemctl show "$candidate" --property=Id --value 2>/dev/null)
                [ -n "$canonical" ] || canonical=$candidate
                case " $time_services " in *" $canonical "*) ;; *) active_count=$((active_count + 1)); time_services="$time_services $canonical";; esac
            fi
        done
        if have timedatectl; then capture system-time timedatectl show --property=Timezone,LocalRTC,CanNTP,NTP,NTPSynchronized,TimeUSec,RTCTimeUSec; fi
        ;;
    openrc)
        for candidate in chronyd ntpd ntp-client; do
            if [ -f "/etc/init.d/$candidate" ] && rc-service "$candidate" status >/dev/null 2>&1; then active_count=$((active_count + 1)); time_services="$time_services $candidate"; fi
        done
        ;;
    *) finding Unknown active-time-daemon "No supported init service provider."; ;;
esac
fact active-time-daemons "$time_services"
if [ "$active_count" -gt 1 ]; then finding Warn competing-daemons "Multiple time services are active; verify which controls the clock."; elif [ "$active_count" = 0 ]; then finding Unknown active-time-daemon "No recognized active time daemon; other implementations may exist."; else finding Info active-time-daemon "One recognized time daemon is active."; fi
if have chronyc; then
    capture chrony-tracking chronyc -n tracking
    capture chrony-sources chronyc -n sources
    capture chrony-statistics chronyc -n sourcestats
fi
if have ntpq; then capture ntp-peers ntpq -pn; fi
if have timedatectl; then
    case "$time_services" in *systemd-timesyncd.service*) capture timesyncd-status timedatectl timesync-status;; esac
fi
time_source_projection() {
    for file in /etc/chrony/chrony.conf /etc/chrony.conf /etc/ntp.conf /etc/ntpsec/ntp.conf /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf; do
        [ -f "$file" ] || continue
        if [ -r "$file" ]; then
            awk '
                $1=="server" || $1=="pool" || $1=="peer" {print FILENAME ": " $1 " " $2; next}
                /^[ \t]*(NTP|FallbackNTP)[ \t]*=/ {print FILENAME ": " $0}
            ' "$file"
        else finding Unknown time-source-access "A time configuration file is unreadable: $file"; fi
    done
}
capture configured-sources time_source_projection
finding Info source-scope "Only source endpoints are exported; authentication keys and key material are excluded. Included configuration fragments may require local review."

finish
