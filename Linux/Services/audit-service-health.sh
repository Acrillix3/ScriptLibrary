#!/bin/sh
# What it does
# Inspect service startup, failed states, and selected service dependencies using systemd or OpenRC.
# Available flags
# --help; --output-dir DIRECTORY; --service NAME optionally selects one service for detailed state and dependency checks.
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.

SCRIPT_NAME=audit-service-health
DESCRIPTION='Inspect service startup, failed states, and selected service dependencies using systemd or OpenRC.'
FLAGS='--service NAME optionally selects one service for detailed state and dependency checks.'
OPTIONS=service
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


service=$(arg service '')
case "$service" in -*|*[!A-Za-z0-9_.@:-]*) die "Invalid service name."; esac
case "$INIT_SYSTEM" in
    systemd)
        capture failed-services systemctl --no-pager --plain --failed --type=service
        if [ "$LAST_CAPTURE_RC" = 0 ]; then
            failed_names=$(systemctl --no-legend --plain --failed --type=service 2>/dev/null)
            failed_count=$(printf '%s\n' "$failed_names" | awk 'NF {n++} END {print n+0}')
            fact failed-service-count "$failed_count"
            if [ "$failed_count" -gt 0 ]; then finding Warn service-health "One or more services are failed."; else finding Pass failed-services "No failed service units were reported."; fi
        fi
        capture startup-services systemctl --no-pager list-unit-files --type=service
        if [ -n "$service" ]; then
            case "$service" in *.service) ;; *.*) die "Only service units are supported.";; *) service="$service.service";; esac
            capture selected-service systemctl show "$service" --property=Id,LoadState,ActiveState,SubState,UnitFileState,Result,NRestarts,Requires,Wants,After
            state=$(systemctl show "$service" --property=LoadState --value 2>/dev/null)
            case "$state" in loaded) ;; not-found) finding Unknown selected-service "The service unit was not found.";; *) finding Unknown selected-service "Service load state is unavailable or is not loaded.";; esac
        fi
        ;;
    openrc)
        capture openrc-services rc-status -s
        capture openrc-crashed rc-status -c
        capture openrc-startup rc-update show -v
        if [ -n "$service" ]; then
            capture selected-service rc-service "$service" status
            if [ "$LAST_CAPTURE_RC" != 0 ]; then finding Warn selected-service "Service is stopped, crashed, inaccessible, or absent; inspect its status."; fi
            if have rc-depend; then capture selected-dependencies rc-depend "$service"; else finding Unknown dependencies "rc-depend is unavailable."; fi
        fi
        ;;
    *) finding Unknown init "Only detected systemd and OpenRC instances are supported."; ;;
esac
finding Info scope "Stopped or disabled services may be intentional; compare the report with the server's approved role."

finish
