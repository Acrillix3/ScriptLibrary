#!/bin/sh
# What it does
# Plan or change one selected service's startup and runtime state, with separate restart confirmation.
# Available flags
# --help; --output-dir DIRECTORY; --service NAME --enabled yes|no|keep (default keep) --state start|stop|restart|keep (default keep) --runlevel NAME (OpenRC, default default).
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=configure-service-state
DESCRIPTION='Plan or change one selected service'"'"'s startup and runtime state, with separate restart confirmation.'
FLAGS='--service NAME --enabled yes|no|keep (default keep) --state start|stop|restart|keep (default keep) --runlevel NAME (OpenRC, default default).'
OPTIONS='service enabled state runlevel'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


service=$(arg service '')
enabled=$(arg enabled keep)
state=$(arg state keep)
runlevel=$(arg runlevel default)
case "$service" in ''|-*|*[!A-Za-z0-9_.@:-]*) die "Specify a valid service name."; esac
case "$enabled" in yes|no|keep) ;; *) die "Enabled must be yes, no, or keep."; esac
case "$state" in start|stop|restart|keep) ;; *) die "State must be start, stop, restart, or keep."; esac
case "$runlevel" in ''|-*|*[!A-Za-z0-9_-]*) die "Invalid OpenRC runlevel."; esac
[ "$enabled" != keep ] || [ "$state" != keep ] || die "Specify a startup or runtime state change."
case "$INIT_SYSTEM" in
    systemd)
        case "$service" in *.service) ;; *.*) die "Only service units are supported.";; *) service="$service.service";; esac
        load_state=$(systemctl show "$service" --property=LoadState --value 2>/dev/null)
        [ "$load_state" = loaded ] || die "The selected service is not loaded; masked and absent services are not changed."
        capture before-service systemctl show "$service" --property=Id,LoadState,ActiveState,SubState,UnitFileState
        if [ "$APPLY" = 1 ]; then require_root; fi
        case "$enabled" in yes) change enable-service systemctl enable "$service";; no) change disable-service systemctl disable "$service";; esac
        case "$state" in start|stop) change runtime-service systemctl "$state" "$service";; restart) restart_service "$service";; esac
        if [ "$APPLY" = 1 ]; then capture after-service systemctl show "$service" --property=Id,LoadState,ActiveState,SubState,UnitFileState; fi
        ;;
    openrc)
        [ -f "/etc/init.d/$service" ] || die "The selected OpenRC service does not exist."
        [ -d "/etc/runlevels/$runlevel" ] || die "The selected OpenRC runlevel does not exist."
        capture before-service rc-service "$service" status
        capture before-startup rc-update show "$runlevel"
        if [ "$APPLY" = 1 ]; then require_root; fi
        case "$enabled" in yes) change enable-service rc-update add "$service" "$runlevel";; no) change disable-service rc-update del "$service" "$runlevel";; esac
        case "$state" in start|stop) change runtime-service rc-service "$service" "$state";; restart) restart_service "$service";; esac
        if [ "$APPLY" = 1 ]; then capture after-service rc-service "$service" status; capture after-startup rc-update show "$runlevel"; fi
        ;;
    *) die "Only detected systemd and OpenRC are supported."; ;;
esac
finding Info restart "Restart requests require their own interactive confirmation; --defer-restarts always leaves them pending."

finish
