#!/bin/sh
# What it does
# Plan or perform one narrow CUPS queue recovery action without deleting jobs.
# Available flags
# --help; --output-dir DIRECTORY; --queue NAME --action enable|accept|release (default enable); release asks for separate confirmation before pending jobs resume.
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=repair-print-queue
DESCRIPTION='Plan or perform one narrow CUPS queue recovery action without deleting jobs.'
FLAGS='--queue NAME --action enable|accept|release (default enable); release asks for separate confirmation before pending jobs resume.'
OPTIONS='queue action'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


queue=$(arg queue '')
action=$(arg action enable)
case "$queue" in ''|-*|*[!A-Za-z0-9_.-]*) die "Specify a simple --queue name."; esac
case "$action" in enable|accept|release) ;; *) die "Action must be enable, accept, or release."; esac
have lpstat || die "CUPS client tools are required."
lpstat -p "$queue" >/dev/null 2>&1 || die "The selected queue does not exist or is inaccessible."
capture current-queue lpstat -p "$queue"
capture current-accepting lpstat -a "$queue"
finding Info scope "Only the named queue is affected; print jobs are not cancelled or deleted."
if [ "$APPLY" = 1 ]; then require_root; fi
case "$action" in
    enable) have cupsenable || die "cupsenable is unavailable."; change enable-queue cupsenable "$queue";;
    accept) have cupsaccept || die "cupsaccept is unavailable."; change accept-queue cupsaccept "$queue";;
    release)
        have cupsenable || die "cupsenable is unavailable."
        if [ "$APPLY" = 0 ]; then
            finding Info plan "Would resume the named queue and release its held pending jobs after confirmation."
        elif confirm_disruption "Release pending jobs on $queue now?"; then
            change release-queue cupsenable --release "$queue"
        fi
        ;;
esac
if [ "$APPLY" = 1 ]; then capture resulting-queue lpstat -p "$queue"; fi

finish
