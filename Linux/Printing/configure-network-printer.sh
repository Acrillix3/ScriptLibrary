#!/bin/sh
# What it does
# Plan or create a local CUPS queue using IPP Everywhere or an explicitly approved installed model.
# Available flags
# --help; --output-dir DIRECTORY; --queue NAME --uri ipp[s]://HOST/PATH|socket://HOST:PORT --driver MODEL (default everywhere); only creates a new unshared queue.
# --apply; --dry-run; --defer-restarts (defer disruptive activation).
# How it works
# Detects Linux capabilities, records private reports, and marks missing evidence Unknown.
# Shows a plan first; changes require --apply and restarts require separate confirmation.

SCRIPT_NAME=configure-network-printer
DESCRIPTION='Plan or create a local CUPS queue using IPP Everywhere or an explicitly approved installed model.'
FLAGS='--queue NAME --uri ipp[s]://HOST/PATH|socket://HOST:PORT --driver MODEL (default everywhere); only creates a new unshared queue.'
OPTIONS='queue uri driver'
MUTATING=true

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"


queue=$(arg queue '')
uri=$(arg uri '')
driver=$(arg driver everywhere)
case "$queue" in ''|-*|*[!A-Za-z0-9_.-]*) die "Specify a simple new --queue name."; esac
case "$uri" in ipp://?*|ipps://?*|socket://?*) ;; *) die "Specify an ipp, ipps, or socket URI."; esac
case "$uri" in *'@'*|*'?'*|*'#'*|*' '*|*'
'*) die "Credentials, query strings, fragments, and whitespace are not accepted in printer URIs."; esac
case "$driver" in ''|-*|*'
'*) die "Specify an installed driver model or everywhere."; esac
have lpadmin && have lpstat || die "CUPS administrative/client tools are required."
if ! lpstat -r >/dev/null 2>&1; then die "CUPS scheduler is unavailable."; fi
if lpstat -p "$queue" >/dev/null 2>&1; then die "Queue already exists; this script creates queues and will not overwrite one."; fi
if [ "$driver" = everywhere ]; then
    case "$uri" in ipp://*|ipps://*) ;; *) die "IPP Everywhere requires an ipp or ipps URI."; esac
else
    have lpinfo || die "lpinfo is needed to verify the approved driver."
    driver_found=$(lpinfo -m 2>/dev/null | awk -v model="$driver" '$1==model {print "yes"; exit}')
    [ "$driver_found" = yes ] || die "The requested model is not listed by lpinfo -m."
    finding Warn legacy-driver "Installed PPD/model drivers are deprecated by CUPS; use IPP Everywhere where supported."
fi
fact queue "$queue"
fact endpoint "$uri"
fact driver "$driver"
finding Info rollback "To remove this newly created queue after reviewing pending jobs: lpadmin -x $queue. Removal itself is not performed by this script."
if [ "$APPLY" = 1 ]; then require_root; fi
change create-cups-queue lpadmin -p "$queue" -E -v "$uri" -m "$driver" -o printer-is-shared=false
if [ "$APPLY" = 1 ]; then
    capture queue-state lpstat -p "$queue"
    capture queue-accepting lpstat -a "$queue"
fi

finish
