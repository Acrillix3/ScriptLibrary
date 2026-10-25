#!/bin/sh
# What it does
# List CUPS queues, default destination, accepting state, device endpoints, and installed driver choices.
# Available flags
# --help; --output-dir DIRECTORY; --queue NAME optionally limits queue details; installed driver listing remains global.
# How it works
# Uses the shared read-only collector, preserving this entrypoint's flags and report scope.

SCRIPT_NAME=get-printer-inventory
DESCRIPTION='List CUPS queues, default destination, accepting state, device endpoints, and installed driver choices.'
FLAGS='--queue NAME optionally limits queue details; installed driver listing remains global.'
OPTIONS=queue
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

[ -r "$LIBRARY_ROOT/lib/cups-audit.inc" ] || die "Missing Linux/lib/cups-audit.inc; copy the complete Linux folder."
. "$LIBRARY_ROOT/lib/cups-audit.inc"
collect_cups_audit inventory

finish
