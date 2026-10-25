#!/bin/sh
# What it does
# Export sanitized CUPS queue and security metadata into the private report directory.
# Available flags
# --help; --output-dir DIRECTORY; No script-specific flags; this is a metadata export, not a complete restorable CUPS backup.
# How it works
# Uses the shared read-only collector, preserving this entrypoint's flags and report scope.

SCRIPT_NAME=export-print-configuration
DESCRIPTION='Export sanitized CUPS queue and security metadata into the private report directory.'
FLAGS='No script-specific flags; this is a metadata export, not a complete restorable CUPS backup.'
OPTIONS=''
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

[ -r "$LIBRARY_ROOT/lib/cups-audit.inc" ] || die "Missing Linux/lib/cups-audit.inc; copy the complete Linux folder."
. "$LIBRARY_ROOT/lib/cups-audit.inc"
collect_cups_audit export

finish
