#!/bin/sh
# What it does
# Audit effective SSH access policy and selected public-key fingerprints and file permissions.
# Available flags
# --help; --output-dir DIRECTORY; --user NAME (optional local account); --client-address IP and --client-host HOST (both needed with user for Match evaluation).
# How it works
# Uses the shared read-only collector, preserving this entrypoint's flags and report scope.

SCRIPT_NAME=audit-ssh-access
DESCRIPTION='Audit effective SSH access policy and selected public-key fingerprints and file permissions.'
FLAGS='--user NAME (optional local account); --client-address IP and --client-host HOST (both needed with user for Match evaluation).'
OPTIONS='user client-address client-host'
MUTATING=false

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 2
LIBRARY_ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd) || exit 2
[ -r "$LIBRARY_ROOT/lib/common.inc" ] || { printf '%s\n' 'Missing Linux/lib/common.inc; copy the complete Linux folder.' >&2; exit 2; }
. "$LIBRARY_ROOT/lib/common.inc"
script_init "$@"
store_args "$@"

[ -r "$LIBRARY_ROOT/lib/ssh-audit.inc" ] || die "Missing Linux/lib/ssh-audit.inc; copy the complete Linux folder."
. "$LIBRARY_ROOT/lib/ssh-audit.inc"
collect_ssh_audit access

finish
